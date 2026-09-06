import hashlib
import os
import re
import struct
import zlib
from typing import List, Tuple, Optional, Dict
from .models import ExtractedFile
from .steganalysis import SteganalysisEngine


# Common magic byte signatures: (name, extension, header_bytes, footer_bytes_or_none, max_size)
FILE_SIGNATURES = [
    ("PNG Image", ".png", b"\x89PNG\r\n\x1a\n", b"IEND\xae\x42\x60\x82", 20_000_000),
    ("JPEG Image", ".jpg", b"\xff\xd8\xff", b"\xff\xd9", 20_000_000),
    ("GIF Image", ".gif", b"GIF87a", b"\x00\x3b", 10_000_000),
    ("GIF Image", ".gif", b"GIF89a", b"\x00\x3b", 10_000_000),
    ("PDF Document", ".pdf", b"%PDF-", b"%%EOF", 50_000_000),
    ("ZIP Archive", ".zip", b"PK\x03\x04", b"PK\x05\x06", 50_000_000),
    ("7-Zip Archive", ".7z", b"7z\xbc\xaf'\x1c", None, 50_000_000),
    ("GZIP Compressed", ".gz", b"\x1f\x8b\x08", None, 30_000_000),
    ("ELF Executable", ".elf", b"\x7fELF", None, 50_000_000),
    ("Windows Executable", ".exe", b"MZ", None, 50_000_000),
]


def sanitize_filename(name: str) -> str:
    """Sanitize string to safe filesystem filename."""
    cleaned = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', name)
    return cleaned[:80] or "extracted_file"


class FileExtractor:
    """
    Handles protocol-level file reassembly (HTTP, FTP, SMTP, ICMP) and
    signature-based magic-byte carving across raw byte buffers.
    """

    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        self.seen_sha256: set = set()
        self.extracted_count = 0

    def _save_file(
        self,
        data: bytes,
        suggested_name: str,
        file_type: str,
        extension: str,
        source_protocol: str,
        stream_id: Optional[int] = None,
        packet_id: Optional[int] = None
    ) -> Optional[ExtractedFile]:
        """Saves file to disk, computes hash, runs steganography inspection."""
        if not data or len(data) < 4:
            return None

        sha256 = hashlib.sha256(data).hexdigest()
        if sha256 in self.seen_sha256:
            return None
        self.seen_sha256.add(sha256)

        self.extracted_count += 1
        safe_name = sanitize_filename(suggested_name)
        if not safe_name.lower().endswith(extension.lower()):
            safe_name += extension

        # Ensure unique disk filename
        base_name, ext = os.path.splitext(safe_name)
        disk_filename = f"{self.extracted_count:03d}_{base_name}{ext}"
        disk_path = os.path.join(self.output_dir, disk_filename)

        try:
            with open(disk_path, "wb") as f:
                f.write(data)
        except Exception as e:
            return None

        # Steganography check
        has_stego, stego_desc, appended_data = SteganalysisEngine.analyze(data, extension)

        # Snippet for preview
        preview = ""
        try:
            preview = data[:200].decode("utf-8", errors="ignore")
        except Exception:
            pass

        record = ExtractedFile(
            filename=disk_filename,
            file_type=file_type,
            extension=extension,
            size_bytes=len(data),
            source_protocol=source_protocol,
            disk_path=disk_path,
            sha256=sha256,
            stream_id=stream_id,
            packet_id=packet_id,
            has_stego_warning=has_stego,
            stego_details=stego_desc,
            preview_snippet=preview
        )

        return record

    # ==========================================
    # 1. HTTP Protocol Reassembly
    # ==========================================
    def extract_from_http(self, payload: bytes, stream_id: Optional[int] = None) -> List[ExtractedFile]:
        """Reassembles HTTP response bodies, decoding gzip/chunked transfers."""
        extracted: List[ExtractedFile] = []
        if not (payload.startswith(b"HTTP/1.") or b"\r\nHTTP/1." in payload):
            return extracted

        # Split multiple HTTP messages if present
        messages = re.split(rb'(?:\r?\n)(?=HTTP/1\.[01] \d{3})', payload)
        for msg in messages:
            if not msg.startswith(b"HTTP/1."):
                continue

            header_end = msg.find(b"\r\n\r\n")
            if header_end == -1:
                header_end = msg.find(b"\n\n")
                if header_end == -1:
                    continue
                headers_raw = msg[:header_end]
                body = msg[header_end+2:]
            else:
                headers_raw = msg[:header_end]
                body = msg[header_end+4:]

            headers_text = headers_raw.decode("latin-1", errors="ignore")
            headers = {}
            for line in headers_text.splitlines()[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            # De-chunk if chunked
            transfer_encoding = headers.get("transfer-encoding", "").lower()
            if "chunked" in transfer_encoding:
                body = self._dechunk_http_body(body)

            # Decompress if gzip/deflate
            content_encoding = headers.get("content-encoding", "").lower()
            if "gzip" in content_encoding:
                try:
                    body = zlib.decompress(body, 16 + zlib.MAX_WBITS)
                except Exception:
                    pass
            elif "deflate" in content_encoding:
                try:
                    body = zlib.decompress(body)
                except Exception:
                    pass

            if not body or len(body) < 8:
                continue

            # Filename detection from Content-Disposition
            content_disp = headers.get("content-disposition", "")
            suggested_name = f"http_stream_{stream_id or 0}"
            fn_match = re.search(r'filename=["\']?([^"\';\r\n]+)', content_disp, re.IGNORECASE)
            if fn_match:
                suggested_name = fn_match.group(1).strip()

            # Determine type from Content-Type
            content_type = headers.get("content-type", "").lower().split(";")[0].strip()
            ext = ".bin"
            file_type = "HTTP Object"
            if "image/png" in content_type:
                ext = ".png"
                file_type = "PNG Image"
            elif "image/jpeg" in content_type or "image/jpg" in content_type:
                ext = ".jpg"
                file_type = "JPEG Image"
            elif "image/gif" in content_type:
                ext = ".gif"
                file_type = "GIF Image"
            elif "application/pdf" in content_type:
                ext = ".pdf"
                file_type = "PDF Document"
            elif "application/zip" in content_type:
                ext = ".zip"
                file_type = "ZIP Archive"
            elif "text/html" in content_type:
                ext = ".html"
                file_type = "HTML Document"
            elif "text/plain" in content_type:
                ext = ".txt"
                file_type = "Plaintext"
            elif "application/json" in content_type:
                ext = ".json"
                file_type = "JSON Data"
            else:
                # Guess extension from content magic
                carved_ext, carved_type = self._detect_magic(body)
                if carved_ext:
                    ext = carved_ext
                    file_type = carved_type

            rec = self._save_file(
                data=body,
                suggested_name=suggested_name,
                file_type=file_type,
                extension=ext,
                source_protocol="HTTP",
                stream_id=stream_id
            )
            if rec:
                extracted.append(rec)

        return extracted

    @staticmethod
    def _dechunk_http_body(data: bytes) -> bytes:
        """Decodes HTTP/1.1 chunked transfer encoding."""
        chunks = bytearray()
        idx = 0
        while idx < len(data):
            crlf = data.find(b"\r\n", idx)
            if crlf == -1:
                break
            line = data[idx:crlf].strip()
            if not line:
                idx = crlf + 2
                continue
            # Chunk size in hex
            chunk_size_str = line.split(b";")[0].strip()
            try:
                chunk_len = int(chunk_size_str, 16)
            except ValueError:
                break
            if chunk_len == 0:
                break
            chunk_start = crlf + 2
            chunk_end = chunk_start + chunk_len
            chunks.extend(data[chunk_start:chunk_end])
            idx = chunk_end + 2
        return bytes(chunks) if chunks else data

    # ==========================================
    # 2. SMTP Protocol Reassembly
    # ==========================================
    def extract_from_smtp(self, payload: bytes, stream_id: Optional[int] = None) -> List[ExtractedFile]:
        """Parses SMTP emails for base64-encoded MIME attachments."""
        extracted: List[ExtractedFile] = []
        if b"Content-Disposition:" not in payload and b"boundary=" not in payload:
            return extracted

        # Search for base64 attachments in MIME parts
        parts = re.split(rb'--[a-zA-Z0-9_-]+', payload)
        for part in parts:
            if b"Content-Disposition:" in part or b"Content-Transfer-Encoding: base64" in part:
                # Find filename
                fn_match = re.search(rb'filename=["\']?([^"\'\r\n]+)', part, re.IGNORECASE)
                suggested_name = fn_match.group(1).decode("latin-1", errors="ignore") if fn_match else f"smtp_stream_{stream_id or 0}"

                # Find body after double newline
                split_idx = part.find(b"\r\n\r\n")
                if split_idx != -1:
                    raw_body = part[split_idx+4:].strip()
                    # Try base64 decode
                    try:
                        import base64
                        cleaned_b64 = re.sub(rb'[\r\n\s]+', b'', raw_body)
                        decoded = base64.b64decode(cleaned_b64, validate=False)
                        if len(decoded) > 10:
                            ext, ftype = self._detect_magic(decoded)
                            rec = self._save_file(
                                data=decoded,
                                suggested_name=suggested_name,
                                file_type=ftype or "Email Attachment",
                                extension=ext or ".bin",
                                source_protocol="SMTP",
                                stream_id=stream_id
                            )
                            if rec:
                                extracted.append(rec)
                    except Exception:
                        pass
        return extracted

    # ==========================================
    # 3. Magic-Byte Carving
    # ==========================================
    def carve_all(self, data: bytes, source_label: str, stream_id: Optional[int] = None, packet_id: Optional[int] = None) -> List[ExtractedFile]:
        """
        Scans byte buffer for known magic headers and carves files.
        """
        extracted: List[ExtractedFile] = []
        if not data or len(data) < 16:
            return extracted

        for ftype, fext, header, footer, max_len in FILE_SIGNATURES:
            start_pos = 0
            while True:
                idx = data.find(header, start_pos)
                if idx == -1:
                    break

                carved_bytes = b""
                if footer:
                    if fext == ".zip":
                        # For ZIP, find EOCD
                        eocd_idx = data.find(b"PK\x05\x06", idx)
                        if eocd_idx != -1 and eocd_idx + 22 <= len(data):
                            comment_len = struct.unpack("<H", data[eocd_idx+20:eocd_idx+22])[0]
                            end_offset = min(len(data), eocd_idx + 22 + comment_len)
                            carved_bytes = data[idx:end_offset]
                    elif fext == ".png":
                        # For PNG, find IEND
                        iend_idx = data.find(b"IEND\xae\x42\x60\x82", idx)
                        if iend_idx != -1:
                            # Also carve any appended data up to max 1MB or next header
                            end_offset = iend_idx + 8
                            # Check if trailer data exists
                            remaining = len(data) - end_offset
                            if 0 < remaining < 1_000_000:
                                end_offset = len(data)
                            carved_bytes = data[idx:end_offset]
                    else:
                        f_idx = data.find(footer, idx + len(header))
                        if f_idx != -1:
                            end_offset = min(len(data), f_idx + len(footer))
                            carved_bytes = data[idx:end_offset]
                else:
                    # Header-only carving (ELF, PE, 7z)
                    end_offset = min(len(data), idx + max_len)
                    carved_bytes = data[idx:end_offset]

                if carved_bytes and len(carved_bytes) >= 16:
                    rec = self._save_file(
                        data=carved_bytes,
                        suggested_name=f"carved_offset_{idx}{fext}",
                        file_type=ftype,
                        extension=fext,
                        source_protocol=f"Carver ({source_label})",
                        stream_id=stream_id,
                        packet_id=packet_id
                    )
                    if rec:
                        extracted.append(rec)

                start_pos = idx + len(header)

        return extracted

    @staticmethod
    def _detect_magic(data: bytes) -> Tuple[str, str]:
        """Returns (extension, type_name) based on header bytes."""
        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            return ".png", "PNG Image"
        if data.startswith(b"\xff\xd8\xff"):
            return ".jpg", "JPEG Image"
        if data.startswith((b"GIF87a", b"GIF89a")):
            return ".gif", "GIF Image"
        if data.startswith(b"%PDF-"):
            return ".pdf", "PDF Document"
        if data.startswith(b"PK\x03\x04"):
            return ".zip", "ZIP Archive"
        if data.startswith(b"7z\xbc\xaf'\x1c"):
            return ".7z", "7-Zip Archive"
        if data.startswith(b"\x1f\x8b\x08"):
            return ".gz", "GZIP Archive"
        if data.startswith(b"\x7fELF"):
            return ".elf", "ELF Binary"
        if data.startswith(b"MZ"):
            return ".exe", "Windows Executable"
        return "", ""

