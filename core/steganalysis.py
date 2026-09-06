import math
import struct
from typing import Tuple, Optional
from io import BytesIO

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data (0.0 to 8.0)."""
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    total = len(data)
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


class SteganalysisEngine:
    """
    Checks files for appended EOF data, embedded archives, and LSB anomalies.
    """

    @staticmethod
    def analyze(data: bytes, file_ext: str = "") -> Tuple[bool, str, Optional[bytes]]:
        """
        Analyzes binary file data.
        Returns: (has_warning, details_string, extracted_appended_data)
        """
        if not data or len(data) < 16:
            return False, "", None

        ext = file_ext.lower().lstrip(".")

        # 1. Check for PNG
        if data.startswith(b"\x89PNG\r\n\x1a\n") or ext == "png":
            return SteganalysisEngine._check_png(data)

        # 2. Check for JPEG
        if (data.startswith(b"\xff\xd8") and b"\xff\xd9" in data) or ext in ("jpg", "jpeg"):
            return SteganalysisEngine._check_jpeg(data)

        # 3. Check for GIF
        if data.startswith((b"GIF87a", b"GIF89a")) or ext == "gif":
            return SteganalysisEngine._check_gif(data)

        # 4. Check for ZIP
        if data.startswith(b"PK\x03\x04") or ext == "zip":
            return SteganalysisEngine._check_zip(data)

        # 5. Check for PDF
        if data.startswith(b"%PDF") or ext == "pdf":
            return SteganalysisEngine._check_pdf(data)

        # Generic check for embedded PK archive in any non-zip file
        pk_idx = data.find(b"PK\x03\x04", 16)
        if pk_idx > 0:
            trailer = data[pk_idx:]
            return True, f"Suspicious embedded ZIP archive detected at offset {pk_idx} ({len(trailer)} bytes)", trailer

        return False, "", None

    @staticmethod
    def _check_png(data: bytes) -> Tuple[bool, str, Optional[bytes]]:
        iend_marker = b"IEND\xae\x42\x60\x82"
        idx = data.find(iend_marker)
        if idx != -1:
            eof_offset = idx + len(iend_marker)
            if eof_offset < len(data):
                extra = data[eof_offset:]
                entropy = calculate_entropy(extra)
                desc = f"Appended data after PNG IEND chunk: {len(extra)} bytes at offset {eof_offset} (Entropy: {entropy:.2f}/8.0)"
                if extra.startswith(b"PK\x03\x04"):
                    desc += " [Embedded ZIP archive detected!]"
                return True, desc, extra

        # Check LSB if PIL available
        if HAS_PIL:
            lsb_warning = SteganalysisEngine._check_lsb_pil(data)
            if lsb_warning:
                return True, lsb_warning, None

        return False, "", None

    @staticmethod
    def _check_jpeg(data: bytes) -> Tuple[bool, str, Optional[bytes]]:
        # JPEG ends with \xff\xd9 (EOI marker). We find the LAST occurrence of \xff\xd9
        idx = data.rfind(b"\xff\xd9")
        if idx != -1:
            eof_offset = idx + 2
            if eof_offset < len(data):
                extra = data[eof_offset:]
                if len(extra) > 4:  # Allow slight trailing null padding
                    entropy = calculate_entropy(extra)
                    desc = f"Appended data after JPEG EOI marker: {len(extra)} bytes at offset {eof_offset} (Entropy: {entropy:.2f}/8.0)"
                    if extra.startswith(b"PK\x03\x04"):
                        desc += " [Embedded ZIP archive detected!]"
                    return True, desc, extra
        return False, "", None

    @staticmethod
    def _check_gif(data: bytes) -> Tuple[bool, str, Optional[bytes]]:
        # GIF ends with trailer 0x3B
        idx = data.rfind(b"\x3b")
        if idx != -1:
            eof_offset = idx + 1
            if eof_offset < len(data):
                extra = data[eof_offset:]
                if len(extra) > 4:
                    return True, f"Appended data after GIF trailer (0x3B): {len(extra)} bytes", extra
        return False, "", None

    @staticmethod
    def _check_zip(data: bytes) -> Tuple[bool, str, Optional[bytes]]:
        # End of central directory record signature PK\x05\x06
        idx = data.rfind(b"PK\x05\x06")
        if idx != -1 and idx + 22 <= len(data):
            try:
                # Offset 20 is comment length (2 bytes unsigned short little-endian)
                comment_len = struct.unpack("<H", data[idx+20:idx+22])[0]
                expected_end = idx + 22 + comment_len
                if expected_end < len(data):
                    extra = data[expected_end:]
                    return True, f"Appended data after ZIP EOCD: {len(extra)} bytes", extra
            except Exception:
                pass
        return False, "", None

    @staticmethod
    def _check_pdf(data: bytes) -> Tuple[bool, str, Optional[bytes]]:
        idx = data.rfind(b"%%EOF")
        if idx != -1:
            eof_offset = idx + 5
            # Skip trailing whitespace/newlines
            while eof_offset < len(data) and data[eof_offset:eof_offset+1] in b"\r\n \t":
                eof_offset += 1
            if eof_offset < len(data):
                extra = data[eof_offset:]
                if len(extra) > 8:
                    return True, f"Appended data after PDF %%EOF: {len(extra)} bytes", extra
        return False, "", None

    @staticmethod
    def _check_lsb_pil(data: bytes) -> Optional[str]:
        """Examine LSB entropy of RGB pixel planes."""
        if not HAS_PIL:
            return None
        try:
            im = Image.open(BytesIO(data))
            if im.mode not in ("RGB", "RGBA"):
                return None
            if hasattr(im, "get_flattened_data"):
                raw_px = list(im.get_flattened_data())[:6000]
                # If flattened, each pixel is 3 or 4 sequential values
                channels = 3 if im.mode == "RGB" else 4
                pixels = [raw_px[i:i+channels] for i in range(0, len(raw_px), channels)]
            else:
                pixels = list(im.getdata())[:2000]
            if not pixels:
                return None
            lsb_bits = []
            for px in pixels:
                # px is tuple (R, G, B) or (R, G, B, A)
                lsb_bits.append(px[0] & 1)
                lsb_bits.append(px[1] & 1)
                lsb_bits.append(px[2] & 1)
            ones = sum(lsb_bits)
            ratio = ones / len(lsb_bits)
            # Normal natural images usually have biased LSB distributions; encrypted/random LSB payload is ~0.50 with high entropy
            if 0.49 <= ratio <= 0.51 and len(lsb_bits) > 3000:
                return f"LSB Anomaly: near-perfect 50/50 bit distribution ({ratio:.3f}) across RGB planes (Potential LSB Stego)"
        except Exception:
            pass
        return None

