import base64
import binascii
import codecs
import re
import urllib.parse
import zlib
from typing import Generator, Tuple, Set

# Regex helpers for detecting encoded tokens inside arbitrary text
BASE64_TOKEN_RE = re.compile(rb'[A-Za-z0-9+/]{12,}={0,2}|[A-Za-z0-9-_]{12,}={0,2}')
HEX_TOKEN_RE = re.compile(rb'(?:[0-9a-fA-F]{2}){4,}')
ESCAPED_HEX_RE = re.compile(rb'(?:\\x[0-9a-fA-F]{2}){3,}')
SPACED_HEX_RE = re.compile(rb'(?:[0-9a-fA-F]{2}[ \t]+){3,}[0-9a-fA-F]{2}')


def is_mostly_printable(data: bytes, threshold: float = 0.70) -> bool:
    """Check if byte sequence consists predominantly of ASCII printable characters."""
    if not data:
        return False
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    return (printable / len(data)) >= threshold


def try_decompress_zlib(data: bytes) -> bytes:
    """Attempt zlib / gzip / raw deflate decompression."""
    if len(data) < 4:
        return b""
    # Try Gzip
    if data.startswith(b"\x1f\x8b"):
        try:
            return zlib.decompress(data, 16 + zlib.MAX_WBITS)
        except Exception:
            pass
    # Try Zlib / Deflate
    try:
        return zlib.decompress(data)
    except Exception:
        pass
    try:
        return zlib.decompress(data, -zlib.MAX_WBITS)
    except Exception:
        pass
    return b""


def try_decode_base64(token: bytes) -> bytes:
    """Attempt standard and URL-safe Base64 decoding with padding fixup."""
    s = token.strip()
    if not s or len(s) < 4:
        return b""
    if not re.fullmatch(rb'[A-Za-z0-9+/=_-]+', s):
        return b""
    # Normalize length with padding
    missing_padding = len(s) % 4
    if missing_padding:
        s += b"=" * (4 - missing_padding)
    # Try standard
    try:
        res = base64.b64decode(s, validate=True)
        if len(res) >= 3 and is_mostly_printable(res, threshold=0.60):
            return res
    except Exception:
        pass
    # Try url-safe
    try:
        res = base64.urlsafe_b64decode(s)
        if len(res) >= 3 and is_mostly_printable(res, threshold=0.60):
            return res
    except Exception:
        pass
    return b""


def try_decode_hex(token: bytes) -> bytes:
    """Attempt hex decoding of raw, spaced, or escaped hex strings."""
    cleaned = token.strip()
    if b"\\x" in cleaned:
        cleaned = cleaned.replace(b"\\x", b"")
    elif b" " in cleaned or b"\t" in cleaned:
        cleaned = re.sub(rb'\s+', b'', cleaned)

    if len(cleaned) < 4 or len(cleaned) % 2 != 0:
        return b""

    if not re.fullmatch(rb'[0-9a-fA-F]+', cleaned):
        return b""

    try:
        res = binascii.unhexlify(cleaned)
        if len(res) >= 3 and is_mostly_printable(res, threshold=0.60):
            return res
    except Exception:
        pass
    return b""


def try_decode_rot13(data: bytes) -> bytes:
    """Attempt ROT13 transformation if data is printable text."""
    if not is_mostly_printable(data, threshold=0.85):
        return b""
    try:
        text = data.decode("latin-1")
        rot = codecs.decode(text, "rot_13")
        return rot.encode("latin-1")
    except Exception:
        return b""


def try_decode_url(data: bytes) -> bytes:
    """Attempt percent-encoding (URL) decoding."""
    if b"%" not in data:
        return b""
    try:
        text = data.decode("latin-1")
        unquoted = urllib.parse.unquote(text)
        if unquoted != text:
            return unquoted.encode("latin-1")
    except Exception:
        pass
    return b""


REVERSED_FLAG_TOKEN_RE = re.compile(rb'\}[A-Za-z0-9_\-\.\+\=/!@#\$%\^&\*\?~ ]{3,100}\{[a-zA-Z0-9_\-\.\$]{2,25}')


def try_decode_reversed(data: bytes) -> bytes:
    """Attempt byte reversal if it looks like reversed flag text (e.g. starts with '}' or ends with '{')."""
    s = data.strip()
    if s.endswith(b"{") or s.startswith(b"}"):
        return s[::-1]
    return b""


class MultiLayerDecoder:
    """
    Recursively extracts and decodes multi-layer payloads (Plain, Base64, Hex, URL, Gzip, ROT13, Reverse)
    yielding (bytes, encoding_path_str).
    """
    def __init__(self, max_depth: int = 3, max_payload_bytes: int = 5_000_000):
        self.max_depth = max_depth
        self.max_payload_bytes = max_payload_bytes

    def decode_all(self, payload: bytes) -> Generator[Tuple[bytes, str], None, None]:
        """
        Yields (decoded_content, 'Encoding Path') for all successfully extracted/decoded branches.
        """
        if not payload:
            return

        # Always yield the original payload first
        yield payload, "Plaintext"

        seen_hashes: Set[int] = {hash(payload)}
        queue = [(payload, "Plaintext", 0)]

        while queue:
            current, path, depth = queue.pop(0)
            if depth >= self.max_depth:
                continue

            # 1. URL Unquote
            if b"%" in current:
                url_dec = try_decode_url(current)
                if url_dec and hash(url_dec) not in seen_hashes:
                    seen_hashes.add(hash(url_dec))
                    new_path = f"{path} -> URL" if path != "Plaintext" else "URL"
                    yield url_dec, new_path
                    queue.append((url_dec, new_path, depth + 1))

            # 2. Decompress Gzip / Zlib / Deflate
            decompressed = try_decompress_zlib(current)
            if decompressed and hash(decompressed) not in seen_hashes:
                seen_hashes.add(hash(decompressed))
                new_path = f"{path} -> Decompressed" if path != "Plaintext" else "Decompressed"
                yield decompressed, new_path
                queue.append((decompressed, new_path, depth + 1))

            # 3. ROT13
            rot13_val = try_decode_rot13(current)
            if rot13_val and rot13_val != current and hash(rot13_val) not in seen_hashes:
                seen_hashes.add(hash(rot13_val))
                new_path = f"{path} -> ROT13" if path != "Plaintext" else "ROT13"
                yield rot13_val, new_path
                queue.append((rot13_val, new_path, depth + 1))

            # 4. Reversed text
            for rev_m in REVERSED_FLAG_TOKEN_RE.finditer(current):
                rev_tok = rev_m.group(0)[::-1]
                if hash(rev_tok) not in seen_hashes:
                    seen_hashes.add(hash(rev_tok))
                    new_path = f"{path} -> Reversed(token)" if path != "Plaintext" else "Reversed(token)"
                    yield rev_tok, new_path
                    queue.append((rev_tok, new_path, depth + 1))

            rev_val = try_decode_reversed(current)
            if rev_val and rev_val != current and hash(rev_val) not in seen_hashes:
                seen_hashes.add(hash(rev_val))
                new_path = f"{path} -> Reversed" if path != "Plaintext" else "Reversed"
                yield rev_val, new_path
                queue.append((rev_val, new_path, depth + 1))

            # 5. Extract Base64 candidates (both full string and embedded tokens)
            b64_candidates = []
            if re.fullmatch(rb'[A-Za-z0-9+/=_-]{4,}', current.strip()):
                b64_full = try_decode_base64(current)
                if b64_full:
                    b64_candidates.append((b64_full, "Base64"))

            matches = BASE64_TOKEN_RE.findall(current)
            for token in matches[:30]:
                sub_b64 = try_decode_base64(token)
                if sub_b64:
                    b64_candidates.append((sub_b64, "Base64(token)"))

            for b_cand, b_label in b64_candidates:
                h = hash(b_cand)
                if h not in seen_hashes:
                    seen_hashes.add(h)
                    new_path = f"{path} -> {b_label}" if path != "Plaintext" else b_label
                    yield b_cand, new_path
                    queue.append((b_cand, new_path, depth + 1))

            # 6. Extract Hex candidates (both full and embedded tokens)
            hex_candidates = []
            if re.fullmatch(rb'[0-9a-fA-F]{4,}', current.strip()):
                hex_full = try_decode_hex(current)
                if hex_full:
                    hex_candidates.append((hex_full, "Hex"))

            for h_match in HEX_TOKEN_RE.finditer(current):
                h_tok = h_match.group(0)
                if len(h_tok) >= 8:
                    sub_hex = try_decode_hex(h_tok)
                    if sub_hex:
                        hex_candidates.append((sub_hex, "Hex(token)"))

            for sh_match in SPACED_HEX_RE.finditer(current):
                sub_hex = try_decode_hex(sh_match.group(0))
                if sub_hex:
                    hex_candidates.append((sub_hex, "SpacedHex"))

            for h_cand, h_label in hex_candidates:
                h = hash(h_cand)
                if h not in seen_hashes:
                    seen_hashes.add(h)
                    new_path = f"{path} -> {h_label}" if path != "Plaintext" else h_label
                    yield h_cand, new_path
                    queue.append((h_cand, new_path, depth + 1))

