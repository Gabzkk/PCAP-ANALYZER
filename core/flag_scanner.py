import json
import os
import re
from typing import List, Dict, Any, Optional, Set
from .models import FlagMatch
from .decoders import MultiLayerDecoder


class FlagScanner:
    """
    High-performance CTF & forensic flag scanner supporting regex patterns
    across multi-layer decodings (plaintext, base64, hex, url, gzip, rot13).
    """

    def __init__(self, patterns_path: Optional[str] = None):
        self.patterns: List[Dict[str, Any]] = []
        self.compiled_patterns: List[tuple] = []  # [(name, compiled_regex_bytes, description)]
        self.decoder = MultiLayerDecoder(max_depth=3)
        self.seen_flags: Set[str] = set()

        if patterns_path and os.path.exists(patterns_path):
            self.load_patterns_from_file(patterns_path)
        else:
            self._load_fallback_patterns()

    def _load_fallback_patterns(self):
        fallback = [
            {"name": "Hack The Box", "pattern": r"HTB\{[^}\r\n]+\}", "enabled": True},
            {"name": "TryHackMe", "pattern": r"THM\{[^}\r\n]+\}", "enabled": True},
            {"name": "H4G", "pattern": r"H4G\{[^}\r\n]+\}", "enabled": True},
            {"name": "h4g", "pattern": r"h4g\{[^}\r\n]+\}", "enabled": True},
            {"name": "picoCTF", "pattern": r"[Pp]ico[Cc][Tt][Ff]\{[^}\r\n]+\}", "enabled": True},
            {"name": "Standard Flag", "pattern": r"(?:flag|FLAG)\{[^}\r\n]+\}", "enabled": True},
            {"name": "CTF generic", "pattern": r"CTF\{[^}\r\n]+\}", "enabled": True},
            {"name": "canyouhackit", "pattern": r"canyouhackit\{[^}\r\n]+\}", "enabled": True},
            {"name": "Generic Flag Pattern", "pattern": r"[a-zA-Z0-9_\-\.\$]{2,25}\{[a-zA-Z0-9_\-\.\+\=/!@#\$%\^&\*\?~ ]{4,120}\}", "enabled": True}
        ]
        self.set_patterns(fallback)

    def load_patterns_from_file(self, filepath: str):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                self.set_patterns(data)
        except Exception as e:
            self._load_fallback_patterns()

    def save_patterns_to_file(self, filepath: str):
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.patterns, f, indent=2)

    def set_patterns(self, pattern_list: List[Dict[str, Any]]):
        self.patterns = pattern_list
        self.compiled_patterns = []
        for p in pattern_list:
            if p.get("enabled", True):
                try:
                    pat_str = p["pattern"]
                    # Compile byte-level regex
                    flags = re.IGNORECASE if p.get("ignore_case", False) else 0
                    compiled = re.compile(pat_str.encode("utf-8"), flags)
                    self.compiled_patterns.append((p.get("name", "Custom"), compiled, p.get("description", "")))
                except re.error:
                    pass

    def add_custom_pattern(self, name: str, pattern_str: str, description: str = "", ignore_case: bool = False) -> bool:
        try:
            flags = re.IGNORECASE if ignore_case else 0
            compiled = re.compile(pattern_str.encode("utf-8"), flags)
            self.patterns.append({
                "name": name,
                "pattern": pattern_str,
                "enabled": True,
                "description": description,
                "ignore_case": ignore_case
            })
            self.compiled_patterns.append((name, compiled, description))
            return True
        except re.error:
            return False

    def reset_seen(self):
        self.seen_flags.clear()

    def scan_bytes(
        self,
        payload: bytes,
        source: str,
        packet_id: Optional[int] = None,
        stream_id: Optional[int] = None,
        allow_duplicates: bool = False
    ) -> List[FlagMatch]:
        """
        Scans binary payload across all decoder branches against compiled patterns.
        """
        if not payload or not self.compiled_patterns:
            return []

        results: List[FlagMatch] = []

        for decoded_data, encoding_path in self.decoder.decode_all(payload):
            if not decoded_data:
                continue

            for name, regex_pat, _ in self.compiled_patterns:
                for match in regex_pat.finditer(decoded_data):
                    matched_bytes = match.group(0)
                    try:
                        flag_str = matched_bytes.decode("utf-8", errors="replace")
                    except Exception:
                        flag_str = str(matched_bytes)

                    # Deduplication check: prioritize more specific patterns over generic
                    dedup_key = f"{flag_str}:{encoding_path}"
                    if not allow_duplicates and dedup_key in self.seen_flags:
                        continue
                    self.seen_flags.add(dedup_key)

                    # Context snippet around the flag in the decoded buffer
                    start_idx = max(0, match.start() - 30)
                    end_idx = min(len(decoded_data), match.end() + 30)
                    raw_context = decoded_data[start_idx:end_idx]
                    try:
                        context_str = raw_context.decode("utf-8", errors="replace").replace("\r", " ").replace("\n", " ")
                    except Exception:
                        context_str = repr(raw_context)

                    results.append(FlagMatch(
                        flag=flag_str,
                        pattern_name=name,
                        source=source,
                        encoding=encoding_path,
                        packet_id=packet_id,
                        stream_id=stream_id,
                        offset=match.start(),
                        context=context_str
                    ))

        return results

