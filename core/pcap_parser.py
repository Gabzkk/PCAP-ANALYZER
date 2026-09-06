import os
import re
from typing import Generator, Tuple, Optional, Dict, Any

from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP, DNS, Raw


PCAP_MAGIC_BYTES = [
    b"\xd4\xc3\xb2\xa1",  # Standard pcap (little endian)
    b"\xa1\xb2\xc3\xd4",  # Standard pcap (big endian)
    b"\x4d\x3c\xb2\xa1",  # Nanosecond pcap (little endian)
    b"\xa1\xb2\x3c\x4d",  # Nanosecond pcap (big endian)
    b"\x0a\x0d\x0d\x0a",  # pcapng Section Header Block
]


def validate_capture_file(filepath: str) -> Tuple[bool, str, str]:
    """
    Validates if a file exists and is a recognized capture or dump format.
    Returns: (is_valid, format_type, error_message)
    """
    if not os.path.exists(filepath):
        return False, "Unknown", f"File does not exist: {filepath}"

    file_size = os.path.getsize(filepath)
    if file_size == 0:
        return False, "Unknown", "File is empty (0 bytes)."

    try:
        with open(filepath, "rb") as f:
            header = f.read(32)
    except Exception as e:
        return False, "Unknown", f"Failed to read file: {e}"

    # Check PCAP/PCAPNG magic bytes
    for magic in PCAP_MAGIC_BYTES:
        if header.startswith(magic):
            fmt = "PCAP-NG" if magic == b"\x0a\x0d\x0d\x0a" else "PCAP"
            return True, fmt, ""

    # Check if raw text / log / hex dump
    try:
        sample_text = header.decode("utf-8", errors="strict")
        if sample_text.isprintable() or "\n" in sample_text or "\r" in sample_text:
            return True, "Text Dump", ""
    except UnicodeDecodeError:
        pass

    # Allow fallback attempt for scapy
    return True, "Capture/Binary", ""


class StreamingCaptureParser:
    """
    Memory-efficient streaming parser for PCAP, PCAPNG, and text network dumps.
    """

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.file_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0

    def parse_packets(self) -> Generator[Dict[str, Any], None, None]:
        """
        Yields normalized packet dictionary for each packet in capture:
        {
            'packet_id': int,
            'timestamp': float,
            'proto': str,
            'src_ip': str,
            'src_port': int,
            'dst_ip': str,
            'dst_port': int,
            'payload': bytes,
            'summary': str,
            'is_syn': bool
        }
        """
        is_valid, fmt, err = validate_capture_file(self.filepath)
        if not is_valid:
            raise ValueError(err)

        if fmt == "Text Dump":
            yield from self._parse_text_dump()
            return

        # Scapy PcapReader for streaming
        packet_id = 0
        with PcapReader(self.filepath) as pcap_reader:
            for pkt in pcap_reader:
                packet_id += 1
                pkt_dict = self._normalize_scapy_packet(pkt, packet_id)
                if pkt_dict:
                    yield pkt_dict

    def _normalize_scapy_packet(self, pkt, packet_id: int) -> Optional[Dict[str, Any]]:
        timestamp = float(pkt.time) if hasattr(pkt, "time") else 0.0

        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif IPv6 in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst

        proto = "IP"
        src_port = 0
        dst_port = 0
        is_syn = False
        payload = b""

        if TCP in pkt:
            proto = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flags = pkt[TCP].flags
            is_syn = bool(flags & 0x02)
            if Raw in pkt:
                payload = bytes(pkt[Raw].load)
        elif UDP in pkt:
            proto = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            if DNS in pkt:
                proto = "DNS"
                # If DNS layer present, capture raw payload or serialized DNS
                try:
                    payload = bytes(pkt[DNS])
                except Exception:
                    pass
            elif Raw in pkt:
                payload = bytes(pkt[Raw].load)
        elif ICMP in pkt:
            proto = "ICMP"
            if Raw in pkt:
                payload = bytes(pkt[Raw].load)
        else:
            if Raw in pkt:
                payload = bytes(pkt[Raw].load)

        summary_str = f"#{packet_id} {proto} {src_ip}:{src_port} -> {dst_ip}:{dst_port} len={len(payload)}"

        return {
            "packet_id": packet_id,
            "timestamp": timestamp,
            "proto": proto,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "payload": payload,
            "summary": summary_str,
            "is_syn": is_syn
        }

    def _parse_text_dump(self) -> Generator[Dict[str, Any], None, None]:
        """Parses plain text dumps / logs containing packet hex or strings."""
        packet_id = 0
        with open(self.filepath, "rb") as f:
            for line in f:
                packet_id += 1
                yield {
                    "packet_id": packet_id,
                    "timestamp": 0.0,
                    "proto": "TEXT",
                    "src_ip": "127.0.0.1",
                    "src_port": 0,
                    "dst_ip": "127.0.0.1",
                    "dst_port": 0,
                    "payload": line,
                    "summary": f"Line #{packet_id} (Text Dump)",
                    "is_syn": False
                }

