from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
import time


@dataclass
class FlagMatch:
    """Represents a discovered CTF or forensic flag."""
    flag: str
    pattern_name: str
    source: str
    encoding: str
    packet_id: Optional[int] = None
    stream_id: Optional[int] = None
    offset: Optional[int] = None
    context: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flag": self.flag,
            "pattern_name": self.pattern_name,
            "source": self.source,
            "encoding": self.encoding,
            "packet_id": self.packet_id,
            "stream_id": self.stream_id,
            "offset": self.offset,
            "context": self.context,
            "timestamp": self.timestamp
        }


@dataclass
class ExtractedFile:
    """Represents a carved or reconstructed file from network traffic."""
    filename: str
    file_type: str
    extension: str
    size_bytes: int
    source_protocol: str
    disk_path: str
    sha256: str
    stream_id: Optional[int] = None
    packet_id: Optional[int] = None
    has_stego_warning: bool = False
    stego_details: str = ""
    preview_snippet: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "file_type": self.file_type,
            "extension": self.extension,
            "size_bytes": self.size_bytes,
            "source_protocol": self.source_protocol,
            "disk_path": self.disk_path,
            "sha256": self.sha256,
            "stream_id": self.stream_id,
            "packet_id": self.packet_id,
            "has_stego_warning": self.has_stego_warning,
            "stego_details": self.stego_details,
            "preview_snippet": self.preview_snippet,
            "timestamp": self.timestamp
        }


@dataclass
class StreamInfo:
    """Represents a TCP or UDP session stream."""
    stream_id: int
    protocol: str
    app_protocol: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    packet_count: int = 0
    total_bytes: int = 0
    client_payload: bytearray = field(default_factory=bytearray)
    server_payload: bytearray = field(default_factory=bytearray)
    start_time: float = 0.0
    end_time: float = 0.0
    app_detection: str = "transport"

    @property
    def flow_key(self) -> tuple:
        # Canonical flow representation (sorted endpoint pairs)
        ep1 = (self.src_ip, self.src_port)
        ep2 = (self.dst_ip, self.dst_port)
        return (self.protocol, min(ep1, ep2), max(ep1, ep2))


@dataclass
class AnalysisSummary:
    """Consolidated summary metrics of a capture analysis run."""
    capture_file: str
    file_size_bytes: int = 0
    total_packets: int = 0
    processed_packets: int = 0
    total_streams: int = 0
    protocol_counts: Dict[str, int] = field(default_factory=dict)
    flags_count: int = 0
    files_count: int = 0
    stego_alerts_count: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    duration_seconds: float = 0.0
    error_count: int = 0
    transport_counts: Dict[str, int] = field(default_factory=dict)
    protocol_details: List[Dict[str, Any]] = field(default_factory=list)
    protocol_details_omitted: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capture_file": self.capture_file,
            "file_size_bytes": self.file_size_bytes,
            "total_packets": self.total_packets,
            "processed_packets": self.processed_packets,
            "total_streams": self.total_streams,
            "protocol_counts": self.protocol_counts,
            "transport_counts": self.transport_counts,
            "protocol_details": self.protocol_details,
            "protocol_details_omitted": self.protocol_details_omitted,
            "flags_count": self.flags_count,
            "files_count": self.files_count,
            "stego_alerts_count": self.stego_alerts_count,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": round(self.duration_seconds, 2),
            "error_count": self.error_count
        }
