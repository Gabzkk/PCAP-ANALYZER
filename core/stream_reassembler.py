from typing import Dict, Tuple, Optional
from .models import StreamInfo


class StreamReassembler:
    """
    Tracks and reassembles bi-directional TCP and UDP streams from packets.
    """

    def __init__(self):
        # Maps canonical flow key -> StreamInfo
        self.streams: Dict[Tuple, StreamInfo] = {}
        # Maps canonical flow key -> initial client endpoint (ip, port)
        self.flow_initiators: Dict[Tuple, Tuple[str, int]] = {}
        self.next_stream_id = 1

    def _get_flow_key(self, proto: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> Tuple:
        ep1 = (src_ip, src_port)
        ep2 = (dst_ip, dst_port)
        return (proto, min(ep1, ep2), max(ep1, ep2))

    def detect_app_protocol(self, proto: str, src_port: int, dst_port: int, payload: bytes) -> str:
        """Heuristically identify the application protocol."""
        ports = {src_port, dst_port}

        # Check by ports first
        if 80 in ports or 8080 in ports or 8000 in ports or 8888 in ports:
            return "HTTP"
        if 21 in ports:
            return "FTP"
        if 20 in ports:
            return "FTP-DATA"
        if 25 in ports or 587 in ports:
            return "SMTP"
        if 23 in ports:
            return "Telnet"
        if 53 in ports:
            return "DNS"
        if 22 in ports:
            return "SSH"

        # Check by payload signatures
        if payload:
            if payload.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"HTTP/1.")):
                return "HTTP"
            if payload.startswith((b"USER ", b"PASS ", b"220 ", b"331 ")):
                return "FTP"
            if payload.startswith((b"EHLO ", b"HELO ", b"MAIL FROM:", b"RCPT TO:")):
                return "SMTP"
            if payload.startswith(b"SSH-"):
                return "SSH"
            if payload.startswith((b"\xff\xfd", b"\xff\xfb", b"\xff\xfa")):
                return "Telnet"

        return proto

    def process_packet(
        self,
        proto: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        payload: bytes,
        timestamp: float,
        is_syn: bool = False
    ) -> StreamInfo:
        """
        Updates stream tracking for an incoming packet.
        """
        flow_key = self._get_flow_key(proto, src_ip, src_port, dst_ip, dst_port)

        if flow_key not in self.streams:
            stream_id = self.next_stream_id
            self.next_stream_id += 1
            app_proto = self.detect_app_protocol(proto, src_port, dst_port, payload)

            self.streams[flow_key] = StreamInfo(
                stream_id=stream_id,
                protocol=proto,
                app_protocol=app_proto,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                packet_count=0,
                total_bytes=0,
                start_time=timestamp,
                end_time=timestamp
            )
            self.flow_initiators[flow_key] = (src_ip, src_port)

        stream = self.streams[flow_key]
        stream.packet_count += 1
        stream.total_bytes += len(payload)
        stream.end_time = max(stream.end_time, timestamp)

        # Refine app protocol if initial was generic
        if stream.app_protocol in ("TCP", "UDP") and payload:
            refined = self.detect_app_protocol(proto, src_port, dst_port, payload)
            if refined != proto:
                stream.app_protocol = refined

        # Append directional payload
        if payload:
            initiator = self.flow_initiators[flow_key]
            if (src_ip, src_port) == initiator:
                stream.client_payload.extend(payload)
            else:
                stream.server_payload.extend(payload)

        return stream

    def get_all_streams(self) -> Dict[Tuple, StreamInfo]:
        return self.streams

    def reset(self):
        self.streams.clear()
        self.flow_initiators.clear()
        self.next_stream_id = 1

