from typing import Dict, Tuple, Optional
from .models import StreamInfo
from .protocols import detect_protocol


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
        """Identify signatures first, then transport-specific service hints."""
        return detect_protocol(proto, src_port, dst_port, payload)[0]

    def process_packet(
        self,
        proto: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        payload: bytes,
        timestamp: float,
        is_syn: bool = False,
        app_protocol: Optional[str] = None,
        detection: Optional[str] = None
    ) -> StreamInfo:
        """
        Updates stream tracking for an incoming packet.
        """
        flow_key = self._get_flow_key(proto, src_ip, src_port, dst_ip, dst_port)
        candidate, evidence = detect_protocol(proto, src_port, dst_port, payload)
        if app_protocol is not None:
            candidate = app_protocol
            evidence = detection or evidence

        if flow_key not in self.streams:
            stream_id = self.next_stream_id
            self.next_stream_id += 1

            self.streams[flow_key] = StreamInfo(
                stream_id=stream_id,
                protocol=proto,
                app_protocol=candidate,
                app_detection=evidence,
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

        rank = {"transport": 0, "port": 1, "signature": 2, "dissector": 3}
        if rank[evidence] > rank[stream.app_detection] or (
            rank[evidence] == rank[stream.app_detection] and candidate not in ("TCP", "UDP", "TLS", "HTTPS / TLS")
        ):
            stream.app_protocol = candidate
            stream.app_detection = evidence

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
