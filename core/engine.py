import os
import time
from typing import List, Optional, Dict

from PyQt6.QtCore import QThread, pyqtSignal

from .models import FlagMatch, ExtractedFile, AnalysisSummary, StreamInfo
from .pcap_parser import StreamingCaptureParser, validate_capture_file
from .stream_reassembler import StreamReassembler
from .flag_scanner import FlagScanner
from .file_extractor import FileExtractor


class AnalysisEngine(QThread):
    """
    Asynchronous forensic analysis engine running in a dedicated QThread.
    Emits thread-safe Qt signals to update the UI without blocking.
    """

    # Qt Signals
    progress_updated = pyqtSignal(int, int, float, str)  # (current, total, pct, status)
    flag_found = pyqtSignal(object)                     # FlagMatch
    file_extracted = pyqtSignal(object)                 # ExtractedFile
    log_message = pyqtSignal(str, str)                  # (level, message)
    analysis_finished = pyqtSignal(object)              # AnalysisSummary
    error_occurred = pyqtSignal(str)                    # error message

    def __init__(
        self,
        filepaths: List[str],
        output_dir: str,
        flag_scanner: FlagScanner,
        parent=None
    ):
        super().__init__(parent)
        self.filepaths = filepaths
        self.output_dir = output_dir
        self.flag_scanner = flag_scanner
        self._is_stopped = False

        # Accumulators for results across all files processed in this run
        self.found_flags: List[FlagMatch] = []
        self.extracted_files: List[ExtractedFile] = []
        self.total_packets_processed = 0
        self.summary: Optional[AnalysisSummary] = None

    def stop(self):
        """Requests cooperative cancellation of analysis."""
        self._is_stopped = True
        self.log_message.emit("WARNING", "Stop requested by user. Terminating analysis...")

    def run(self):
        """Main thread execution."""
        start_time = time.time()
        self.found_flags.clear()
        self.extracted_files.clear()
        self.total_packets_processed = 0

        self.flag_scanner.reset_seen()

        total_files = len(self.filepaths)
        if total_files == 0:
            self.error_occurred.emit("No capture files specified for analysis.")
            return

        combined_protocol_counts: Dict[str, int] = {}
        total_streams_count = 0
        total_stego_count = 0
        total_size_bytes = 0

        try:
            for file_idx, filepath in enumerate(self.filepaths, 1):
                if self._is_stopped:
                    break

                self.log_message.emit("INFO", f"[{file_idx}/{total_files}] Opening capture: {os.path.basename(filepath)}")
                is_valid, fmt, err = validate_capture_file(filepath)
                if not is_valid:
                    self.log_message.emit("ERROR", f"Validation error for {filepath}: {err}")
                    continue

                fsize = os.path.getsize(filepath)
                total_size_bytes += fsize

                file_output_dir = os.path.join(
                    self.output_dir,
                    os.path.splitext(os.path.basename(filepath))[0]
                )
                file_extractor = FileExtractor(file_output_dir)
                stream_reassembler = StreamReassembler()
                parser = StreamingCaptureParser(filepath)

                # Estimate packet count based on filesize (average 300 bytes per packet)
                est_packets = max(100, fsize // 300)
                pkt_count = 0
                last_progress_emit = 0.0

                # 1. Packet Streaming & Immediate Payload Inspection
                for pkt_info in parser.parse_packets():
                    if self._is_stopped:
                        break

                    pkt_count += 1
                    self.total_packets_processed += 1
                    proto = pkt_info["proto"]
                    combined_protocol_counts[proto] = combined_protocol_counts.get(proto, 0) + 1

                    payload = pkt_info["payload"]
                    pkt_id = pkt_info["packet_id"]

                    # Update stream reassembler
                    if proto in ("TCP", "UDP"):
                        stream_reassembler.process_packet(
                            proto=proto,
                            src_ip=pkt_info["src_ip"],
                            src_port=pkt_info["src_port"],
                            dst_ip=pkt_info["dst_ip"],
                            dst_port=pkt_info["dst_port"],
                            payload=payload,
                            timestamp=pkt_info["timestamp"],
                            is_syn=pkt_info["is_syn"]
                        )

                    # Scan raw packet payload for flags
                    if payload and len(payload) >= 4:
                        flags_in_pkt = self.flag_scanner.scan_bytes(
                            payload=payload,
                            source=f"{os.path.basename(filepath)} - Packet #{pkt_id}",
                            packet_id=pkt_id
                        )
                        for fl in flags_in_pkt:
                            self.found_flags.append(fl)
                            self.flag_found.emit(fl)
                            self.log_message.emit("FOUND", f"Flag discovered in Packet #{pkt_id}: {fl.flag} ({fl.encoding})")

                    # ICMP payload carving
                    if proto == "ICMP" and payload and len(payload) >= 16:
                        carved = file_extractor.carve_all(
                            data=payload,
                            source_label=f"ICMP #{pkt_id}",
                            packet_id=pkt_id
                        )
                        for cf in carved:
                            self._handle_extracted_file(cf)

                    # Emit progress throttled at 50ms intervals
                    now = time.time()
                    if now - last_progress_emit >= 0.05:
                        last_progress_emit = now
                        pct = min(90.0, (pkt_count / est_packets) * 90.0)
                        self.progress_updated.emit(
                            self.total_packets_processed,
                            est_packets * total_files,
                            pct,
                            f"Analyzing {os.path.basename(filepath)}: {pkt_count:,} packets..."
                        )

                if self._is_stopped:
                    break

                # 2. Stream Reassembly Analysis & Protocol File Reconstruction
                all_streams = stream_reassembler.get_all_streams()
                total_streams_count += len(all_streams)
                self.log_message.emit("INFO", f"Reassembled {len(all_streams)} streams. Extracting application payloads...")

                for stream_key, stream in all_streams.items():
                    if self._is_stopped:
                        break

                    # Check client and server streams
                    for direction, s_payload in [("Client->Server", bytes(stream.client_payload)),
                                                 ("Server->Client", bytes(stream.server_payload))]:
                        if not s_payload or len(s_payload) < 4:
                            continue

                        # Scan full reassembled stream buffer for flags
                        stream_source = f"{os.path.basename(filepath)} - Stream #{stream.stream_id} ({direction})"
                        flags_in_stream = self.flag_scanner.scan_bytes(
                            payload=s_payload,
                            source=stream_source,
                            stream_id=stream.stream_id
                        )
                        for fl in flags_in_stream:
                            self.found_flags.append(fl)
                            self.flag_found.emit(fl)
                            self.log_message.emit("FOUND", f"Flag discovered in Stream #{stream.stream_id}: {fl.flag} ({fl.encoding})")

                        # Protocol-specific extraction
                        if stream.app_protocol == "HTTP" or b"HTTP/1." in s_payload:
                            http_files = file_extractor.extract_from_http(s_payload, stream_id=stream.stream_id)
                            for hf in http_files:
                                self._handle_extracted_file(hf)

                        if stream.app_protocol == "SMTP" or b"boundary=" in s_payload or b"Content-Disposition:" in s_payload:
                            smtp_files = file_extractor.extract_from_smtp(s_payload, stream_id=stream.stream_id)
                            for sf in smtp_files:
                                self._handle_extracted_file(sf)

                        # Generic magic byte carving on stream buffer
                        carved_files = file_extractor.carve_all(
                            data=s_payload,
                            source_label=f"Stream #{stream.stream_id} {direction}",
                            stream_id=stream.stream_id
                        )
                        for cf in carved_files:
                            self._handle_extracted_file(cf)

            end_time = time.time()
            duration = end_time - start_time

            for ef in self.extracted_files:
                if ef.has_stego_warning:
                    total_stego_count += 1

            self.summary = AnalysisSummary(
                capture_file=os.path.basename(self.filepaths[0]) if total_files == 1 else f"{total_files} Files Batch",
                file_size_bytes=total_size_bytes,
                total_packets=self.total_packets_processed,
                processed_packets=self.total_packets_processed,
                total_streams=total_streams_count,
                protocol_counts=combined_protocol_counts,
                flags_count=len(self.found_flags),
                files_count=len(self.extracted_files),
                stego_alerts_count=total_stego_count,
                start_time=start_time,
                end_time=end_time,
                duration_seconds=duration,
                error_count=0
            )

            self.progress_updated.emit(self.total_packets_processed, self.total_packets_processed, 100.0, "Analysis complete.")
            self.log_message.emit("INFO", f"Analysis finished in {duration:.2f}s. Found {len(self.found_flags)} flags, extracted {len(self.extracted_files)} files.")
            self.analysis_finished.emit(self.summary)

        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            self.log_message.emit("ERROR", f"Analysis failed with exception: {e}\n{tb}")
            self.error_occurred.emit(f"Error analyzing capture: {str(e)}")

    def _handle_extracted_file(self, extracted_file: ExtractedFile):
        """Processes an extracted file: inspects for flags, logs warnings, emits to UI."""
        self.extracted_files.append(extracted_file)
        self.file_extracted.emit(extracted_file)

        if extracted_file.has_stego_warning:
            self.log_message.emit("WARNING", f"Stego Warning on {extracted_file.filename}: {extracted_file.stego_details}")
        else:
            self.log_message.emit("INFO", f"Extracted {extracted_file.file_type}: {extracted_file.filename} ({extracted_file.size_bytes:,} bytes)")

        # Also scan the extracted file content for flags
        try:
            if os.path.exists(extracted_file.disk_path):
                with open(extracted_file.disk_path, "rb") as f:
                    file_bytes = f.read()
                file_flags = self.flag_scanner.scan_bytes(
                    payload=file_bytes,
                    source=f"File: {extracted_file.filename}",
                    stream_id=extracted_file.stream_id,
                    packet_id=extracted_file.packet_id
                )
                for fl in file_flags:
                    self.found_flags.append(fl)
                    self.flag_found.emit(fl)
                    self.log_message.emit("FOUND", f"Flag discovered inside {extracted_file.filename}: {fl.flag}")
        except Exception:
            pass
