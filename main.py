#!/usr/bin/env python3
import os
import sys
import argparse

# Ensure local package imports work from project root
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)


def run_cli_mode(args):
    """Headless CLI mode for batch automation or headless environments."""
    from core.flag_scanner import FlagScanner
    from core.pcap_parser import validate_capture_file
    from core.file_extractor import FileExtractor
    from core.stream_reassembler import StreamReassembler
    from core.pcap_parser import StreamingCaptureParser
    from core.reporter import ForensicReporter
    from core.models import AnalysisSummary
    from core.protocols import ProtocolSummary
    from contextlib import closing

    patterns_file = args.patterns or os.path.join(CURRENT_DIR, "default_patterns.json")
    scanner = FlagScanner(patterns_file)

    target_files = []
    if os.path.isdir(args.target):
        import glob
        for ext in ("*.pcap", "*.pcapng", "*.cap", "*.dump", "*.txt", "*.log"):
            target_files.extend(glob.glob(os.path.join(args.target, ext)))
    elif os.path.isfile(args.target):
        target_files = [args.target]

    if not target_files:
        print(f"[-] Error: Target file or directory not found: {args.target}")
        sys.exit(1)

    output_dir = os.path.abspath(args.output_dir or "extracted_files")
    os.makedirs(output_dir, exist_ok=True)

    print(f"[*] Starting PCAP Forensic Analysis on {len(target_files)} target file(s)...")
    all_flags = []
    all_files = []
    total_packets = 0
    protocols = ProtocolSummary()
    total_streams = 0

    import time
    start_time = time.time()

    for idx, target in enumerate(target_files, 1):
        print(f"[*] [{idx}/{len(target_files)}] Processing: {target}")
        is_val, fmt, err = validate_capture_file(target)
        if not is_val:
            print(f"[-] Validation failed for {target}: {err}")
            continue

        file_out = os.path.join(output_dir, os.path.splitext(os.path.basename(target))[0])
        extractor = FileExtractor(file_out)
        reassembler = StreamReassembler()
        parser = StreamingCaptureParser(target)
        print(f"[*] Protocol reader: {parser.backend}")

        # 1. Packet streaming
        with closing(parser.parse_packets()) as packets:
            for pkt in packets:
                total_packets += 1
                proto = pkt["proto"]
                protocols.add_packet(pkt, os.path.basename(target))
                payload = pkt["payload"]

                if proto in ("TCP", "UDP"):
                    reassembler.process_packet(
                        proto=proto,
                        src_ip=pkt["src_ip"],
                        src_port=pkt["src_port"],
                        dst_ip=pkt["dst_ip"],
                        dst_port=pkt["dst_port"],
                        payload=payload,
                        timestamp=pkt["timestamp"],
                        is_syn=pkt["is_syn"],
                        app_protocol=pkt.get("app_protocol"),
                        detection=pkt.get("detection")
                    )

                if payload and len(payload) >= 4:
                    flags = scanner.scan_bytes(
                        payload=payload,
                        source=f"{os.path.basename(target)} - Pkt #{pkt['packet_id']}",
                        packet_id=pkt["packet_id"]
                    )
                    for fl in flags:
                        print(f"  [+] FLAG: {fl.flag} ({fl.pattern_name}) [Enc: {fl.encoding}]")
                        all_flags.append(fl)

                if proto in ("ICMP", "ICMPv6") and payload and len(payload) >= 16:
                    carved = extractor.carve_all(payload, f"ICMP #{pkt['packet_id']}", packet_id=pkt["packet_id"])
                    all_files.extend(carved)

        # 2. Streams reassembly
        streams = reassembler.get_all_streams()
        total_streams += len(streams)
        for s_id, stream in streams.items():
            for d_name, p_data in [("Client->Server", bytes(stream.client_payload)),
                                   ("Server->Client", bytes(stream.server_payload))]:
                if not p_data:
                    continue
                flags = scanner.scan_bytes(
                    payload=p_data,
                    source=f"Stream #{stream.stream_id} {d_name}",
                    stream_id=stream.stream_id
                )
                for fl in flags:
                    print(f"  [+] FLAG in Stream: {fl.flag} ({fl.pattern_name}) [Enc: {fl.encoding}]")
                    all_flags.append(fl)

                # Extract protocol files
                if stream.app_protocol == "HTTP" or b"HTTP/1." in p_data:
                    all_files.extend(extractor.extract_from_http(p_data, stream_id=stream.stream_id))
                if stream.app_protocol == "SMTP" or b"boundary=" in p_data:
                    all_files.extend(extractor.extract_from_smtp(p_data, stream_id=stream.stream_id))
                # Carving
                all_files.extend(extractor.carve_all(p_data, f"Stream #{stream.stream_id}", stream_id=stream.stream_id))

        # Check extracted files for flags
        for ef in all_files:
            if ef.has_stego_warning:
                print(f"  [!] STEGO ALERT: {ef.filename} - {ef.stego_details}")
            if os.path.exists(ef.disk_path):
                with open(ef.disk_path, "rb") as f:
                    fb = f.read()
                f_flags = scanner.scan_bytes(fb, f"File: {ef.filename}")
                for fl in f_flags:
                    print(f"  [+] FLAG inside {ef.filename}: {fl.flag}")
                    all_flags.append(fl)

    end_time = time.time()
    duration = end_time - start_time

    summary = AnalysisSummary(
        capture_file=os.path.basename(args.target),
        file_size_bytes=os.path.getsize(args.target) if os.path.isfile(args.target) else 0,
        total_packets=total_packets,
        processed_packets=total_packets,
        total_streams=total_streams,
        protocol_counts=protocols.protocol_counts,
        transport_counts=protocols.transport_counts,
        protocol_details=protocols.details,
        protocol_details_omitted=protocols.details_omitted,
        flags_count=len(all_flags),
        files_count=len(all_files),
        stego_alerts_count=sum(1 for f in all_files if f.has_stego_warning),
        start_time=start_time,
        end_time=end_time,
        duration_seconds=duration
    )

    print("\n" + "="*60)
    print(f"[*] ANALYSIS COMPLETE in {duration:.2f}s")
    print(f"[*] Packets: {total_packets:,} | Flags: {len(all_flags)} | Extracted Files: {len(all_files)}")
    print("="*60)

    for protocol, count in sorted(protocols.protocol_counts.items()):
        print(f"[*] {protocol}: {count:,} packets")

    # Exports
    if args.export_json:
        ForensicReporter.export_json(summary, all_flags, all_files, args.export_json)
        print(f"[+] Exported JSON report: {args.export_json}")
    if args.export_html:
        ForensicReporter.export_html(summary, all_flags, all_files, args.export_html)
        print(f"[+] Exported HTML report: {args.export_html}")
    if args.export_pdf:
        # Note: PDF requires Qt
        try:
            from PyQt6.QtWidgets import QApplication
            app = QApplication.instance() or QApplication(sys.argv)
            ok = ForensicReporter.export_pdf(summary, all_flags, all_files, args.export_pdf)
            if ok:
                print(f"[+] Exported PDF report: {args.export_pdf}")
        except Exception as e:
            print(f"[-] PDF export error: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="PCAP/Network Forensics & Flag Extraction Suite with GUI"
    )
    parser.add_argument("target", nargs="?", default="", help="Path to .pcap, .pcapng, or dump directory")
    parser.add_argument("--cli", action="store_true", help="Run in headless CLI mode instead of GUI")
    parser.add_argument("--patterns", default="", help="Path to custom regex patterns JSON")
    parser.add_argument("--output-dir", default="extracted_files", help="Directory to save extracted files")
    parser.add_argument("--export-html", default="", help="Path to save HTML report (CLI mode)")
    parser.add_argument("--export-json", default="", help="Path to save JSON report (CLI mode)")
    parser.add_argument("--export-pdf", default="", help="Path to save PDF report (CLI mode)")

    args = parser.parse_args()

    if args.cli:
        if not args.target:
            print("[-] Error: Target capture required for CLI mode. Usage: python3 main.py <target.pcap> --cli")
            sys.exit(1)
        run_cli_mode(args)
        return

    # GUI Mode
    from PyQt6.QtWidgets import QApplication
    from ui.main_window import MainWindow

    # Configure high-dpi scaling
    os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"

    app = QApplication(sys.argv)
    app.setApplicationName("PCAP Forensics Suite")

    patterns_path = args.patterns or os.path.join(CURRENT_DIR, "default_patterns.json")
    window = MainWindow(patterns_file=patterns_path, output_dir=args.output_dir)

    if args.target:
        window.inp_target.setText(os.path.abspath(args.target))

    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
