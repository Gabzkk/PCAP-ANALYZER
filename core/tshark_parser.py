"""Streaming Wireshark dissection, retaining the original transport payload."""

import json
import os
import subprocess
import tempfile

from .protocols import canonical_protocol, detect_protocol


FIELDS = (
    "frame.number", "frame.time_epoch", "frame.protocols", "_ws.col.Protocol", "_ws.col.Info",
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "tcp.srcport", "tcp.dstport",
    "udp.srcport", "udp.dstport", "tcp.flags.syn", "tcp.payload", "udp.payload", "data.data",
    "tls.handshake.extensions_server_name", "tls.handshake.extensions_alpn_str",
    "x509af.serialNumber", "x509sat.uTF8String",
)


def normalize_layers(layers):
    def first(field, default=""):
        values = layers.get(field.replace(".", "_").lower(), [])
        return values[0] if values else default

    stack = first("frame.protocols").split(":")
    transport = next((p.upper() for p in stack if p in ("tcp", "udp", "icmp", "icmpv6")), "IP")
    if transport == "ICMPV6":
        transport = "ICMPv6"
    prefix = transport.lower()
    src_port = int(first(f"{prefix}.srcport", "0"))
    dst_port = int(first(f"{prefix}.dstport", "0"))
    # Do not use data.data for a TCP ACK: it might belong to a nested protocol.
    payload_hex = first(f"{prefix}.payload") if transport in ("TCP", "UDP") else first("data.data")
    payload = bytes.fromhex(payload_hex.replace(":", ""))
    app, detection = detect_protocol(transport, src_port, dst_port, payload)
    decoded = canonical_protocol(first("_ws.col.Protocol", transport))
    if decoded not in ("TCP", "UDP", "IP", "IPv6", "DATA"):
        app, detection = decoded, "dissector"
    # Preserve secure service names, while retaining TLS in the protocol stack.
    service, _ = detect_protocol(transport, src_port, dst_port, b"")
    if app == "TLS" and service in ("HTTPS / TLS", "SMTPS", "POP3S", "IMAPS", "LDAPS", "SIPS", "MQTTS"):
        app = service
    metadata = {}
    for field, label in (
        ("tls.handshake.extensions_server_name", "SNI"),
        ("tls.handshake.extensions_alpn_str", "ALPN advertised/selected"),
        ("x509af.serialNumber", "Certificate serial"),
        ("x509sat.uTF8String", "Certificate names"),
    ):
        values = layers.get(field.replace(".", "_").lower(), [])
        if values:
            metadata[label] = ", ".join(values)[:1024]
    details = first("_ws.col.Info")[:2048]
    if metadata:
        details += " | " + " | ".join(f"{key}: {value}" for key, value in metadata.items())
    packet_id = int(first("frame.number"))
    src_ip = first("ip.src") or first("ipv6.src", "0.0.0.0")
    dst_ip = first("ip.dst") or first("ipv6.dst", "0.0.0.0")
    return {
        "packet_id": packet_id, "timestamp": float(first("frame.time_epoch", "0")),
        "proto": transport, "transport": transport, "app_protocol": app,
        "detection": detection, "details": details, "metadata": metadata,
        "protocol_stack": stack, "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": src_port, "dst_port": dst_port, "payload": payload,
        "is_syn": first("tcp.flags.syn") == "1",
        "summary": f"#{packet_id} {app} {src_ip}:{src_port} -> {dst_ip}:{dst_port} {details}",
    }


def parse_tshark(filepath, executable):
    """Yield packets; always reap the child, including when the iterator closes."""
    command = [executable, "-n", "-l", "-r", os.path.abspath(filepath), "-T", "ek"]
    for field in FIELDS:
        command.extend(("-e", field))
    # A file avoids stderr pipe deadlocks on malformed captures or config warnings.
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as errors:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=errors,
                                   text=True, encoding="utf-8", errors="replace")
        try:
            for line in process.stdout:
                record = json.loads(line)
                if "layers" in record:
                    yield normalize_layers(record["layers"])
            if process.wait() != 0:
                errors.seek(0)
                raise ValueError(f"TShark could not read capture: {errors.read(4096).strip()}")
        finally:
            process.stdout.close()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
