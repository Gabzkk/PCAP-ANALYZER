"""Conservative fallback detection when a full dissector is unavailable."""

TCP_SERVICES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 139: "SMB", 143: "IMAP",
    389: "LDAP", 443: "HTTPS / TLS", 445: "SMB", 465: "SMTPS",
    587: "SMTP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1883: "MQTT", 2049: "NFS", 3389: "RDP", 5060: "SIP", 5061: "SIPS",
    8000: "HTTP", 8080: "HTTP", 8443: "HTTPS / TLS", 8883: "MQTTS", 8888: "HTTP",
}
UDP_SERVICES = {
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 123: "NTP",
    161: "SNMP", 162: "SNMP", 2049: "NFS", 3389: "RDP", 5060: "SIP",
}


def detect_protocol(transport, src_port, dst_port, payload):
    """Return (application, evidence); ports are hints, never proof of decoding."""
    if transport == "TCP":
        signatures = [
            ("HTTP/2", (b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",)),
            ("HTTP", (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ",
                      b"OPTIONS ", b"PATCH ", b"CONNECT ", b"HTTP/1.")),
            ("SSH", (b"SSH-",)),
            ("SMTP", (b"EHLO ", b"HELO ", b"MAIL FROM:", b"RCPT TO:")),
            ("Telnet", (b"\xff\xfd", b"\xff\xfb", b"\xff\xfa", b"\xff\xfe", b"\xff\xfc")),
        ]
        for name, prefixes in signatures:
            if payload.startswith(prefixes):
                return name, "signature"
        smb = payload[4:8] if payload[:1] == b"\x00" else payload[:4]
        if smb in (b"\xffSMB", b"\xfeSMB", b"\xfdSMB", b"\xfcSMB"):
            return ("SMB" if smb == b"\xffSMB" else "SMB2"), "signature"
        if len(payload) >= 5 and payload[0] in (20, 21, 22, 23) and payload[1:2] == b"\x03" and payload[2] <= 4:
            return "TLS", "signature"
    if transport in ("TCP", "UDP") and (
        payload.startswith(b"SIP/2.0 ") or
        (payload.split(b" ", 1)[0] in (b"INVITE", b"ACK", b"BYE", b"REGISTER", b"CANCEL", b"OPTIONS")
         and b" SIP/2.0\r\n" in payload[:2048])
    ):
        return "SIP", "signature"
    services = TCP_SERVICES if transport == "TCP" else UDP_SERVICES if transport == "UDP" else {}
    # A service on the source endpoint usually identifies a response.
    for port in (src_port, dst_port):
        if port in services:
            return services[port], "port"
    return transport, "transport"


def canonical_protocol(name):
    """Keep display names stable across Wireshark versions."""
    upper = name.upper()
    if upper.startswith(("TLS", "SSL")):
        return "TLS"
    return {"HTTP2": "HTTP/2", "HTTP3": "HTTP/3", "TELNET": "Telnet",
            "POP": "POP3", "BOOTP": "DHCP", "ICMPV6": "ICMPv6",
            "RDPUDP": "RDP", "T.125": "RDP"}.get(upper, name)


class ProtocolSummary:
    """Shared CLI/GUI packet accounting with a bounded sample of readable details."""

    DETAIL_LIMIT = 500

    def __init__(self):
        self.protocol_counts = {}
        self.transport_counts = {}
        self.details = []
        self.details_omitted = 0

    def add_packet(self, packet, capture):
        app = packet.get("app_protocol", packet["proto"])
        transport = packet.get("transport", packet["proto"])
        self.protocol_counts[app] = self.protocol_counts.get(app, 0) + 1
        self.transport_counts[transport] = self.transport_counts.get(transport, 0) + 1
        if len(self.details) >= self.DETAIL_LIMIT:
            self.details_omitted += 1
            return
        self.details.append({
            "capture": capture, "packet_id": packet["packet_id"],
            "protocol": app, "transport": transport,
            "source": f"{packet['src_ip']}:{packet['src_port']}",
            "destination": f"{packet['dst_ip']}:{packet['dst_port']}",
            "detection": packet.get("detection", "transport"),
            "details": packet.get("details", packet["summary"])[:8192],
        })
