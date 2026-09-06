import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from scapy.all import BOOTP, DHCP, DNS, DNSQR, Ether, IP, IPv6, TCP, UDP, Raw, wrpcap
from scapy.layers.inet6 import ICMPv6EchoRequest

from core.pcap_parser import StreamingCaptureParser
from core.stream_reassembler import StreamReassembler
from core.protocols import ProtocolSummary
from core.tshark_parser import normalize_layers


class TestProtocolSupport(unittest.TestCase):
    def test_stream_keeps_dissection_when_ack_only_has_port_hint(self):
        reassembler = StreamReassembler()
        args = dict(proto="TCP", src_ip="1.1.1.1", src_port=55000,
                    dst_ip="2.2.2.2", dst_port=80, timestamp=1)
        stream = reassembler.process_packet(**args, payload=b"preface", app_protocol="HTTP/2", detection="dissector")
        reassembler.process_packet(**args, payload=b"", app_protocol="HTTP", detection="port")
        self.assertEqual(stream.app_protocol, "HTTP/2")
        self.assertEqual(stream.packet_count, 2)

    def test_details_are_bounded_but_counts_include_every_packet(self):
        summary = ProtocolSummary()
        packet = StreamingCaptureParser("unused")._normalize_scapy_packet(IP()/UDP(dport=53)/DNS(), 1)
        for _ in range(summary.DETAIL_LIMIT + 3):
            summary.add_packet(packet, "test.pcap")
        self.assertEqual(len(summary.details), summary.DETAIL_LIMIT)
        self.assertEqual(summary.details_omitted, 3)
        self.assertEqual(summary.protocol_counts, {"DNS": summary.DETAIL_LIMIT + 3})
        self.assertEqual(summary.transport_counts, {"UDP": summary.DETAIL_LIMIT + 3})

    def test_dissected_dynamic_protocols_and_secure_service_labels(self):
        for name, stack, port, expected in [
            ("RTP", "eth:ip:udp:rtp", 40000, "RTP"),
            ("QUIC", "eth:ip:udp:quic", 443, "QUIC"),
            ("HTTP3", "eth:ip:udp:quic:http3", 443, "HTTP/3"),
            ("HTTP2", "eth:ip:tcp:tls:http2", 443, "HTTP/2"),
            ("TLSv1.3", "eth:ip:tcp:tls", 465, "SMTPS"),
            ("TLSv1.2", "eth:ip:tcp:tls", 995, "POP3S"),
            ("TLSv1.3", "eth:ip:tcp:tls", 993, "IMAPS"),
            ("TLSv1.3", "eth:ip:tcp:tls", 636, "LDAPS"),
        ]:
            transport = "udp" if ":udp:" in stack else "tcp"
            with self.subTest(name=name, port=port):
                pkt = normalize_layers({"frame_number": ["1"], "frame_protocols": [stack],
                                        "_ws_col_protocol": [name], f"{transport}_dstport": [str(port)]})
                self.assertEqual(pkt["app_protocol"], expected)
                self.assertEqual(pkt["detection"], "dissector")

    def test_no_tshark_falls_back_and_text_dumps_still_work(self):
        with tempfile.TemporaryDirectory() as tmp, patch("core.pcap_parser.shutil.which", return_value=None):
            path = os.path.join(tmp, "dns.pcap")
            wrpcap(path, [Ether()/IP()/UDP(dport=53)/DNS(qd=DNSQR(qname="example.test"))])
            parser = StreamingCaptureParser(path)
            self.assertEqual(parser.backend, "Scapy")
            self.assertEqual(list(parser.parse_packets())[0]["app_protocol"], "DNS")
            path = os.path.join(tmp, "test.txt")
            with open(path, "w") as f:
                f.write("flag{text_dump}\n")
            self.assertEqual(list(StreamingCaptureParser(path).parse_packets())[0]["payload"], b"flag{text_dump}\n")

    @unittest.skipUnless(shutil.which("tshark"), "TShark is optional")
    def test_visible_tls_handshake_does_not_claim_http2_payload(self):
        from scapy.layers.tls.handshake import TLSClientHello
        from scapy.layers.tls.extensions import TLS_Ext_ServerName, ServerName, TLS_Ext_ALPN, ProtocolName
        from scapy.layers.tls.record import TLS
        hello = TLS(msg=[TLSClientHello(ext=[
            TLS_Ext_ServerName(servernames=[ServerName(servername=b"example.test")]),
            TLS_Ext_ALPN(protocols=[ProtocolName(protocol=b"h2")]),
        ])])
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "tls.pcap")
            wrpcap(path, [Ether()/IP()/TCP(sport=55000, dport=443, flags="PA")/hello])
            packet = list(StreamingCaptureParser(path).parse_packets())[0]
            self.assertEqual(packet["app_protocol"], "HTTPS / TLS")
            self.assertEqual(packet["metadata"]["SNI"], "example.test")
            self.assertIn("h2", packet["details"])

    def test_transport_specific_service_detection(self):
        detector = StreamReassembler().detect_app_protocol
        services = {
            "TCP": {20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
                    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
                    143: "IMAP", 389: "LDAP", 443: "HTTPS / TLS", 445: "SMB",
                    465: "SMTPS", 587: "SMTP", 636: "LDAPS", 993: "IMAPS",
                    995: "POP3S", 1883: "MQTT", 2049: "NFS", 3389: "RDP", 5060: "SIP"},
            "UDP": {53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP",
                    123: "NTP", 161: "SNMP", 162: "SNMP", 2049: "NFS", 3389: "RDP",
                    5060: "SIP"},
        }
        for transport, ports in services.items():
            for port, expected in ports.items():
                with self.subTest(transport=transport, port=port):
                    self.assertEqual(detector(transport, 55000, port, b""), expected)
                    self.assertEqual(detector(transport, port, 55000, b""), expected)
        self.assertEqual(detector("UDP", 55000, 80, b""), "UDP")
        self.assertEqual(detector("UDP", 55000, 443, b"random"), "UDP")
        self.assertEqual(detector("TCP", 55000, 55001, b"220 hello\r\n"), "TCP")

    @unittest.skipUnless(shutil.which("tshark"), "TShark is optional")
    def test_nfs_rpc_calls_and_replies_are_readable_over_tcp_and_udp(self):
        from scapy.contrib.oncrpc import RPC, RPC_Call, RPC_Reply, RM_Header

        packets = []
        # NULL calls exercise version identification and matching RPC replies.
        for index, (transport, version) in enumerate(((UDP, 2), (UDP, 3), (TCP, 3), (TCP, 4)), 1):
            call = RPC(xid=index)/RPC_Call(program=100003, pversion=version,
                                           procedure=0, aflavor=0, vflavor=0)
            reply = RPC(xid=index, mtype=1)/RPC_Reply()
            if transport == TCP:
                call, reply = RM_Header()/call, RM_Header()/reply
            flags = {"flags": "PA"} if transport == TCP else {}
            packets.extend([
                Ether()/IP(src="192.0.2.1", dst="192.0.2.2")/transport(sport=55000 + index, dport=2049, **flags)/call,
                Ether()/IP(src="192.0.2.2", dst="192.0.2.1")/transport(sport=2049, dport=55000 + index, **flags)/reply,
            ])
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "nfs.pcap")
            wrpcap(path, packets)
            parsed = list(StreamingCaptureParser(path).parse_packets())
            self.assertEqual(len(parsed), len(packets))
            summary = ProtocolSummary()
            for original, packet in zip(packets, parsed):
                with self.subTest(packet=packet["packet_id"]):
                    self.assertEqual(packet["app_protocol"], "NFS")
                    self.assertEqual(packet["detection"], "dissector")
                    self.assertIn("NULL", packet["details"])
                    self.assertEqual(packet["payload"], bytes(original[packet["transport"]].payload))
                    summary.add_packet(packet, "nfs.pcap")
            self.assertEqual(summary.protocol_counts, {"NFS": 8})
            self.assertEqual(summary.transport_counts, {"TCP": 4, "UDP": 4})
            self.assertTrue(all(detail["protocol"] == "NFS" for detail in summary.details))

    def test_signatures_override_ports_without_guessing_encrypted_http(self):
        detector = StreamReassembler().detect_app_protocol
        for payload, expected in [
            (b"SSH-2.0-test\r\n", "SSH"),
            (b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "HTTP/2"),
            (b"\x00\x00\x00\x40\xfeSMB" + b"\x00" * 60, "SMB2"),
            (b"\x16\x03\x03\x00\x04test", "TLS"),
        ]:
            with self.subTest(expected=expected):
                self.assertEqual(detector("TCP", 55000, 80, payload), expected)

    def test_scapy_preserves_structured_payload_and_transport(self):
        parser = StreamingCaptureParser("unused")
        for pkt, app in [
            (IP()/UDP(sport=68, dport=67)/BOOTP()/DHCP(options=[("message-type", "discover"), "end"]), "DHCP"),
            (IP()/UDP(sport=55000, dport=53)/DNS(qd=DNSQR(qname="example.test")), "DNS"),
            (IP()/TCP(sport=55000, dport=53)/DNS(qd=DNSQR(qname="example.test")), "DNS"),
        ]:
            with self.subTest(app=app):
                normalized = parser._normalize_scapy_packet(pkt, 1)
                transport = "TCP" if TCP in pkt else "UDP"
                self.assertEqual(normalized["transport"], transport)
                self.assertEqual(normalized["app_protocol"], app)
                self.assertEqual(normalized["payload"], bytes(pkt[transport].payload))
        pkt = IPv6()/ICMPv6EchoRequest(data=b"flag{ipv6_echo}")
        normalized = parser._normalize_scapy_packet(pkt, 2)
        self.assertEqual(normalized["proto"], "ICMPv6")
        self.assertIn(b"flag{ipv6_echo}", normalized["payload"])

    @unittest.skipUnless(shutil.which("tshark"), "TShark is optional")
    def test_tshark_reads_real_capture_with_details(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "capture with spaces.pcap")
            payload = b"GET /hello HTTP/1.1\r\nHost: example.test\r\n\r\n"
            wrpcap(path, [Ether()/IP()/TCP(sport=55000, dport=80, flags="PA")/Raw(payload),
                          Ether()/IP()/UDP(sport=55001, dport=53)/DNS(qd=DNSQR(qname="example.test"))])
            packets = list(StreamingCaptureParser(path).parse_packets())
            self.assertEqual([p["app_protocol"] for p in packets], ["HTTP", "DNS"])
            self.assertEqual(packets[0]["payload"], payload)
            self.assertIn("/hello", packets[0]["details"])
            self.assertIn("example.test", packets[1]["details"])
            self.assertEqual(packets[1]["transport"], "UDP")

    @unittest.skipUnless(shutil.which("tshark"), "TShark is optional")
    def test_binary_and_plaintext_application_dissectors(self):
        from scapy.layers.ntp import NTPHeader
        from scapy.layers.snmp import SNMP, SNMPget
        from scapy.contrib.mqtt import MQTT, MQTTConnect
        from scapy.layers.smb2 import SMB2_Header, SMB2_Negotiate_Protocol_Request
        from scapy.layers.netbios import NBTSession
        applications = [
            (UDP(sport=68, dport=67)/BOOTP()/DHCP(options=[("message-type", "discover"), "end"]), "DHCP"),
            (UDP(sport=55000, dport=123)/NTPHeader(mode=3), "NTP"),
            (UDP(sport=55000, dport=161)/SNMP(PDU=SNMPget()), "SNMP"),
            (TCP(sport=55001, dport=1883, flags="PA")/MQTT()/MQTTConnect(protoname=b"MQTT", protolevel=4, clientId=b"test"), "MQTT"),
            (TCP(sport=55002, dport=445, flags="PA")/NBTSession()/SMB2_Header()/SMB2_Negotiate_Protocol_Request(Dialects=[0x202]), "SMB2"),
            (TCP(sport=55003, dport=80, flags="PA")/Raw(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00"), "HTTP/2"),
            (TCP(sport=55004, dport=21, flags="PA")/Raw(b"USER test\r\n"), "FTP"),
            (TCP(sport=55005, dport=25, flags="PA")/Raw(b"EHLO example.test\r\n"), "SMTP"),
            (TCP(sport=55006, dport=110, flags="PA")/Raw(b"USER test\r\n"), "POP3"),
            (TCP(sport=55007, dport=143, flags="PA")/Raw(b"a001 CAPABILITY\r\n"), "IMAP"),
            (UDP(sport=55008, dport=69)/Raw(b"\x00\x01example.txt\x00octet\x00"), "TFTP"),
            (TCP(sport=55009, dport=22, flags="PA")/Raw(b"SSH-2.0-test\r\n"), "SSH"),
            (IPv6()/ICMPv6EchoRequest(data=b"flag{ipv6_tshark}"), "ICMPv6"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "protocols.pcapng")
            from scapy.utils import PcapNgWriter
            with PcapNgWriter(path) as writer:
                for packet, _ in applications:
                    writer.write(Ether()/packet if IPv6 in packet else Ether()/IP()/packet)
            packets = list(StreamingCaptureParser(path).parse_packets())
            self.assertEqual(len(packets), len(applications))
            for parsed, (original, expected) in zip(packets, applications):
                with self.subTest(expected=expected):
                    self.assertEqual(parsed["app_protocol"], expected)
                    self.assertEqual(parsed["detection"], "dissector")
                    self.assertTrue(parsed["details"])
            self.assertIn(b"flag{ipv6_tshark}", packets[-1]["payload"])

    @unittest.skipUnless(shutil.which("tshark"), "TShark is optional")
    def test_tshark_is_reaped_on_early_close_and_reports_bad_capture(self):
        import subprocess
        real_popen = subprocess.Popen
        children = []

        def record_child(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            return child

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "test.pcap")
            wrpcap(path, [Ether()/IP()/UDP(dport=123)/Raw(b"test")] * 20)
            with patch("core.tshark_parser.subprocess.Popen", side_effect=record_child):
                packets = StreamingCaptureParser(path).parse_packets()
                next(packets)
                packets.close()
            self.assertIsNotNone(children[0].poll())
            with open(path, "wb") as f:
                f.write(b"\xd4\xc3\xb2\xa1\x00")
            with self.assertRaisesRegex(ValueError, "TShark could not read capture"):
                list(StreamingCaptureParser(path).parse_packets())


if __name__ == "__main__":
    unittest.main()
