# Protocol support

The GUI and CLI automatically use **TShark** when it is on `PATH`. This uses Wireshark's protocol dissectors to read PCAP and PCAPNG captures offline, with network name resolution disabled. The console identifies the selected reader. If TShark is absent, the built-in Scapy reader preserves transport payloads and identifies common services using signatures and transport-specific port hints.

Install TShark with your operating system's package manager, or install it with Wireshark and add its executable directory to `PATH`. Check availability with `tshark --version`, then restart the application. A current Wireshark/TShark 4.x release is recommended; tests were run with TShark 4.7.2 and Scapy 2.7.0. TShark is an optional system dependency, not a Python package. No capture privileges are needed for reading existing files.

## What you can read

| Protocol | Reading with TShark |
|---|---|
| TCP / UDP | Endpoints, transport payloads, packet details, and bidirectional flow grouping |
| HTTP | Plaintext request/response summaries; existing HTTP/1 body and file extraction |
| HTTPS / TLS | Visible handshake information, SNI, ALPN, certificate names and serials when present |
| HTTP/2 | Decoded frame summaries when plaintext or decryptable; TLS ALPN is shown separately |
| HTTP/3 / QUIC | QUIC packet details and available handshake metadata; HTTP/3 summaries when decryptable |
| DNS | Queries and response summaries over UDP and TCP |
| FTP / FTP-DATA | Control commands and recognized data-channel traffic |
| SSH | Visible version/banner and encrypted packet metadata |
| Telnet | Plaintext traffic and negotiation summaries |
| SMTP / SMTPS | Plaintext commands and existing MIME extraction; TLS metadata for encrypted sessions |
| POP3 / POP3S | Plaintext command/response summaries or TLS metadata |
| IMAP / IMAPS | Plaintext command/response summaries or TLS metadata |
| DHCP | Address-assignment message summaries and preserved serialized payloads |
| SMB / SMB2 | File-sharing operation summaries when visible; encrypted records remain protected |
| NFS | Visible NFSv2/v3/v4 RPC operation summaries; TCP/UDP port 2049 service hints in the Scapy fallback |
| NTP | Time protocol message summaries |
| SNMP | Visible monitoring request/response summaries; encrypted SNMPv3 content stays protected |
| RDP | Recognized desktop negotiation/packet summaries; encrypted content stays protected |
| SIP / RTP | Call signaling and media packet summaries when the dissector identifies the flow |
| MQTT | Visible connection/publish/control summaries |
| LDAP / LDAPS | Visible directory operation summaries or TLS metadata |
| TFTP | File-transfer request/block summaries |
| ICMP / ICMPv6 | Diagnostic message summaries and payload scanning; excluded from TCP/UDP stream counts |

Detection depends on captured content, enabled TShark dissectors, ports, and session context. Dynamic FTP-DATA, TFTP, and RTP flows may require the preceding control/signaling exchange. An arbitrary UDP packet on port 443 is not automatically labeled QUIC or HTTP/3. Unknown traffic remains readable as generic transport data. The Scapy fallback does not provide full HTTP/2, QUIC/HTTP/3, or RTP dissection.

NFS uses the existing protocol details, counts, payload scanning, and report paths. TShark supplies [NFS dissection](https://www.wireshark.org/docs/dfref/n/nfs.html); the fallback treats [TCP/UDP port 2049](https://www.rfc-editor.org/info/rfc1813/) as a service hint. RPC replies and nonstandard service ports may require a matching call or preceding RPC discovery traffic. Encrypted NFS content remains protected, and NFS file reconstruction is not added.

## Results and limits

- **Overview → Protocol distribution** and CLI totals count each packet once under its detected application, or its transport when unknown. JSON also contains separate `transport_counts`; these are a different grouping of the same packets.
- **Overview → Protocol details** and JSON/HTML/PDF reports retain the first **500 packet details per analysis**, across the batch. `protocol_details_omitted` records later packets; protocol totals and payload scanning continue for the entire capture. Each detail includes capture, packet number, protocol, endpoints, evidence, and readable text.
- Evidence `dissector` means a decoder recognized the protocol, `signature` means a recognizable payload prefix, and `port` is only a service hint. Empty TCP acknowledgements can therefore carry a port hint even when earlier packets had stronger protocol evidence.
- Encryption is not bypassed. SNI can be absent or protected by ECH; certificates are not generally visible in TLS 1.3 without session secrets. ALPN in a ClientHello advertises possible protocols and is not proof that HTTP/2 or HTTP/3 application traffic was decoded.
- TShark uses its existing local Wireshark preferences and any usable secrets embedded in the capture. Configured decryption can expose more details. This application does not add a key-import UI or independently decrypt TLS, SSH, RDP, or other encrypted payloads.
- Protocol reading is distinct from file reconstruction. New dissector details do not add automatic SMB file recovery, RTP audio playback, HTTP/2 or HTTP/3 object extraction, or application text-stream viewers. The flag scanner and generic carver retain the original transport bytes; decrypted or decompressed data inside TShark is not automatically fed to them.
- Existing flow buffers concatenate directional payloads in capture order. They do not implement sequence-aware TCP retransmission removal or out-of-order repair. UDP flow grouping does not make UDP a reliable byte stream. TShark performs its own protocol dissection/reassembly separately.
- If installed TShark fails, the error is reported rather than silently retrying and potentially duplicating already processed packets. Text dumps continue through the text reader.

Implementation references: [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html), [Wireshark TLS documentation](https://wiki.wireshark.org/tls).

Run checks with:

```bash
QT_QPA_PLATFORM=offscreen python3 -m unittest discover -s tests -q
```

TShark integration tests use locally generated PCAP/PCAPNG fixtures and skip when the optional executable is absent. Fallback and detection tests run independently of TShark.
