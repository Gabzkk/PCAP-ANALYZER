import unittest
import os
import shutil
import tempfile

from core.flag_scanner import FlagScanner
from core.decoders import MultiLayerDecoder
from core.pcap_parser import validate_capture_file, StreamingCaptureParser
from core.stream_reassembler import StreamReassembler
from core.file_extractor import FileExtractor
from tests.test_pcap_generator import generate_synthetic_pcap


class TestForensicEngine(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp()
        cls.pcap_path = os.path.join(cls.temp_dir, "test_synthetic.pcap")
        generate_synthetic_pcap(cls.pcap_path)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_validation(self):
        is_val, fmt, err = validate_capture_file(self.pcap_path)
        self.assertTrue(is_val)
        self.assertIn("PCAP", fmt)

    def test_decoders(self):
        decoder = MultiLayerDecoder()

        # 1. Base64
        import base64
        b64_sample = b"PREFIX:" + base64.b64encode(b"flag{b64_test_content}") + b":SUFFIX"
        dec_results = [data for data, path in decoder.decode_all(b64_sample)]
        self.assertTrue(any(b"flag{b64_test_content}" in d for d in dec_results))

        # 2. Hex
        hex_sample = b"HEX_EXFIL: " + b"flag{hex_test_content}".hex().encode()
        dec_results = [data for data, path in decoder.decode_all(hex_sample)]
        self.assertTrue(any(b"flag{hex_test_content}" in d for d in dec_results))

        # 3. URL
        url_sample = b"GET /?flag=flag%7Burl_test_content%7D"
        dec_results = [data for data, path in decoder.decode_all(url_sample)]
        self.assertTrue(any(b"flag{url_test_content}" in d for d in dec_results))

        # 4. ROT13
        import codecs
        rot13_sample = codecs.encode("flag{rot13_test_content}", "rot_13").encode()
        dec_results = [data for data, path in decoder.decode_all(rot13_sample)]
        self.assertTrue(any(b"flag{rot13_test_content}" in d for d in dec_results))

        # 5. Reversed
        rev_sample = b"}tnetnoc_tset_desrever{galf"
        dec_results = [data for data, path in decoder.decode_all(rev_sample)]
        self.assertTrue(any(b"flag{reversed_test_content}" in d for d in dec_results))

    def test_synthetic_pcap_end_to_end(self):
        patterns_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "default_patterns.json")
        scanner = FlagScanner(patterns_path)

        out_dir = os.path.join(self.temp_dir, "extracted")
        extractor = FileExtractor(out_dir)
        reassembler = StreamReassembler()
        parser = StreamingCaptureParser(self.pcap_path)

        found_flags = []
        extracted_files = []

        # 1. Packet parsing
        for pkt in parser.parse_packets():
            proto = pkt["proto"]
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
                    is_syn=pkt["is_syn"]
                )

            if payload:
                flags = scanner.scan_bytes(payload, source=f"Pkt #{pkt['packet_id']}", packet_id=pkt["packet_id"])
                found_flags.extend(flags)

        # 2. Streams reassembly
        streams = reassembler.get_all_streams()
        self.assertGreaterEqual(len(streams), 3)

        for s_id, stream in streams.items():
            for d_name, p_data in [("C2S", bytes(stream.client_payload)), ("S2C", bytes(stream.server_payload))]:
                if not p_data:
                    continue

                s_flags = scanner.scan_bytes(p_data, source=f"Stream #{stream.stream_id}", stream_id=stream.stream_id)
                found_flags.extend(s_flags)

                # HTTP extraction
                if stream.app_protocol == "HTTP" or b"HTTP/1." in p_data:
                    extracted = extractor.extract_from_http(p_data, stream_id=stream.stream_id)
                    extracted_files.extend(extracted)

                # Carving
                carved = extractor.carve_all(p_data, f"Stream #{stream.stream_id}", stream_id=stream.stream_id)
                extracted_files.extend(carved)

        # Scan extracted files for flags
        for ef in extracted_files:
            if os.path.exists(ef.disk_path):
                with open(ef.disk_path, "rb") as f:
                    fb = f.read()
                f_flags = scanner.scan_bytes(fb, source=f"File: {ef.filename}")
                found_flags.extend(f_flags)

        flag_texts = {f.flag for f in found_flags}

        # Verify ground truth flags were all captured
        self.assertIn("flag{raw_plaintext_packet}", flag_texts)
        self.assertIn("picoCTF{base64_udp_secret}", flag_texts)
        self.assertIn("THM{hex_dns_tunnel}", flag_texts)
        self.assertIn("H4G{url_encoded_param}", flag_texts)
        self.assertIn("flag{gzip_compressed_http_body}", flag_texts)
        self.assertIn("HTB{png_stego_after_iend}", flag_texts)
        self.assertIn("HTB{rot13_icmp_secret}", flag_texts)
        self.assertIn("HTB{reversed_flag_in_stream}", flag_texts)

        # Verify stego warning was generated on secret_cat.png
        stego_files = [f for f in extracted_files if f.has_stego_warning]
        self.assertGreaterEqual(len(stego_files), 1)

    def test_h4g_pattern(self):
        patterns_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "default_patterns.json")
        scanner = FlagScanner(patterns_path)
        sample = b"DATA: h4g{lowercase_flag_example_12345} END"
        matches = scanner.scan_bytes(sample, source="test")
        matched_patterns = {m.pattern_name for m in matches}
        self.assertIn("h4g", matched_patterns)
        self.assertTrue(any(m.flag == "h4g{lowercase_flag_example_12345}" for m in matches))


if __name__ == "__main__":
    unittest.main()

