import unittest
import os
import shutil
import tempfile
from core.file_extractor import FileExtractor
from core.steganalysis import SteganalysisEngine


class TestCarverAndSteganalysis(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.extractor = FileExtractor(self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_png_stego_appended_data(self):
        png_header = b"\x89PNG\r\n\x1a\n"
        ihdr = b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"
        iend = b"\x00\x00\x00\x00IEND\xae\x42\x60\x82"
        extra = b"SECRET_TRAILING_BYTES_HTB{test_stego}"
        stego_png = png_header + ihdr + iend + extra

        has_warning, details, appended = SteganalysisEngine.analyze(stego_png, "png")
        self.assertTrue(has_warning)
        self.assertIn("Appended data after PNG IEND chunk", details)
        self.assertEqual(appended, extra)

    def test_clean_png_no_warning(self):
        png_header = b"\x89PNG\r\n\x1a\n"
        ihdr = b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"
        iend = b"\x00\x00\x00\x00IEND\xae\x42\x60\x82"
        clean_png = png_header + ihdr + iend

        has_warning, details, appended = SteganalysisEngine.analyze(clean_png, "png")
        self.assertFalse(has_warning)

    def test_jpeg_stego_appended_data(self):
        soi = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        eoi = b"\xff\xd9"
        extra = b"AppendedSecretTrailerData"
        jpeg_data = soi + eoi + extra

        has_warning, details, appended = SteganalysisEngine.analyze(jpeg_data, "jpg")
        self.assertTrue(has_warning)
        self.assertIn("Appended data after JPEG EOI", details)
        self.assertEqual(appended, extra)

    def test_magic_byte_carving(self):
        # Embed a PNG inside arbitrary traffic noise
        noise_before = b"RandomTCPGarbageData12345678"
        png_header = b"\x89PNG\r\n\x1a\n"
        ihdr = b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"
        iend = b"\x00\x00\x00\x00IEND\xae\x42\x60\x82"
        valid_png = png_header + ihdr + iend
        noise_after = b"MoreTrafficAfterImage"

        full_stream = noise_before + valid_png + noise_after

        carved = self.extractor.carve_all(full_stream, "TestStream", stream_id=1)
        self.assertGreaterEqual(len(carved), 1)
        self.assertEqual(carved[0].extension, ".png")
        self.assertTrue(os.path.exists(carved[0].disk_path))


if __name__ == "__main__":
    unittest.main()

