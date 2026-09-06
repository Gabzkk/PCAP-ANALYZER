import unittest
import os
import shutil
import tempfile
import sys
from unittest.mock import patch
from threading import Event

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QTimer

# Ensure headless offscreen platform is set
os.environ["QT_QPA_PLATFORM"] = "offscreen"

from ui.main_window import MainWindow
from core.models import AnalysisSummary, FlagMatch, ExtractedFile
from core.reporter import ForensicReporter
from core.engine import AnalysisEngine
from tests.test_pcap_generator import generate_synthetic_pcap


class TestHeadlessGUI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication(sys.argv)
        cls.temp_dir = tempfile.mkdtemp()
        cls.pcap_path = os.path.join(cls.temp_dir, "test_gui_capture.pcap")
        generate_synthetic_pcap(cls.pcap_path)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_main_window_init(self):
        patterns_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "default_patterns.json")
        out_dir = os.path.join(self.temp_dir, "gui_out")
        win = MainWindow(patterns_file=patterns_path, output_dir=out_dir)

        # Verify UI components
        self.assertIsNotNone(win.inp_target)
        self.assertIsNotNone(win.btn_start)
        self.assertIsNotNone(win.btn_stop)
        self.assertIsNotNone(win.tab_flags)
        self.assertIsNotNone(win.tab_files)
        self.assertIsNotNone(win.tab_summary)
        self.assertIsNotNone(win.tab_console)

        # Test setting target and theme toggle
        win.inp_target.setText(self.pcap_path)
        self.assertEqual(win.inp_target.text(), self.pcap_path)

        win._toggle_theme()
        self.assertFalse(win.is_dark_theme)
        win._toggle_theme()
        self.assertTrue(win.is_dark_theme)

    def test_gui_analysis_flow(self):
        patterns_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "default_patterns.json")
        out_dir = os.path.join(self.temp_dir, "gui_out_flow")
        win = MainWindow(patterns_file=patterns_path, output_dir=out_dir)
        win.inp_target.setText(self.pcap_path)

        # Trigger analysis
        win.start_analysis()
        self.assertIsNotNone(win.engine)

        # Wait for thread completion
        win.engine.wait(5000)
        self.app.processEvents()

        # Check results in tabs
        self.assertGreaterEqual(len(win.tab_flags.flags), 5)
        self.assertGreaterEqual(len(win.tab_files.files), 1)
        self.assertIsNotNone(win.latest_summary)

        # Test Report Export (JSON, HTML, PDF)
        json_rep = os.path.join(self.temp_dir, "test_report.json")
        html_rep = os.path.join(self.temp_dir, "test_report.html")
        pdf_rep = os.path.join(self.temp_dir, "test_report.pdf")

        ForensicReporter.export_json(win.latest_summary, win.tab_flags.flags, win.tab_files.files, json_rep)
        self.assertTrue(os.path.exists(json_rep))

        ForensicReporter.export_html(win.latest_summary, win.tab_flags.flags, win.tab_files.files, html_rep)
        self.assertTrue(os.path.exists(html_rep))

        pdf_ok = ForensicReporter.export_pdf(win.latest_summary, win.tab_flags.flags, win.tab_files.files, pdf_rep)
        self.assertTrue(pdf_ok)
        self.assertTrue(os.path.exists(pdf_rep))

    def test_live_results_respect_filter_and_cannot_be_edited(self):
        win = MainWindow(output_dir=os.path.join(self.temp_dir, "filter_out"))
        win.tab_flags.search_input.setText("wanted")
        win.tab_flags.add_flag(FlagMatch(flag="flag{other}", pattern_name="CTF", source="Packet", encoding="Plain"))
        win.tab_flags.add_flag(FlagMatch(flag="flag{wanted}", pattern_name="CTF", source="Packet", encoding="Plain"))
        self.assertTrue(win.tab_flags.table.isRowHidden(0))
        self.assertFalse(win.tab_flags.table.isRowHidden(1))
        self.assertEqual(win.tab_flags.table.editTriggers(), win.tab_flags.table.EditTrigger.NoEditTriggers)

    def test_mixed_dropped_files_and_directories_expand_and_deduplicate(self):
        win = MainWindow(output_dir=os.path.join(self.temp_dir, "batch_out"))
        folder = os.path.join(self.temp_dir, "captures")
        os.makedirs(folder, exist_ok=True)
        capture = os.path.join(folder, "example.Pcap")
        shutil.copyfile(self.pcap_path, capture)
        win._on_files_dropped([folder, self.pcap_path, capture])
        self.assertEqual(set(win._get_target_file_list()), {capture, self.pcap_path})
        self.assertEqual(len(win._get_target_file_list()), 2)

    def test_restart_clears_summary_and_locks_capture_controls(self):
        win = MainWindow(output_dir=os.path.join(self.temp_dir, "restart_out"))
        win.inp_target.setText(self.pcap_path)
        win.start_analysis()
        win.engine.wait(5000)
        self.app.processEvents()
        self.assertIsNotNone(win.latest_summary)
        win.start_analysis()
        try:
            self.assertIsNone(win.latest_summary)
            self.assertFalse(win.inp_target.isEnabled())
            self.assertFalse(win.btn_export.isEnabled())
        finally:
            win.engine.wait(5000)
            self.app.processEvents()
        self.assertTrue(win.btn_export.isEnabled())
        self.assertTrue(win.inp_target.isEnabled())

    def test_immediate_stop_is_not_lost_when_worker_starts(self):
        win = MainWindow(output_dir=os.path.join(self.temp_dir, "immediate_stop"))
        engine = AnalysisEngine([self.pcap_path], win.output_dir, win.flag_scanner)
        engine.stop()
        engine.run()
        self.assertEqual(engine.total_packets_processed, 0)

    def test_stop_keeps_partial_results_and_restores_controls(self):
        entered, release = Event(), Event()

        def delayed_packets(_parser):
            entered.set()
            release.wait(5)
            yield from ()

        win = MainWindow(output_dir=os.path.join(self.temp_dir, "stop_out"))
        win.inp_target.setText(self.pcap_path)
        with patch("core.engine.StreamingCaptureParser.parse_packets", delayed_packets):
            win.start_analysis()
            try:
                self.assertTrue(entered.wait(2))
                win.stop_analysis()
                self.assertFalse(win.btn_start.isEnabled())
                self.assertFalse(win.btn_stop.isEnabled())
            finally:
                release.set()
                self.assertTrue(win.engine.wait(5000))
                self.app.processEvents()
        self.assertEqual(win.lbl_state.text(), "Stopped")
        self.assertLess(win.progress_bar.value(), 100)
        self.assertIsNotNone(win.latest_summary)
        self.assertTrue(win.btn_start.isEnabled())

    def test_files_filter_full_hash_and_new_rows(self):
        win = MainWindow(output_dir=os.path.join(self.temp_dir, "file_filter"))
        win.tab_files.search_input.setText("abcdef")
        for filename, digest in [("other.txt", "0" * 64), ("match.txt", "0" * 58 + "abcdef")]:
            win.tab_files.add_file(ExtractedFile(filename, "Text", ".txt", 1, "HTTP", "", digest))
        self.assertTrue(win.tab_files.table.isRowHidden(0))
        self.assertFalse(win.tab_files.table.isRowHidden(1))
        win.tab_files.table.selectRow(1)
        self.assertTrue(win.tab_files.btn_preview.isEnabled())
        win.tab_files.search_input.setText("missing")
        self.assertFalse(win.tab_files.btn_preview.isEnabled())

    def test_console_preserves_literal_text_when_switching_themes(self):
        win = MainWindow(output_dir=os.path.join(self.temp_dir, "console_out"))
        win.tab_console.log("FOUND", "flag{<payload>&amp;}")
        before = win.tab_console.console_box.toPlainText()
        self.assertIn("flag{<payload>&amp;}", before)
        win.set_theme(False)
        self.assertEqual(win.tab_console.console_box.toPlainText(), before)

    def test_close_waits_for_active_worker(self):
        entered, release = Event(), Event()

        def delayed_packets(_parser):
            entered.set()
            release.wait(5)
            yield from ()

        win = MainWindow(output_dir=os.path.join(self.temp_dir, "close_out"))
        win.show()
        win.inp_target.setText(self.pcap_path)
        with patch("core.engine.StreamingCaptureParser.parse_packets", delayed_packets):
            win.start_analysis()
            try:
                self.assertTrue(entered.wait(2))
                win.close()
                self.assertTrue(win.isVisible())
                self.assertEqual(win.lbl_state.text(), "Stopping")
            finally:
                release.set()
                self.assertTrue(win.engine.wait(5000))
                self.app.processEvents()
                self.app.processEvents()
        self.assertFalse(win.isVisible())

    def test_worker_error_restores_controls_without_exporting_stale_data(self):
        win = MainWindow(output_dir=os.path.join(self.temp_dir, "error_out"))
        win.inp_target.setText(self.pcap_path)
        with patch("core.engine.StreamingCaptureParser.parse_packets", side_effect=OSError("Cannot read capture")), \
                patch("ui.main_window.QMessageBox.critical"):
            win.start_analysis()
            self.assertTrue(win.engine.wait(5000))
            self.app.processEvents()
        self.assertEqual(win.lbl_state.text(), "Error")
        self.assertTrue(win.btn_start.isEnabled())
        self.assertTrue(win.inp_target.isEnabled())
        self.assertFalse(win.btn_export.isEnabled())
        self.assertIsNone(win.latest_summary)


if __name__ == "__main__":
    unittest.main()
