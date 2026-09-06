import os
from typing import List

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QLineEdit, QProgressBar, QTabWidget, QFileDialog,
    QMessageBox, QMenuBar, QMenu, QStatusBar, QFrame, QScrollArea, QLayout
)
from PyQt6.QtGui import QAction, QDragEnterEvent, QDropEvent
from PyQt6.QtCore import Qt, pyqtSignal, QSize, QTimer

from core.flag_scanner import FlagScanner
from core.engine import AnalysisEngine
from core.models import AnalysisSummary, FlagMatch, ExtractedFile
from core.pcap_parser import validate_capture_file

from ui.tabs.flags_tab import FlagsTab
from ui.tabs.files_tab import FilesTab
from ui.tabs.summary_tab import SummaryTab
from ui.tabs.console_tab import ConsoleTab

from ui.dialogs.regex_dialog import RegexManagerDialog
from ui.dialogs.export_dialog import ExportReportDialog
from ui.styles.themes import DARK_THEME_QSS, LIGHT_THEME_QSS
from ui.icons import icon


class DropZoneWidget(QFrame):
    """
    Drag and drop target area accepting capture files or directories.
    """
    files_dropped = pyqtSignal(list)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("dropZone")
        self.setAcceptDrops(True)
        self.setMinimumHeight(145)

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        symbol = QLabel()
        symbol.setPixmap(icon("upload").pixmap(32, 32))
        symbol.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(symbol)
        self.lbl_text = QLabel("Drop captures here")
        self.lbl_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.lbl_text)
        hint = QLabel("PCAP, PCAPNG or text dumps\nFiles and folders supported")
        hint.setObjectName("muted")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(hint)

    def _set_drag_active(self, active):
        self.setProperty("dragActive", active)
        self.style().unpolish(self)
        self.style().polish(self)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self._set_drag_active(True)

    def dragLeaveEvent(self, event):
        self._set_drag_active(False)

    def dropEvent(self, event: QDropEvent):
        self._set_drag_active(False)
        urls = event.mimeData().urls()
        filepaths = [u.toLocalFile() for u in urls if u.isLocalFile()]
        if filepaths:
            self.files_dropped.emit(filepaths)
            event.acceptProposedAction()


class MainWindow(QMainWindow):
    """
    Main application window for PCAP Network Forensics & Flag Extraction Tool.
    """

    def __init__(self, patterns_file: str = "default_patterns.json", output_dir: str = "extracted_files"):
        super().__init__()
        self.setWindowTitle("PCAP Forensics & Flag Extraction Suite")
        self.resize(1320, 840)
        self.setMinimumSize(1024, 700)
        self.setWindowIcon(icon("capture"))
        self._stop_requested = False
        self._close_pending = False

        self.patterns_file = patterns_file
        self.output_dir = os.path.abspath(output_dir)
        os.makedirs(self.output_dir, exist_ok=True)

        self.flag_scanner = FlagScanner(patterns_file)
        self.engine: AnalysisEngine = None
        self.is_dark_theme = True
        self.latest_summary: AnalysisSummary = None

        self._init_menu()
        self._init_ui()
        self.set_theme(dark=True)

    def _init_menu(self):
        menubar = self.menuBar()

        # File Menu
        menu_file = menubar.addMenu("&File")

        act_open_file = QAction(icon("file"), "Open &Capture File...", self)
        self.act_open_file = act_open_file
        act_open_file.setShortcut("Ctrl+O")
        act_open_file.triggered.connect(self._browse_single_file)
        menu_file.addAction(act_open_file)

        act_open_folder = QAction(icon("folder"), "Open &Directory (Batch Mode)...", self)
        self.act_open_folder = act_open_folder
        act_open_folder.setShortcut("Ctrl+Shift+O")
        act_open_folder.triggered.connect(self._browse_folder)
        menu_file.addAction(act_open_folder)

        menu_file.addSeparator()

        self.act_export = QAction(icon("export"), "&Export Forensic Report...", self)
        self.act_export.setShortcut("Ctrl+E")
        self.act_export.setEnabled(False)
        self.act_export.triggered.connect(self._open_export_dialog)
        menu_file.addAction(self.act_export)

        menu_file.addSeparator()

        act_exit = QAction("E&xit", self)
        act_exit.setShortcut("Ctrl+Q")
        act_exit.triggered.connect(self.close)
        menu_file.addAction(act_exit)

        # Tools Menu
        menu_tools = menubar.addMenu("&Tools")

        act_regex = QAction(icon("settings"), "Manage &Regex Patterns...", self)
        self.act_regex = act_regex
        act_regex.setShortcut("Ctrl+R")
        act_regex.triggered.connect(self._open_regex_manager)
        menu_tools.addAction(act_regex)

        act_open_out = QAction(icon("folder"), "Open &Extracted Files Folder", self)
        act_open_out.triggered.connect(self._open_output_dir)
        menu_tools.addAction(act_open_out)

        # View Menu
        menu_view = menubar.addMenu("&View")
        self.act_theme = QAction(icon("theme"), "Toggle &Light / Dark Theme", self)
        self.act_theme.setShortcut("Ctrl+T")
        self.act_theme.triggered.connect(self._toggle_theme)
        menu_view.addAction(self.act_theme)

        # Help Menu
        menu_help = menubar.addMenu("&Help")
        act_about = QAction("&About", self)
        act_about.triggered.connect(self._show_about)
        menu_help.addAction(act_about)

    def _init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(24, 20, 24, 20)
        main_layout.setSpacing(20)

        header = QHBoxLayout()
        brand_icon = QLabel()
        brand_icon.setPixmap(icon("capture", "#369ab1").pixmap(40, 40))
        header.addWidget(brand_icon)
        brand = QVBoxLayout()
        brand.setSpacing(3)
        eyebrow = QLabel("NETWORK INVESTIGATION")
        eyebrow.setObjectName("eyebrow")
        title = QLabel("PCAP Forensics")
        title.setObjectName("appTitle")
        brand.addWidget(eyebrow)
        brand.addWidget(title)
        header.addLayout(brand)
        header.addStretch()
        self.lbl_state = QLabel("Ready")
        self.lbl_state.setObjectName("stateBadge")
        header.addWidget(self.lbl_state)
        self.btn_theme = QPushButton(icon("theme"), "Light theme")
        self.btn_theme.setToolTip("Switch color theme (Ctrl+T)")
        self.btn_theme.clicked.connect(self._toggle_theme)
        header.addWidget(self.btn_theme)
        self.btn_export = QPushButton(icon("export"), "Export report")
        self.btn_export.setEnabled(False)
        self.btn_export.clicked.connect(self._open_export_dialog)
        header.addWidget(self.btn_export)
        main_layout.addLayout(header)

        body = QHBoxLayout()
        body.setSpacing(20)
        self.sidebar = QFrame()
        self.sidebar.setObjectName("sidebar")
        side = QVBoxLayout(self.sidebar)
        side.setSizeConstraint(QLayout.SizeConstraint.SetMinimumSize)
        side.setContentsMargins(18, 20, 18, 20)
        side.setSpacing(12)
        heading = QLabel("Capture workspace")
        heading.setObjectName("sectionTitle")
        side.addWidget(heading)
        subtitle = QLabel("Load evidence to begin your analysis.")
        subtitle.setObjectName("muted")
        subtitle.setWordWrap(True)
        side.addWidget(subtitle)
        self.drop_zone = DropZoneWidget()
        self.drop_zone.files_dropped.connect(self._on_files_dropped)
        side.addWidget(self.drop_zone)

        label = QLabel("Capture path or folder")
        side.addWidget(label)
        self.inp_target = QLineEdit()
        self.inp_target.setPlaceholderText("Select or paste a capture path")
        self.inp_target.setAccessibleName("Capture path or folder")
        self.inp_target.textChanged.connect(lambda text: self.inp_target.setToolTip(text))
        label.setBuddy(self.inp_target)
        side.addWidget(self.inp_target)
        browse = QHBoxLayout()
        self.btn_browse_file = QPushButton(icon("file"), "Open file")
        self.btn_browse_file.clicked.connect(self._browse_single_file)
        self.btn_browse_file.setToolTip("Open capture (Ctrl+O)")
        browse.addWidget(self.btn_browse_file)
        self.btn_browse_dir = QPushButton(icon("folder"), "Folder")
        self.btn_browse_dir.clicked.connect(self._browse_folder)
        self.btn_browse_dir.setToolTip("Analyze a folder of captures (Ctrl+Shift+O)")
        browse.addWidget(self.btn_browse_dir)
        side.addLayout(browse)
        side.addSpacing(8)
        self.btn_start = QPushButton(icon("play", "#ffffff"), "Start analysis")
        self.btn_start.setObjectName("btnStart")
        self.btn_start.setMinimumHeight(42)
        self.btn_start.clicked.connect(self.start_analysis)
        side.addWidget(self.btn_start)
        self.btn_stop = QPushButton(icon("stop"), "Stop analysis")
        self.btn_stop.setObjectName("btnStop")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_analysis)
        side.addWidget(self.btn_stop)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setAccessibleName("Analysis progress")
        side.addWidget(self.progress_bar)
        self.lbl_progress = QLabel("Waiting for a capture")
        self.lbl_progress.setObjectName("muted")
        self.lbl_progress.setWordWrap(True)
        side.addWidget(self.lbl_progress)
        side.addStretch()
        tools_title = QLabel("ANALYSIS TOOLS")
        tools_title.setObjectName("eyebrow")
        side.addWidget(tools_title)
        self.btn_patterns = QPushButton(icon("settings"), "Flag patterns")
        self.btn_patterns.clicked.connect(self._open_regex_manager)
        side.addWidget(self.btn_patterns)
        btn_output = QPushButton(icon("folder"), "Output folder")
        btn_output.clicked.connect(self._open_output_dir)
        side.addWidget(btn_output)
        sidebar_scroll = QScrollArea()
        sidebar_scroll.setWidgetResizable(True)
        sidebar_scroll.setFixedWidth(270)
        sidebar_scroll.setFrameShape(QFrame.Shape.NoFrame)
        sidebar_scroll.setWidget(self.sidebar)
        body.addWidget(sidebar_scroll)

        workspace = QFrame()
        workspace.setObjectName("workspace")
        results = QVBoxLayout(workspace)
        results.setContentsMargins(8, 12, 8, 8)
        results.setSpacing(8)
        self.tabs = QTabWidget()
        self.tabs.setIconSize(QSize(18, 18))
        self.tab_flags = FlagsTab()
        self.tab_files = FilesTab(self.output_dir)
        self.tab_summary = SummaryTab()
        self.tab_console = ConsoleTab()
        self.tabs.addTab(self.tab_flags, icon("flag"), "Flags (0)")
        self.tabs.addTab(self.tab_files, icon("folder"), "Files (0)")
        self.tabs.addTab(self.tab_summary, icon("chart"), "Overview")
        self.tabs.addTab(self.tab_console, icon("terminal"), "Console")
        self.tabs.setCurrentIndex(2)
        results.addWidget(self.tabs)
        body.addWidget(workspace, 1)
        main_layout.addLayout(body, 1)

        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("Ready. Open or drop a capture to begin.")
        local = QLabel("Local analysis  |  PCAP / PCAPNG / DUMP")
        local.setObjectName("muted")
        self.statusBar.addPermanentWidget(local)

    def set_theme(self, dark: bool):
        self.is_dark_theme = dark
        self.tab_console.set_theme(dark)
        self.btn_theme.setText("Light theme" if dark else "Dark theme")
        if dark:
            self.setStyleSheet(DARK_THEME_QSS)
        else:
            self.setStyleSheet(LIGHT_THEME_QSS)

    def _toggle_theme(self):
        self.set_theme(not self.is_dark_theme)

    def _browse_single_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Capture File",
            "",
            "Capture Files (*.pcap *.pcapng *.cap *.dump *.txt *.log);;All Files (*)"
        )
        if path:
            self.inp_target.setText(path)

    def _browse_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Select Folder Containing Captures")
        if path:
            self.inp_target.setText(path)

    def _on_files_dropped(self, paths: List[str]):
        if self.engine and self.engine.isRunning():
            return
        if paths:
            if len(paths) == 1:
                self.inp_target.setText(paths[0])
            else:
                # Comma separated list of dropped files
                self.inp_target.setText(";".join(paths))

    def _get_target_file_list(self) -> List[str]:
        raw_target = self.inp_target.text().strip()
        # A real path may itself contain a semicolon.
        paths = [raw_target] if os.path.exists(raw_target) else raw_target.split(";")
        captures = []
        extensions = {".pcap", ".pcapng", ".cap", ".dump", ".txt", ".log"}
        for path in paths:
            path = path.strip()
            if os.path.isdir(path):
                captures.extend(sorted(
                    entry.path for entry in os.scandir(path)
                    if entry.is_file() and os.path.splitext(entry.name)[1].lower() in extensions
                ))
            elif os.path.isfile(path):
                captures.append(path)
        return list(dict.fromkeys(os.path.abspath(path) for path in captures))

    def _set_running(self, running):
        self.btn_start.setEnabled(not running)
        self.btn_stop.setEnabled(running)
        for control in (self.inp_target, self.btn_browse_file, self.btn_browse_dir,
                        self.drop_zone, self.btn_patterns, self.act_open_file,
                        self.act_open_folder, self.act_regex):
            control.setEnabled(not running)
        can_export = not running and self.latest_summary is not None
        self.act_export.setEnabled(can_export)
        self.btn_export.setEnabled(can_export)

    def start_analysis(self):
        if self.engine and self.engine.isRunning():
            return
        try:
            targets = self._get_target_file_list()
        except OSError as error:
            QMessageBox.warning(self, "Cannot open capture folder", str(error))
            return
        if not targets:
            QMessageBox.warning(
                self,
                "Invalid Target",
                "Please select or drop valid capture file(s) before starting."
            )
            return

        # Pre-validate first file
        is_val, fmt, err = validate_capture_file(targets[0])
        if not is_val:
            QMessageBox.critical(self, "File Validation Error", f"Cannot parse {targets[0]}:\n{err}")
            return

        # Reset UI
        self.latest_summary = None
        self._stop_requested = False
        self.tab_flags.clear()
        self.tab_files.clear()
        self.tab_summary.clear()
        self.tab_console.clear()
        self.tabs.setTabText(0, "Flags (0)")
        self.tabs.setTabText(1, "Files (0)")

        self._set_running(True)
        self.lbl_state.setText("Analyzing")
        self.lbl_progress.setText("Reading capture...")
        self.progress_bar.setValue(0)

        self.tab_console.log("INFO", f"Starting analysis on {len(targets)} capture file(s)...")

        # Launch background engine
        self.engine = AnalysisEngine(
            filepaths=targets,
            output_dir=self.output_dir,
            flag_scanner=self.flag_scanner,
            parent=self
        )
        self.engine.progress_updated.connect(self._on_progress)
        self.engine.flag_found.connect(self._on_flag_found)
        self.engine.file_extracted.connect(self._on_file_extracted)
        self.engine.log_message.connect(self._on_log_message)
        self.engine.analysis_finished.connect(self._on_analysis_finished)
        self.engine.error_occurred.connect(self._on_error)
        self.engine.finished.connect(self._on_worker_finished)

        self.engine.start()
        self.statusBar.showMessage(f"Analyzing {len(targets)} file(s)...")

    def stop_analysis(self):
        if self.engine and self.engine.isRunning():
            self._stop_requested = True
            self.engine.stop()
            self.lbl_state.setText("Stopping")
            self.lbl_progress.setText("Waiting for analysis to stop...")
            self.statusBar.showMessage("Stopping analysis...")
            self.btn_stop.setEnabled(False)

    def _on_progress(self, current: int, total: int, pct: float, status: str):
        if not self._stop_requested:
            self.progress_bar.setValue(int(pct))
            self.lbl_progress.setText(f"{int(pct)}%  |  {current:,} packets processed")
            self.statusBar.showMessage(status)

    def _on_flag_found(self, flag: FlagMatch):
        self.tab_flags.add_flag(flag)
        count = len(self.tab_flags.flags)
        self.tabs.setTabText(0, f"Flags ({count})")

    def _on_file_extracted(self, extracted_file: ExtractedFile):
        self.tab_files.add_file(extracted_file)
        count = len(self.tab_files.files)
        self.tabs.setTabText(1, f"Files ({count})")

    def _on_log_message(self, level: str, msg: str):
        self.tab_console.log(level, msg)

    def _on_analysis_finished(self, summary: AnalysisSummary):
        self.latest_summary = summary
        self.tab_summary.update_summary(summary)
        stopped = self._stop_requested
        self.lbl_state.setText("Stopped" if stopped else "Complete")
        if not stopped:
            self.progress_bar.setValue(100)
        self.lbl_progress.setText("Partial results available" if stopped else "Analysis complete")
        outcome = "Stopped" if stopped else "Finished"
        self.statusBar.showMessage(
            f"{outcome} in {summary.duration_seconds:.2f}s | {summary.flags_count} flags | {summary.files_count} files"
        )
        # Switch to summary or flags tab if flags were found
        if summary.flags_count > 0:
            self.tabs.setCurrentIndex(0)
        else:
            self.tabs.setCurrentIndex(2)

    def _on_error(self, err_msg: str):
        self.btn_stop.setEnabled(False)
        self.lbl_state.setText("Error")
        self.lbl_progress.setText("Analysis failed. Check the console for details.")
        self.statusBar.showMessage("Analysis encountered an error.")
        QMessageBox.critical(self, "Analysis Error", err_msg)

    def _on_worker_finished(self):
        self._set_running(False)
        if self._close_pending:
            QTimer.singleShot(0, self.close)

    def closeEvent(self, event):
        if self.engine and self.engine.isRunning():
            self._close_pending = True
            self.stop_analysis()
            event.ignore()
        else:
            event.accept()

    def _open_export_dialog(self):
        if self.engine and self.engine.isRunning():
            return
        if not self.latest_summary:
            QMessageBox.information(self, "Export", "Run an analysis first before exporting.")
            return

        dialog = ExportReportDialog(
            summary=self.latest_summary,
            flags=self.tab_flags.flags,
            files=self.tab_files.files,
            default_dir=os.getcwd(),
            parent=self
        )
        dialog.exec()

    def _open_regex_manager(self):
        if self.engine and self.engine.isRunning():
            return
        dialog = RegexManagerDialog(self.flag_scanner, self)
        dialog.exec()

    def _open_output_dir(self):
        self.tab_files.open_output_folder()

    def _show_about(self):
        QMessageBox.about(
            self,
            "About PCAP Forensics & Flag Extraction Suite",
            "<h3>PCAP Forensics & Flag Extraction Suite</h3>"
            "<p>A desktop application for network capture analysis, session reconstruction, "
            "file carving, stego anomaly detection, and automated CTF flag discovery.</p>"
            "<p><b>Features:</b>"
            "<ul>"
            "<li>Multi-layer decoding (Base64, Hex, URL, Gzip, ROT13, Reversed)</li>"
            "<li>Protocol reassembly (HTTP, FTP, SMTP, DNS, ICMP)</li>"
            "<li>File signature carving and Stego trailer checks</li>"
            "<li>JSON, HTML, and vector PDF reporting</li>"
            "</ul></p>"
        )
