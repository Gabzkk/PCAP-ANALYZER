from ui.icons import icon
import os
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QCheckBox, QGroupBox,
    QPushButton, QLineEdit, QLabel, QFileDialog, QMessageBox
)
from core.models import AnalysisSummary, FlagMatch, ExtractedFile
from core.reporter import ForensicReporter, HAS_QT_PDF


class ExportReportDialog(QDialog):
    """
    Dialog to export forensic findings to JSON, HTML, and PDF.
    """

    def __init__(
        self,
        summary: AnalysisSummary,
        flags: list[FlagMatch],
        files: list[ExtractedFile],
        default_dir: str = "",
        parent=None
    ):
        super().__init__(parent)
        self.summary = summary
        self.flags = flags
        self.files = files
        self.default_dir = default_dir or os.getcwd()

        self.setWindowTitle("Export Forensic Report")
        self.resize(500, 320)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        # Formats Group
        grp_formats = QGroupBox("Select Report Formats")
        fmt_layout = QVBoxLayout(grp_formats)

        self.chk_html = QCheckBox("HTML Interactive Dashboard Report (.html)")
        self.chk_html.setChecked(True)
        fmt_layout.addWidget(self.chk_html)

        self.chk_json = QCheckBox("JSON Structured Raw Data (.json)")
        self.chk_json.setChecked(True)
        fmt_layout.addWidget(self.chk_json)

        self.chk_pdf = QCheckBox("PDF Vector Document (.pdf)")
        self.chk_pdf.setChecked(True)
        if not HAS_QT_PDF:
            self.chk_pdf.setEnabled(False)
            self.chk_pdf.setText("PDF (Unavailable: QtPrintSupport not found)")
        fmt_layout.addWidget(self.chk_pdf)

        layout.addWidget(grp_formats)

        # Destination Directory
        grp_dest = QGroupBox("Destination Directory")
        dest_layout = QHBoxLayout(grp_dest)

        self.inp_dir = QLineEdit(self.default_dir)
        self.btn_browse = QPushButton(icon("folder"), "Browse...")
        self.btn_browse.clicked.connect(self._browse_dir)

        dest_layout.addWidget(self.inp_dir)
        dest_layout.addWidget(self.btn_browse)
        layout.addWidget(grp_dest)

        # Base Filename
        grp_base = QGroupBox("Report Base Name")
        base_layout = QHBoxLayout(grp_base)
        base_default = f"forensic_report_{os.path.splitext(self.summary.capture_file)[0]}"
        self.inp_base = QLineEdit(base_default)
        base_layout.addWidget(self.inp_base)
        layout.addWidget(grp_base)

        # Action buttons
        btn_bar = QHBoxLayout()
        btn_bar.addStretch()

        self.btn_export = QPushButton(icon("export", "#ffffff"), "Export reports")
        self.btn_export.setObjectName("primaryButton")
        self.btn_export.clicked.connect(self._do_export)
        btn_bar.addWidget(self.btn_export)

        self.btn_cancel = QPushButton(icon("close"), "Cancel")
        self.btn_cancel.clicked.connect(self.reject)
        btn_bar.addWidget(self.btn_cancel)

        layout.addLayout(btn_bar)

    def _browse_dir(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Output Directory", self.inp_dir.text())
        if dir_path:
            self.inp_dir.setText(dir_path)

    def _do_export(self):
        dest_dir = self.inp_dir.text().strip()
        base_name = self.inp_base.text().strip()

        if not dest_dir or not base_name:
            QMessageBox.warning(self, "Missing Input", "Please provide a valid destination folder and base name.")
            return

        os.makedirs(dest_dir, exist_ok=True)
        exported = []

        # 1. HTML
        if self.chk_html.isChecked():
            html_path = os.path.join(dest_dir, f"{base_name}.html")
            try:
                ForensicReporter.export_html(self.summary, self.flags, self.files, html_path)
                exported.append(f"HTML: {html_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export HTML: {e}")

        # 2. JSON
        if self.chk_json.isChecked():
            json_path = os.path.join(dest_dir, f"{base_name}.json")
            try:
                ForensicReporter.export_json(self.summary, self.flags, self.files, json_path)
                exported.append(f"JSON: {json_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export JSON: {e}")

        # 3. PDF
        if self.chk_pdf.isChecked() and HAS_QT_PDF:
            pdf_path = os.path.join(dest_dir, f"{base_name}.pdf")
            try:
                ok = ForensicReporter.export_pdf(self.summary, self.flags, self.files, pdf_path)
                if ok:
                    exported.append(f"PDF: {pdf_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export PDF: {e}")

        if exported:
            msg = "Reports successfully created:\n\n" + "\n".join(exported)
            QMessageBox.information(self, "Export Complete", msg)
            self.accept()

