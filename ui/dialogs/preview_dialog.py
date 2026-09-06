from html import escape
from ui.icons import icon
import os
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit,
    QPushButton, QTabWidget, QWidget, QMessageBox, QApplication
)
from PyQt6.QtGui import QPixmap, QFont
from PyQt6.QtCore import Qt
from core.models import ExtractedFile


def format_hex_dump(data: bytes, max_bytes: int = 65536) -> str:
    """Formats binary data into standard hex dump: offset | hex | ascii."""
    lines = []
    chunk = data[:max_bytes]
    for i in range(0, len(chunk), 16):
        sub = chunk[i:i+16]
        hex_bytes = " ".join(f"{b:02x}" for b in sub)
        # Pad hex display to 48 chars
        hex_bytes_padded = hex_bytes.ljust(48)
        ascii_chars = "".join(chr(b) if 32 <= b <= 126 else "." for b in sub)
        lines.append(f"{i:08x}  {hex_bytes_padded}  |{ascii_chars}|")
    if len(data) > max_bytes:
        lines.append(f"... [Truncated. Showing first {max_bytes:,} of {len(data):,} bytes]")
    return "\n".join(lines)


class FilePreviewDialog(QDialog):
    """
    Multi-mode file viewer dialog supporting Image Preview, Text Preview, and Hex Dump.
    """

    def __init__(self, extracted_file: ExtractedFile, parent=None):
        super().__init__(parent)
        self.file_info = extracted_file
        self.setWindowTitle(f"File Inspection: {extracted_file.filename}")
        self.resize(800, 600)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)

        # Header Info Card
        header_text = (
            f"<b>File:</b> {escape(self.file_info.filename)} &bull; "
            f"<b>Type:</b> {escape(self.file_info.file_type)} &bull; "
            f"<b>Size:</b> {self.file_info.size_bytes:,} bytes<br>"
            f"<b>SHA256:</b> <code>{escape(self.file_info.sha256)}</code><br>"
            f"<b>Source Protocol:</b> {escape(self.file_info.source_protocol)}"
        )
        if self.file_info.has_stego_warning:
            header_text += (
                f"<br><b>Stego warning:</b> "
                f"<span>{escape(self.file_info.stego_details)}</span>"
            )

        lbl_header = QLabel(header_text)
        lbl_header.setTextFormat(Qt.TextFormat.RichText)
        lbl_header.setObjectName("previewHeader")
        lbl_header.setWordWrap(True)
        lbl_header.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(lbl_header)

        # Read file data
        raw_data = b""
        if os.path.exists(self.file_info.disk_path):
            try:
                with open(self.file_info.disk_path, "rb") as f:
                    raw_data = f.read()
            except Exception as e:
                raw_data = f"Error reading file: {e}".encode("utf-8")

        # Tabs for different preview modes
        tabs = QTabWidget()

        # Mode 1: Image (if image extension)
        is_image = self.file_info.extension.lower() in (".png", ".jpg", ".jpeg", ".gif", ".bmp")
        if is_image:
            tab_img = QWidget()
            img_layout = QVBoxLayout(tab_img)
            lbl_img = QLabel()
            lbl_img.setAlignment(Qt.AlignmentFlag.AlignCenter)
            pix = QPixmap(self.file_info.disk_path)
            if not pix.isNull():
                if pix.width() > 700 or pix.height() > 400:
                    pix = pix.scaled(700, 400, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
                lbl_img.setPixmap(pix)
            else:
                lbl_img.setText("Failed to load image pixmap.")
            img_layout.addWidget(lbl_img)
            tabs.addTab(tab_img, icon("image"), "Image")

        # Mode 2: Text View
        tab_text = QWidget()
        text_layout = QVBoxLayout(tab_text)
        txt_edit = QTextEdit()
        txt_edit.setReadOnly(True)
        txt_edit.setFont(QFont("monospace", 10))
        try:
            txt_content = raw_data.decode("utf-8", errors="replace")
            txt_edit.setPlainText(txt_content)
        except Exception:
            txt_edit.setPlainText("(Binary content not decodable as text)")
        text_layout.addWidget(txt_edit)
        tabs.addTab(tab_text, icon("file"), "Text")

        # Mode 3: Hex Dump View
        tab_hex = QWidget()
        hex_layout = QVBoxLayout(tab_hex)
        txt_hex = QTextEdit()
        txt_hex.setReadOnly(True)
        txt_hex.setFont(QFont("monospace", 10))
        txt_hex.setPlainText(format_hex_dump(raw_data))
        hex_layout.addWidget(txt_hex)
        tabs.addTab(tab_hex, icon("code"), "Hex dump")

        layout.addWidget(tabs)

        # Bottom Actions
        btn_bar = QHBoxLayout()
        btn_copy_hash = QPushButton(icon("copy"), "Copy SHA256")
        btn_copy_hash.clicked.connect(lambda: self._copy(self.file_info.sha256))
        btn_bar.addWidget(btn_copy_hash)

        btn_copy_path = QPushButton(icon("copy"), "Copy File Path")
        btn_copy_path.clicked.connect(lambda: self._copy(self.file_info.disk_path))
        btn_bar.addWidget(btn_copy_path)

        btn_bar.addStretch()

        btn_close = QPushButton(icon("close"), "Close")
        btn_close.clicked.connect(self.accept)
        btn_bar.addWidget(btn_close)

        layout.addLayout(btn_bar)

    def _copy(self, text: str):
        QApplication.clipboard().setText(text)
        QMessageBox.information(self, "Copied", "Copied to clipboard.")

