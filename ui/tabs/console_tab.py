from html import escape
from ui.icons import icon
from ui.styles.themes import PALETTES
import time
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QPushButton,
    QLineEdit, QCheckBox, QFileDialog, QMessageBox
)
from PyQt6.QtGui import QTextCursor, QColor
from PyQt6.QtCore import Qt


class ConsoleTab(QWidget):
    """
    Tab 4: Real-time verbose colored forensic console log.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._dark = True
        self._entries = []
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Toolbar
        top_bar = QHBoxLayout()

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search console logs...")
        self.search_input.setAccessibleName("Search console logs")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.returnPressed.connect(self._find_next)
        top_bar.addWidget(self.search_input)

        self.btn_find = QPushButton(icon("search"), "Find")
        self.btn_find.clicked.connect(self._find_next)
        top_bar.addWidget(self.btn_find)

        self.chk_autoscroll = QCheckBox("Auto-scroll")
        self.chk_autoscroll.setChecked(True)
        top_bar.addWidget(self.chk_autoscroll)

        self.btn_clear = QPushButton(icon("trash"), "Clear")
        self.btn_clear.clicked.connect(self.clear)
        top_bar.addWidget(self.btn_clear)

        self.btn_export = QPushButton(icon("save"), "Save log")
        self.btn_export.clicked.connect(self.save_log)
        top_bar.addWidget(self.btn_export)

        layout.addLayout(top_bar)

        # Console Text Box
        self.console_box = QTextEdit()
        self.console_box.setReadOnly(True)
        self.console_box.setFontFamily("monospace")
        self.console_box.setObjectName("console")
        self.console_box.setPlaceholderText("Analysis activity will appear here.")
        layout.addWidget(self.console_box)

    def log(self, level: str, message: str):
        """Appends a color-coded log message with timestamp."""
        ts = time.strftime("%H:%M:%S", time.localtime())

        self._entries.append((ts, level, message))
        self._append_entry(ts, level, message)

    def _append_entry(self, ts, level, message):
        palette = PALETTES["dark" if self._dark else "light"]
        color = palette[{"FOUND": "success", "WARNING": "warning", "ERROR": "error"}.get(level.upper(), "muted")]
        html = (f"<span style='color:{palette['muted']}'>[{ts}]</span> "
                f"<b style='color:{color}'>[{escape(level.upper())}]</b> {escape(message)}")
        scrollbar = self.console_box.verticalScrollBar()
        scroll_position = scrollbar.value()
        self.console_box.append(html)

        if self.chk_autoscroll.isChecked():
            cursor = self.console_box.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            self.console_box.setTextCursor(cursor)
        else:
            scrollbar.setValue(scroll_position)

    def set_theme(self, dark):
        self._dark = dark
        self.console_box.clear()
        for entry in self._entries:
            self._append_entry(*entry)

    def clear(self):
        self._entries.clear()
        self.console_box.clear()

    def _find_next(self):
        text = self.search_input.text()
        if text:
            found = self.console_box.find(text)
            if not found:
                # Wrap around to start
                cursor = self.console_box.textCursor()
                cursor.movePosition(QTextCursor.MoveOperation.Start)
                self.console_box.setTextCursor(cursor)
                self.console_box.find(text)

    def save_log(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Console Log", "forensic_console.log", "Log Files (*.log);;Text Files (*.txt)")
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self.console_box.toPlainText())
                QMessageBox.information(self, "Saved", f"Log saved successfully to {path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save log: {e}")

