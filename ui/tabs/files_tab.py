from html import escape
from ui.icons import icon
from ui.widgets import EmptyState, configure_evidence_table
import os
import subprocess
import sys
from typing import List, Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLineEdit, QLabel, QHeaderView, QMessageBox
)
from PyQt6.QtGui import QDesktopServices, QColor
from PyQt6.QtCore import Qt, QUrl

from core.models import ExtractedFile
from ui.dialogs.preview_dialog import FilePreviewDialog


class FilesTab(QWidget):
    """
    Tab 2: Table displaying extracted & carved files with steganography alerts.
    """

    def __init__(self, output_dir: str, parent=None):
        super().__init__(parent)
        self.output_dir = output_dir
        self.files: List[ExtractedFile] = []
        self._visible_count = 0
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Toolbar
        top_bar = QHBoxLayout()

        self.lbl_count = QLabel("Extracted Files: 0")
        self.lbl_count.setObjectName("countLabel")
        layout.addWidget(self.lbl_count)


        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter files by name, type, or hash...")
        self.search_input.textChanged.connect(self._filter_table)
        self.search_input.setClearButtonEnabled(True)
        self.search_input.setAccessibleName("Filter files")
        self.search_input.setMinimumWidth(130)
        top_bar.addWidget(self.search_input)

        self.btn_preview = QPushButton(icon("search"), "Preview")
        self.btn_preview.clicked.connect(self.preview_selected_file)
        top_bar.addWidget(self.btn_preview)

        self.btn_open_folder = QPushButton(icon("folder"), "Output folder")
        self.btn_open_folder.clicked.connect(self.open_output_folder)
        top_bar.addWidget(self.btn_open_folder)

        layout.addLayout(top_bar)

        # Table
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels([
            "Filename", "Type", "Size", "Source Protocol", "Stego Status", "SHA256"
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.cellDoubleClicked.connect(self._on_row_double_clicked)
        configure_evidence_table(self.table)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self.table.setColumnWidth(2, 100)
        layout.addWidget(self.table, 1)
        self.empty_state = EmptyState("folder", "No extracted files yet",
                                      "Reconstructed files and carved payloads will appear here.")
        layout.addWidget(self.empty_state, 1)
        self.table.hide()
        self.table.itemSelectionChanged.connect(self._update_actions)
        self._update_actions()

    def set_output_dir(self, output_dir: str):
        self.output_dir = output_dir

    def add_file(self, extracted_file: ExtractedFile):
        """Adds newly extracted file live to table."""
        self.files.append(extracted_file)
        row = self.table.rowCount()
        self.table.insertRow(row)

        item_fn = QTableWidgetItem(extracted_file.filename)
        item_fn.setToolTip(extracted_file.filename)
        item_type = QTableWidgetItem(extracted_file.file_type)
        item_size = QTableWidgetItem(f"{extracted_file.size_bytes:,} B")
        item_proto = QTableWidgetItem(extracted_file.source_protocol)

        # Stego status with warning color
        if extracted_file.has_stego_warning:
            item_stego = QTableWidgetItem(icon("warning"), "Anomaly detected")
            item_stego.setToolTip(extracted_file.stego_details)
        else:
            item_stego = QTableWidgetItem(icon("check"), "No alert")

        item_hash = QTableWidgetItem(extracted_file.sha256[:16] + "...")
        item_hash.setToolTip(extracted_file.sha256)

        self.table.setItem(row, 0, item_fn)
        self.table.setItem(row, 1, item_type)
        self.table.setItem(row, 2, item_size)
        self.table.setItem(row, 3, item_proto)
        self.table.setItem(row, 4, item_stego)
        self.table.setItem(row, 5, item_hash)

        match = self._row_matches(row, self.search_input.text().strip().lower())
        self.table.setRowHidden(row, not match)
        self._visible_count += match
        self._update_filter_state()

    def clear(self):
        self.files.clear()
        self.table.setRowCount(0)
        self._visible_count = 0
        self._update_filter_state()

    def _update_actions(self):
        selected = any(not self.table.isRowHidden(index.row())
                       for index in self.table.selectionModel().selectedRows())
        self.btn_preview.setEnabled(selected)

    def _row_matches(self, row, query):
        values = [self.table.item(row, col).text() for col in range(self.table.columnCount())]
        return query in " ".join(values + [self.files[row].sha256]).lower()

    def _filter_table(self, query: str):
        query = query.strip().lower()
        self._visible_count = 0
        for row in range(self.table.rowCount()):
            match = self._row_matches(row, query)
            self.table.setRowHidden(row, not match)
            self._visible_count += match
        self._update_filter_state()

    def _update_filter_state(self):
        visible = self._visible_count
        self.lbl_count.setText(f"{visible} of {len(self.files)} files")
        self.table.setVisible(visible > 0)
        self.empty_state.setVisible(visible == 0)
        self.empty_state.title.setText("No matching files" if self.files else "No extracted files yet")
        self.empty_state.description.setText(
            "Try another search or clear the filter." if self.files else
            "Reconstructed files and carved payloads will appear here.")
        self._update_actions()

    def preview_selected_file(self):
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.information(self, "Select File", "Please select a file row in the table first.")
            return

        row_idx = selected_rows[0].row()
        if 0 <= row_idx < len(self.files):
            file_info = self.files[row_idx]
            dialog = FilePreviewDialog(file_info, self)
            dialog.exec()

    def _on_row_double_clicked(self, row: int, col: int):
        if 0 <= row < len(self.files):
            file_info = self.files[row]
            dialog = FilePreviewDialog(file_info, self)
            dialog.exec()

    def open_output_folder(self):
        target_dir = os.path.abspath(self.output_dir)
        if not os.path.exists(target_dir):
            os.makedirs(target_dir, exist_ok=True)

        if sys.platform == "win32":
            os.startfile(target_dir)
        elif sys.platform == "darwin":
            subprocess.run(["open", target_dir], check=False)
        else:
            subprocess.run(["xdg-open", target_dir], check=False)
