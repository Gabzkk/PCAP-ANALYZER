from ui.icons import icon
import re
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLineEdit, QLabel, QHeaderView, QMessageBox,
    QFileDialog, QGroupBox, QCheckBox
)
from PyQt6.QtCore import Qt
from core.flag_scanner import FlagScanner


class RegexManagerDialog(QDialog):
    """
    Dialog to view, add, test, enable/disable, and import/export custom regex patterns.
    """

    def __init__(self, flag_scanner: FlagScanner, parent=None):
        super().__init__(parent)
        self.flag_scanner = flag_scanner
        self.setWindowTitle("Custom Regex Pattern Manager")
        self.resize(920, 640)
        self._init_ui()
        self._load_table_data()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        # 1. Existing Patterns Table
        grp_table = QGroupBox("Configured Flag Patterns")
        table_layout = QVBoxLayout(grp_table)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Enabled", "Pattern Name", "Regex Pattern", "Description"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(34)

        table_layout.addWidget(self.table)

        table_btn_bar = QHBoxLayout()
        self.btn_toggle_all = QPushButton(icon("check"), "Toggle All")
        self.btn_toggle_all.clicked.connect(self._toggle_all)
        table_btn_bar.addWidget(self.btn_toggle_all)

        self.btn_delete = QPushButton(icon("trash"), "Delete Selected")
        self.btn_delete.clicked.connect(self._delete_selected)
        table_btn_bar.addWidget(self.btn_delete)

        table_btn_bar.addStretch()

        self.btn_import = QPushButton(icon("upload"), "Import Patterns (JSON)")
        self.btn_import.clicked.connect(self._import_patterns)
        table_btn_bar.addWidget(self.btn_import)

        self.btn_export = QPushButton(icon("export"), "Export Patterns (JSON)")
        self.btn_export.clicked.connect(self._export_patterns)
        table_btn_bar.addWidget(self.btn_export)

        table_layout.addLayout(table_btn_bar)
        layout.addWidget(grp_table)

        # 2. Add & Test New Pattern Group
        grp_add = QGroupBox("Add New Custom Regex")
        add_layout = QVBoxLayout(grp_add)

        row1 = QHBoxLayout()
        self.inp_name = QLineEdit()
        self.inp_name.setPlaceholderText("Pattern Name (e.g. MyCTF)")
        self.inp_regex = QLineEdit()
        self.inp_regex.setPlaceholderText("Regex Pattern (e.g. MyCTF\\{[^\\}]+\\})")
        row1.addWidget(self.inp_name, 1)
        row1.addWidget(self.inp_regex, 2)
        add_layout.addLayout(row1)

        row2 = QHBoxLayout()
        self.inp_desc = QLineEdit()
        self.inp_desc.setPlaceholderText("Description (Optional)")
        self.btn_add = QPushButton(icon("plus"), "Add pattern")
        self.btn_add.clicked.connect(self._add_pattern)
        row2.addWidget(self.inp_desc, 2)
        row2.addWidget(self.btn_add, 1)
        add_layout.addLayout(row2)

        # Live Regex Tester
        test_row = QHBoxLayout()
        self.inp_test_str = QLineEdit()
        self.inp_test_str.setPlaceholderText("Test String to evaluate regex against...")
        self.lbl_test_res = QLabel("Test Result: -")
        self.lbl_test_res.setObjectName("muted")
        self.lbl_test_res.setWordWrap(True)
        self.btn_test = QPushButton(icon("play"), "Test Regex")
        self.btn_test.clicked.connect(self._test_regex)

        test_row.addWidget(self.inp_test_str, 2)
        test_row.addWidget(self.btn_test)
        test_row.addWidget(self.lbl_test_res, 1)
        add_layout.addLayout(test_row)

        layout.addWidget(grp_add)

        # Bottom Dialog Actions
        bottom_bar = QHBoxLayout()
        bottom_bar.addStretch()

        self.btn_save_close = QPushButton(icon("save"), "Save & Apply")
        self.btn_save_close.setObjectName("primaryButton")
        self.btn_save_close.setIcon(icon("save", "#ffffff"))
        self.btn_save_close.clicked.connect(self._save_and_apply)
        bottom_bar.addWidget(self.btn_save_close)

        self.btn_cancel = QPushButton(icon("close"), "Cancel")
        self.btn_cancel.clicked.connect(self.reject)
        bottom_bar.addWidget(self.btn_cancel)

        layout.addLayout(bottom_bar)

    def _load_table_data(self):
        self.table.setRowCount(0)
        for row, p in enumerate(self.flag_scanner.patterns):
            self.table.insertRow(row)

            chk = QTableWidgetItem()
            chk.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            chk.setCheckState(Qt.CheckState.Checked if p.get("enabled", True) else Qt.CheckState.Unchecked)

            item_name = QTableWidgetItem(p.get("name", ""))
            item_pat = QTableWidgetItem(p.get("pattern", ""))
            item_desc = QTableWidgetItem(p.get("description", ""))

            self.table.setItem(row, 0, chk)
            self.table.setItem(row, 1, item_name)
            self.table.setItem(row, 2, item_pat)
            self.table.setItem(row, 3, item_desc)

    def _toggle_all(self):
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item:
                cur = item.checkState()
                item.setCheckState(Qt.CheckState.Unchecked if cur == Qt.CheckState.Checked else Qt.CheckState.Checked)

    def _delete_selected(self):
        selected = self.table.selectionModel().selectedRows()
        if not selected:
            QMessageBox.information(self, "Delete", "Please select row(s) to delete.")
            return

        for idx in sorted([s.row() for s in selected], reverse=True):
            self.table.removeRow(idx)

    def _test_regex(self):
        pat_str = self.inp_regex.text().strip()
        test_str = self.inp_test_str.text()
        if not pat_str:
            self.lbl_test_res.setText("Enter a regex pattern.")
            self.lbl_test_res.setStyleSheet("color: #ef4444;")
            return

        try:
            rx = re.compile(pat_str, re.IGNORECASE)
            match = rx.search(test_str)
            if match:
                self.lbl_test_res.setText(f"MATCH: {match.group(0)}")
                self.lbl_test_res.setStyleSheet("color: #10b981; font-weight: bold;")
            else:
                self.lbl_test_res.setText("NO MATCH")
                self.lbl_test_res.setStyleSheet("color: #ef4444; font-weight: bold;")
        except re.error as e:
            self.lbl_test_res.setText(f"Invalid Regex: {e}")
            self.lbl_test_res.setStyleSheet("color: #ef4444;")

    def _add_pattern(self):
        name = self.inp_name.text().strip()
        pat = self.inp_regex.text().strip()
        desc = self.inp_desc.text().strip()

        if not name or not pat:
            QMessageBox.warning(self, "Invalid Input", "Please provide both a Pattern Name and Regex.")
            return

        try:
            re.compile(pat)
        except re.error as e:
            QMessageBox.critical(self, "Invalid Regex", f"Regex syntax error: {e}")
            return

        row = self.table.rowCount()
        self.table.insertRow(row)

        chk = QTableWidgetItem()
        chk.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
        chk.setCheckState(Qt.CheckState.Checked)

        self.table.setItem(row, 0, chk)
        self.table.setItem(row, 1, QTableWidgetItem(name))
        self.table.setItem(row, 2, QTableWidgetItem(pat))
        self.table.setItem(row, 3, QTableWidgetItem(desc))

        self.inp_name.clear()
        self.inp_regex.clear()
        self.inp_desc.clear()
        self.lbl_test_res.setText("Test Result: -")

    def _import_patterns(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import Regex Patterns", "", "JSON Files (*.json);;All Files (*)")
        if path:
            self.flag_scanner.load_patterns_from_file(path)
            self._load_table_data()
            QMessageBox.information(self, "Imported", f"Successfully loaded patterns from {path}")

    def _export_patterns(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Regex Patterns", "custom_patterns.json", "JSON Files (*.json)")
        if path:
            self._collect_table_data()
            self.flag_scanner.save_patterns_to_file(path)
            QMessageBox.information(self, "Exported", f"Saved {len(self.flag_scanner.patterns)} patterns to {path}")

    def _collect_table_data(self):
        updated = []
        for r in range(self.table.rowCount()):
            chk_item = self.table.item(r, 0)
            enabled = (chk_item.checkState() == Qt.CheckState.Checked) if chk_item else True
            name_item = self.table.item(r, 1)
            pat_item = self.table.item(r, 2)
            desc_item = self.table.item(r, 3)

            name = name_item.text().strip() if name_item else "Custom"
            pattern = pat_item.text().strip() if pat_item else ""
            desc = desc_item.text().strip() if desc_item else ""

            if pattern:
                updated.append({
                    "name": name,
                    "pattern": pattern,
                    "enabled": enabled,
                    "description": desc
                })
        self.flag_scanner.set_patterns(updated)

    def _save_and_apply(self):
        self._collect_table_data()
        self.accept()

