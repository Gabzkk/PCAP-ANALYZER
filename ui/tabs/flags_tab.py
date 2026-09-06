from html import escape
from ui.icons import icon
from ui.widgets import EmptyState, configure_evidence_table
from typing import List, Optional
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLineEdit, QLabel, QHeaderView, QMessageBox,
    QDialog, QTextEdit, QApplication
)
from PyQt6.QtCore import Qt
from core.models import FlagMatch


class FlagContextDialog(QDialog):
    """Shows detailed information and surrounding payload context for a selected flag."""
    def __init__(self, flag_match: FlagMatch, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Flag Details & Forensic Context")
        self.resize(650, 400)

        layout = QVBoxLayout(self)

        info_text = (
            f"<b>Flag:</b> <span style='font-family: monospace;'>{escape(flag_match.flag)}</span><br>"
            f"<b>Pattern Type:</b> {escape(flag_match.pattern_name)}<br>"
            f"<b>Encoding Path:</b> {escape(flag_match.encoding)}<br>"
            f"<b>Source:</b> {escape(flag_match.source)}<br>"
            f"<b>Offset:</b> {flag_match.offset if flag_match.offset is not None else 'N/A'}<br>"
            f"<b>Packet ID:</b> {flag_match.packet_id if flag_match.packet_id is not None else 'N/A'}<br>"
            f"<b>Stream ID:</b> {flag_match.stream_id if flag_match.stream_id is not None else 'N/A'}"
        )
        lbl_info = QLabel(info_text)
        lbl_info.setTextFormat(Qt.TextFormat.RichText)
        lbl_info.setWordWrap(True)
        lbl_info.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(lbl_info)

        layout.addWidget(QLabel("<b>Surrounding Forensic Payload Context:</b>"))
        self.txt_context = QTextEdit()
        self.txt_context.setReadOnly(True)
        self.txt_context.setFontFamily("monospace")
        self.txt_context.setPlainText(flag_match.context or "(No context available)")
        layout.addWidget(self.txt_context)

        btn_box = QHBoxLayout()
        btn_copy = QPushButton(icon("copy"), "Copy Flag")
        btn_copy.clicked.connect(lambda: self._copy(flag_match.flag))
        btn_close = QPushButton(icon("close"), "Close")
        btn_close.clicked.connect(self.accept)
        btn_box.addWidget(btn_copy)
        btn_box.addStretch()
        btn_box.addWidget(btn_close)
        layout.addLayout(btn_box)

    def _copy(self, text: str):
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
        QMessageBox.information(self, "Copied", "Flag copied to clipboard!")


class FlagsTab(QWidget):
    """
    Tab 1: Table displaying discovered flags live during analysis.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.flags: List[FlagMatch] = []
        self._visible_count = 0
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Toolbar
        top_bar = QHBoxLayout()

        self.lbl_count = QLabel("Flags Discovered: 0")
        self.lbl_count.setObjectName("countLabel")
        layout.addWidget(self.lbl_count)


        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter flags by keyword, pattern, or encoding...")
        self.search_input.textChanged.connect(self._filter_table)
        self.search_input.setClearButtonEnabled(True)
        self.search_input.setAccessibleName("Filter flags")
        self.search_input.setMinimumWidth(130)
        top_bar.addWidget(self.search_input)

        self.btn_copy_selected = QPushButton(icon("copy"), "Copy selected")
        self.btn_copy_selected.clicked.connect(self.copy_selected_flag)
        top_bar.addWidget(self.btn_copy_selected)

        self.btn_copy_all = QPushButton(icon("copy"), "Copy all")
        self.btn_copy_all.clicked.connect(self.copy_all_flags)
        top_bar.addWidget(self.btn_copy_all)

        layout.addLayout(top_bar)

        # Table
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels([
            "Flag", "Pattern Type", "Source", "Encoding", "Packet / Stream ID"
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.cellDoubleClicked.connect(self._on_row_double_clicked)
        configure_evidence_table(self.table)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self.table.setColumnWidth(2, 220)
        layout.addWidget(self.table, 1)
        self.empty_state = EmptyState("flag", "No flags to inspect yet",
                                      "Run an analysis to discover flags and inspect their payload context.")
        layout.addWidget(self.empty_state, 1)
        self.table.hide()
        self.table.itemSelectionChanged.connect(self._update_actions)
        self._update_actions()

    def add_flag(self, flag: FlagMatch):
        """Appends a new flag to the table live."""
        self.flags.append(flag)
        row = self.table.rowCount()
        self.table.insertRow(row)

        item_flag = QTableWidgetItem(flag.flag)
        item_flag.setFont(self.table.font())
        item_flag.setToolTip(flag.flag)
        item_flag.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)

        item_pattern = QTableWidgetItem(flag.pattern_name)
        item_source = QTableWidgetItem(flag.source)
        item_source.setToolTip(flag.source)
        item_encoding = QTableWidgetItem(flag.encoding)
        item_encoding.setToolTip(flag.encoding)

        ps_id = ""
        if flag.packet_id is not None:
            ps_id = f"Pkt #{flag.packet_id}"
        elif flag.stream_id is not None:
            ps_id = f"Stream #{flag.stream_id}"
        item_ps = QTableWidgetItem(ps_id)

        self.table.setItem(row, 0, item_flag)
        self.table.setItem(row, 1, item_pattern)
        self.table.setItem(row, 2, item_source)
        self.table.setItem(row, 3, item_encoding)
        self.table.setItem(row, 4, item_ps)

        match = self._row_matches(row, self.search_input.text().strip().lower())
        self.table.setRowHidden(row, not match)
        self._visible_count += match
        self._update_filter_state()

    def clear(self):
        self.flags.clear()
        self.table.setRowCount(0)
        self._visible_count = 0
        self._update_filter_state()

    def _update_actions(self):
        selected = any(not self.table.isRowHidden(index.row())
                       for index in self.table.selectionModel().selectedRows())
        self.btn_copy_selected.setEnabled(selected)
        self.btn_copy_all.setEnabled(bool(self.flags))

    def _row_matches(self, row, query):
        return any(query in self.table.item(row, col).text().lower()
                   for col in range(self.table.columnCount()))

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
        self.lbl_count.setText(f"{visible} of {len(self.flags)} flags")
        self.table.setVisible(visible > 0)
        self.empty_state.setVisible(visible == 0)
        self.empty_state.title.setText("No matching flags" if self.flags else "No flags to inspect yet")
        self.empty_state.description.setText(
            "Try another search or clear the filter." if self.flags else
            "Run an analysis to discover flags and inspect their payload context.")
        self._update_actions()

    def copy_selected_flag(self):
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.information(self, "Select Flag", "Please select a row in the table first.")
            return

        row_idx = selected_rows[0].row()
        item = self.table.item(row_idx, 0)
        if item:
            flag_text = item.text()
            QApplication.clipboard().setText(flag_text)
            QMessageBox.information(self, "Copied", f"Copied to clipboard:\n{flag_text}")

    def copy_all_flags(self):
        if not self.flags:
            QMessageBox.information(self, "No Flags", "No flags to copy.")
            return

        all_text = "\n".join(f.flag for f in self.flags)
        QApplication.clipboard().setText(all_text)
        QMessageBox.information(self, "Copied All", f"Copied {len(self.flags)} flags to clipboard.")

    def _on_row_double_clicked(self, row: int, col: int):
        if 0 <= row < len(self.flags):
            flag_match = self.flags[row]
            dialog = FlagContextDialog(flag_match, self)
            dialog.exec()
