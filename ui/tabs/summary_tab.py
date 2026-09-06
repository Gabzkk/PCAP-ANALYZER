import time
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QFrame,
    QTableWidget, QTableWidgetItem, QHeaderView, QGroupBox, QScrollArea
)
from PyQt6.QtCore import Qt
from core.models import AnalysisSummary
from ui.icons import icon
from ui.widgets import EmptyState, configure_evidence_table


class SummaryCard(QFrame):
    """A consistent, readable metric with a semantic line icon."""
    def __init__(self, title, symbol, initial_value="0", parent=None):
        super().__init__(parent)
        self.setObjectName("metricCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)
        heading = QHBoxLayout()
        self.lbl_title = QLabel(title)
        self.lbl_title.setObjectName("metricTitle")
        heading.addWidget(self.lbl_title)
        heading.addStretch()
        mark = QLabel()
        mark.setPixmap(icon(symbol).pixmap(18, 18))
        heading.addWidget(mark)
        layout.addLayout(heading)
        self.lbl_value = QLabel(initial_value)
        self.lbl_value.setObjectName("metricValue")
        layout.addWidget(self.lbl_value)

    def set_value(self, val):
        self.lbl_value.setText(val)


class SummaryTab(QWidget):
    """Capture overview and protocol distribution backed by engine results."""
    def __init__(self, parent=None):
        super().__init__(parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        content = QWidget()
        scroll.setWidget(content)
        outer.addWidget(scroll)
        layout = QVBoxLayout(content)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)
        heading = QLabel("Investigation overview")
        heading.setObjectName("sectionTitle")
        layout.addWidget(heading)
        description = QLabel("Capture statistics, recovered evidence and traffic distribution.")
        description.setObjectName("muted")
        description.setWordWrap(True)
        layout.addWidget(description)

        grid = QGridLayout()
        grid.setSpacing(10)
        self.card_flags = SummaryCard("Flags discovered", "flag")
        self.card_files = SummaryCard("Files recovered", "folder")
        self.card_packets = SummaryCard("Packets analyzed", "capture")
        self.card_streams = SummaryCard("Streams rebuilt", "network")
        self.card_stego = SummaryCard("Stego alerts", "warning")
        self.card_duration = SummaryCard("Elapsed time", "clock", "0.0s")
        for index, card in enumerate((self.card_flags, self.card_files, self.card_packets,
                                      self.card_streams, self.card_stego, self.card_duration)):
            grid.addWidget(card, index // 3, index % 3)
            grid.setColumnStretch(index % 3, 1)
        layout.addLayout(grid)

        grp_details = QGroupBox("Capture details")
        details_layout = QVBoxLayout(grp_details)
        self.lbl_meta = QLabel("No capture loaded. Select a file or folder from the workspace.")
        self.lbl_meta.setTextFormat(Qt.TextFormat.PlainText)
        self.lbl_meta.setWordWrap(True)
        self.lbl_meta.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        details_layout.addWidget(self.lbl_meta)
        layout.addWidget(grp_details)

        grp_proto = QGroupBox("Protocol distribution")
        proto_layout = QVBoxLayout(grp_proto)
        self.proto_table = QTableWidget(0, 3)
        self.proto_table.setMinimumHeight(180)
        self.proto_table.setHorizontalHeaderLabels(["Protocol", "Packets", "Traffic share"])
        self.proto_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.proto_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.proto_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.proto_table.setAlternatingRowColors(True)
        configure_evidence_table(self.proto_table)
        proto_layout.addWidget(self.proto_table)
        self.empty_state = EmptyState("chart", "Your traffic, in focus",
                                      "Start an analysis to see the protocols inside your capture.")
        proto_layout.addWidget(self.empty_state)
        self.proto_table.hide()
        layout.addWidget(grp_proto, 1)

        grp_readings = QGroupBox("Protocol details")
        readings_layout = QVBoxLayout(grp_readings)
        self.readings_note = QLabel("Decoded fields appear here after analysis. Port labels are service hints.")
        self.readings_note.setWordWrap(True)
        readings_layout.addWidget(self.readings_note)
        self.details_table = QTableWidget(0, 5)
        self.details_table.setMinimumHeight(200)
        self.details_table.setHorizontalHeaderLabels(["Capture", "Packet", "Protocol", "Evidence", "Details"])
        configure_evidence_table(self.details_table)
        self.details_table.setAlternatingRowColors(True)
        self.details_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.details_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        readings_layout.addWidget(self.details_table)
        layout.addWidget(grp_readings, 1)

    def update_summary(self, summary: AnalysisSummary):
        self.card_flags.set_value(str(summary.flags_count))
        self.card_files.set_value(str(summary.files_count))
        self.card_packets.set_value(f"{summary.processed_packets:,}")
        self.card_streams.set_value(str(summary.total_streams))
        self.card_stego.set_value(str(summary.stego_alerts_count))
        self.card_duration.set_value(f"{summary.duration_seconds:.2f}s")
        self.lbl_meta.setText(
            f"{summary.capture_file}  |  {summary.file_size_bytes:,} bytes\n"
            f"Started  {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(summary.start_time))}\n"
            f"Finished  {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(summary.end_time))}"
        )
        self.proto_table.setRowCount(0)
        total_pkts = max(1, summary.processed_packets)
        sorted_protos = sorted(summary.protocol_counts.items(), key=lambda item: item[1], reverse=True)
        for row, (proto, count) in enumerate(sorted_protos):
            self.proto_table.insertRow(row)
            self.proto_table.setItem(row, 0, QTableWidgetItem(proto))
            self.proto_table.setItem(row, 1, QTableWidgetItem(f"{count:,}"))
            self.proto_table.setItem(row, 2, QTableWidgetItem(f"{count / total_pkts * 100:.1f}%"))
        self.proto_table.setVisible(bool(sorted_protos))
        self.empty_state.setVisible(not sorted_protos)
        self.empty_state.title.setText("No protocol traffic found")
        self.empty_state.description.setText("This capture produced no protocol counts. Check the console for details.")
        self.details_table.setRowCount(0)
        for row, detail in enumerate(summary.protocol_details):
            self.details_table.insertRow(row)
            for col, key in enumerate(("capture", "packet_id", "protocol", "detection", "details")):
                item = QTableWidgetItem(str(detail[key]))
                item.setToolTip(f"{detail['source']} → {detail['destination']}\n{detail['details']}")
                self.details_table.setItem(row, col, item)
        self.readings_note.setText(
            f"Showing {len(summary.protocol_details):,} packet details; {summary.protocol_details_omitted:,} omitted. "
            "Port = service hint. Encrypted payloads require session keys; visible handshake fields may be shown."
        )

    def clear(self):
        for card in (self.card_flags, self.card_files, self.card_packets, self.card_streams, self.card_stego):
            card.set_value("0")
        self.card_duration.set_value("0.0s")
        self.lbl_meta.setText("Analysis in progress. Capture details will appear when it finishes.")
        self.proto_table.setRowCount(0)
        self.details_table.setRowCount(0)
        self.readings_note.setText("Reading protocol details…")
        self.proto_table.hide()
        self.empty_state.show()
        self.empty_state.title.setText("Analyzing traffic")
        self.empty_state.description.setText("Protocol distribution will appear when the analysis finishes.")
