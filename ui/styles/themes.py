"""Shared desktop design tokens and complete light/dark widget styling."""

from pathlib import Path


PALETTES = {
    "dark": dict(bg="#101923", surface="#162330", raised="#1c2d3c", text="#e3ecf4",
                 muted="#9cb0c1", border="#2c4052", accent="#54b9cf", select="#235267",
                 success="#7ad5b1", warning="#edbb70", error="#f08e91"),
    "light": dict(bg="#edf2f6", surface="#ffffff", raised="#e8eff5", text="#203345",
                  muted="#536b80", border="#c5d2dd", accent="#15748a", select="#d4eaf0",
                  success="#18764f", warning="#946013", error="#b63845"),
}


def stylesheet(mode):
    p = dict(PALETTES[mode], check=Path(__file__).with_name("check.svg").as_posix())
    return """
QWidget { color: %(text)s; font-family: "Inter", "Segoe UI", "DejaVu Sans"; font-size: 12px; }
QMainWindow, QDialog { background: %(bg)s; }
QScrollArea { background: %(bg)s; border: 0; }
QLabel { background: transparent; }
QLabel#appTitle { font-size: 23px; font-weight: 700; }
QLabel#eyebrow { color: %(accent)s; font-size: 10px; font-weight: 700; letter-spacing: 2px; }
QLabel#muted, QLabel#metricTitle { color: %(muted)s; }
QLabel#sectionTitle { font-size: 15px; font-weight: 600; }
QLabel#stateBadge { background: %(raised)s; color: %(accent)s; border: 1px solid %(border)s; border-radius: 12px; padding: 5px 12px; font-weight: 600; }
QLabel#metricValue { font-family: "DejaVu Sans Mono", monospace; font-size: 27px; font-weight: 700; }
QLabel#countLabel { color: %(accent)s; font-weight: 600; }
QLabel#previewHeader { background: %(raised)s; border-radius: 6px; padding: 12px; }
QFrame#sidebar, QFrame#workspace, QFrame#metricCard { background: %(surface)s; border: 1px solid %(border)s; border-radius: 8px; }
QFrame#dropZone { background: %(raised)s; border: 1px dashed %(muted)s; border-radius: 6px; }
QFrame#dropZone[dragActive="true"] { border: 2px dashed %(accent)s; }
QMenuBar { background: %(surface)s; border-bottom: 1px solid %(border)s; padding: 3px 10px; }
QMenuBar::item { padding: 5px 10px; background: transparent; }
QMenuBar::item:selected, QMenu::item:selected { background: %(select)s; }
QMenu { background: %(surface)s; border: 1px solid %(border)s; padding: 5px; }
QMenu::item { padding: 7px 28px; }
QMenu::item:disabled { color: %(muted)s; }
QMenu::separator { height: 1px; background: %(border)s; margin: 4px 8px; }
QPushButton { background: %(raised)s; border: 1px solid %(border)s; border-radius: 5px; padding: 8px 10px; font-weight: 600; }
QPushButton:hover { background: %(select)s; border-color: %(accent)s; }
QPushButton:focus { border: 2px solid %(accent)s; padding: 7px 9px; }
QPushButton:pressed { background: %(border)s; }
QPushButton#btnStart, QPushButton#primaryButton { background: #18798f; color: #ffffff; border-color: #258ba1; }
QPushButton#btnStart:hover, QPushButton#primaryButton:hover { background: #20899f; }
QPushButton#btnStop { color: %(error)s; }
QPushButton:disabled, QPushButton#btnStart:disabled, QPushButton#btnStop:disabled { background: %(surface)s; color: %(muted)s; border-color: %(border)s; }
QLineEdit, QTextEdit, QPlainTextEdit { background: %(surface)s; border: 1px solid %(border)s; border-radius: 5px; padding: 8px; selection-background-color: %(select)s; selection-color: %(text)s; }
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus { border-color: %(accent)s; }
QLineEdit:disabled { color: %(muted)s; background: %(raised)s; }
QTextEdit#console { font-family: "DejaVu Sans Mono", monospace; font-size: 12px; }
QTabWidget::pane { border: 0; border-top: 1px solid %(border)s; }
QTabBar::tab { background: transparent; color: %(muted)s; padding: 12px 14px; border-bottom: 2px solid transparent; }
QTabBar::tab:selected { color: %(accent)s; border-bottom: 2px solid %(accent)s; }
QTabBar::tab:hover { background: %(raised)s; }
QTableWidget, QTableView { background: %(surface)s; alternate-background-color: %(raised)s; border: 1px solid %(border)s; border-radius: 5px; gridline-color: %(border)s; selection-background-color: %(select)s; selection-color: %(text)s; }
QTableWidget::item { padding: 5px 8px; border: 0; }
QTableWidget::item:selected { background: %(select)s; color: %(text)s; }
QHeaderView::section { background: %(raised)s; color: %(muted)s; border: 0; border-bottom: 1px solid %(border)s; padding: 10px 8px; font-size: 11px; font-weight: 600; }
QTableCornerButton::section { background: %(raised)s; border: 0; }
QGroupBox { background: %(surface)s; border: 1px solid %(border)s; border-radius: 6px; margin-top: 20px; padding: 14px 8px 8px; font-weight: 600; }
QGroupBox::title { subcontrol-origin: margin; left: 8px; padding: 0 4px; color: %(muted)s; }
QProgressBar { background: %(raised)s; border: 0; border-radius: 3px; min-height: 6px; max-height: 6px; }
QProgressBar::chunk { background: %(accent)s; border-radius: 3px; }
QCheckBox { spacing: 8px; }
QCheckBox::indicator { width: 14px; height: 14px; border: 1px solid %(muted)s; border-radius: 3px; background: %(surface)s; }
QCheckBox::indicator:checked { background: #18798f; border-color: #18798f; image: url("%(check)s"); }
QCheckBox:focus { color: %(accent)s; }
QStatusBar { background: %(surface)s; color: %(muted)s; border-top: 1px solid %(border)s; padding: 4px 12px; }
QStatusBar::item { border: 0; }
QScrollBar:vertical { background: %(surface)s; width: 10px; margin: 0; }
QScrollBar:horizontal { background: %(surface)s; height: 10px; margin: 0; }
QScrollBar::handle { background: %(border)s; border-radius: 4px; min-height: 24px; min-width: 24px; }
QScrollBar::handle:hover { background: %(muted)s; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }
QToolTip { background: %(raised)s; color: %(text)s; border: 1px solid %(border)s; padding: 6px; }
""" % p


DARK_THEME_QSS = stylesheet("dark")
LIGHT_THEME_QSS = stylesheet("light")
