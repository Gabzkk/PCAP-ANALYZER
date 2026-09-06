"""Small, bundled line icons rendered by Qt; no icon font or network required."""
from functools import lru_cache

from PyQt6.QtCore import Qt, QByteArray
from PyQt6.QtGui import QIcon, QPixmap, QPainter
from PyQt6.QtSvg import QSvgRenderer


PATHS = {
    "capture": '<rect x="3" y="3" width="18" height="18" rx="4"/><path d="M3 12h4l2-5 4 10 2-5h6"/>',
    "upload": '<path d="M12 16V3m-5 5 5-5 5 5M4 15v5h16v-5"/>',
    "file": '<path d="M14 3H5v18h14V8l-5-5v5h5M8 12h8m-8 4h6"/>',
    "folder": '<path d="M3 7V4h6l3 3h9v13H3V7Z"/>',
    "play": '<path d="m8 4 12 8-12 8V4Z"/>',
    "stop": '<rect x="5" y="5" width="14" height="14" rx="2"/>',
    "flag": '<path d="M5 21V3m0 1c5-4 9 4 15 0v10c-6 4-10-4-15 0"/>',
    "chart": '<path d="M4 3v17h17M8 16v-4m5 4V6m5 10V9"/>',
    "terminal": '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3m6 0h4"/>',
    "copy": '<rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V3H3v13h5"/>',
    "search": '<circle cx="10" cy="10" r="6"/><path d="m15 15 6 6"/>',
    "export": '<path d="M12 15V3m-4 4 4-4 4 4M4 13v7h16v-7"/>',
    "save": '<path d="M4 3h13l4 4v14H3V3h1Zm3 0v6h10V3M7 21v-7h10v7"/>',
    "trash": '<path d="M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7m4-7v7"/>',
    "settings": '<path d="M4 6h16M4 12h16M4 18h16"/><circle cx="8" cy="6" r="2"/><circle cx="16" cy="12" r="2"/><circle cx="10" cy="18" r="2"/>',
    "theme": '<circle cx="12" cy="12" r="8"/><path d="M12 4v16"/>',
    "warning": '<path d="m12 3 10 18H2L12 3Zm0 6v5m0 3v.1"/>',
    "check": '<path d="m5 12 4 4L19 6"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v6l4 2"/>',
    "network": '<rect x="8" y="3" width="8" height="5" rx="1"/><path d="M12 8v5M5 16v-3h14v3"/><rect x="2" y="16" width="6" height="5" rx="1"/><rect x="16" y="16" width="6" height="5" rx="1"/>',
    "plus": '<path d="M12 4v16M4 12h16"/>',
    "close": '<path d="m6 6 12 12M6 18 18 6"/>',
    "image": '<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8" cy="8" r="2"/><path d="m3 17 6-5 4 4 4-6 4 5"/>',
    "code": '<path d="m7 6-5 6 5 6m10-12 5 6-5 6M14 3l-4 18"/>',
}


@lru_cache(maxsize=128)
def icon(name: str, color: str = "#718ba2") -> QIcon:
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" '
           f'fill="none" stroke="{color}" stroke-width="1.7" '
           f'stroke-linecap="round" stroke-linejoin="round">{PATHS[name]}</svg>')
    renderer = QSvgRenderer(QByteArray(svg.encode()))
    result = QIcon()
    for size in (16, 20, 24, 32, 48, 64):
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        renderer.render(painter)
        painter.end()
        result.addPixmap(pixmap)
    return result
