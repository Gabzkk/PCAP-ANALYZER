# Desktop UI review and redesign

The project is a Python application with a native PyQt6 interface and a separate CLI. `core/engine.py` runs capture analysis in a background Qt thread, connecting the parser, stream reassembler, file extractor, and flag scanner. Signals deliver results to the four UI tabs. `core/reporter.py` supplies JSON, HTML, and PDF exports for both interfaces.

The redesign retains that structure and adds a capture sidebar, a persistent status badge and export action, consistent dark/light tokens, bundled SVG line icons, and shared evidence-table and empty-state presentation. No dependencies were added. Narrow windows scroll the sidebar and wide evidence tables instead of overlapping controls.

Functional corrections cover live filtering, searching complete file hashes, read-only evidence, mixed file/folder selection, duplicate targets, stale summaries on restart, cancellation, closing during analysis, and error recovery. Capture and pattern controls remain locked until the worker exits. Newly arriving results are filtered individually, avoiding a full table scan for every insertion. Rich-text context and console output preserve literal evidence text.

## Verification

- All 18 tests passed with `QT_QPA_PLATFORM=offscreen python3 -m unittest discover -s tests -v`.
- `python3 -m compileall -q main.py core ui tests` passed.
- Qt mouse-click checks exercised file selection, starting analysis, copying a flag, exporting JSON/HTML/PDF, and testing/adding/applying a regex.
- Rendered dark/light screens at 1320×840 and 1024×700, populated result tabs, and preview/pattern/export dialogs. Verified image rendering with a valid PNG; the existing synthetic fixture's malformed PNG exercises the preview failure state.
- Scanned UI source, report templates, and README for remaining emoji: none found.

Verification used Qt's offscreen platform on Linux; native OS file-picker and desktop-folder integration were not manually exercised on other platforms.

The AST graph was refreshed with `graphify update .`: 333 nodes and 722 edges. Graphify reported no nodes for the JSON data files `default_patterns.json` and `report.json`; these remain absent from the code graph. Community labels were automatically adjusted by graphify.

Implementation references: [Qt icons](https://doc.qt.io/qt-6/qicon.html), [Qt thread lifecycle](https://doc.qt.io/qt-6/qthread.html), and [Qt stylesheet reference](https://doc.qt.io/qt-6/stylesheet-reference.html).

## Screenshots

- [Dark workspace](screenshots/workspace-dark.png)
- [Light workspace](screenshots/workspace-light.png)
- [Analysis overview](screenshots/analysis-overview.png)
