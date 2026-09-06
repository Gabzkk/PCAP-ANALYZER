import json
import os
import time
from typing import List, Optional
from .models import FlagMatch, ExtractedFile, AnalysisSummary

# Try importing Qt PDF generator
try:
    from PyQt6.QtGui import QTextDocument, QPdfWriter, QPageLayout, QPageSize
    from PyQt6.QtCore import QSizeF
    HAS_QT_PDF = True
except ImportError:
    HAS_QT_PDF = False


class ForensicReporter:
    """
    Exports forensic findings to JSON, HTML, and vector PDF.
    """

    @staticmethod
    def export_json(summary: AnalysisSummary, flags: List[FlagMatch], files: List[ExtractedFile], output_path: str):
        data = {
            "metadata": {
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                "tool": "PCAP Network Forensics & Flag Extraction Tool"
            },
            "summary": summary.to_dict(),
            "flags": [f.to_dict() for f in flags],
            "extracted_files": [ef.to_dict() for ef in files]
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def generate_html(summary: AnalysisSummary, flags: List[FlagMatch], files: List[ExtractedFile]) -> str:
        flags_rows = ""
        for idx, f in enumerate(flags, 1):
            esc_flag = f.flag.replace("<", "&lt;").replace(">", "&gt;")
            esc_ctx = f.context.replace("<", "&lt;").replace(">", "&gt;")
            flags_rows += f"""
            <tr>
                <td><strong>{idx}</strong></td>
                <td><code class="flag-text">{esc_flag}</code></td>
                <td><span class="badge badge-pattern">{f.pattern_name}</span></td>
                <td>{f.source}</td>
                <td><span class="badge badge-encoding">{f.encoding}</span></td>
                <td><small class="context-snippet">{esc_ctx}</small></td>
            </tr>
            """

        files_rows = ""
        for idx, ef in enumerate(files, 1):
            stego_badge = ""
            if ef.has_stego_warning:
                stego_badge = f"""<span class="badge badge-warning" title="{ef.stego_details}">Stego Alert</span>"""
            else:
                stego_badge = """<span class="badge badge-clean">Clean</span>"""

            files_rows += f"""
            <tr>
                <td><strong>{idx}</strong></td>
                <td><strong>{ef.filename}</strong></td>
                <td>{ef.file_type}</td>
                <td>{ef.size_bytes:,} bytes</td>
                <td><span class="badge badge-proto">{ef.source_protocol}</span></td>
                <td>{stego_badge}</td>
                <td><code class="hash-text">{ef.sha256[:16]}...</code></td>
            </tr>
            """

        proto_rows = ""
        for proto, count in sorted(summary.protocol_counts.items(), key=lambda x: x[1], reverse=True):
            pct = (count / max(1, summary.processed_packets)) * 100
            proto_rows += f"""
            <tr>
                <td><strong>{proto}</strong></td>
                <td>{count:,}</td>
                <td>
                    <div class="progress-bar-bg">
                        <div class="progress-bar-fill" style="width: {pct:.1f}%;"></div>
                    </div>
                </td>
                <td>{pct:.1f}%</td>
            </tr>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PCAP Forensics & Flag Extraction Report</title>
    <style>
        :root {{
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --border-color: #30363d;
            --text-primary: #c9d1d9;
            --text-muted: #8b949e;
            --accent-cyan: #58a6ff;
            --accent-green: #3fb950;
            --accent-orange: #d29922;
            --accent-red: #f85149;
            --accent-purple: #bc8cff;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-primary);
            margin: 0;
            padding: 30px;
            line-height: 1.5;
        }}
        .header {{
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0 0 10px 0;
            color: #ffffff;
            font-size: 28px;
        }}
        .header .meta {{
            color: var(--text-muted);
            font-size: 14px;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 30px;
        }}
        .metric-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
            text-align: center;
        }}
        .metric-val {{
            font-size: 32px;
            font-weight: bold;
            color: var(--accent-cyan);
            margin-top: 6px;
        }}
        .metric-val.green {{ color: var(--accent-green); }}
        .metric-val.orange {{ color: var(--accent-orange); }}
        .metric-val.red {{ color: var(--accent-red); }}
        .metric-title {{
            font-size: 13px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .section-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
        }}
        .section-title {{
            font-size: 18px;
            margin-top: 0;
            margin-bottom: 16px;
            color: #ffffff;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }}
        th, td {{
            padding: 10px 14px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            background-color: #21262d;
            color: #ffffff;
            font-weight: 600;
        }}
        tr:hover td {{
            background-color: rgba(255,255,255,0.02);
        }}
        .flag-text {{
            background: #21262d;
            color: #7ee787;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 13px;
            font-weight: 600;
            font-family: monospace;
        }}
        .hash-text {{
            font-family: monospace;
            color: var(--text-muted);
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
        }}
        .badge-pattern {{ background: #1f3554; color: #58a6ff; border: 1px solid #388bfd; }}
        .badge-encoding {{ background: #2f2249; color: #d2a8ff; border: 1px solid #8957e5; }}
        .badge-proto {{ background: #1b382b; color: #7ee787; border: 1px solid #238636; }}
        .badge-warning {{ background: #4d2d00; color: #ffab70; border: 1px solid #bd5b00; }}
        .badge-clean {{ background: #16261f; color: #56d364; border: 1px solid #2ea043; }}
        .context-snippet {{
            color: var(--text-muted);
            font-family: monospace;
        }}
        .progress-bar-bg {{
            background: #21262d;
            border-radius: 4px;
            height: 10px;
            width: 100%;
            overflow: hidden;
        }}
        .progress-bar-fill {{
            background: var(--accent-cyan);
            height: 100%;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Network Forensics & Flag Extraction Report</h1>
        <div class="meta">
            Target Capture: <strong>{summary.capture_file}</strong> ({summary.file_size_bytes:,} bytes) &bull;
            Duration: <strong>{summary.duration_seconds:.2f}s</strong> &bull;
            Generated: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}
        </div>
    </div>

    <div class="metrics-grid">
        <div class="metric-card">
            <div class="metric-title">Flags Discovered</div>
            <div class="metric-val green">{summary.flags_count}</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">Files Extracted</div>
            <div class="metric-val">{summary.files_count}</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">Packets Analyzed</div>
            <div class="metric-val">{summary.processed_packets:,}</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">Reassembled Streams</div>
            <div class="metric-val">{summary.total_streams}</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">Stego Alerts</div>
            <div class="metric-val {'red' if summary.stego_alerts_count > 0 else ''}">{summary.stego_alerts_count}</div>
        </div>
    </div>

    <div class="section-card">
        <h2 class="section-title">Flags Found ({len(flags)})</h2>
        {"<table><thead><tr><th>#</th><th>Flag</th><th>Pattern</th><th>Source</th><th>Encoding Path</th><th>Context Snippet</th></tr></thead><tbody>" + flags_rows + "</tbody></table>" if flags else "<p style='color: var(--text-muted);'>No flags detected matching active regex patterns.</p>"}
    </div>

    <div class="section-card">
        <h2 class="section-title">Extracted & Carved Files ({len(files)})</h2>
        {"<table><thead><tr><th>#</th><th>Filename</th><th>Type</th><th>Size</th><th>Source Protocol</th><th>Stego Status</th><th>SHA256</th></tr></thead><tbody>" + files_rows + "</tbody></table>" if files else "<p style='color: var(--text-muted);'>No files extracted or carved.</p>"}
    </div>

    <div class="section-card">
        <h2 class="section-title">Protocol Distribution</h2>
        <table>
            <thead>
                <tr><th>Protocol</th><th>Packets</th><th>Distribution</th><th>Percentage</th></tr>
            </thead>
            <tbody>
                {proto_rows}
            </tbody>
        </table>
    </div>
</body>
</html>"""
        return html

    @staticmethod
    def export_html(summary: AnalysisSummary, flags: List[FlagMatch], files: List[ExtractedFile], output_path: str):
        content = ForensicReporter.generate_html(summary, flags, files)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

    @staticmethod
    def export_pdf(summary: AnalysisSummary, flags: List[FlagMatch], files: List[ExtractedFile], output_path: str) -> bool:
        """Exports report to PDF using Qt's native QPdfWriter and QTextDocument."""
        if not HAS_QT_PDF:
            return False

        html_content = ForensicReporter.generate_html(summary, flags, files)

        doc = QTextDocument()
        doc.setHtml(html_content)

        writer = QPdfWriter(output_path)
        writer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
        writer.setPageMargins(QPageLayout().margins())

        doc.print(writer)
        return True

