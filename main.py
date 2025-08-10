import sys
import os
import platform
import subprocess
import json
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTableWidget, QTableWidgetItem, QTabWidget, QFileDialog, QLabel, QTextEdit,
    QProgressBar, QMessageBox, QHeaderView, QComboBox, QGroupBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal

# Optional imports
try:
    from scapy.all import rdpcap, Dot11Beacon, Dot11Elt, Dot11
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False


# ---------------------- Utility functions ----------------------

def run_cmd(cmd: List[str]) -> str:
    """Run command and return stdout text. Raises CalledProcessError on failure."""
    out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
    return out.decode(errors='ignore')


def assess_risk_from_security(security: str, encryption_field: Optional[str] = None) -> str:
    s = (security or '').upper()
    e = (encryption_field or '').upper()
    if 'WEP' in s or 'WEP' in e:
        return 'HIGH'
    if 'NONE' in s or 'OPEN' in s:
        return 'HIGH'
    if 'WPA3' in s or 'SAE' in s:
        return 'LOW'
    if 'WPA2' in s or 'WPA2' in e:
        # if TKIP appears
        if 'TKIP' in s or 'TKIP' in e:
            return 'MEDIUM'
        return 'MEDIUM'
    if 'WPA' in s:
        return 'MEDIUM'
    return 'UNKNOWN'


def severity_color(sev: str) -> Qt.GlobalColor:
    if sev == 'HIGH':
        return Qt.red
    if sev == 'MEDIUM':
        return Qt.darkYellow
    if sev == 'LOW':
        return Qt.green
    return Qt.lightGray


# ---------------------- Scanning Threads ----------------------

class SystemScanThread(QThread):
    finished_signal = pyqtSignal(list)
    log_signal = pyqtSignal(str)

    def __init__(self, iface: Optional[str] = None):
        super().__init__()
        self.iface = iface

    def run(self):
        os_name = platform.system().lower()
        self.log_signal.emit(f'Detected platform: {os_name}')
        try:
            if 'windows' in os_name:
                self.log_signal.emit('Running netsh scan...')
                raw = run_cmd(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'])
                networks = parse_netsh_output(raw)
            elif 'linux' in os_name:
                if shutil_which('nmcli'):
                    self.log_signal.emit('Running nmcli scan...')
                    raw = run_cmd(['nmcli', '-f', 'SSID,SECURITY,BSSID,CHAN,SIGNAL', 'dev', 'wifi', 'list'])
                    networks = parse_nmcli_output(raw)
                else:
                    self.log_signal.emit('nmcli not found on Linux')
                    networks = []
            else:
                self.log_signal.emit('Unsupported platform for system scanning')
                networks = []
        except subprocess.CalledProcessError as e:
            self.log_signal.emit('System scan failed: ' + str(e))
            networks = []
        except Exception:
            self.log_signal.emit('System scan unexpected error:\n' + traceback.format_exc())
            networks = []

        # add risk assessment
        for n in networks:
            n['risk'] = assess_risk_from_security(n.get('security', ''), n.get('encryption', ''))
        self.finished_signal.emit(networks)


class PcapAnalysisThread(QThread):
    finished_signal = pyqtSignal(list)
    log_signal = pyqtSignal(str)

    def __init__(self, pcap_path: str):
        super().__init__()
        self.pcap_path = pcap_path

    def run(self):
        if not SCAPY_AVAILABLE:
            self.log_signal.emit('Scapy not available; cannot analyze pcap')
            self.finished_signal.emit([])
            return
        self.log_signal.emit(f'Opening PCAP: {self.pcap_path}')
        try:
            packets = rdpcap(self.pcap_path)
        except Exception as e:
            self.log_signal.emit('Failed to read pcap: ' + str(e))
            self.finished_signal.emit([])
            return

        seen = {}
        for pkt in packets:
            if not pkt.haslayer(Dot11Beacon):
                continue
            try:
                bssid = pkt[Dot11].addr3
            except Exception:
                continue
            ssid = ''
            channel = None
            security = ''
            # iterate Dot11Elt
            elt = pkt.getlayer(Dot11Elt)
            while elt:
                try:
                    if elt.ID == 0:
                        ssid = elt.info.decode(errors='ignore')
                    elif elt.ID == 3 and elt.info:
                        channel = elt.info[0]
                    elif elt.ID == 48:
                        security += 'RSN '
                    elif elt.ID == 221:
                        security += 'WPA '
                    elt = elt.payload.getlayer(Dot11Elt)
                except Exception:
                    break
            seen.setdefault(bssid, {'ssid': ssid, 'security': security.strip(), 'channel': channel, 'signal': getattr(pkt, 'dBm_AntSignal', None)})

        result = []
        for b, v in seen.items():
            entry = {'bssid': b, 'ssid': v['ssid'], 'security': v['security'], 'channel': v['channel'], 'signal': v['signal']}
            entry['risk'] = assess_risk_from_security(entry['security'])
            result.append(entry)
        self.finished_signal.emit(result)


# ---------------------- Parsing helpers ----------------------

import shutil

def shutil_which(name: str) -> Optional[str]:
    try:
        return shutil.which(name)
    except Exception:
        return None


def parse_netsh_output(raw: str) -> List[Dict[str, Any]]:
    networks = []
    lines = raw.splitlines()
    cur = None
    for line in lines:
        s = line.strip()
        if s.startswith('SSID') and ':' in s and 'BSSID' not in s:
            cur = {'ssid': s.split(':', 1)[1].strip()}
            networks.append(cur)
        elif s.lower().startswith('authentication') and cur is not None:
            cur['security'] = s.split(':', 1)[1].strip()
        elif s.lower().startswith('encryption') and cur is not None:
            cur['encryption'] = s.split(':', 1)[1].strip()
        elif s.lower().startswith('bssid') and cur is not None:
            cur.setdefault('bssids', []).append(s.split(':', 1)[1].strip())
        elif s.lower().startswith('signal') and cur is not None:
            cur['signal'] = s.split(':', 1)[1].strip()
    # flatten bssids into first bssid
    for n in networks:
        if 'bssids' in n:
            n['bssid'] = ','.join(n['bssids'])
    return networks


def parse_nmcli_output(raw: str) -> List[Dict[str, Any]]:
    lines = [l for l in raw.splitlines() if l.strip()]
    networks = []
    # skip header if present
    for line in lines[1:]:
        cols = re.split(r'\s{2,}', line.strip())
        if not cols:
            continue
        networks.append({'ssid': cols[0], 'security': cols[1] if len(cols)>1 else '', 'bssid': cols[2] if len(cols)>2 else None, 'channel': cols[3] if len(cols)>3 else None, 'signal': cols[4] if len(cols)>4 else None})
    return networks


# ---------------------- Main GUI ----------------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('AirSentinel – Wireless Security Audit & Analysis Tool')
        self.resize(1000, 700)

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.scan_tab = QWidget()
        self.pcap_tab = QWidget()
        self.report_tab = QWidget()

        self._build_scan_tab()
        self._build_pcap_tab()
        self._build_report_tab()

        self.tabs.addTab(self.scan_tab, 'Live Scan')
        self.tabs.addTab(self.pcap_tab, 'PCAP Analysis')
        self.tabs.addTab(self.report_tab, 'Reports')

        self.scan_results: List[Dict[str, Any]] = []
        self.pcap_results: List[Dict[str, Any]] = []

    def _build_scan_tab(self):
        layout = QVBoxLayout()
        w = QWidget(); w.setLayout(layout)

        top = QHBoxLayout()
        self.scan_btn = QPushButton('Start System Scan')
        self.scan_btn.clicked.connect(self.start_system_scan)
        top.addWidget(self.scan_btn)

        self.iface_combo = QComboBox()
        self.iface_combo.setEditable(True)
        self.iface_combo.setToolTip('Optional interface name (e.g., wlan0)')
        top.addWidget(QLabel('Interface (optional):'))
        top.addWidget(self.iface_combo)

        layout.addLayout(top)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(['SSID', 'BSSID', 'Security', 'Channel', 'Signal', 'Risk'])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.table)

        bottom = QHBoxLayout()
        self.progress = QProgressBar(); self.progress.setRange(0, 100); self.progress.setValue(0)
        bottom.addWidget(self.progress)
        self.log = QTextEdit(); self.log.setReadOnly(True); self.log.setFixedHeight(120)
        bottom.addWidget(self.log)
        layout.addLayout(bottom)

        self.scan_tab.setLayout(layout)

    def _build_pcap_tab(self):
        layout = QVBoxLayout(); w = QWidget(); w.setLayout(layout)

        top = QHBoxLayout()
        self.open_pcap_btn = QPushButton('Open PCAP File')
        self.open_pcap_btn.clicked.connect(self.open_pcap)
        top.addWidget(self.open_pcap_btn)
        layout.addLayout(top)

        self.pcap_table = QTableWidget(0, 6)
        self.pcap_table.setHorizontalHeaderLabels(['SSID', 'BSSID', 'Security', 'Channel', 'Signal', 'Risk'])
        self.pcap_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.pcap_table)

        self.pcap_log = QTextEdit(); self.pcap_log.setReadOnly(True); self.pcap_log.setFixedHeight(120)
        layout.addWidget(self.pcap_log)

        self.pcap_tab.setLayout(layout)

    def _build_report_tab(self):
        layout = QVBoxLayout(); w = QWidget(); w.setLayout(layout)

        ops = QHBoxLayout()
        self.export_json_btn = QPushButton('Export JSON')
        self.export_json_btn.clicked.connect(self.export_json)
        ops.addWidget(self.export_json_btn)

        self.export_md_btn = QPushButton('Export Markdown')
        self.export_md_btn.clicked.connect(self.export_md)
        ops.addWidget(self.export_md_btn)

        self.export_pdf_btn = QPushButton('Export PDF')
        self.export_pdf_btn.clicked.connect(self.export_pdf)
        ops.addWidget(self.export_pdf_btn)

        layout.addLayout(ops)

        self.report_preview = QTextEdit(); self.report_preview.setReadOnly(True)
        layout.addWidget(self.report_preview)

        self.report_tab.setLayout(layout)

    # ---------------------- Actions ----------------------

    def start_system_scan(self):
        self.log.append('Starting system scan...')
        self.progress.setValue(5)
        iface = self.iface_combo.currentText().strip() or None
        self.scan_thread = SystemScanThread(iface=iface)
        self.scan_thread.finished_signal.connect(self.system_scan_finished)
        self.scan_thread.log_signal.connect(self.append_log)
        self.scan_btn.setEnabled(False)
        self.scan_thread.start()

    def append_log(self, text: str):
        self.log.append(text)

    def system_scan_finished(self, networks: List[Dict[str, Any]]):
        self.scan_btn.setEnabled(True)
        self.progress.setValue(100)
        self.scan_results = networks
        self.populate_table(self.table, networks)
        self.log.append(f'Scan finished - {len(networks)} networks found')
        self.generate_report_preview()

    def populate_table(self, table: QTableWidget, networks: List[Dict[str, Any]]):
        table.setRowCount(0)
        for n in networks:
            row = table.rowCount()
            table.insertRow(row)
            table.setItem(row, 0, QTableWidgetItem(n.get('ssid') or '<hidden>'))
            table.setItem(row, 1, QTableWidgetItem(n.get('bssid') or ''))
            table.setItem(row, 2, QTableWidgetItem(n.get('security') or ''))
            table.setItem(row, 3, QTableWidgetItem(str(n.get('channel') or '')))
            table.setItem(row, 4, QTableWidgetItem(str(n.get('signal') or '')))
            risk_item = QTableWidgetItem(n.get('risk') or 'UNKNOWN')
            color = severity_color(n.get('risk') or '')
            risk_item.setBackground(color)
            table.setItem(row, 5, risk_item)

    def open_pcap(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Open PCAP', filter='PCAP Files (*.pcap *.pcapng);;All files (*)')
        if not path:
            return
        if not SCAPY_AVAILABLE:
            QMessageBox.critical(self, 'Missing dependency', 'Scapy is not installed. Install with `pip install scapy` to analyze pcap files.')
            return
        self.pcap_log.append(f'Analyzing PCAP: {path}')
        self.pcap_thread = PcapAnalysisThread(path)
        self.pcap_thread.finished_signal.connect(self.pcap_analysis_finished)
        self.pcap_thread.log_signal.connect(self.pcap_log.append)
        self.pcap_thread.start()

    def pcap_analysis_finished(self, networks: List[Dict[str, Any]]):
        self.pcap_results = networks
        self.populate_table(self.pcap_table, networks)
        self.pcap_log.append(f'PCAP analysis finished - {len(networks)} networks found')
        self.generate_report_preview()

    def generate_report_preview(self):
        report = {'generated': datetime.now(timezone.utc).isoformat(), 'scans': []}
        if self.scan_results:
            report['scans'].append({'type': 'system', 'networks': self.scan_results})
        if self.pcap_results:
            report['scans'].append({'type': 'pcap', 'networks': self.pcap_results})
        text = json.dumps(report, indent=2)
        self.report_preview.setText(text)

    def export_json(self):
        path, _ = QFileDialog.getSaveFileName(self, 'Save JSON', filter='JSON Files (*.json)')
        if not path:
            return
        report = self.report_preview.toPlainText()
        try:
            Path(path).write_text(report)
            QMessageBox.information(self, 'Saved', f'Saved JSON report to {path}')
        except Exception as e:
            QMessageBox.critical(self, 'Error', str(e))

    def export_md(self):
        path, _ = QFileDialog.getSaveFileName(self, 'Save Markdown', filter='Markdown Files (*.md)')
        if not path:
            return
        md = self._build_md_report()
        try:
            Path(path).write_text(md)
            QMessageBox.information(self, 'Saved', f'Saved Markdown report to {path}')
        except Exception as e:
            QMessageBox.critical(self, 'Error', str(e))

    def export_pdf(self):
        if not REPORTLAB_AVAILABLE:
            QMessageBox.critical(self, 'Missing dependency', 'reportlab is not installed. Install with `pip install reportlab` to export PDF.')
            return
        path, _ = QFileDialog.getSaveFileName(self, 'Save PDF', filter='PDF Files (*.pdf)')
        if not path:
            return
        try:
            md = self._build_md_report()
            # simple PDF generation: write text lines to PDF
            c = canvas.Canvas(path, pagesize=letter)
            width, height = letter
            y = height - 40
            for line in md.splitlines():
                c.drawString(40, y, line[:100])
                y -= 12
                if y < 40:
                    c.showPage()
                    y = height - 40
            c.save()
            QMessageBox.information(self, 'Saved', f'Saved PDF report to {path}')
        except Exception as e:
            QMessageBox.critical(self, 'Error', str(e))

    def _build_md_report(self) -> str:
        try:
            obj = json.loads(self.report_preview.toPlainText())
        except Exception:
            return '# Report\n\n<empty>'
        lines = ['# Wireless Defensive Audit Report', f'Generated: {obj.get("generated")}', '']
        for scan in obj.get('scans', []):
            lines.append(f"## Scan Type: {scan.get('type')}")
            for n in scan.get('networks', []):
                lines.append(f"### {n.get('ssid') or '<hidden>'} ({n.get('bssid') or 'N/A'})")
                lines.append(f"- Security: {n.get('security')}")
                lines.append(f"- Channel: {n.get('channel')}")
                lines.append(f"- Signal: {n.get('signal')}")
                lines.append(f"- Risk: {n.get('risk')}")
                if n.get('issues'):
                    for iss in n.get('issues'):
                        lines.append(f"  - [{iss.get('severity')}] {iss.get('description')}")
                lines.append('')
        return '\n'.join(lines)


# ---------------------- Entry point ----------------------

def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
