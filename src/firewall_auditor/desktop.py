"""Qt operator console. All inspection runs on a worker; mutation stays in Phase 3 CLI."""
import json
from pathlib import Path
from PySide6.QtCore import QObject, QThread, Signal, Slot
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
    QHBoxLayout, QLabel, QPushButton, QComboBox, QLineEdit, QPlainTextEdit, QTabWidget)


class Worker(QObject):
    progress = Signal(str)
    result = Signal(object)
    failed = Signal(str)
    finished = Signal()

    def __init__(self, task):
        super().__init__()
        self.task = task

    @Slot()
    def run(self):
        try:
            self.result.emit(self.task(self.progress.emit))
        except Exception as exc:
            # Provider exceptions can include credentials. Never display their text.
            self.failed.emit('Operation failed (' + type(exc).__name__ +
                             '). Check local SSH agent, configuration, API access and quota.')
        finally:
            self.finished.emit()


def audit_task(root, host, model, goal):
    # Capture the selected inputs before starting; no widgets are accessed by workers.
    def task(progress):
        from .agent import AgentController
        from .context import load_context
        from .gemini import GeminiProvider
        from .phase3_ledger import Ledger
        from .reports import write_report
        from .tools import Inspector
        from .transport import load_hosts
        from .web import browser_report

        class Observed(AgentController):
            def record(self, event):
                ok = super().record(event)
                progress('Agent event: ' + str(event.get('event', event.get('type', 'recorded'))))
                return ok

        provider = GeminiProvider(model, api_version='v1beta')
        try:
            report = Observed(Inspector(load_hosts(str(root / 'config/hosts.local.json'))),
                provider, host, load_context(str(root / 'config/context.local.json'), host),
                audit=Ledger(root / 'audit/audit.sqlite3')).run(goal)
            write_report(report, root / 'reports/phase4-desktop-latest')
            return {'source': 'Fresh desktop audit', 'report': browser_report(report)}
        finally:
            provider.close()
    return task


def evidence_task(root):
    def task(progress):
        from .phase3_ledger import Ledger
        result = {'source': 'Saved evidence; this does not retest the VMs', 'receipts': {}}
        for name in ('phase3-last-result.json', 'phase3-watchdog-result.json'):
            path = root / 'reports' / name
            if path.exists():
                result['receipts'][name] = json.loads(path.read_text(encoding='utf-8-sig'))
        ledger = root / 'audit/audit.sqlite3'
        if ledger.exists():
            result['audit_hash_chain_valid'] = Ledger(ledger).verify()
        else:
            result['audit_hash_chain_valid'] = None
        return result
    return task


class Console(QMainWindow):
    def __init__(self, root, hosts, model, task_factory=audit_task):
        super().__init__()
        self.root, self.model, self.task_factory = Path(root), model, task_factory
        self.thread = self.worker = None
        self.setWindowTitle('Secure Firewall Auditor ? Phase 4')
        self.resize(1050, 740)
        body = QWidget(); layout = QVBoxLayout(body); self.setCentralWidget(body)
        layout.addWidget(QLabel('Read-only audit console | Firewall changes require the existing Phase 3 approval workflow'))
        row = QHBoxLayout(); self.host = QComboBox(); self.host.addItems(sorted(hosts))
        if 'ubuntu-vm' in hosts: self.host.setCurrentText('ubuntu-vm')
        row.addWidget(QLabel('Configured test VM:')); row.addWidget(self.host)
        row.addWidget(QLabel('Model: ' + model)); layout.addLayout(row)
        self.goal = QLineEdit('Audit the selected host firewall configuration.')
        self.goal.setMaxLength(2000); layout.addWidget(self.goal)
        buttons = QHBoxLayout()
        self.run_button = QPushButton('Run live audit')
        self.evidence_button = QPushButton('Review saved Phase 3 evidence')
        buttons.addWidget(self.run_button); buttons.addWidget(self.evidence_button); layout.addLayout(buttons)
        self.status = QLabel('Ready. Live audit sends VM inspection data to Gemini.'); layout.addWidget(self.status)
        tabs = QTabWidget(); layout.addWidget(tabs)
        self.output = QPlainTextEdit(); self.output.setReadOnly(True); tabs.addTab(self.output, 'Findings and evidence')
        self.log = QPlainTextEdit(); self.log.setReadOnly(True)
        self.log.document().setMaximumBlockCount(500); tabs.addTab(self.log, 'Progress')
        guidance = QPlainTextEdit(); guidance.setReadOnly(True)
        guidance.setPlainText('Configuration: config/hosts.local.json and config/context.local.json.\n'
            'Enroll host keys and load your encrypted SSH key into the Windows SSH agent locally.\n'
            'Credentials are never entered into goals or evidence.\n\n'
            'Remediation: use scripts/run_phase3.py. Review its fresh proposal and type its exact approval hash.\n'
            'This console exposes no firewall mutation tools. Existing verified lab rules remain in place.\n\n'
            'Saved receipts are historical evidence, not a fresh connectivity test.\n'
            'Phase 4 live acceptance also requires a native desktop run and the separate HTTPS browser checks.')
        tabs.addTab(guidance, 'Operator guide')
        self.run_button.clicked.connect(self.start_audit)
        self.evidence_button.clicked.connect(lambda: self.start(evidence_task(self.root)))

    @Slot()
    def start_audit(self):
        goal = self.goal.text().strip()
        if not goal:
            self.status.setText('Enter an audit goal.'); return
        self.start(self.task_factory(self.root, self.host.currentText(), self.model, goal))

    def start(self, task):
        if self.thread is not None: return
        self.status.setText('Running in background. No firewall rules will be changed.')
        for widget in (self.run_button, self.evidence_button, self.host, self.goal): widget.setEnabled(False)
        self.thread = QThread(self); self.worker = Worker(task)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.log.appendPlainText)
        self.worker.result.connect(self.show_result)
        self.worker.failed.connect(self.status.setText)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.finished)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    @Slot(object)
    def show_result(self, result):
        self.output.setPlainText(json.dumps(result, indent=2, ensure_ascii=False))
        report = result.get('report', {})
        self.status.setText(str(result.get('source', 'Result')) + ': ' + str(report.get('status', 'loaded')))

    @Slot()
    def finished(self):
        self.thread = self.worker = None
        for widget in (self.run_button, self.evidence_button, self.host, self.goal): widget.setEnabled(True)

    def closeEvent(self, event):
        if self.thread is not None:
            self.status.setText('Wait for the bounded audit to finish before closing.'); event.ignore()
        else:
            event.accept()
