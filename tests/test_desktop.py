import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
import threading
import time
import pytest
pytest.importorskip('PySide6')
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QCoreApplication, QEvent
_APPLICATION = QApplication.instance() or QApplication([])
from firewall_auditor.desktop import Console, Worker, evidence_task

@pytest.fixture(scope='module')
def app():
    yield _APPLICATION
    _APPLICATION.processEvents()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    _APPLICATION.processEvents()

def drain(app, window):
    deadline = time.monotonic() + 5
    while window.thread is not None and time.monotonic() < deadline:
        app.processEvents(); time.sleep(.005)
    assert window.thread is None

def test_worker_errors_do_not_disclose_secret(app):
    def fail(progress): raise RuntimeError('secret-api-key')
    w = Worker(fail); errors=[]; done=[]
    w.failed.connect(errors.append); w.finished.connect(lambda: done.append(True)); w.run()
    assert 'secret-api-key' not in errors[0]
    assert 'RuntimeError' in errors[0] and done

def test_audit_runs_off_ui_thread_and_prevents_overlap(app, tmp_path):
    main = threading.get_ident(); identities=[]
    def factory(root, host, model, goal):
        assert host == 'ubuntu-vm'
        def task(progress):
            identities.append(threading.get_ident()); time.sleep(.05)
            return {'source':'Synthetic test', 'report':{'status':'complete'}}
        return task
    w=Console(tmp_path, {'ubuntu-vm':None}, 'test-model', factory)
    w.start_audit(); running=w.thread
    assert not w.run_button.isEnabled()
    w.start_audit(); assert w.thread is running
    assert not w.close()
    drain(app,w)
    assert identities and identities[0] != main
    assert w.run_button.isEnabled() and 'complete' in w.status.text()
    assert w.close()

def test_empty_goal_does_not_start(app,tmp_path):
    w=Console(tmp_path, {'ubuntu-vm':None}, 'test')
    w.goal.setText(' '); w.start_audit()
    assert w.thread is None
    w.close()

def test_missing_saved_evidence_is_not_a_pass(tmp_path):
    result=evidence_task(tmp_path)(lambda text:None)
    assert result['audit_hash_chain_valid'] is None
    assert result['receipts']=={}
    assert 'does not retest' in result['source']
