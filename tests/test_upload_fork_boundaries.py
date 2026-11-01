"""Forked workers must neither inherit stale ownership nor unlock the parent."""

import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest

import whatsapp_e2ee

pytestmark = pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork lifecycle")

SCRIPT = r'''
import fcntl, json, multiprocessing, os, signal, subprocess, sys, threading, traceback
from pathlib import Path
if sys.argv[2] == 'threaded_close_only':
    import gc
    # Earlier hooks may collect the abandoned stacks of vanished threads.
    os.register_at_fork(after_in_child=gc.collect)
from whatsapp_e2ee import Database, SQLiteStore
from whatsapp_e2ee.media_jobs import MediaJobs
from whatsapp_e2ee.media_transfer import Uploads, UploadReceipt, Reconciliation, UploadUncertain
from whatsapp_e2ee import upload_coordination as coordination

root, mode, alias = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
directory = root / 'storage'
directory.mkdir()
path = directory / 'media.db'
db = Database(path)
child_path = (path.with_name('MEDIA.DB') if alias == 'file' else
              root / 'STORAGE' / path.name if alias == 'directory' else path)
if not child_path.exists() or not os.path.samefile(path, child_path):
    db.close()
    print(json.dumps({'skip': 'case-insensitive filesystem required'}))
    sys.exit(0)
jobs = MediaJobs(SQLiteStore(db, 'owner'), clock_ms=lambda: 123000)
media = jobs.prepare('m', b'media', 'image')
receipt = UploadReceipt('/uploaded', 123000, media.encrypted_hash)
uploads = Uploads(jobs)
def lost(request):
    b''.join(request.body)
    raise TimeoutError('response lost')
try:
    uploads.send('m', 'https://media.invalid/upload', lost, lambda *_: receipt)
except TimeoutError:
    pass
before = uploads.pending('m')
assert before['state'] == 'unknown'
guard = coordination.upload_operation(jobs.store, 'm')
parent, child = multiprocessing.Pipe()
pid = None

def recv():
    assert parent.poll(4), 'child did not finish its operation'
    return parent.recv()

def cleanup():
    if pid:
        try:
            waited, _ = os.waitpid(pid, os.WNOHANG)
            if not waited:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
        except ChildProcessError:
            pass
    parent.close()
    child.close()
    db.close()

def recover_in_child():
    try:
        parent.close()
        # Only the upload-lock layer is inherited; application DB connections
        # are explicitly reopened by each worker.
        db.close()
        fresh = Database(child_path)
        worker = Uploads(MediaJobs(SQLiteStore(fresh, 'owner')))
        child.send('ready')
        assert child.recv() == 'active'
        try:
            worker.reconcile('m', lambda _: Reconciliation('found', receipt))
        except UploadUncertain:
            child.send('blocked')
        else:
            raise AssertionError('fork cleanup released the active parent lock')
        assert child.recv() == 'released'
        assert worker.reconcile('m', lambda _: Reconciliation('found', receipt)) == receipt
        final = worker.pending('m')
        assert final['count'] == before['count'] and final['request_id'] == before['request_id']
        fresh.close()
        child.send('recovered')
        os._exit(0)
    except BaseException:
        traceback.print_exc()
        os._exit(3)

def start_child():
    global pid
    pid = os.fork()
    if not pid:
        recover_in_child()
    child.close()
    assert recv() == 'ready'

PROBE = r"""
import sys
from whatsapp_e2ee import Database, SQLiteStore
from whatsapp_e2ee.media_jobs import MediaJobs
from whatsapp_e2ee.media_transfer import Uploads, Reconciliation, UploadReceipt, UploadUncertain
d=Database(sys.argv[1]);j=MediaJobs(SQLiteStore(d,'owner'));m=j.load('m')
try:
    Uploads(j).reconcile('m',lambda _:Reconciliation('found',UploadReceipt('/uploaded',123000,m.encrypted_hash)))
except UploadUncertain:
    print('blocked')
else:
    print('acquired')
d.close()
"""

try:
    if mode in ('acquired', 'partial', 'close_only'):
        original = coordination.upload_operation._acquire_file
        spawned = False
        def acquire(operation, file):
            global spawned
            original(operation, file)
            if not spawned:
                spawned = True
                start_child()
        if mode == 'partial':
            coordination.upload_operation._acquire_file = acquire
        real_flock = fcntl.flock
        with guard:
            if mode != 'partial':
                start_child()
            parent.send('active')
            assert recv() == 'blocked'
            if mode == 'close_only':
                # Model OS closure on a crash: close both parent descriptors
                # without an explicit flock unlock, while the child stays alive.
                fcntl.flock = lambda fd, op: None if op == fcntl.LOCK_UN else real_flock(fd, op)
        fcntl.flock = real_flock
        coordination.upload_operation._acquire_file = original
        parent.send('released')
        assert recv() == 'recovered'
        assert os.waitpid(pid, 0)[1] == 0
        assert uploads.pending('m')['state'] == 'uploaded'
    elif mode in ('unwind', 'exception', 'crash'):
        with guard:
            pid = os.fork()
            if not pid:
                if mode != 'crash':
                    error = RuntimeError('child abort') if mode == 'exception' else None
                    guard.__exit__(type(error) if error else None, error, None)
                os._exit(27 if mode == 'crash' else 0)
            assert os.waitpid(pid, 0)[1] == (27 << 8 if mode == 'crash' else 0)
            result = subprocess.run([sys.executable, '-c', PROBE, str(path)],
                                    capture_output=True, text=True, timeout=4)
            assert result.returncode == 0 and result.stdout.strip() == 'blocked', result.stdout + result.stderr
        assert uploads.reconcile('m', lambda _: Reconciliation('found', receipt)) == receipt
    elif mode == 'registry_held':
        entered, release = threading.Event(), threading.Event()
        def hold():
            with coordination._guard:
                entered.set()
                assert release.wait(4)
        with guard:
            thread = threading.Thread(target=hold)
            thread.start()
            assert entered.wait(4)
            timer = threading.Timer(0.05, release.set)
            timer.start()
            start_child()
            timer.join(4)
            thread.join(4)
            parent.send('active')
            assert recv() == 'blocked'
        parent.send('released')
        assert recv() == 'recovered'
        assert os.waitpid(pid, 0)[1] == 0
    elif mode == 'threaded_close_only':
        entered, release = threading.Event(), threading.Event()
        def hold_operation():
            with coordination.upload_operation(jobs.store, 'm'):
                entered.set()
                assert release.wait(5)
        thread = threading.Thread(target=hold_operation)
        thread.start()
        assert entered.wait(4)
        try:
            start_child()
            parent.send('active')
            assert recv() == 'blocked'
            real_flock = fcntl.flock
            fcntl.flock = lambda fd, op: None if op == fcntl.LOCK_UN else real_flock(fd, op)
            release.set()
            thread.join(4)
            assert not thread.is_alive()
            fcntl.flock = real_flock
            parent.send('released')
            assert recv() == 'recovered'
            assert os.waitpid(pid, 0)[1] == 0
        finally:
            release.set()
            thread.join(4)
    print(json.dumps({'mode': mode, 'passed': True}))
finally:
    cleanup()
'''


def run_scenario(tmp_path, mode, alias="none"):
    package_root = Path(whatsapp_e2ee.__file__).resolve().parents[1]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(package_root) + os.pathsep + env.get("PYTHONPATH", "")
    process = subprocess.Popen(
        [sys.executable, "-c", SCRIPT, str(tmp_path), mode, alias],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate(timeout=5)
        pytest.fail("Fork regression timed out: " + stdout + stderr)
    assert process.returncode == 0, stdout + stderr
    if '"skip"' in stdout:
        pytest.skip("Case-insensitive filesystem required")
    assert '"passed": true' in stdout, stdout + stderr


@pytest.mark.parametrize("mode", ["acquired", "partial", "close_only"])
@pytest.mark.parametrize("alias", ["none", "file", "directory"])
def test_child_reconciles_after_parent_releases_inherited_operation(tmp_path, mode, alias):
    run_scenario(tmp_path, mode, alias)


@pytest.mark.parametrize("mode", ["unwind", "exception", "crash"])
def test_child_cleanup_cannot_unlock_parent_operation(tmp_path, mode):
    run_scenario(tmp_path, mode)


def test_fork_waits_for_registry_critical_section(tmp_path):
    run_scenario(tmp_path, "registry_held")


def test_fork_during_another_threads_upload_closes_inherited_descriptors(tmp_path):
    run_scenario(tmp_path, "threaded_close_only")
