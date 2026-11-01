"""Nonblocking upload ownership across threads, SQLite handles and processes."""

import errno
import hashlib
import os
import threading
import weakref
from pathlib import Path

from whatsapp_e2ee.store import key

_guard = threading.Lock()
_locks = weakref.WeakValueDictionary()


class UploadBusy(RuntimeError):
    pass


class _LocalLock:
    def __init__(self):
        self.lock = threading.Lock()


class upload_operation:
    """Hold an upload-only lock without holding a SQLite transaction.

    File locks are released by the OS after process exit. Persistent empty lock
    files must not be unlinked while other workers may still reference them.
    """

    def __init__(self, store, id):
        self.store, self.id = store, id
        self.local = None
        self._files = []

    def __enter__(self):
        store, id = self.store, self.id
        with store.db.lock:
            database = next(
                row[2]
                for row in store.db.connection.execute("PRAGMA database_list")
                if row[1] == "main"
            )
            # SQLite TEXT affinity makes owner=1 and owner="1" the same owner.
            owner = store.db.connection.execute(
                "SELECT CAST(? AS TEXT)", (store.owner,)
            ).fetchone()[0]
        path = Path(database).resolve() if database else None
        if path is None:
            file_id = None
        else:
            status = path.stat()
            file_id = (
                ("file", status.st_dev, status.st_ino)
                if status.st_ino
                else ("path", str(path).casefold() if os.name == "nt" else str(path))
            )
        identity = (file_id if path is not None else store.db, owner, id)
        with _guard:
            local = _locks.get(identity)
            if local is None:
                local = _LocalLock()
                _locks[identity] = local
        if not local.lock.acquire(blocking=False):
            raise UploadBusy("Another upload or reconciliation is active")
        self.local = local
        try:
            if path is not None:
                directory = path.parent / ".wa-upload-locks"
                directory.mkdir(mode=0o700, exist_ok=True)
                # File identity unifies case aliases. Also hold the previous
                # pathname lock so workers from before this fix still exclude us.
                names = {
                    hashlib.sha256(key(value, owner, id).encode()).hexdigest()
                    for value in (file_id, str(path))
                }
                for name in sorted(names):
                    self._acquire_file(directory / name)
        except BaseException:
            self._release()
            raise

    def __exit__(self, exc_type, exc_value, traceback):
        self._release()
        # Avoid generator context managers assigning to frozen exceptions.
        return False

    def _acquire_file(self, path):
        fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        entry = [fd, False]
        self._files.append(entry)
        if os.name == "nt":
            import msvcrt

            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\0")
            os.lseek(fd, 0, os.SEEK_SET)
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            except OSError as error:
                if error.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                    raise
                raise UploadBusy("Another upload or reconciliation is active") from error
        else:
            import fcntl

            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise UploadBusy("Another upload or reconciliation is active") from error
        entry[1] = True

    def _release(self):
        files, self._files = self._files, []
        local, self.local = self.local, None
        failure = None
        try:
            for fd, locked in reversed(files):
                try:
                    try:
                        if locked and os.name == "nt":
                            import msvcrt

                            os.lseek(fd, 0, os.SEEK_SET)
                            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                        elif locked:
                            import fcntl

                            fcntl.flock(fd, fcntl.LOCK_UN)
                    finally:
                        os.close(fd)
                except BaseException as error:
                    # A failed unlock/close must not strand the remaining locks.
                    if failure is None:
                        failure = error
        finally:
            if local is not None:
                local.lock.release()
        if failure is not None:
            raise failure


__all__ = ["UploadBusy", "upload_operation"]
