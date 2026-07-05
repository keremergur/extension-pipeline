"""Tee stdout/stderr to a per-run console.txt while still printing to the terminal.

The verifier emits everything through ``print``/``log_*`` to stdout (and the
occasional traceback to stderr). To get a persistent, real-time copy of that
output under the run directory we wrap ``sys.stdout``/``sys.stderr`` with a tee
that flushes on every write, so the file can be tailed as the run progresses.

The run directory only exists partway through ``main()``, so output produced
before that is buffered and flushed to the file the moment it is attached.
"""
import sys
from pathlib import Path


class _TeeStream:
    """Write to the original stream and, once attached, to a file too."""

    def __init__(self, base_stream):
        self._base = base_stream
        self._file = None
        self._pending = []  # buffers writes until a file is attached

    def attach(self, file_obj):
        self._file = file_obj
        if self._pending:
            file_obj.write("".join(self._pending))
            file_obj.flush()
            self._pending.clear()

    def write(self, data):
        n = self._base.write(data)
        if self._file is not None:
            self._file.write(data)
            self._file.flush()  # flush every write so the file updates in real time
        else:
            self._pending.append(data)
        return n

    def flush(self):
        try:
            self._base.flush()
        except Exception:
            pass
        if self._file is not None:
            self._file.flush()

    def isatty(self):
        return getattr(self._base, "isatty", lambda: False)()

    def fileno(self):
        return self._base.fileno()

    def __getattr__(self, name):
        return getattr(self._base, name)


class ConsoleTee:
    """Mirror stdout/stderr to a run-specific ``console.txt``.

    Usage::

        tee = ConsoleTee()
        tee.start_capture()          # begin tee-ing (buffers until file is set)
        try:
            ...
            tee.set_file(run_dir / "console.txt")
            ...
        finally:
            tee.stop()
    """

    def __init__(self):
        self._orig_stdout = None
        self._orig_stderr = None
        self._stdout_tee = None
        self._stderr_tee = None
        self._file = None

    def start_capture(self):
        self._orig_stdout = sys.stdout
        self._orig_stderr = sys.stderr
        self._stdout_tee = _TeeStream(self._orig_stdout)
        self._stderr_tee = _TeeStream(self._orig_stderr)
        sys.stdout = self._stdout_tee
        sys.stderr = self._stderr_tee

    def set_file(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        # buffering=1 -> line-buffered; combined with per-write flushing this
        # keeps console.txt close to real time.
        self._file = open(path, "a", encoding="utf-8", buffering=1)
        if self._stdout_tee is not None:
            self._stdout_tee.attach(self._file)
        if self._stderr_tee is not None:
            self._stderr_tee.attach(self._file)

    def stop(self):
        if self._orig_stdout is not None:
            sys.stdout = self._orig_stdout
        if self._orig_stderr is not None:
            sys.stderr = self._orig_stderr
        if self._file is not None:
            try:
                self._file.flush()
                self._file.close()
            finally:
                self._file = None
