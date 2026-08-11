# encoding: utf-8
"""
CPython stand-ins for the Jython/Java classes SAVER_LOGGER.py imports, so the
extension's logic can be tested without Burp or a JVM.

Call install() BEFORE importing SAVER_LOGGER. Swing/AWT widgets are replaced
with inert Magic objects (the UI is not under test); java.io / java.nio
classes are functional so CSV exports write real files; threads and locks map
onto Python's threading module.
"""
import sys
import threading
import time
import types

try:
    import queue as _queue
except ImportError:  # pragma: no cover - py2 fallback
    import Queue as _queue


class Magic(object):
    """Inert stand-in: callable, chainable attribute access, swallows everything."""

    def __call__(self, *args, **kwargs):
        return Magic()

    def __getattr__(self, name):
        value = Magic()
        object.__setattr__(self, name, value)
        return value


# --------------- burp interfaces (used as base classes) --------------- #

class IBurpExtender(object):
    pass


class IHttpListener(object):
    pass


class IExtensionStateListener(object):
    pass


class ITab(object):
    pass


class IProxyListener(object):
    pass


class IScannerListener(object):
    pass


# --------------- java.lang --------------- #

class Runnable(object):
    pass


class Thread(object):
    def __init__(self, runnable=None):
        self._runnable = runnable
        self._thread = None

    def setDaemon(self, daemon):
        pass

    def start(self):
        self._thread = threading.Thread(target=self._runnable.run)
        self._thread.daemon = True
        self._thread.start()

    def join(self, millis=None):
        if self._thread is not None:
            self._thread.join(millis / 1000.0 if millis else None)

    def isAlive(self):
        return self._thread is not None and self._thread.is_alive()

    @staticmethod
    def sleep(millis):
        time.sleep(millis / 1000.0)


class System(object):
    @staticmethod
    def currentTimeMillis():
        return int(time.time() * 1000)

    @staticmethod
    def identityHashCode(obj):
        return id(obj)


# --------------- java.util --------------- #

class TimerTask(object):
    def run(self):
        pass


class Timer(object):
    """Inert: scheduled tasks are recorded but never fired (tests drive the
    logic directly instead of waiting on wall-clock timers)."""

    def __init__(self, name=None, is_daemon=False):
        self.scheduled = []
        self.cancelled = False

    def schedule(self, task, delay, period=None):
        self.scheduled.append((task, delay, period))

    def cancel(self):
        self.cancelled = True


# --------------- java.util.concurrent --------------- #

class ReentrantLock(object):
    def __init__(self):
        self._lock = threading.RLock()

    def lock(self):
        self._lock.acquire()

    def unlock(self):
        self._lock.release()


class TimeUnit(object):
    MILLISECONDS = 'MILLISECONDS'
    SECONDS = 'SECONDS'


class LinkedBlockingQueue(object):
    """Functional stand-in used by the performance branch."""

    def __init__(self):
        self._q = _queue.Queue()

    def put(self, item):
        self._q.put(item)

    def offer(self, item):
        self._q.put(item)
        return True

    def poll(self, timeout=None, unit=None):
        try:
            if timeout is None:
                return self._q.get_nowait()
            return self._q.get(timeout=timeout / 1000.0)
        except _queue.Empty:
            return None

    def size(self):
        return self._q.qsize()

    def drainTo(self, collection):
        count = 0
        while True:
            try:
                collection.append(self._q.get_nowait())
                count += 1
            except _queue.Empty:
                return count


# --------------- java.io (functional, so exports write real files) --------------- #

class File(object):
    def __init__(self, path):
        self.path = path

    def getAbsolutePath(self):
        return self.path

    def exists(self):
        import os
        return os.path.exists(self.path)

    def mkdirs(self):
        import os
        try:
            os.makedirs(self.path)
            return True
        except OSError:
            return False


class FileOutputStream(object):
    def __init__(self, path, append=False):
        if isinstance(path, File):
            path = path.path
        self._file = open(path, 'ab' if append else 'wb')


class OutputStreamWriter(object):
    def __init__(self, fos, charset=None):
        self._file = fos._file


class BufferedWriter(object):
    def __init__(self, writer):
        self._file = writer._file

    def write(self, text):
        self._file.write(text.encode('utf-8'))

    def flush(self):
        self._file.flush()

    def close(self):
        self._file.close()


# --------------- java.nio.charset --------------- #

class Charset(object):
    @staticmethod
    def forName(name):
        return name


_SWING_NAMES = [
    'JPanel', 'JButton', 'JFileChooser', 'JTextPane', 'JScrollPane',
    'JOptionPane', 'JCheckBox', 'JLabel', 'JTextField', 'JTabbedPane',
    'BorderFactory', 'JSpinner', 'SpinnerNumberModel', 'UIManager',
    'JTextArea', 'SwingUtilities',
]
_AWT_NAMES = [
    'BorderLayout', 'Dimension', 'Font', 'GridBagLayout',
    'GridBagConstraints', 'Insets', 'FlowLayout',
]


def _module(name, **attrs):
    mod = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(mod, key, value)
    sys.modules[name] = mod
    return mod


def install():
    """Register all Java module stand-ins in sys.modules."""
    _module('burp',
            IBurpExtender=IBurpExtender, IHttpListener=IHttpListener,
            IExtensionStateListener=IExtensionStateListener, ITab=ITab,
            IProxyListener=IProxyListener, IScannerListener=IScannerListener)

    javax = _module('javax')
    javax.swing = _module('javax.swing', **dict((n, Magic()) for n in _SWING_NAMES))

    java = _module('java')
    java.awt = _module('java.awt', **dict((n, Magic()) for n in _AWT_NAMES))
    java.io = _module('java.io',
                      File=File, FileOutputStream=FileOutputStream,
                      OutputStreamWriter=OutputStreamWriter,
                      BufferedWriter=BufferedWriter)
    java.nio = _module('java.nio')
    java.nio.charset = _module('java.nio.charset', Charset=Charset)
    java.lang = _module('java.lang', Thread=Thread, Runnable=Runnable, System=System)
    java.util = _module('java.util', Timer=Timer, TimerTask=TimerTask)
    locks = _module('java.util.concurrent.locks', ReentrantLock=ReentrantLock)
    java.util.concurrent = _module('java.util.concurrent',
                                   locks=locks,
                                   LinkedBlockingQueue=LinkedBlockingQueue,
                                   TimeUnit=TimeUnit)
