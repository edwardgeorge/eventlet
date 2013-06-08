from collections import deque
import imp
import itertools
import os
import sys

from eventlet import greenio
from eventlet import event
from eventlet import hubs
from eventlet import timeout
from eventlet import patcher

threading = patcher.original('threading')
Queue_module = patcher.original('Queue')
Queue = Queue_module.Queue
Empty = Queue_module.Empty

DEFAULT_SIZE = int(os.environ.get('EVENTLET_THREADPOOL_SIZE', 20))
SYS_EXCS = (KeyboardInterrupt, SystemExit)
EXC_CLASSES = (Exception, timeout.Timeout)

_threadpool = None


class ThreadPool(object):
    def __init__(self, size=DEFAULT_SIZE):
        assert size >= 0, "Can't specify negative number of threads"
        if size == 0:
            import warnings
            warnings.warn("Zero threads in tpool.  All tpool.execute calls"
                          " will execute in main thread."
                          "  Check the value of the environment variable"
                          " EVENTLET_THREADPOOL_SIZE.", RuntimeWarning)
        self.size = size
        self.threads = set()
        self._signal = sig = greenio._IOSignal()
        self._hub = hub = hubs.get_hub()
        self._listener = hub.add(hub.READ, sig.r.fileno(),
                                 self._handle_response)
        self._is_setup = False
        self.setup()

    def setup(self):
        if self._is_setup:
            return
        self.request_queue = Queue(maxsize=-1)
        self.response_queue = Queue(maxsize=-1)
        self._start_threads(self.size)
        self._is_setup = True

    def _start_threads(self, size):
        reqq, rspq = self.request_queue, self.response_queue
        for i in xrange(size):
            t = threading.Thread(target=self._thread_main,
                                 args=(reqq, rspq, self._signal.send),
                                 name="tpool_thread_%d" % (i, ))
            t.daemon = True
            t.start()
            self.threads.add(t)

    def resize(self, newsize):
        if newsize > self.size:
            self._start_threads(newsize - self.size)
        for i in xrange(0, newsize - self.size):
            self.request_queue.put(None)

    def _handle_response(self, fileno):
        self._signal.drain()
        rspq = self.response_queue
        while not rspq.empty():
            try:
                (e, rv) = rspq.get(block=False)
                if rv[0]:
                    e.send_exception(*rv[1])
                else:
                    e.send(rv[1])
                e = rv = None
            except Empty:
                return

    def _thread_main(self, requestq, responseq, signalresp):
        while True:
            try:
                msg = requestq.get()
            except AttributeError:
                return  # can't get anything off of a dud queue
            if msg is None:
                return
            (e, meth, args, kwargs) = msg
            rv = None
            try:
                rv = (False, meth(*args, **kwargs))
            except SYS_EXCS:
                raise
            except EXC_CLASSES:
                rv = (True, sys.exc_info())
            # test_leakage_from_tracebacks verifies that the use of
            # exc_info does not lead to memory leaks
            responseq.put((e, rv))
            msg = meth = args = kwargs = e = rv = None
            signalresp()

    def execute(self, func, *args, **kwargs):
        # if already in tpool, don't recurse into the tpool
        # also, call functions directly if we're inside an import lock, because
        # if meth does any importing (sadly common), it will hang
        if not self._is_setup:
            self.setup()
        my_thread = threading.currentThread()
        if my_thread in self.threads or imp.lock_held() or self.size == 0:
            return func(*args, **kwargs)

        e = event.Event()
        self.request_queue.put((e, func, args, kwargs))
        # raises exception if sent
        return e.wait()

    def killall(self):
        threads = self.threads
        reqq = self.request_queue
        for thr in threads:
            reqq.put(None)
        for thr in threads:
            thr.join()
        threads.clear()
        self._is_setup = False

    def starmap(self, function, iterable):
        if not self._is_setup:
            self.setup()
        events = deque()
        for args in iterable:
            e = event.Event()
            self.request_queue.put((e, function, args, {}))
            events.append(e)
        while events:
            yield events.popleft().wait()

    def imap(self, function, *iterables):
        return self.starmap(function, itertools.izip(*iterables))


def setup():
    # deprecated
    global _threadpool
    if _threadpool is None:
        _threadpool = ThreadPool()
    _threadpool.setup()


def execute(func, *args, **kwargs):
    """
    Execute *meth* in a Python thread, blocking the current coroutine/
    greenthread until the method completes.

    The primary use case for this is to wrap an object or module that is not
    amenable to monkeypatching or any of the other tricks that Eventlet uses
    to achieve cooperative yielding.  With tpool, you can force such objects to
    cooperate with green threads by sticking them in native threads, at the cost
    of some overhead.
    """
    global _threadpool
    if _threadpool is None:
        _threadpool = ThreadPool()
    return _threadpool.execute(func, *args, **kwargs)


def killall():
    global _threadpool
    if not _threadpool:
        return
    _threadpool.killall()
    _threadpool = None


def proxy_call(autowrap, f, *args, **kwargs):
    """
    Call a function *f* and returns the value.  If the type of the return value
    is in the *autowrap* collection, then it is wrapped in a :class:`Proxy`
    object before return.

    Normally *f* will be called in the threadpool with :func:`execute`; if the
    keyword argument "nonblocking" is set to ``True``, it will simply be
    executed directly.  This is useful if you have an object which has methods
    that don't need to be called in a separate thread, but which return objects
    that should be Proxy wrapped.
    """
    if kwargs.pop('nonblocking', False):
        rv = f(*args, **kwargs)
    else:
        rv = execute(f, *args, **kwargs)
    if isinstance(rv, autowrap):
        return Proxy(rv, autowrap)
    else:
        return rv


class Proxy(object):
    """
    a simple proxy-wrapper of any object that comes with a
    methods-only interface, in order to forward every method
    invocation onto a thread in the native-thread pool.  A key
    restriction is that the object's methods should not switch
    greenlets or use Eventlet primitives, since they are in a
    different thread from the main hub, and therefore might behave
    unexpectedly.  This is for running native-threaded code
    only.

    It's common to want to have some of the attributes or return
    values also wrapped in Proxy objects (for example, database
    connection objects produce cursor objects which also should be
    wrapped in Proxy objects to remain nonblocking).  *autowrap*, if
    supplied, is a collection of types; if an attribute or return
    value matches one of those types (via isinstance), it will be
    wrapped in a Proxy.  *autowrap_names* is a collection
    of strings, which represent the names of attributes that should be
    wrapped in Proxy objects when accessed.
    """
    def __init__(self, obj, autowrap=(), autowrap_names=()):
        self._obj = obj
        self._autowrap = autowrap
        self._autowrap_names = autowrap_names

    def __getattr__(self, attr_name):
        f = getattr(self._obj, attr_name)
        if not hasattr(f, '__call__'):
            if (isinstance(f, self._autowrap) or
                    attr_name in self._autowrap_names):
                return Proxy(f, self._autowrap)
            return f

        def doit(*args, **kwargs):
            result = proxy_call(self._autowrap, f, *args, **kwargs)
            if (attr_name in self._autowrap_names
                    and not isinstance(result, Proxy)):
                return Proxy(result)
            return result
        return doit

    # the following are a buncha methods that the python interpeter
    # doesn't use getattr to retrieve and therefore have to be defined
    # explicitly
    def __getitem__(self, key):
        return proxy_call(self._autowrap, self._obj.__getitem__, key)
    def __setitem__(self, key, value):
        return proxy_call(self._autowrap, self._obj.__setitem__, key, value)
    def __deepcopy__(self, memo=None):
        return proxy_call(self._autowrap, self._obj.__deepcopy__, memo)
    def __copy__(self, memo=None):
        return proxy_call(self._autowrap, self._obj.__copy__, memo)
    def __call__(self, *a, **kw):
        if '__call__' in self._autowrap_names:
            return Proxy(proxy_call(self._autowrap, self._obj, *a, **kw))
        else:
            return proxy_call(self._autowrap, self._obj, *a, **kw)
    # these don't go through a proxy call, because they're likely to
    # be called often, and are unlikely to be implemented on the
    # wrapped object in such a way that they would block
    def __eq__(self, rhs):
        return self._obj == rhs
    def __hash__(self):
        return self._obj.__hash__()
    def __repr__(self):
        return self._obj.__repr__()
    def __str__(self):
        return self._obj.__str__()
    def __len__(self):
        return len(self._obj)
    def __nonzero__(self):
        return bool(self._obj)
    def __iter__(self):
        it = iter(self._obj)
        if it == self._obj:
            return self
        else:
            return Proxy(it)
    def next(self):
        return proxy_call(self._autowrap, self._obj.next)
