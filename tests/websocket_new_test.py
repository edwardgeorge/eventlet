import imp
import errno
import new
import os
import shutil
import struct
import sys
import tempfile

import eventlet
from eventlet import event
from eventlet.green import httplib
from eventlet.green import socket
from eventlet.green import subprocess
from eventlet import websocket

from tests import skip_unless
from tests.wsgi_test import _TestBase


def autobahntestsuite_available(_f):
    # don't actually import because it pulls in twisted
    try:
        imp.find_module('autobahntestsuite')
    except ImportError:
        return False
    return True


# demo app
def handle(ws):
    if ws.path == '/echo':
        while True:
            m = ws.wait()
            if m is None:
                break
            ws.send(m)
    elif ws.path == '/range':
        for i in xrange(10):
            ws.send("msg %d" % i)
            eventlet.sleep(0.01)
    elif ws.path == '/error':
        # some random socket error that we shouldn't normally get
        raise socket.error(errno.ENOTSOCK)
    else:
        ws.close()

wsapp = websocket.WebSocketWSGI(handle)


class AutobahnTestCase(_TestBase):
    TEST_TIMEOUT = None

    def set_site(self):
        self.site = wsapp

    def _create_spec(self, version, port, cases=None):
        cases = cases or ['*']
        return {
            "options": {"failByDrop": False, },
            "enable-ssl": False,
            "servers": [{"url": "ws://localhost:%d/echo" % (port, ),
                         "agent": "eventlet-websocket",
                         "options": {"version": version, }, }],
            "cases": cases,
            "exclude-cases": [],
            "exclude-agent-cases": {}, }

    def _perform_test(self, version, cases=None):
        spec = self._create_spec(version, self.port, cases=cases)
        new_mod = """
import sys
from autobahntestsuite.fuzzing import FuzzingClientFactory
from twisted.internet import reactor

class OurFactory(FuzzingClientFactory):
    def createReports(self):
        pass

    def logCase(self, results):
        caseid = results['id']
        if results['behavior'] not in ('OK', 'INFORMATIONAL'):
            reactor.stop()
            sys.stderr.write("Case %%s behavior failed\\n" %% (caseid, ))
        elif results['behaviorClose'] not in ('OK', 'INFORMATIONAL'):
            reactor.stop()
            sys.stderr.write("Case %%s close behavior failed\\n" %% (caseid, ))

spec = %(spec)r
OurFactory(spec)
reactor.run()
""" % {'spec': spec, }
        testtmpdir = tempfile.mkdtemp('_websocket_test')
        mod_path = os.path.join(testtmpdir, 'newmod.py')
        try:
            f = open(mod_path, 'w')
            f.write(new_mod)
            f.close()
            print 'starting...'
            p = subprocess.Popen(
                [sys.executable, mod_path],
                # using devnull because subprocess blocks on 2.7
                # https://github.com/eventlet/eventlet/pull/24
                stdout=open(os.devnull, 'wb'),
                stderr=subprocess.PIPE)
            stdout, stderr = p.communicate()
            print stdout, stderr
            assert not p.returncode, stderr
        finally:
            shutil.rmtree(testtmpdir)

    spec = _create_spec(None, 18, 0)
    script = ("from autobahntestsuite.fuzzing import FuzzingClientFactory;"
              "spec = %r; f = FuzzingClientFactory(spec);"
              "import sys; sys.stderr.write('\\n'.join(f.specCases));") % (spec, )
    p = subprocess.Popen([sys.executable, '-c', script],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    assert not p.returncode, stderr
    for version in (8, 13, 18):
        for case in stderr.splitlines():
            case = case.strip()
            name = 'test_hybi%d_%s' % (version, case.replace('.', '_'), )
            print name
            locals()[name] = skip_unless(autobahntestsuite_available)(
                new.function(
                    (lambda self: self._perform_test(version, [case])).func_code,
                    {'case': case, 'version': version, }, name))
    del p, case, version, stdout, stderr, script, spec, name



class TestWebSocket(_TestBase):
    TEST_TIMEOUT = 5

    def set_site(self):
        self.site = wsapp

    def test_incomplete_headers_13(self):
        headers = dict(kv.split(': ') for kv in [
                "Upgrade: websocket",
                # NOTE: intentionally no connection header
                "Host: localhost:%s" % self.port,
                "Origin: http://localhost:%s" % self.port,
                "Sec-WebSocket-Version: 13", ])
        http = httplib.HTTPConnection('localhost', self.port)
        http.request("GET", "/echo", headers=headers)
        resp = http.getresponse()

        self.assertEqual(resp.status, 400)
        self.assertEqual(resp.getheader('connection'), 'close')
        self.assertEqual(resp.read(), '')

        # Now, miss off key
        headers = dict(kv.split(': ') for kv in [
                "Upgrade: websocket",
                "Connection: Upgrade",
                "Host: localhost:%s" % self.port,
                "Origin: http://localhost:%s" % self.port,
                "Sec-WebSocket-Version: 13", ])
        http = httplib.HTTPConnection('localhost', self.port)
        http.request("GET", "/echo", headers=headers)
        resp = http.getresponse()

        self.assertEqual(resp.status, 400)
        self.assertEqual(resp.getheader('connection'), 'close')
        self.assertEqual(resp.read(), '')

    def test_correct_upgrade_request_13(self):
        connect = [
                "GET /echo HTTP/1.1",
                "Upgrade: websocket",
                "Connection: Upgrade",
                "Host: localhost:%s" % self.port,
                "Origin: http://localhost:%s" % self.port,
                "Sec-WebSocket-Version: 13",
                "Sec-WebSocket-Key: d9MXuOzlVQ0h+qRllvSCIg==", ]
        sock = eventlet.connect(
            ('localhost', self.port))

        sock.sendall('\r\n'.join(connect) + '\r\n\r\n')
        result = sock.recv(1024)
        ## The server responds the correct Websocket handshake
        self.assertEqual(result,
                         '\r\n'.join(['HTTP/1.1 101 Switching Protocols',
                                      'Upgrade: websocket',
                                      'Connection: Upgrade',
                                      'Sec-WebSocket-Accept: ywSyWXCPNsDxLrQdQrn5RFNRfBU=\r\n\r\n', ]))

    def test_send_recv_13(self):
        connect = [
                "GET /echo HTTP/1.1",
                "Upgrade: websocket",
                "Connection: Upgrade",
                "Host: localhost:%s" % self.port,
                "Origin: http://localhost:%s" % self.port,
                "Sec-WebSocket-Version: 13",
                "Sec-WebSocket-Key: d9MXuOzlVQ0h+qRllvSCIg==", ]
        sock = eventlet.connect(
            ('localhost', self.port))

        sock.sendall('\r\n'.join(connect) + '\r\n\r\n')
        first_resp = sock.recv(1024)
        ws = websocket.RFC6455WebSocket(sock, {}, client=True)
        ws.send('hello')
        assert ws.wait() == 'hello'
        ws.send('hello world!\x01')
        ws.send(u'hello world again!')
        assert ws.wait() == 'hello world!\x01'
        assert ws.wait() == u'hello world again!'
        ws.close()
        eventlet.sleep(0.01)

    def test_breaking_the_connection_13(self):
        error_detected = [False]
        done_with_request = event.Event()
        site = self.site
        def error_detector(environ, start_response):
            try:
                try:
                    return site(environ, start_response)
                except:
                    error_detected[0] = True
                    raise
            finally:
                done_with_request.send(True)
        self.site = error_detector
        self.spawn_server()
        connect = [
                "GET /echo HTTP/1.1",
                "Upgrade: websocket",
                "Connection: Upgrade",
                "Host: localhost:%s" % self.port,
                "Origin: http://localhost:%s" % self.port,
                "Sec-WebSocket-Version: 13",
                "Sec-WebSocket-Key: d9MXuOzlVQ0h+qRllvSCIg==", ]
        sock = eventlet.connect(
            ('localhost', self.port))
        sock.sendall('\r\n'.join(connect) + '\r\n\r\n')
        resp = sock.recv(1024)  # get the headers
        sock.close()  # close while the app is running
        done_with_request.wait()
        self.assert_(not error_detected[0])

    def test_client_closing_connection_13(self):
        error_detected = [False]
        done_with_request = event.Event()
        site = self.site
        def error_detector(environ, start_response):
            try:
                try:
                    return site(environ, start_response)
                except:
                    error_detected[0] = True
                    raise
            finally:
                done_with_request.send(True)
        self.site = error_detector
        self.spawn_server()
        connect = [
                "GET /echo HTTP/1.1",
                "Upgrade: websocket",
                "Connection: Upgrade",
                "Host: localhost:%s" % self.port,
                "Origin: http://localhost:%s" % self.port,
                "Sec-WebSocket-Version: 13",
                "Sec-WebSocket-Key: d9MXuOzlVQ0h+qRllvSCIg==", ]
        sock = eventlet.connect(
            ('localhost', self.port))
        sock.sendall('\r\n'.join(connect) + '\r\n\r\n')
        resp = sock.recv(1024)  # get the headers
        closeframe = struct.pack('!BBIH', 1 << 7 | 8, 1 << 7 | 2, 0, 1000)
        sock.sendall(closeframe)  # "Close the connection" packet.
        done_with_request.wait()
        self.assert_(not error_detected[0])

    def test_client_invalid_packet_13(self):
        error_detected = [False]
        done_with_request = event.Event()
        site = self.site
        def error_detector(environ, start_response):
            try:
                try:
                    return site(environ, start_response)
                except:
                    error_detected[0] = True
                    raise
            finally:
                done_with_request.send(True)
        self.site = error_detector
        self.spawn_server()
        connect = [
                "GET /echo HTTP/1.1",
                "Upgrade: websocket",
                "Connection: Upgrade",
                "Host: localhost:%s" % self.port,
                "Origin: http://localhost:%s" % self.port,
                "Sec-WebSocket-Version: 13",
                "Sec-WebSocket-Key: d9MXuOzlVQ0h+qRllvSCIg==", ]
        sock = eventlet.connect(
            ('localhost', self.port))
        sock.sendall('\r\n'.join(connect) + '\r\n\r\n')
        resp = sock.recv(1024)  # get the headers
        sock.sendall('\x07\xff') # Weird packet.
        done_with_request.wait()
        self.assert_(not error_detected[0])
