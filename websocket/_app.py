import selectors
import sys
import threading
import time
import traceback
from ._abnf import ABNF
from ._core import WebSocket, getdefaulttimeout
from ._exceptions import *
from . import _logging


__all__ = ["WebSocketApp"]


class Dispatcher:
    def __init__(self, app, ping_timeout):
        self.app = app
        self.ping_timeout = ping_timeout

    def read(self, sock, read_callback, check_callback):
        while self.app.keep_running:
            sel = selectors.DefaultSelector()
            sel.register(self.app.sock.sock, selectors.EVENT_READ)

            r = sel.select(self.ping_timeout)
            if r:
                if not read_callback():
                    break
            check_callback()
            sel.close()


class SSLDispatcher:
    def __init__(self, app, ping_timeout):
        self.app = app
        self.ping_timeout = ping_timeout

    def read(self, sock, read_callback, check_callback):
        while self.app.keep_running:
            r = self.select()
            if r:
                if not read_callback():
                    break
            check_callback()

    def select(self):
        sock = self.app.sock.sock
        if sock.pending():
            return [sock,]

        sel = selectors.DefaultSelector()
        sel.register(sock, selectors.EVENT_READ)

        r = sel.select(self.ping_timeout)
        sel.close()

        if len(r) > 0:
            return r[0][0]


class WrappedDispatcher:
    def __init__(self, app, ping_timeout, dispatcher):
        self.app = app
        self.ping_timeout = ping_timeout
        self.dispatcher = dispatcher

    def read(self, sock, read_callback, check_callback):
        self.dispatcher.read(sock, read_callback)
        self.ping_timeout and self.dispatcher.timeout(self.ping_timeout, check_callback)


class WebSocketApp:
    def __init__(self, url, header=None,
                 on_open=None, on_message=None, on_error=None,
                 on_close=None, on_ping=None, on_pong=None,
                 on_cont_message=None,
                 keep_running=True, get_mask_key=None, cookie=None,
                 subprotocols=None,
                 on_data=None):
        self.url = url
        self.header = header if header is not None else []
        self.cookie = cookie

        self.on_open = on_open
        self.on_message = on_message
        self.on_data = on_data
        self.on_error = on_error
        self.on_close = on_close
        self.on_ping = on_ping
        self.on_pong = on_pong
        self.on_cont_message = on_cont_message
        self.keep_running = False
        self.get_mask_key = get_mask_key
        self.sock = None
        self.last_ping_tm = 0
        self.last_pong_tm = 0
        self.subprotocols = subprotocols

    def send(self, data, opcode=ABNF.OPCODE_TEXT):
        if not self.sock or self.sock.send(data, opcode) == 0:
            raise WebSocketConnectionClosedException("Connection is already closed.")

    def close(self, **kwargs):
        self.keep_running = False
        if self.sock:
            self.sock.close(**kwargs)
            self.sock = None

    def _send_ping(self, interval, event, payload):
        while not event.wait(interval):
            self.last_ping_tm = time.time()
            if self.sock:
                try:
                    self.sock.ping(payload)
                except Exception as ex:
                    _logging.warning("send_ping routine terminated: {}".format(ex))
                    break

    def run_forever(self, sockopt=None, sslopt=None,
                    ping_interval=0, ping_timeout=None,
                    ping_payload="",
                    http_proxy_host=None, http_proxy_port=None,
                    http_no_proxy=None, http_proxy_auth=None,
                    skip_utf8_validation=False,
                    host=None, origin=None, dispatcher=None,
                    suppress_origin=False, proxy_type=None):
        if ping_timeout is not None and ping_timeout <= 0:
            raise WebSocketException("Ensure ping_timeout > 0")
        if ping_interval is not None and ping_interval < 0:
            raise WebSocketException("Ensure ping_interval >= 0")
        if ping_timeout and ping_interval and ping_interval <= ping_timeout:
            raise WebSocketException("Ensure ping_interval > ping_timeout")
        if not sockopt:
            sockopt = []
        if not sslopt:
            sslopt = {}
        if self.sock:
            raise WebSocketException("socket is already opened")
        thread = None
        self.keep_running = True
        self.last_ping_tm = 0
        self.last_pong_tm = 0

        def teardown(close_frame=None):
            if thread and thread.is_alive():
                event.set()
                thread.join()
            self.keep_running = False
            if self.sock:
                self.sock.close()
            close_status_code, close_reason = self._get_close_args(
                close_frame if close_frame else None)
            self.sock = None
            self._callback(self.on_close, close_status_code, close_reason)

        try:
            self.sock = WebSocket(
                self.get_mask_key, sockopt=sockopt, sslopt=sslopt,
                fire_cont_frame=self.on_cont_message is not None,
                skip_utf8_validation=skip_utf8_validation,
                enable_multithread=True)
            self.sock.settimeout(getdefaulttimeout())
            self.sock.connect(
                self.url, header=self.header, cookie=self.cookie,
                http_proxy_host=http_proxy_host,
                http_proxy_port=http_proxy_port, http_no_proxy=http_no_proxy,
                http_proxy_auth=http_proxy_auth, subprotocols=self.subprotocols,
                host=host, origin=origin, suppress_origin=suppress_origin,
                proxy_type=proxy_type)
            dispatcher = self.create_dispatcher(ping_timeout, dispatcher)

            self._callback(self.on_open)

            if ping_interval:
                event = threading.Event()
                thread = threading.Thread(
                    target=self._send_ping, args=(ping_interval, event, ping_payload))
                thread.daemon = True
                thread.start()

            def read():
                if not self.keep_running:
                    return teardown()

                op_code, frame = self.sock.recv_data_frame(True)
                if op_code == ABNF.OPCODE_CLOSE:
                    return teardown(frame)
                elif op_code == ABNF.OPCODE_PING:
                    self._callback(self.on_ping, frame.data)
                elif op_code == ABNF.OPCODE_PONG:
                    self.last_pong_tm = time.time()
                    self._callback(self.on_pong, frame.data)
                elif op_code == ABNF.OPCODE_CONT and self.on_cont_message:
                    self._callback(self.on_data, frame.data,
                                   frame.opcode, frame.fin)
                    self._callback(self.on_cont_message,
                                   frame.data, frame.fin)
                else:
                    data = frame.data
                    if op_code == ABNF.OPCODE_TEXT:
                        data = data.decode("utf-8")
                    self._callback(self.on_data, data, frame.opcode, True)
                    self._callback(self.on_message, data)

                return True

            def check():
                if (ping_timeout):
                    has_timeout_expired = time.time() - self.last_ping_tm > ping_timeout
                    has_pong_not_arrived_after_last_ping = self.last_pong_tm - self.last_ping_tm < 0
                    has_pong_arrived_too_late = self.last_pong_tm - self.last_ping_tm > ping_timeout

                    if (self.last_ping_tm and
                            has_timeout_expired and
                            (has_pong_not_arrived_after_last_ping or has_pong_arrived_too_late)):
                        raise WebSocketTimeoutException("ping/pong timed out")
                return True

            dispatcher.read(self.sock.sock, read, check)
            return False
        except (Exception, KeyboardInterrupt, SystemExit) as e:
            self._callback(self.on_error, e)
            if isinstance(e, SystemExit):
                # propagate SystemExit further
                raise
            teardown()
            return not isinstance(e, KeyboardInterrupt)

    def create_dispatcher(self, ping_timeout, dispatcher=None):
        if dispatcher:  
            return WrappedDispatcher(self, ping_timeout, dispatcher)
        timeout = ping_timeout or 10
        if self.sock.is_ssl():
            return SSLDispatcher(self, timeout)

        return Dispatcher(self, timeout)

    def _get_close_args(self, close_frame):
        if not self.on_close or not close_frame:
            return [None, None]
        if close_frame.data and len(close_frame.data) >= 2:
            close_status_code = 256 * close_frame.data[0] + close_frame.data[1]
            reason = close_frame.data[2:].decode('utf-8')
            return [close_status_code, reason]
        else:
            return [None, None]

    def _callback(self, callback, *args):
        if callback:
            try:
                callback(self, *args)

            except Exception as e:
                _logging.error("error from callback {}: {}".format(callback, e))
                if self.on_error:
                    self.on_error(self, e)