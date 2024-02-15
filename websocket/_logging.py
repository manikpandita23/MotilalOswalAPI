import logging

from websockets import WebSocketException 

_logger = logging.getLogger('websocket')
try:
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):
        def emit(self, record): pass

_logger.addHandler(NullHandler())
_traceEnabled = False

__all__ = ["enableTrace", "dump", "error", "warning", "debug", "trace","isEnabledForError", "isEnabledForDebug", "isEnabledForTrace"]

def trace(*args, **kwargs):
    if _traceEnabled:
        _logger.debug(*args, **kwargs)
        raise WebSocketException("Web Socket Trace")
import os
import sys
import re
import urllib.request as urllib2  
import base64
from datetime import datetime
from xmlrpc.server import SimpleXMLRPCServer  
from xmlrpc.client import DateTime  
from websocket._base import BaseConnection
from websocket._handshake import handshake
from websocket._httpstream import httpStream
from websocket._url import safeunquote, safequote

class Connection(BaseConnection):
    def __init__(self, host='localhost', port=8000,
                 resource='/', protocols=None, origin=None,
                 headers={}, mask=True, debug=False,
                 trace=False):
        super().__init__(host, port, resource, protocols, origin, headers, mask, debug)
        self.trace = trace

    def enableTrace(self, traceable, handler=None):
        global _traceEnabled
        _traceEnabled = traceable
        if traceable:
            if handler is None:
                handler = logging.StreamHandler()
            _logger.addHandler(handler)
            _logger.setLevel(logging.DEBUG)

    def dump(self, title, message):
        if _traceEnabled:
            _logger.debug("--- %s ---" % title)
            _logger.debug(message)
            _logger.debug("-----------------------")

    def error(self, msg):
        _logger.error(msg)

    def warning(self, msg):
        _logger.warning(msg)

    def debug(self, msg):
        _logger.debug(msg)

    def isEnabledForError(self):
        return _logger.isEnabledFor(logging.ERROR)

    def isEnabledForDebug(self):
        return _logger.isEnabledFor(logging.DEBUG)

    def isEnabledForTrace(self):
        return _traceEnabled
