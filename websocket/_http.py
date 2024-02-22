import errno
import os
import socket
import ssl
from base64 import encodebytes as base64encode

from ._exceptions import *
from ._logging import *
from ._socket import *
from ._url import *

__all__ = ["proxy_info", "connect", "read_headers"]

try:
    from python_socks.sync import Proxy
    from python_socks._types import ProxyType
    HAVE_PYTHON_SOCKS = True
except ImportError:
    HAVE_PYTHON_SOCKS = False

    class ProxyError(Exception):
        pass

    class ProxyTimeoutError(Exception):
        pass

    class ProxyConnectionError(Exception):
        pass


DEFAULT_SOCKET_OPTION = [
    (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
    (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1),
]


class proxy_info:
    def __init__(self, **options):
        self.proxy_host = options.get("http_proxy_host", None)
        if self.proxy_host:
            self.proxy_port = options.get("http_proxy_port", 0)
            self.auth = options.get("http_proxy_auth", None)
            self.no_proxy = options.get("http_no_proxy", None)
            self.proxy_protocol = options.get("proxy_type", "http")
            self.proxy_timeout = options.get("timeout", None)
            if self.proxy_protocol not in ['http', 'socks4', 'socks4a', 'socks5', 'socks5h']:
                raise ProxyError("Only http, socks4, socks5 proxy protocols are supported")
        else:
            self.proxy_port = 0
            self.auth = None
            self.no_proxy = None
            self.proxy_protocol = "http"


def _start_proxied_socket(url, options, proxy):
    if not HAVE_PYTHON_SOCKS:
        raise WebSocketException("Python Socks is needed for SOCKS proxying but is not available")

    hostname, port, resource, is_secure = parse_url(url)

    if proxy.proxy_protocol == "socks5":
        rdns = False
        proxy_type = ProxyType.SOCKS5
    if proxy.proxy_protocol == "socks4":
        rdns = False
        proxy_type = ProxyType.SOCKS4
    if proxy.proxy_protocol == "socks5h":
        rdns = True
        proxy_type = ProxyType.SOCKS5
    if proxy.proxy_protocol == "socks4a":
        rdns = True
        proxy_type = ProxyType.SOCKS4

    ws_proxy = Proxy.create(
        proxy_type=proxy_type,
        host=proxy.proxy_host,
        port=int(proxy.proxy_port),
        username=proxy.auth[0] if proxy.auth else None,
        password=proxy.auth[1] if proxy.auth else None,
        rdns=rdns)

    sock = ws_proxy.connect(hostname, port, timeout=proxy.proxy_timeout)

    if is_secure and HAVE_SSL:
        sock = _ssl_socket(sock, options.sslopt, hostname)
    elif is_secure:
        raise WebSocketException("SSL not available.")

    return sock, (hostname, port, resource)


def connect(url, options, proxy, custom_socket=None):
    if proxy.proxy_host and not custom_socket and not (proxy.proxy_protocol == "http"):
        return _start_proxied_socket(url, options, proxy)

    hostname, port, resource, is_secure = parse_url(url)

    if custom_socket:
        return custom_socket, (hostname, port, resource)

    addrinfo_list, need_tunnel, auth = _get_addrinfo_list(
        hostname, port, is_secure, proxy)
    if not addrinfo_list:
        raise WebSocketException("Host not found: {}:{}".format(hostname, port))

    sock = None
    try:
        sock = _open_socket(addrinfo_list, options.sockopt, options.timeout)
        if need_tunnel:
            sock = _tunnel(sock, hostname, port, auth)

        if is_secure:
            if HAVE_SSL:
                sock = _ssl_socket(sock, options.sslopt, hostname)
            else:
                raise WebSocketException("SSL not available.")

        return sock, (hostname, port, resource)
    except Exception as e:
        if sock:
            sock.close()
        raise WebSocketException(str(e))


def _get_addrinfo_list(hostname, port, is_secure, proxy):
    phost, pport, pauth = get_proxy_info(
        hostname, is_secure, proxy.proxy_host, proxy.proxy_port, proxy.auth, proxy.no_proxy)
    try:
        if not phost:
            addrinfo_list = socket.getaddrinfo(
                hostname, port, 0, socket.SOCK_STREAM, socket.SOL_TCP)
            return addrinfo_list, False, None
        else:
            pport = pport and pport or 80
            addrinfo_list = socket.getaddrinfo(phost, pport, 0, socket.SOCK_STREAM, socket.SOL_TCP)
            return addrinfo_list, True, pauth
    except socket.gaierror as e:
        raise WebSocketAddressException(e)


def _open_socket(addrinfo_list, sockopt, timeout):
    err = None
    for addrinfo in addrinfo_list:
        family, socktype, proto = addrinfo[:3]
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        for opts in DEFAULT_SOCKET_OPTION:
            sock.setsockopt(*opts)
        for opts in sockopt:
            sock.setsockopt(*opts)

        address = addrinfo[4]
        err = None
        while not err:
            try:
                sock.connect(address)
            except socket.error as error:
                error.remote_ip = str(address[0])
                eConnRefused = (errno.ECONNREFUSED, errno.WSAECONNREFUSED, errno.ENETUNREACH)
                if error.errno in eConnRefused:
                    err = error
                    continue
                else:
                    if sock:
                        sock.close()
                    raise error
            else:
                break
        else:
            continue
        break
    else:
        if err:
            raise err

    return sock


def _wrap_sni_socket(sock, sslopt, hostname, check_hostname):
    context = sslopt.get('context', None)
    if not context:
        context = ssl.SSLContext(sslopt.get('ssl_version', ssl.PROTOCOL_TLS_CLIENT))

        if sslopt.get('cert_reqs', ssl.CERT_NONE) != ssl.CERT_NONE:
            cafile = sslopt.get('ca_certs', None)
            capath = sslopt.get('ca_cert_path', None)
            if cafile or capath:
                context.load_verify_locations(cafile=cafile, capath=capath)
            elif hasattr(context, 'load_default_certs'):
                context.load_default_certs(ssl.Purpose.SERVER_AUTH)
        if sslopt.get('certfile', None):
            context.load_cert_chain(
                sslopt['certfile'],
                sslopt.get('keyfile', None),
                sslopt.get('password', None),
            )

        if sslopt.get('cert_reqs', ssl.CERT_NONE) == ssl.CERT_NONE and not sslopt.get('check_hostname', False):
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        else:
            context.check_hostname = sslopt.get('check_hostname', True)
            context.verify_mode = sslopt.get('cert_reqs', ssl.CERT_REQUIRED)

        if 'ciphers' in sslopt:
            context.set_ciphers(sslopt['ciphers'])
        if 'cert_chain' in sslopt:
            certfile, keyfile, password = sslopt['cert_chain']
            context.load_cert_chain(certfile, keyfile, password)
        if 'ecdh_curve' in sslopt:
            context.set_ecdh_curve(sslopt['ecdh_curve'])

    return context.wrap_socket(
        sock,
        do_handshake_on_connect=sslopt.get('do_handshake_on_connect', True),
        suppress_ragged_eofs=sslopt.get('suppress_ragged_eofs', True),
        server_hostname=hostname,
    )


def _ssl_socket(sock, user_sslopt, hostname):
    sslopt = dict(cert_reqs=ssl.CERT_REQUIRED)
    sslopt.update(user_sslopt)

    certPath = os.environ.get('WEBSOCKET_CLIENT_CA_BUNDLE')
    if certPath and os.path.isfile(certPath) \
            and user_sslopt.get('ca_certs', None) is None:
        sslopt['ca_certs'] = certPath
    elif certPath and os.path.isdir(certPath) \
            and user_sslopt.get('ca_cert_path', None) is None:
        sslopt['ca_cert_path'] = certPath

    if sslopt.get('server_hostname', None):
        hostname = sslopt['server_hostname']

    check_hostname = sslopt.get('check_hostname', True)
    sock = _wrap_sni_socket(sock, sslopt, hostname, check_hostname)

    return sock


def _tunnel(sock, host, port, auth):
    debug("Connecting proxy...")
    connect_header = "CONNECT %s:%d HTTP/1.1\r\n" % (host, port)
    connect_header += "Host: %s:%d\r\n" % (host, port)

    if auth and auth[0]:
        auth_str = auth[0]
        if auth[1]:
            auth_str += ":" + auth[1]
        encoded_str = base64encode(auth_str.encode()).strip().decode().replace('\n', '')
        connect_header += "Proxy-Authorization: Basic %s\r\n" % encoded_str
    connect_header += "\r\n"
    dump("request header", connect_header)

    send(sock, connect_header)

    try:
        status, resp_headers, status_message = read_headers(sock)
    except Exception as e:
        raise WebSocketProxyException(str(e))

    if status != 200:
        raise WebSocketProxyException(
            "Failed CONNECT via proxy status: {}".format(status))

    return sock


def read_headers(sock):
    status = None
    status_message = None
    headers = {}
    trace("--- response header ---")

    while True:
        line = recv_line(sock)
        line = line.decode('utf-8').strip()
        if not line:
            break
        trace(line)
        if not status:
            status_info = line.split(" ", 2)
            status = int(status_info[1])
            if len(status_info) > 2:
                status_message = status_info[2]
        else:
            kv = line.split(":", 1)
            if len(kv) == 2:
                key, value = kv
                if key.lower() == "set-cookie" and headers.get("set-cookie"):
                    headers["set-cookie"] = headers.get("set-cookie") + "; " + value.strip()
                else:
                    headers[key.lower()] = value.strip()
            else:
                raise WebSocketException("Invalid header")

    trace("-----------------------")

    return status, headers, status_message
