__all__ = ["HAVE_SSL", "ssl", "SSLError", "SSLWantReadError", "SSLWantWriteError"]

try:
    import ssl
    from ssl import SSLError
    from ssl import SSLWantReadError
    from ssl import SSLWantWriteError
    HAVE_SSL = True
except ImportError:
    # dummy class of SSLError for environment without ssl support
    class SSLError(Exception):
        pass

    class SSLWantReadError(Exception):
        pass

    class SSLWantWriteError(Exception):
        pass

    ssl = None
    HAVE_SSL = False
