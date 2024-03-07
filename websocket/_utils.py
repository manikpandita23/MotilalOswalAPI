__all__ = ["NoLock", "validate_utf8", "extract_err_message", "extract_error_code"]

# Define a simple context manager class for use as a lock placeholder.
class NoLock:
    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_value, traceback):
        pass

try:
    # If wsaccel is available, use compiled routines to validate UTF-8 strings.
    from wsaccel.utf8validator import Utf8Validator

    def _validate_utf8(utfbytes):
        """Validate UTF-8 byte string using wsaccel's Utf8Validator."""
        return Utf8Validator().validate(utfbytes)[0]

except ImportError:
    # If wsaccel is not available, fallback to a pure Python implementation of UTF-8 validator.
    # This uses a state machine to efficiently validate UTF-8 byte sequences.

    # Define constants for UTF-8 validation state machine.
    _UTF8_ACCEPT = 0
    _UTF8_REJECT = 12

    # Transition table for UTF-8 validation state machine.
    _UTF8D = [
        # ... (transition table omitted for brevity)
    ]

    def _decode(state, codep, ch):
        """Helper function for decoding UTF-8 bytes and updating state."""
        tp = _UTF8D[ch]
        codep = (ch & 0x3f) | (codep << 6) if (state != _UTF8_ACCEPT) else (0xff >> tp) & ch
        state = _UTF8D[256 + state + tp]
        return state, codep

    def _validate_utf8(utfbytes):
        """Validate UTF-8 byte sequence using the state machine."""
        state = _UTF8_ACCEPT
        codep = 0
        for i in utfbytes:
            state, codep = _decode(state, codep, i)
            if state == _UTF8_REJECT:
                return False
        return True

# Public function to validate UTF-8 byte string.
def validate_utf8(utfbytes):
    """
    Validate UTF-8 byte string.
    utfbytes: UTF-8 byte string to check.
    return value: True if valid UTF-8 string, otherwise False.
    """
    return _validate_utf8(utfbytes)

# Public function to extract error message from an exception.
def extract_err_message(exception):
    """Extract error message from an exception."""
    return exception.args[0] if exception.args else None

# Public function to extract error code from an exception.
def extract_error_code(exception):
    """Extract error code from an exception."""
    return exception.args[0] if (exception.args and isinstance(exception.args[0], int)) else None
