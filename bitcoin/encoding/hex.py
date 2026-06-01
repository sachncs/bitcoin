"""Hexadecimal encoding/decoding helpers."""


def encode_hex(data: bytes) -> str:
    """Return the lowercase hex-encoded representation of *data*.

    Args:
        data: Bytes to encode.

    Returns:
        Hex-encoded string.

    Raises:
        TypeError: If *data* is not ``bytes``.
    """
    return data.hex()


def decode_hex(hex_str: str) -> bytes:
    """Decode a hex string to bytes.

    Args:
        hex_str: Hex-encoded string.

    Returns:
        Decoded bytes.

    Raises:
        TypeError: If *hex_str* is not ``str``.
        ValueError: If the string has an odd length or contains
            non-hex characters.
    """
    return bytes.fromhex(hex_str)
