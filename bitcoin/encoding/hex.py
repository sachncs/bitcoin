"""Hexadecimal encoding/decoding helpers."""


def encode_hex(data: bytes) -> str:
    """Encode bytes as a hexadecimal string.

    Args:
        data: The bytes to encode.

    Returns:
        The hex-encoded string.

    Raises:
        AttributeError: If *data* is not bytes (delegates to ``data.hex()``).
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
