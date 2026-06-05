"""DER-encoded ECDSA signature parsing and serialization."""

from functools import lru_cache


@lru_cache(maxsize=2048)
def encode_der(r: int, s: int, s_high_ok: bool = False) -> bytes:
    """Encode ``(r, s)`` as a DER-encoded ECDSA signature.

    When *s_high_ok* is ``False`` (the default), *s* is negated if it
    exceeds ``CURVE_ORDER / 2`` to produce a low-*s* signature.

    Args:
        r: R component of the signature.
        s: S component of the signature.
        s_high_ok: If ``True``, allow *s* to exceed half the curve order.

    Returns:
        DER-encoded signature bytes.
    """
    from bitcoin.curve.params import CURVE_ORDER

    half_order = CURVE_ORDER // 2
    if not s_high_ok and s > half_order:
        s = CURVE_ORDER - s

    def __encode_int(value: int) -> bytes:
        """Encode an integer as a DER INTEGER tag.

        Args:
            value: Integer to encode.

        Returns:
            DER-encoded INTEGER tag (``0x02 || length || value``),
            with a leading ``0x00`` byte if the high bit is set.
        """
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
        return bytes([0x02, len(raw)]) + raw

    r_enc = __encode_int(r)
    s_enc = __encode_int(s)
    content = r_enc + s_enc
    return bytes([0x30, len(content)]) + content


@lru_cache(maxsize=2048)
def decode_der(sig: bytes) -> tuple[int, int]:
    """Decode a DER-encoded ECDSA signature.

    Args:
        sig: DER-encoded signature bytes.

    Returns:
        Tuple of ``(r, s)`` signature components.

    Raises:
        ValueError: If the encoding is malformed or contains trailing
            data.
    """
    if len(sig) < 6 or sig[0] != 0x30:
        raise ValueError("Not a valid DER signature.")

    offset = 2
    if sig[1] != len(sig) - 2:
        raise ValueError("Invalid DER sequence length.")

    r, offset = decode_int(sig, offset)
    s, offset = decode_int(sig, offset)

    if offset != len(sig):
        raise ValueError("Trailing data in DER signature.")

    return r, s


def decode_int(data: bytes, offset: int) -> tuple[int, int]:
    """Decode a DER INTEGER tag at a given offset.

    Args:
        data: DER-encoded byte string.
        offset: Start position of the INTEGER tag.

    Returns:
        Tuple of ``(value, new_offset)`` where *new_offset* points
        past the decoded integer.

    Raises:
        ValueError: If the tag is missing, malformed, or truncated.
    """
    if offset + 2 > len(data) or data[offset] != 0x02:
        raise ValueError("Invalid DER integer tag.")
    length = data[offset + 1]
    start = offset + 2
    end = start + length
    if end > len(data):
        raise ValueError("Truncated DER integer.")
    raw = data[start:end]
    value = int.from_bytes(raw, "big")
    return value, end
