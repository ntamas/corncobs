from ._cobs import decode, encode, DecodeError

__all__ = ("decode", "encode", "encoding_overhead", "max_encoded_length", "DecodeError")


def encoding_overhead(source_len: int) -> int:
    """Calculates the maximum overhead when encoding a message with the given
    length. The overhead is a maximum of [n/254] bytes (one in 254 bytes)
    rounded up.
    """
    return (source_len + 253) // 254 if source_len > 0 else 1


def max_encoded_length(source_len: int) -> int:
    """Calculates the maximum possible size of an encoded message given the
    length of the source message.
    """
    return source_len + encoding_overhead(source_len)
