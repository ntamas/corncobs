from itertools import islice
import cobs.cobs as cobs
import corncobs

from random import randbytes, randint


test_data = randbytes(10_000_000)
encoded_test_data = corncobs.encode(test_data)


incremental_test_data = [randbytes(randint(1, 1000)) for _ in range(1000)]
encoded_incremental_test_data = b"\x00".join(
    corncobs.encode(chunk) for chunk in incremental_test_data
)
chunked_incremental_test_data: list[bytes] = []

it = iter(encoded_incremental_test_data)
while True:
    chunk_size = randint(1, 512)
    next_chunk = bytes(islice(it, chunk_size))
    if not next_chunk:
        break

    chunked_incremental_test_data.append(next_chunk)


decoder = corncobs.Decoder(strict=False)
strict_decoder = corncobs.Decoder(strict=True)


def encode_using_cobs():
    cobs.encode(test_data)


def encode_using_corncobs():
    corncobs.encode(test_data)


def decode_using_cobs():
    cobs.decode(encoded_test_data)


def decode_using_corncobs():
    corncobs.decode(encoded_test_data)


def decode_using_corncobs_non_strict():
    corncobs.decode(encoded_test_data, strict=False)


def decode_using_corncobs_incremental_base():
    for chunk in encoded_incremental_test_data.split(b"\x00"):
        corncobs.decode(chunk, strict=False)


def decode_using_corncobs_incremental():
    decoder.reset()
    for chunk in chunked_incremental_test_data:
        decoder(chunk)
    decoder.advance(0)


def decode_using_corncobs_incremental_strict_base():
    for chunk in encoded_incremental_test_data.split(b"\x00"):
        corncobs.decode(chunk, strict=True)


def decode_using_corncobs_incremental_strict():
    strict_decoder.reset()
    for chunk in chunked_incremental_test_data:
        strict_decoder(chunk)
    strict_decoder.advance(0)


__benchmarks__ = [
    (encode_using_cobs, encode_using_corncobs, "Encode 10,000,000 bytes"),
    (decode_using_cobs, decode_using_corncobs, "Decode 10,000,000 bytes"),
    (
        decode_using_cobs,
        decode_using_corncobs_non_strict,
        "Decode 10,000,000 bytes, non-strict mode",
    ),
    (
        decode_using_corncobs_incremental_base,
        decode_using_corncobs_incremental,
        "Incremental decoding overhead",
    ),
    (
        decode_using_corncobs_incremental_strict_base,
        decode_using_corncobs_incremental_strict,
        "Strict incremental decoding overhead",
    ),
]
