import cobs.cobs as cobs
import corncobs

from random import randbytes


test_data = randbytes(10_000_000)
encoded_test_data = corncobs.encode(test_data)


def encode_using_cobs():
    cobs.encode(test_data)


def encode_using_corncobs():
    corncobs.encode(test_data)


def decode_using_cobs():
    cobs.decode(encoded_test_data)


def decode_using_corncobs():
    corncobs.decode(encoded_test_data)


__benchmarks__ = [
    (encode_using_cobs, encode_using_corncobs, "Encode 10,000,000 bytes"),
    (decode_using_cobs, decode_using_corncobs, "Decode 10,000,000 bytes"),
]
