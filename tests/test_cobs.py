"""Unit tests for Consistent Overhead Byte Stuffing (COBS).

These tests are adapted from the `cobs` Python package. See the original
repository at: https://github.com/cmcqueen/cobs-python/

Original license: https://github.com/cmcqueen/cobs-python/blob/main/LICENSE.txt
"""

import random
from array import array
from itertools import islice
from typing import Iterator

import corncobs as cobs  # pyright: ignore[reportMissingTypeStubs]
from pytest import raises


def non_zero_generator() -> Iterator[int]:
    while True:
        for i in range(1, 50):
            yield from range(1, 256, i)


def non_zero_bytes(length: int) -> bytes:
    return bytes(islice(non_zero_generator(), length))


class TestPredefinedEncodings:
    predefined_encodings = [
        [b"", b"\x01"],
        [b"1", b"\x021"],
        [b"12345", b"\x0612345"],
        [b"12345\x006789", b"\x0612345\x056789"],
        [b"\x0012345\x006789", b"\x01\x0612345\x056789"],
        [b"12345\x006789\x00", b"\x0612345\x056789\x01"],
        [b"\x00", b"\x01\x01"],
        [b"\x00\x00", b"\x01\x01\x01"],
        [b"\x00\x00\x00", b"\x01\x01\x01\x01"],
        [bytes(bytearray(range(1, 254))), bytes(b"\xfe" + bytearray(range(1, 254)))],
        [bytes(bytearray(range(1, 255))), bytes(b"\xff" + bytearray(range(1, 255)))],
        [
            bytes(bytearray(range(1, 256))),
            bytes(b"\xff" + bytearray(range(1, 255)) + b"\x02\xff"),
        ],
        [
            bytes(bytearray(range(0, 256))),
            bytes(b"\x01\xff" + bytearray(range(1, 255)) + b"\x02\xff"),
        ],
    ]

    def test_predefined_encodings(self):
        for test_string, expected_encoded_string in self.predefined_encodings:
            encoded = cobs.encode(test_string)
            assert encoded == expected_encoded_string

    def test_decode_predefined_encodings(self):
        for test_string, expected_encoded_string in self.predefined_encodings:
            decoded = cobs.decode(expected_encoded_string)
            assert test_string == decoded

    def test_decode_predefined_encodings_incremental(self):
        decoder = cobs.Decoder(strict=True)

        for test_string, encoded in self.predefined_encodings:
            for ch in encoded:
                assert decoder.advance(ch) is None
            assert test_string == decoder.advance(0)

            assert decoder.advance_many(encoded) == []
            assert decoder.advance(0) == test_string

            assert decoder.advance_many(encoded + b"\x00") == [test_string]


class TestPredefinedDecodeError:
    decode_error_test_strings = [
        (b"\x00", 0),
        (b"\x05123", 4),
        (b"\x051234\x00", 6),
        (b"\x0512\x004", 3),
    ]

    def test_predefined_decode_error(self):
        for test_encoded, _ in self.decode_error_test_strings:
            with raises(cobs.DecodeError):
                cobs.decode(test_encoded)

    def test_predefined_decode_error_incremental(self):
        decoder = cobs.Decoder(strict=True)

        for encoded, failure_index in self.decode_error_test_strings:
            for index, ch in enumerate(encoded):
                if index == failure_index:
                    with raises(cobs.DecodeError):
                        decoder.advance(ch)
                    break
                else:
                    decoder.advance(ch)
            else:
                with raises(cobs.DecodeError):
                    decoder.advance(0)


class TestZeros:
    def test_zeros(self):
        decoder = cobs.Decoder(strict=True)

        for length in range(520):
            test_string = b"\x00" * length
            encoded = cobs.encode(test_string)
            expected_encoded = b"\x01" * (length + 1)
            assert (
                encoded == expected_encoded
            ), f"encoding zeros failed for length {length}"

            decoded = cobs.decode(encoded)
            assert decoded == test_string, f"decoding zeros failed for length {length}"

            for ch in encoded:
                assert decoder.advance(ch) is None
            assert decoder.advance(0) == test_string

            assert decoder.advance_many(encoded) == []
            assert decoder.advance(0) == test_string

            assert decoder.advance_many(encoded + b"\x00") == [test_string]


class TestNonZeros:
    def simple_encode_non_zeros_only(self, in_bytes: bytes):
        out_list: list[bytes] = []
        for i in range(0, len(in_bytes), 254):
            data_block = in_bytes[i : i + 254]
            out_list.append(bytes([len(data_block) + 1]))
            out_list.append(data_block)
        return b"".join(out_list)

    def test_non_zeros(self):
        decoder = cobs.Decoder(strict=True)

        for length in range(1, 1000):
            test_string = non_zero_bytes(length)
            encoded = cobs.encode(test_string)
            expected_encoded = self.simple_encode_non_zeros_only(test_string)
            assert encoded == expected_encoded, (
                f"encoded != expected_encoded for length {length}\n"
                f"encoded: {encoded!r}\n"
                f"expected_encoded: {expected_encoded!r}"
            )

            for ch in encoded:
                assert decoder.advance(ch) is None
            assert decoder.advance(0) == test_string

            assert decoder.advance_many(encoded) == []
            assert decoder.advance(0) == test_string

            assert decoder.advance_many(encoded + b"\x00") == [test_string]

    def test_non_zeros_and_trailing_zero(self):
        decoder = cobs.Decoder(strict=True)

        for length in range(1, 1000):
            non_zeros_string = non_zero_bytes(length)
            test_string = non_zeros_string + b"\x00"
            encoded = cobs.encode(test_string)
            if (len(non_zeros_string) % 254) == 0:
                expected_encoded = (
                    self.simple_encode_non_zeros_only(non_zeros_string) + b"\x01\x01"
                )
            else:
                expected_encoded = (
                    self.simple_encode_non_zeros_only(non_zeros_string) + b"\x01"
                )
            assert encoded == expected_encoded, (
                f"encoded != expected_encoded for length {length}\n"
                f"encoded: {encoded!r}\n"
                f"expected_encoded: {expected_encoded!r}"
            )

            for ch in encoded:
                assert decoder.advance(ch) is None
            assert decoder.advance(0) == test_string

            assert decoder.advance_many(encoded) == []
            assert decoder.advance(0) == test_string

            assert decoder.advance_many(encoded + b"\x00") == [test_string]


class TestRandomData:
    NUM_TESTS = 5000
    MAX_LENGTH = 2000

    def generate_test_strings(self) -> Iterator[bytes]:
        for _ in range(self.NUM_TESTS):
            length = random.randint(0, self.MAX_LENGTH)
            yield bytes(random.randint(0, 255) for _ in range(length))

    def test_random(self):
        test_strings: list[bytes] = []
        encoded_strings: list[bytes] = []

        for test_string in self.generate_test_strings():
            encoded = cobs.encode(test_string)
            test_strings.append(test_string)
            encoded_strings.append(encoded)

            assert b"\x00" not in encoded, (
                f"encoding contains zero byte(s):\n"
                f"original: {test_string!r}\n"
                f"encoded: {encoded!r}"
            )
            assert len(encoded) <= len(test_string) + 1 + (len(test_string) // 254), (
                f"encoding too big:\n"
                f"original: {test_string!r}\n"
                f"encoded: {encoded!r}" % (repr(test_string), repr(encoded)),
            )

            decoded = cobs.decode(encoded)
            assert decoded == test_string, (
                f"encoding and decoding random data failed:\n"
                f"original: {test_string!r}\n"
                f"decoded: {decoded!r}"
            )

        # Decode all strings incrementally, feeding one byte at a time
        decoder = cobs.Decoder(strict=True)
        for test_string, encoded in zip(test_strings, encoded_strings):
            for ch in encoded:
                assert decoder.advance(ch) is None
            assert decoder.advance(0) == test_string

        # Decode all strings incrementally, feeding random-sized chunks
        decoder = cobs.Decoder(strict=True)
        full_input = b"\x00".join(encoded_strings) + b"\x00"
        results: list[bytes] = []
        it = iter(full_input)
        while True:
            chunk_size = random.randint(1, 32)
            next_chunk = bytes(islice(it, chunk_size))
            if not next_chunk:
                break

            results.extend(decoder.advance_many(next_chunk))

        assert results == test_strings


class TestInputTypes:
    predefined_encodings = [
        [b"", b"\x01"],
        [b"1", b"\x021"],
        [b"12345", b"\x0612345"],
        [b"12345\x006789", b"\x0612345\x056789"],
        [b"\x0012345\x006789", b"\x01\x0612345\x056789"],
        [b"12345\x006789\x00", b"\x0612345\x056789\x01"],
    ]

    def test_unicode_string(self):
        """Test that Unicode strings are not encoded or decoded.
        They should raise a TypeError."""
        for test_string, expected_encoded_string in self.predefined_encodings:
            unicode_test_string = test_string.decode("latin")
            with raises(TypeError):
                cobs.encode(unicode_test_string)  # pyright: ignore[reportArgumentType]
            unicode_encoded_string = expected_encoded_string.decode("latin")
            with raises(TypeError):
                cobs.decode(unicode_encoded_string)  # pyright: ignore[reportArgumentType]

    def test_bytearray(self):
        """Test that bytearray objects can be encoded or decoded."""
        for test_string, expected_encoded_string in self.predefined_encodings:
            bytearray_test_string = bytearray(test_string)
            encoded = cobs.encode(bytearray_test_string)
            assert encoded == expected_encoded_string

            bytearray_encoded_string = bytearray(expected_encoded_string)
            decoded = cobs.decode(bytearray_encoded_string)
            assert decoded == test_string

    def test_array_of_bytes(self):
        """Test that array of bytes objects (array('B', ...)) can be encoded or decoded."""
        for test_string, expected_encoded_string in self.predefined_encodings:
            array_test_string = array("B", test_string)
            encoded = cobs.encode(array_test_string)
            assert encoded == expected_encoded_string

            array_encoded_string = array("B", expected_encoded_string)
            decoded = cobs.decode(array_encoded_string)
            assert decoded == test_string


class TestDecoder:
    def test_decoder_is_strict_by_default(self):
        decoder = cobs.Decoder()
        assert decoder.strict is True

    def test_decoder_can_be_set_to_non_strict(self):
        decoder = cobs.Decoder(strict=False)
        assert decoder.strict is False

    def test_decoder_strict_property_can_be_changed(self):
        decoder = cobs.Decoder(strict=True)
        assert decoder.strict is True
        decoder.strict = False
        assert decoder.strict is False
        decoder.strict = True
        assert decoder.strict is True

    def test_decoder_examples_from_readme(self):
        decoder = cobs.Decoder()

        encoded = b"\x051234"
        for ch in encoded:
            assert decoder.advance(ch) is None
        assert decoder.advance(0) == b"1234"

        encoded = b"\x051234\x00\x07abcdef\x00"
        assert decoder.advance_many(encoded[:9]) == [b"1234"]
        assert decoder.pending == b"ab"
        assert decoder.num_pending == 2
        assert decoder.advance_many(encoded[9:]) == [b"abcdef"]
        assert not decoder.pending

    def test_decoder_with_max_length(self):
        decoder = cobs.Decoder(strict=False)
        assert (
            decoder(
                b"this is an invalid\x00message in COBS because it has an extra "
                b"null byte in the middle"
            )
            == []
        )

        decoder = cobs.Decoder(max_length=10, strict=True)
        with raises(cobs.DecodeError):
            decoder(
                b"this is an invalid\x00message in COBS because it has an extra "
                b"null byte in the middle"
            )

        decoder = cobs.Decoder(max_length=10, strict=False)
        assert decoder(
            b"this is an invalid\x00message in COBS because it has an extra "
            b"null byte in the middle. But look, there is a valid message "
            b"at the end:\x00\x051234\x00"
        ) == [b"1234"]


class TestUtil:
    def test_encoded_len_calc(self):
        assert cobs.encoding_overhead(5) == 1
        assert cobs.max_encoded_length(5) == 6

    def test_encoded_len_calc_empty_packet(self):
        assert cobs.encoding_overhead(0) == 1
        assert cobs.max_encoded_length(0) == 1

    def test_encoded_len_calc_still_one_byte_overhead(self):
        assert cobs.encoding_overhead(254) == 1
        assert cobs.max_encoded_length(254) == 255

    def test_encoded_len_calc_two_byte_overhead(self):
        assert cobs.encoding_overhead(255) == 2
        assert cobs.max_encoded_length(255) == 257
