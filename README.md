# corncobs

**corncobs** is a high-performance Python wrapper around the Rust crate **`corncobs`**, providing fast and allocation-efficient implementations of **Consistent Overhead Byte Stuffing (COBS)** encoding and decoding.

COBS ensures that arbitrary binary data can be framed without ambiguity by eliminating all zero bytes—making it ideal for serial protocols, embedded systems, and any application where reliable packet boundaries matter.

By leveraging Rust’s speed and safety guarantees, `corncobs` delivers significantly faster performance than pure-Python alternatives while maintaining a clean, Pythonic API.

## Features

- 🚀 **Blazing-fast COBS encoding/decoding** powered by Rust
- 🛡️ **Memory-safe** and efficient: minimal allocations, predictable overhead
- 🐍 **Simple, no-frills API** for basic COBS encoding and decoding, with an option for incremental decoding for streaming data
- 🔧 **Drop-in replacement** for the `cobs.cobs` module of `cobs` itself. All unit tests of `cobs` also pass with `corncobs`.
- 🧪 Fully tested and validated

## Installation

```bash
pip install corncobs
```

Wheels are provided for major platforms. Building from source requires a Rust toolchain.

## Usage

```python
from corncobs import encode, decode

data = b"\x00\x11\x22\x00\x33"
encoded = encode(data)
decoded = decode(encoded)

assert decoded == data
```

For cases when the encoded data is guaranteed to be valid COBS-encoded data (or when you have other mechanisms suchs as checksums to detect data corruption), you can disable strict mode in the decoder for a slight performance boost:

```python
decoded = decode(encoded, strict=False)
```

If you have an input stream that produces chunks of bytes to be decoded, you can build an incremental decoder object that keeps track of partially decoded messages. You can feed single bytes into the decoder with its `advance()` method, or entire chunks with its `advance_many()` method. `advance()` returns the newly parsed message in response to a zero byte, or `None` if more bytes are needed:

```python
from corncobs import Decoder

decoder = Decoder()
encoded = b"\x051234"
for ch in encoded:
    assert decoder.advance(ch) is None
assert decoder.advance(0) == b"1234"
```

Note that the decoder does not return the message until it receives the terminating null byte as it cannot know whether new bytes would arrive to extend the current message or not.

`advance_many()` accepts entire chunks at once and returns a list of messages parsed from the chunk. You can also retrieve the collected-but-not-yet-returned bytes from the decoder with its `pending` property, or the _number_ of pending bytes with its `num_pending` property (which is more efficient because you do not need to copy bytes from the Rust side to the Python side):

```python
decoder = Decoder()
encoded = b"\x051234\x00\x07abcdef\x00"
assert decoder.advance_many(encoded[:9]) == [b"1234"]
assert decoder.pending == b"ab"
assert decoder.num_pending == 2
assert decoder.advance_many(encoded[9:]) == [b"abcdef"]
assert not decoder.pending
```

`advance_many()` is equivalent to calling the decoder as if it was a function, so you can write code like this (even with async iterators):

```python
for chunk in stream:
    for message in decoder(chunk):
        print(message.hex(" "))
```

Decoders are strict by default, but you can also disable strict mode for a slight performance boost. In non-strict mode, decoders will assume that they receive valid COBS-encoded input and may freely copy bytes from the input to the output until the next overhead byte without checking that the copied chunk contains no zeros. In this case, you should also set an upper limit on the number of pending bytes with the `max_length` property to drive the parser into an error state if it seems like the current parsed message would be too long (which can happen for erroneous inputs):

```python
decoder = Decoder(strict=False)
assert decoder(
    b"this is an invalid\x00message in COBS because it has an extra "
    b"null byte in the middle"
) == []

decoder = Decoder(max_length=10, strict=False)
assert decoder(
    b"this is an invalid\x00message in COBS because it has an extra "
    b"null byte in the middle. But look, there is a valid message "
    b"at the end:\x00\x051234\x00"
) == [b"1234"]
```

## Project Status

`corncobs` is stable and production-ready.

## License

`corncobs` is licensed under the **Mozilla Public License, version 2.0**, matching the upstream Rust project.
