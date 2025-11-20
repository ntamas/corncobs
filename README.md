# corncobs

**corncobs** is a high-performance Python wrapper around the Rust crate **`corncobs`**, providing fast and allocation-efficient implementations of **Consistent Overhead Byte Stuffing (COBS)** encoding and decoding.

COBS ensures that arbitrary binary data can be framed without ambiguity by eliminating all zero bytes—making it ideal for serial protocols, embedded systems, and any application where reliable packet boundaries matter.

By leveraging Rust’s speed and safety guarantees, `corncobs` delivers significantly faster performance than pure-Python alternatives while maintaining a clean, Pythonic API.

## Features

* 🚀 **Blazing-fast COBS encoding/decoding** powered by Rust
* 🛡️ **Memory-safe** and efficient: minimal allocations, predictable overhead
* 🐍 **Simple, no-frills API** for basic COBS encoding and decoding, with an option for incremental decoding for streaming data
* 🔧 **Drop-in replacement** for the `cobs.cobs` module of `cobs` itself. All unit tests of `cobs` also pass with `corncobs`.
* 🧪 Fully tested and validated

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

## Project Status

`corncobs` is stable and production-ready.

## License

`corncobs` is licensed under the **Mozilla Public License, version 2.0**, matching the upstream Rust project.
