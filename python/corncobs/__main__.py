"""Simple command-line interface for encoding and decoding streams of bytes with
COBS encoding.
"""

import sys
from argparse import ArgumentParser
from typing import Protocol

from corncobs import Decoder, encode


class Options(Protocol):
    decode: bool
    max_length: int | None
    strict: bool


def create_parser() -> ArgumentParser:
    parser = ArgumentParser(
        description="Encode or decode streams of bytes with COBS encoding"
    )
    parser.add_argument(
        "-d",
        "--decode",
        action="store_true",
        default=False,
        help="decode the input stream instead of encoding it",
    )
    parser.add_argument(
        "--max-length",
        metavar="N",
        type=int,
        default=None,
        help="maximum allowed length of decoded messages; used in lenient mode to "
        "detect encoding errors",
    )
    parser.add_argument(
        "--lenient",
        action="store_true",
        default=False,
        help="use lenient mode when decoding the input stream",
    )
    return parser


def main() -> int:
    parser = create_parser()
    args: Options = parser.parse_args()

    if args.decode:
        decoder = Decoder(max_length=args.max_length, strict=not args.lenient)
        while True:
            chunk = sys.stdin.buffer.read()
            if not chunk:
                break

            for message in decoder.advance_many(chunk):
                sys.stdout.buffer.write(message)

    else:
        sys.stdout.buffer.write(encode(sys.stdin.buffer.read()))

    return 0


if __name__ == "__main__":
    sys.exit(main())
