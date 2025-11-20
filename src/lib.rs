use pyo3::{create_exception, prelude::*};

create_exception!(corncobs_py, DecodeError, pyo3::exceptions::PyRuntimeError);

struct CorncobsError(corncobs::CobsError);

impl From<corncobs::CobsError> for CorncobsError {
    fn from(err: corncobs::CobsError) -> CorncobsError {
        CorncobsError(err)
    }
}

impl From<CorncobsError> for PyErr {
    fn from(err: CorncobsError) -> PyErr {
        DecodeError::new_err(format!("{}", err.0))
    }
}

enum DecoderErrorCode {
    UnexpectedError,
    ZeroByteInInput,
    ExceededMaxLength,
}

impl Into<PyErr> for DecoderErrorCode {
    fn into(self) -> PyErr {
        match self {
            DecoderErrorCode::UnexpectedError => {
                DecodeError::new_err("unexpected error during decoding. This is probably a bug.")
            }
            DecoderErrorCode::ZeroByteInInput => DecodeError::new_err("input contains zero byte"),
            DecoderErrorCode::ExceededMaxLength => {
                DecodeError::new_err("decoded message exceeded maximum length")
            }
        }
    }
}

#[pymodule]
#[pyo3(name = "_cobs")]
mod corncobs_py {
    use std::{cmp::min, mem::take};

    use corncobs::ZERO;
    use pyo3::{
        prelude::*,
        types::{PyBytes, PyList},
    };

    use super::DecoderErrorCode;

    #[pymodule_export]
    use super::DecodeError;

    /// Encode a string using Consistent Overhead Byte Stuffing (COBS).
    ///
    /// The encoding guarantees no zero bytes in the output. The output
    /// string will be expanded slightly, by a predictable amount. The sentinel
    /// zero byte (used as a packet separator) is not included in the output.
    ///
    /// An empty string is encoded to '\\x01'.
    ///
    /// Args:
    ///     in_bytes: input byte string to encode
    ///
    /// Returns:
    ///    Encoded byte string.
    #[pyfunction]
    fn encode<'p>(py: Python<'p>, in_bytes: Vec<u8>) -> PyResult<Bound<'p, PyBytes>> {
        let mut out_bytes = vec![0u8; corncobs::max_encoded_len(in_bytes.len())];
        let encoded_size = py.detach(|| corncobs::encode_buf(&in_bytes, &mut out_bytes));
        Ok(PyBytes::new(py, &out_bytes[..encoded_size - 1]))
    }

    /// Decode a string using Consistent Overhead Byte Stuffing (COBS).
    ///
    /// Args:
    ///     in_bytes: input byte string to decode
    ///     strict: if True (default), an exception will be raised if the input
    ///             contains zero bytes. If False, it is assumed that the input
    ///             does not contain zero bytes and that we can freely copy
    ///             slices of the input buffer to the output buffer as needed.
    ///
    /// Returns:
    ///     Decoded byte string.
    ///
    /// Raises:
    ///     DecodeError: if the input is not a valid COBS encoded string. Certain
    ///         invalid inputs _may_ be accepted if `strict` is False.
    #[pyfunction]
    #[pyo3(signature = (in_bytes, *, strict = true))]
    fn decode<'p>(
        py: Python<'p>,
        mut in_bytes: Vec<u8>,
        strict: bool,
    ) -> PyResult<Bound<'p, PyBytes>> {
        // We need to check whether in_bytes contains a zero because corncobs
        // won't do that for performance reasons - but we want to stay compatible
        // with cobs which does check for that.
        if strict && in_bytes.contains(&ZERO) {
            return Err(DecoderErrorCode::ZeroByteInInput.into());
        }

        let result = py
            .detach(|| corncobs::decode_in_place(&mut in_bytes))
            .map_err(|e| super::CorncobsError::from(e))?;
        Ok(PyBytes::new(py, &in_bytes[..result]))
    }

    /// State of an incremental COBS decoder.
    ///
    /// There are four types of bytes in a COBS-encoded input:
    ///
    /// - unaltered data bytes: these bytes are copied directly to the output
    /// - altered data bytes: these bytes represent zero bytes in the original
    ///   input, and they contain the offset to the next altered byte or a
    ///   packet separator byte (zero)
    /// - overhead bytes: these bytes indicate the relative offset to the next
    ///   zero byte, but unlike altered data bytes, a zero byte does not need to
    ///   be inserted in the output when reaching the next overhead byte
    /// - packet separator bytes: these are zero bytes that indicate the end of
    ///   a COBS-encoded packet.
    ///
    /// It is enough to have two states in the decoder: Separator(bool) and
    /// Data(bool, u8). Separator is an overhead or packet separator byte.
    /// Data(u8, bool) represents an altered or unaltered data byte (altered
    /// if the counter is zero, unaltered otherwise). The boolean in both
    /// states indicates whether a zero byte should be appended to the output
    /// when reaching the next overhead byte.
    enum DState {
        /// Next byte is a separator or overhead byte that contains a relative
        /// offset to the next zero byte.
        Overhead(bool),
        /// Next byte is an altered or unaltered data byte. Payload consists of
        /// a relative offset from this byte to the next overhead byte, and a
        /// boolean indicating whether a zero byte should be appended to the
        /// output when reaching the next overhead byte.
        Data(u8, bool),
        /// Special state for error recovery: do nothing until a zero byte is
        /// encountered, then reset.
        Error,
    }

    impl Default for DState {
        fn default() -> Self {
            DState::Overhead(false)
        }
    }

    #[pyclass]
    #[derive(Default)]
    /// Incremental COBS decoder.
    ///
    /// This class allows decoding data in chunks, maintaining state between
    /// calls. The implementation is modelled based on the `Decoder` struct in the
    /// `corncobs` Rust crate, but is adapted to support feeding multiple bytes
    /// in one call.
    struct Decoder {
        state: DState,
        message: Vec<u8>,

        /// Maximum allowed length of a message being decoded. If the number of
        /// collected-but-not-yet-returned bytes exceeds this length, the decoder
        /// enters an error state. If None (default), no length limit is enforced.
        #[pyo3(get, set)]
        max_length: Option<usize>,

        /// Whether the decoder is in strict mode. In strict mode, the decoder
        /// raises an error if it encounters invalid COBS input. In non-strict
        /// mode, the decoder attempts to recover by resetting its state.
        #[pyo3(get, set)]
        strict: bool,
    }

    impl Decoder {
        /// Checks whether the number of pending bytes exceeds the maximum length.
        fn check_length(&mut self) -> PyResult<()> {
            if let Some(max_length) = self.max_length {
                if self.message.len() > max_length {
                    return self.handle_error(DecoderErrorCode::ExceededMaxLength, 0);
                }
            }
            Ok(())
        }

        /// Handles a parsing error
        fn handle_error(&mut self, code: DecoderErrorCode, byte: u8) -> PyResult<()> {
            self.message.clear();
            self.state = if byte == 0 {
                DState::default()
            } else {
                DState::Error
            };

            if self.strict {
                Err(code.into())
            } else {
                Ok(())
            }
        }
    }

    #[pymethods]
    impl Decoder {
        #[new]
        #[pyo3(signature = (*, max_length = None, strict = true))]
        fn new(max_length: Option<usize>, strict: bool) -> Self {
            Decoder {
                max_length,
                strict,
                ..Default::default()
            }
        }

        /// Feeds a new byte into the decoder.
        ///
        /// Args:
        ///     byte: The next byte to feed into the decoder
        ///
        /// Raises:
        ///     DecodeError: if the input is not a valid COBS encoded string.
        ///
        /// Returns:
        ///     A new, fully assembled message if the current byte marked an
        ///     end of a message; None otherwise.
        pub fn advance<'p>(
            &mut self,
            py: Python<'p>,
            byte: u8,
        ) -> PyResult<Option<Bound<'p, PyBytes>>> {
            match self.state {
                DState::Overhead(append_zero) => {
                    if append_zero {
                        self.message.push(0);
                    }
                    if let Some(offset) = byte.checked_sub(1) {
                        self.state = DState::Data(offset, offset < 254);
                    } else {
                        self.handle_error(DecoderErrorCode::ZeroByteInInput, byte)?;
                    }
                }
                DState::Data(offset, append_zero) => {
                    if offset == 0 {
                        // Altered byte
                        if let Some(offset) = byte.checked_sub(1) {
                            // Message continues
                            if append_zero {
                                self.message.push(0);
                            }
                            self.state = DState::Data(offset, offset < 254);
                        } else {
                            // End of message
                            let result = PyBytes::new(py, &take(&mut self.message));
                            self.state = DState::default();
                            return Ok(Some(result));
                        }
                    } else {
                        // At this point we should not see a zero byte
                        if byte == 0 {
                            self.handle_error(DecoderErrorCode::ZeroByteInInput, byte)?;
                        } else {
                            self.message.push(byte);
                            self.state = DState::Data(offset - 1, append_zero);
                        }
                    }
                }
                DState::Error => {
                    if byte == 0 {
                        self.reset();
                    }
                }
            };

            self.check_length()?;

            Ok(None)
        }

        /// Feeds multiple new bytes into the decoder.
        ///
        /// Args:
        ///     bytes: The next bytes to feed into the decoder
        ///
        /// Raises:
        ///     DecodeError: if the input is not a valid COBS encoded string.
        ///
        /// Returns:
        ///     List of fully assembled messages during the processing of the
        ///     input bytes.
        pub fn advance_many<'p>(
            &mut self,
            py: Python<'p>,
            bytes: &[u8],
        ) -> PyResult<Bound<'p, PyList>> {
            let mut result: Vec<Bound<'p, PyBytes>> = Vec::new();
            let mut index = 0;

            while index < bytes.len() {
                let byte = bytes[index];
                index += 1;

                match self.state {
                    DState::Overhead(append_zero) => {
                        if append_zero {
                            self.message.push(0);
                        }
                        if let Some(offset) = byte.checked_sub(1) {
                            // If we commit ourselves to this offset, it means
                            // that we will copy this many extra bytes to the
                            // message. Check whether that would exceed max_length.
                            if let Some(max_length) = self.max_length
                                && self.message.len() + (offset as usize) > max_length
                            {
                                self.handle_error(DecoderErrorCode::ExceededMaxLength, byte)?;
                            } else {
                                self.state = DState::Data(offset, offset < 254);
                            }
                        } else {
                            self.handle_error(DecoderErrorCode::ZeroByteInInput, byte)?;
                        }
                    }
                    DState::Data(offset, append_zero) => {
                        if let Some(remaining) = offset.checked_sub(1) {
                            // `byte` from the iterator and the next `remaining`
                            // bytes are unaltered data bytes so we can copy
                            // them directly to the message being assembled.
                            // In strict mode, we need to check whether any of
                            // the copied bytes is zero.
                            if remaining > 0 {
                                let end = min(index + (remaining as usize), bytes.len());
                                let to_copy = &bytes[(index - 1)..end];
                                if self.strict && to_copy.contains(&0) {
                                    self.handle_error(DecoderErrorCode::ZeroByteInInput, byte)?;
                                    // Since we are in strict mode, we will never get here
                                }

                                self.message.extend_from_slice(to_copy);
                                index = end;

                                let consumed = to_copy.len() as u8;
                                if consumed <= offset {
                                    self.state = DState::Data(offset - consumed, append_zero);
                                } else {
                                    // This should not happen, but handle it
                                    // gracefully.
                                    self.handle_error(DecoderErrorCode::UnexpectedError, byte)?;
                                }
                            } else {
                                // Only `byte` is an unaltered data byte.
                                if byte == 0 {
                                    self.handle_error(DecoderErrorCode::ZeroByteInInput, byte)?;
                                } else {
                                    self.message.push(byte);
                                    self.state = DState::Data(remaining, append_zero);
                                }
                            }
                        } else {
                            // Altered byte
                            if let Some(offset) = byte.checked_sub(1) {
                                // Message continues
                                if append_zero {
                                    self.message.push(0);
                                }
                                self.state = DState::Data(offset, offset < 254);
                            } else {
                                // End of message
                                result.push(PyBytes::new(py, &take(&mut self.message)));
                                self.state = DState::default();
                            }
                        }
                    }
                    DState::Error => {
                        if byte == 0 {
                            self.reset();
                        }
                    }
                };
            }

            self.check_length()?;

            PyList::new(py, result)
        }

        /// Alias to `advance_many()` method for feeding multiple bytes.
        pub fn __call__<'p>(
            &mut self,
            py: Python<'p>,
            bytes: &[u8],
        ) -> PyResult<Bound<'p, PyList>> {
            self.advance_many(py, bytes)
        }

        /// Resets the state of the decoder.
        pub fn reset(&mut self) {
            self.state = DState::default();
            self.message.clear();
        }

        /// Returns the number of collected-but-not-yet-returned bytes.
        #[getter]
        pub fn num_pending(&self) -> usize {
            self.message.len()
        }

        /// Returns the collected-but-not-yet-returned bytes.
        #[getter]
        pub fn pending<'p>(&self, py: Python<'p>) -> Bound<'p, PyBytes> {
            PyBytes::new(py, &self.message)
        }
    }
}
