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

#[pymodule]
#[pyo3(name = "_cobs")]
mod corncobs_py {
    use pyo3::{prelude::*, types::PyBytes};

    #[pymodule_export]
    use super::DecodeError;

    /// Encode a string using Consistent Overhead Byte Stuffing (COBS).
    ///
    /// The encoding guarantees no zero bytes in the output. The output
    /// string will be expanded slightly, by a predictable amount.
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

    #[pyfunction]
    fn decode<'p>(py: Python<'p>, mut in_bytes: Vec<u8>) -> PyResult<Bound<'p, PyBytes>> {
        // We need to check whether in_bytes contains a zero because corncobs
        // won't do that for performance reasons - but we want to stay compatible
        // with cobs which does check for that.
        if in_bytes.contains(&0) {
            return Err(DecodeError::new_err("input contains zero byte"));
        }

        let result = py
            .detach(|| corncobs::decode_in_place(&mut in_bytes))
            .map_err(|e| super::CorncobsError::from(e))?;
        Ok(PyBytes::new(py, &in_bytes[..result]))
    }
}
