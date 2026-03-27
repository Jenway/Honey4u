use pyo3::PyResult;
use pyo3::exceptions::PyValueError;
use rkyv::rancor::Error;
use rkyv::{Archive, Deserialize, Serialize};

pub(crate) fn encode<T>(value: &T) -> PyResult<Vec<u8>>
where
    T: for<'a> Serialize<
        rkyv::api::high::HighSerializer<
            rkyv::util::AlignedVec,
            rkyv::ser::allocator::ArenaHandle<'a>,
            Error,
        >,
    >,
{
    rkyv::to_bytes::<Error>(value)
        .map(|bytes| bytes.to_vec())
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

pub(crate) fn decode<T>(payload: &[u8]) -> PyResult<T>
where
    T: Archive,
    for<'a> <T as Archive>::Archived: rkyv::bytecheck::CheckBytes<rkyv::api::high::HighValidator<'a, Error>>
        + Deserialize<T, rkyv::api::high::HighDeserializer<Error>>,
{
    rkyv::from_bytes::<T, Error>(payload).map_err(|e| PyValueError::new_err(e.to_string()))
}
