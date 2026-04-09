use rkyv::rancor::Error;
use rkyv::{Archive, Deserialize, Serialize};

pub fn encode_result<T>(value: &T) -> Result<Vec<u8>, String>
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
        .map_err(|e| e.to_string())
}

pub fn decode_result<T>(payload: &[u8]) -> Result<T, String>
where
    T: Archive,
    for<'a> <T as Archive>::Archived: rkyv::bytecheck::CheckBytes<rkyv::api::high::HighValidator<'a, Error>>
        + Deserialize<T, rkyv::api::high::HighDeserializer<Error>>,
{
    rkyv::from_bytes::<T, Error>(payload).map_err(|e| e.to_string())
}
