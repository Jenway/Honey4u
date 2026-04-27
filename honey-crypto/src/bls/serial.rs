use super::fr::Fr;
use super::g1::G1;
use super::g2::G2;
use serde::{Deserialize, Serialize, de, ser};
use std::convert::TryInto;

// ── Fr Serialization ────────────────────────────────────────────────────────

impl Serialize for Fr {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = self.to_scalar_bytes();
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for Fr {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(de::Error::custom(format!(
                "expected 32 bytes for Fr, got {}",
                bytes.len()
            )));
        }
        let arr = bytes
            .as_slice()
            .try_into()
            .map_err(|_| de::Error::custom(format!("expected 32 bytes, got {}", bytes.len())))?;
        Fr::from_scalar_bytes(arr).ok_or_else(|| de::Error::custom("invalid Fr scalar bytes"))
    }
}

// ── G1 Serialization ────────────────────────────────────────────────────────

impl Serialize for G1 {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = self.to_compressed_bytes();
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for G1 {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        let arr: &[u8; 48] = bytes.as_slice().try_into().map_err(|_| {
            de::Error::custom(format!("expected 48 bytes for G1, got {}", bytes.len()))
        })?;
        G1::from_compressed_bytes(arr).map_err(de::Error::custom)
    }
}
// ── G2 Serialization ────────────────────────────────────────────────────────

impl Serialize for G2 {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = self.to_compressed_bytes();
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for G2 {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 96 {
            return Err(de::Error::custom(format!(
                "expected 96 bytes for G2, got {}",
                bytes.len()
            )));
        }
        let arr: &[u8; 96] = bytes.as_slice().try_into().map_err(|_| {
            de::Error::custom(format!("expected 96 bytes for G2, got {}", bytes.len()))
        })?;
        G2::from_compressed_bytes(arr).map_err(de::Error::custom)
    }
}
