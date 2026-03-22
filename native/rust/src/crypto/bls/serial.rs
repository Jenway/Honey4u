use super::fr::Fr;
use super::g1::G1;
use super::g2::G2;
use blst::{
    BLST_ERROR, blst_bendian_from_scalar, blst_p1, blst_p1_affine, blst_p1_compress,
    blst_p1_from_affine, blst_p1_uncompress, blst_p2, blst_p2_affine, blst_p2_compress,
    blst_p2_from_affine, blst_p2_uncompress, blst_scalar, blst_scalar_from_fr,
};
use serde::{Deserialize, Serialize, de, ser};
use std::convert::TryInto;

// ── Fr Serialization ────────────────────────────────────────────────────────

impl Serialize for Fr {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut bytes = [0u8; 32];
        unsafe {
            let mut scalar = std::mem::zeroed::<blst_scalar>();
            blst_scalar_from_fr(&mut scalar, &self.inner);
            blst_bendian_from_scalar(bytes.as_mut_ptr(), &scalar);
        }
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
        let mut out = [0u8; 48];
        unsafe {
            blst_p1_compress(out.as_mut_ptr(), &self.inner);
        }
        serializer.serialize_bytes(&out)
    }
}

impl<'de> Deserialize<'de> for G1 {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        let arr: &[u8; 48] = bytes.as_slice().try_into().map_err(|_| {
            de::Error::custom(format!("expected 48 bytes for G1, got {}", bytes.len()))
        })?;
        unsafe {
            let mut aff = std::mem::zeroed::<blst_p1_affine>();
            let err = blst_p1_uncompress(&mut aff, arr.as_ptr());
            if err != BLST_ERROR::BLST_SUCCESS {
                return Err(de::Error::custom("invalid compressed G1 point"));
            }
            let mut p = std::mem::zeroed::<blst_p1>();
            blst_p1_from_affine(&mut p, &aff);
            Ok(G1 { inner: p })
        }
    }
}
// ── G2 Serialization ────────────────────────────────────────────────────────

impl Serialize for G2 {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut out = [0u8; 96];
        unsafe {
            blst_p2_compress(out.as_mut_ptr(), &self.inner);
        }
        serializer.serialize_bytes(&out)
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
        unsafe {
            let mut aff = std::mem::zeroed::<blst_p2_affine>();
            let err = blst_p2_uncompress(&mut aff, bytes.as_ptr());
            if err != BLST_ERROR::BLST_SUCCESS {
                return Err(de::Error::custom("invalid compressed G2 point"));
            }
            let mut p = std::mem::zeroed::<blst_p2>();
            blst_p2_from_affine(&mut p, &aff);
            Ok(G2 { inner: p })
        }
    }
}
