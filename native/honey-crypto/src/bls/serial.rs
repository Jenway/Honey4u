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
use std::mem::MaybeUninit;

// ── Fr Serialization ────────────────────────────────────────────────────────

impl Serialize for Fr {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut bytes = [0u8; 32];
        unsafe {
            let mut scalar = MaybeUninit::<blst_scalar>::uninit();
            blst_scalar_from_fr(scalar.as_mut_ptr(), &self.inner);
            let scalar = scalar.assume_init();
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
            let mut aff = MaybeUninit::<blst_p1_affine>::uninit();
            let err = blst_p1_uncompress(aff.as_mut_ptr(), arr.as_ptr());
            if err != BLST_ERROR::BLST_SUCCESS {
                return Err(de::Error::custom("invalid compressed G1 point"));
            }
            let aff = aff.assume_init();
            let mut p = MaybeUninit::<blst_p1>::uninit();
            blst_p1_from_affine(p.as_mut_ptr(), &aff);
            Ok(G1 {
                inner: p.assume_init(),
            })
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
            let mut aff = MaybeUninit::<blst_p2_affine>::uninit();
            let err = blst_p2_uncompress(aff.as_mut_ptr(), bytes.as_ptr());
            if err != BLST_ERROR::BLST_SUCCESS {
                return Err(de::Error::custom("invalid compressed G2 point"));
            }
            let aff = aff.assume_init();
            let mut p = MaybeUninit::<blst_p2>::uninit();
            blst_p2_from_affine(p.as_mut_ptr(), &aff);
            Ok(G2 {
                inner: p.assume_init(),
            })
        }
    }
}
