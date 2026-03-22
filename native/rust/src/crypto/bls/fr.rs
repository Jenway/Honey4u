/// BLS12-381 field/group wrappers
///
// ── Fr ──────────────────────────────────────────────────────────────────────
/// Fr: scalar field element
/// An element of the BLS12-381 scalar field Fr.
use blst::{
    blst_fr, blst_fr_from_scalar, blst_fr_from_uint64, blst_scalar, blst_scalar_from_be_bytes,
};
use rand::RngCore;

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct Fr {
    pub(crate) inner: blst_fr,
}

impl Fr {
    #[inline]
    pub fn from_u64(v: u64) -> Self {
        unsafe {
            let mut fr = std::mem::zeroed::<blst_fr>();
            let limbs = [v, 0u64, 0u64, 0u64];
            blst_fr_from_uint64(&mut fr, limbs.as_ptr());
            Fr { inner: fr }
        }
    }

    pub fn from_scalar_bytes(bytes: &[u8; 32]) -> Option<Self> {
        unsafe {
            let mut scalar = std::mem::zeroed::<blst_scalar>();
            // blst_scalar_from_be_bytes validates that the value is < r (the curve order)
            if blst_scalar_from_be_bytes(&mut scalar, bytes.as_ptr(), 32) {
                let mut fr = std::mem::zeroed::<blst_fr>();
                blst_fr_from_scalar(&mut fr, &scalar);
                Some(Fr { inner: fr })
            } else {
                None
            }
        }
    }

    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        loop {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            unsafe {
                let mut scalar = std::mem::zeroed::<blst_scalar>();
                // blst_scalar_from_be_bytes returns true if value is in range [0, r)
                if blst_scalar_from_be_bytes(&mut scalar, bytes.as_ptr(), 32) {
                    let mut fr = std::mem::zeroed::<blst_fr>();
                    blst_fr_from_scalar(&mut fr, &scalar);
                    return Fr { inner: fr };
                }
            }
        }
    }
}
