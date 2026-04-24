/// BLS12-381 field/group wrappers
///
// ── Fr ──────────────────────────────────────────────────────────────────────
/// Fr: scalar field element
/// An element of the BLS12-381 scalar field Fr.
use blst::{
    blst_fr, blst_fr_from_scalar, blst_fr_from_uint64, blst_scalar, blst_scalar_from_be_bytes,
};
use rand::rand_core::{CryptoRng, Rng};

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct Fr {
    pub(crate) inner: blst_fr,
}

impl Fr {
    #[inline]
    pub fn from_u64(v: u64) -> Self {
        unsafe {
            let mut fr = std::mem::MaybeUninit::<blst_fr>::uninit();
            let limbs = [v, 0u64, 0u64, 0u64];
            blst_fr_from_uint64(fr.as_mut_ptr(), limbs.as_ptr());
            Fr {
                inner: fr.assume_init(),
            }
        }
    }

    pub fn from_scalar_bytes(bytes: &[u8; 32]) -> Option<Self> {
        unsafe {
            let mut scalar = std::mem::MaybeUninit::<blst_scalar>::uninit();
            // blst_scalar_from_be_bytes validates that the value is < r (the curve order)
            if blst_scalar_from_be_bytes(scalar.as_mut_ptr(), bytes.as_ptr(), 32) {
                let mut fr = std::mem::MaybeUninit::<blst_fr>::uninit();
                blst_fr_from_scalar(fr.as_mut_ptr(), scalar.as_ptr());
                Some(Fr {
                    inner: fr.assume_init(),
                })
            } else {
                None
            }
        }
    }

    pub fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        loop {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);

            unsafe {
                let mut scalar = std::mem::MaybeUninit::<blst_scalar>::uninit();
                if blst_scalar_from_be_bytes(scalar.as_mut_ptr(), bytes.as_ptr(), 32) {
                    let mut fr = std::mem::MaybeUninit::<blst_fr>::uninit();
                    blst_fr_from_scalar(fr.as_mut_ptr(), scalar.as_ptr());
                    return Fr {
                        inner: fr.assume_init(),
                    };
                }
            }
        }
    }
}
