use ark_serialize::{CanonicalSerialize, Compress};
use ark_std::marker::PhantomData;
use ark_std::rand::{Rng, RngCore, SeedableRng};
use ark_std::UniformRand;
use digest::generic_array::GenericArray;
use digest::Digest;
use rand_chacha::ChaChaRng;

/// Sample a vector of random elements of type T
pub fn sample_vector<T: UniformRand, R: Rng>(seed: &mut R, length: usize) -> Vec<T> {
    (0..length)
        .collect::<Vec<usize>>()
        .iter()
        .map(|_| T::rand(seed))
        .collect::<Vec<_>>()
}

pub struct FiatShamirRng<D: Digest> {
    r: ChaChaRng,
    seed: GenericArray<u8, D::OutputSize>,
    #[doc(hidden)]
    digest: PhantomData<D>,
}

impl<D: Digest> RngCore for FiatShamirRng<D> {
    #[inline]
    fn next_u32(&mut self) -> u32 {
        self.r.next_u32()
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        self.r.next_u64()
    }

    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.r.fill_bytes(dest);
    }

    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), ark_std::rand::Error> {
        self.r.fill_bytes(dest);
        Ok(())
    }
}

impl<D: Digest> FiatShamirRng<D> {
    /// Create a new `Self` by initializing with a fresh seed.
    /// `self.seed = H(self.seed || new_seed)`.
    #[inline]
    pub fn from_seed<'a, T: 'a + CanonicalSerialize>(seed: &'a T) -> Self {
        let mut bytes = Vec::new();
        seed.serialize_with_mode(&mut bytes, Compress::Yes)
            .expect("failed to convert to bytes");
        let seed = D::digest(&bytes);
        let mut r_seed = [0u8; 32];
        r_seed.copy_from_slice(seed.as_ref());
        let r = ChaChaRng::from_seed(r_seed);
        Self {
            r,
            seed,
            digest: PhantomData,
        }
    }

    /// Refresh `self.seed` with new material. Achieved by setting
    /// `self.seed = H(self.seed || new_seed)`.
    #[inline]
    pub fn absorb<'a, T: 'a + CanonicalSerialize>(&mut self, seed: &'a T) {
        let mut bytes = Vec::new();
        seed.serialize_with_mode(&mut bytes, Compress::Yes)
            .expect("failed to convert to bytes");
        bytes.extend_from_slice(&self.seed);
        self.seed = D::digest(&bytes);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(self.seed.as_ref());
        self.r = ChaChaRng::from_seed(seed);
    }
}
