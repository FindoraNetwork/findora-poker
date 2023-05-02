use ark_std::marker::PhantomData;
use ark_std::UniformRand;
use digest::Digest;
use digest::generic_array::GenericArray;
use ark_std::rand::{Rng, SeedableRng, RngCore};
use ark_ff::{ToBytes, FromBytes};
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
        Ok(self.r.fill_bytes(dest))
    }
}

impl<D: Digest> FiatShamirRng<D> {
    /// Create a new `Self` by initializing with a fresh seed.
    /// `self.seed = H(self.seed || new_seed)`.
    #[inline]
    pub fn from_seed<'a, T: 'a + ToBytes>(seed: &'a T) -> Self {
        let mut bytes = Vec::new();
        seed.write(&mut bytes).expect("failed to convert to bytes");
        let seed = D::digest(&bytes);
        let r_seed: [u8; 32] = FromBytes::read(seed.as_ref()).expect("failed to get [u32; 8]");
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
    pub fn absorb<'a, T: 'a + ToBytes>(&mut self, seed: &'a T) {
        let mut bytes = Vec::new();
        seed.write(&mut bytes).expect("failed to convert to bytes");
        bytes.extend_from_slice(&self.seed);
        self.seed = D::digest(&bytes);
        let seed: [u8; 32] = FromBytes::read(self.seed.as_ref()).expect("failed to get [u32; 8]");
        self.r = ChaChaRng::from_seed(seed);
    }
}