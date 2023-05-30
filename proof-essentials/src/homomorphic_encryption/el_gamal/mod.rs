use crate::error::CryptoError;
use crate::homomorphic_encryption::HomomorphicEncryptionScheme;

use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::{fields::PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::hash::Hash;
use ark_std::ops::Mul;
use ark_std::{marker::PhantomData, rand::Rng};

pub mod arithmetic_definitions;
mod tests;

#[derive(Clone)]
pub struct ElGamal<C: CurveGroup> {
    _group: PhantomData<C>,
}

#[derive(Copy, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Parameters<C: CurveGroup> {
    pub generator: C::Affine,
}

pub type PublicKey<C> = <C as CurveGroup>::Affine;

#[derive(Clone, Copy, Eq, Hash, PartialEq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Plaintext<C: CurveGroup>(pub C::Affine);

pub type Generator<C> = Plaintext<C>;

pub type SecretKey<C> = <C as Group>::ScalarField;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Ciphertext<C: CurveGroup>(pub C::Affine, pub C::Affine);

impl<C: CurveGroup> HomomorphicEncryptionScheme<C::ScalarField> for ElGamal<C> {
    type Parameters = Parameters<C>;
    type Generator = Generator<C>;
    type PublicKey = PublicKey<C>;
    type SecretKey = SecretKey<C>;
    type Plaintext = Plaintext<C>;
    type Ciphertext = Ciphertext<C>;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, CryptoError> {
        // get a random generator
        let generator = C::rand(rng).into();

        Ok(Parameters { generator })
    }

    fn generator<R: Rng>(rng: &mut R) -> Result<Self::Generator, CryptoError> {
        Ok(Generator::rand(rng))
    }

    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), CryptoError> {
        // get a random element from the scalar field
        let secret_key: <C as Group>::ScalarField = C::ScalarField::rand(rng);

        // compute secret_key*generator to derive the public key
        let public_key = pp.generator.mul(secret_key).into();

        Ok((public_key, secret_key))
    }

    fn encrypt(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &Self::Plaintext,
        r: &C::ScalarField,
    ) -> Result<Self::Ciphertext, CryptoError> {
        // compute s = r*pk
        let s = Plaintext(pk.mul_bigint(r.into_bigint()).into_affine());

        // compute c1 = r*generator
        let c1 = pp.generator.mul_bigint(r.into_bigint()).into();

        // compute c2 = m + s
        let c2 = *message + s;

        Ok(Ciphertext(c1, c2.0))
    }

    fn decrypt(
        _pp: &Self::Parameters,
        sk: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, CryptoError> {
        let c1: <C as CurveGroup>::Affine = ciphertext.0;
        let c2: <C as CurveGroup>::Affine = ciphertext.1;

        // compute s = secret_key * c1
        let s = c1.mul_bigint(sk.into_bigint());
        let s_inv = -s;

        // compute message = c2 - s
        let m = c2 + s_inv.into_affine();

        Ok(Plaintext(m.into()))
    }
}
