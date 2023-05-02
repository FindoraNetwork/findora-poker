use crate::error::CryptoError;

use super::proof::Proof;
use super::{Parameters, Statement, Witness};

use crate::utils::rand::FiatShamirRng;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_std::{rand::Rng, UniformRand};
use digest::Digest;

use ark_ec::CurveGroup;
use ark_std::marker::PhantomData;

pub struct Prover<C>
where
    C: CurveGroup,
{
    phantom: PhantomData<C>,
}

impl<C> Prover<C>
where
    C: CurveGroup,
{
    pub fn create_proof<R: Rng, D: Digest>(
        rng: &mut R,
        parameters: &Parameters<C>,
        statement: &Statement<C>,
        witness: &Witness<C>,
        fs_rng: &mut FiatShamirRng<D>,
    ) -> Result<Proof<C>, CryptoError> {
        fs_rng.absorb(b"chaum_pedersen");
        fs_rng.absorb(parameters.g);
        fs_rng.absorb(parameters.h);
        fs_rng.absorb(statement.0);
        fs_rng.absorb(statement.1);

        let omega = C::ScalarField::rand(rng);
        let a = parameters.g.mul_bigint(omega.into_bigint()).into_affine();
        let b = parameters.h.mul_bigint(omega.into_bigint()).into_affine();

        fs_rng.absorb(&a);
        fs_rng.absorb(&b);

        let c = C::ScalarField::rand(fs_rng);

        let r = omega + c * *witness;

        Ok(Proof { a, b, r })
    }
}
