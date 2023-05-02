use crate::error::CryptoError;

use super::{proof::Proof, Parameters, Statement, Witness};

use crate::utils::rand::FiatShamirRng;
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use ark_std::UniformRand;
use digest::Digest;

use ark_ec::{AffineRepr, CurveGroup};
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
        pp: &Parameters<C>,
        statement: &Statement<C>,
        witness: &Witness<C>,
        fs_rng: &mut FiatShamirRng<D>,
    ) -> Result<Proof<C>, CryptoError> {
        let random = C::ScalarField::rand(rng);

        let random_commit = pp.mul_bigint(random.into_bigint()).into();

        fs_rng.absorb(b"schnorr_identity");
        fs_rng.absorb(pp);
        fs_rng.absorb(statement);
        fs_rng.absorb(&random_commit);

        let c = C::ScalarField::rand(fs_rng);

        let opening = random - c * witness;

        Ok(Proof {
            random_commit,
            opening,
        })
    }
}
