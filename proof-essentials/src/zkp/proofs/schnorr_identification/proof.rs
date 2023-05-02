use super::{Parameters, Statement};
use crate::error::CryptoError;

use crate::utils::rand::FiatShamirRng;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use digest::Digest;

#[derive(Copy, Clone, CanonicalDeserialize, CanonicalSerialize, Debug, PartialEq, Eq)]
pub struct Proof<C>
where
    C: CurveGroup,
{
    pub(crate) random_commit: C::Affine,
    pub(crate) opening: C::ScalarField,
}

impl<C: CurveGroup> Proof<C> {
    pub fn verify<D: Digest>(
        &self,
        pp: &Parameters<C>,
        statement: &Statement<C>,
        fs_rng: &mut FiatShamirRng<D>,
    ) -> Result<(), CryptoError> {
        fs_rng.absorb(b"schnorr_identity");
        fs_rng.absorb(pp);
        fs_rng.absorb(statement);
        fs_rng.absorb(&self.random_commit);

        let c = C::ScalarField::rand(fs_rng);

        if pp.mul_bigint(self.opening.into_bigint()) + statement.mul_bigint(c.into_bigint())
            != self.random_commit.into()
        {
            return Err(CryptoError::ProofVerificationError(String::from(
                "Schnorr Identification",
            )));
        }

        Ok(())
    }
}
