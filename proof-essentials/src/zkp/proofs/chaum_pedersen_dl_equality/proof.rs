use crate::error::CryptoError;
use ark_std::ops::Mul;

use super::{Parameters, Statement};

use crate::utils::rand::FiatShamirRng;
use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use digest::Digest;

#[derive(Clone, Copy, Eq, Hash, PartialEq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct Proof<C>
where
    C: CurveGroup,
{
    pub(crate) a: C::Affine,
    pub(crate) b: C::Affine,
    pub(crate) r: C::ScalarField,
}

impl<C: CurveGroup> Proof<C> {
    pub fn verify<D: Digest>(
        &self,
        parameters: &Parameters<C>,
        statement: &Statement<C>,
        fs_rng: &mut FiatShamirRng<D>,
    ) -> Result<(), CryptoError> {
        fs_rng.absorb(b"chaum_pedersen");
        fs_rng.absorb(parameters.g);
        fs_rng.absorb(parameters.h);
        fs_rng.absorb(statement.0);
        fs_rng.absorb(statement.1);
        fs_rng.absorb(&self.a);
        fs_rng.absorb(&self.b);

        let c = C::ScalarField::rand(fs_rng);

        // g * r ==? a + x*c
        if parameters.g.mul(self.r) != self.a.into_group() + statement.0.mul(c) {
            return Err(CryptoError::ProofVerificationError(String::from(
                "Chaum-Pedersen",
            )));
        }

        // h * r ==? b + y*c
        if parameters.h.mul(self.r) != self.b.into_group() + statement.1.mul(c) {
            return Err(CryptoError::ProofVerificationError(String::from(
                "Chaum-Pedersen",
            )));
        }

        Ok(())
    }
}
