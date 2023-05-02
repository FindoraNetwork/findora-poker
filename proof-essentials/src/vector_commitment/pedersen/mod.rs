use crate::error::CryptoError;
use crate::vector_commitment::HomomorphicCommitmentScheme;

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::marker::PhantomData;
use rand::Rng;

pub mod arithmetic_definitions;
mod tests;

pub struct PedersenCommitment<C: CurveGroup> {
    _curve: PhantomData<C>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize, Debug)]
pub struct CommitKey<C: CurveGroup> {
    g: Vec<C::Affine>,
    h: C::Affine,
}

impl<C: CurveGroup> CommitKey<C> {
    pub fn new(g: Vec<C::Affine>, h: C::Affine) -> Self {
        Self { g, h }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Commitment<C: CurveGroup>(pub C::Affine);

impl<C: CurveGroup> HomomorphicCommitmentScheme<C::ScalarField> for PedersenCommitment<C> {
    type CommitKey = CommitKey<C>;
    type Commitment = Commitment<C>;

    fn setup<R: Rng>(public_randomess: &mut R, len: usize) -> CommitKey<C> {
        let mut g = Vec::with_capacity(len);
        for _ in 0..len {
            g.push(C::rand(public_randomess).into_affine());
        }
        let h = C::rand(public_randomess).into_affine();
        CommitKey::<C> { g, h }
    }

    fn commit(
        commit_key: &CommitKey<C>,
        x: &Vec<C::ScalarField>,
        r: C::ScalarField,
    ) -> Result<Self::Commitment, CryptoError> {
        if x.len() > commit_key.g.len() {
            return Err(CryptoError::CommitmentLengthError(
                String::from("Pedersen"),
                x.len(),
                commit_key.g.len(),
            ));
        }

        let scalars = [&[r], x.as_slice()]
            .concat()
            .iter()
            .map(|x| x.into_bigint())
            .collect::<Vec<_>>();

        let bases = [&[commit_key.h], &commit_key.g[..]].concat();

        Ok(Commitment(
            C::msm_bigint(&bases, &scalars[..]).into_affine(),
        ))
    }
}
