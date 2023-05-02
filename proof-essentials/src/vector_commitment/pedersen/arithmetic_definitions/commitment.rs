use super::super::Commitment;
use ark_ff::Zero;
use ark_std::ops::Mul;
use ark_std::UniformRand;
use rand::Rng;

use ark_ec::{AffineRepr, CurveGroup};

impl<C: CurveGroup> Mul<C::ScalarField> for Commitment<C> {
    type Output = Self;
    fn mul(self, x: C::ScalarField) -> Self::Output {
        Self(self.0.mul(x).into_affine())
    }
}

impl<C: CurveGroup> std::ops::Add for Commitment<C> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self((self.0 + rhs.0).into())
    }
}

impl<C: CurveGroup> std::iter::Sum for Commitment<C> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), |a, b| a + b)
    }
}

impl<C: CurveGroup> Zero for Commitment<C> {
    fn zero() -> Self {
        Self(C::Affine::zero())
    }

    fn is_zero(&self) -> bool {
        *self == Self(C::Affine::zero())
    }
}

impl<C: CurveGroup> UniformRand for Commitment<C> {
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Self(C::rand(rng).into_affine())
    }
}
