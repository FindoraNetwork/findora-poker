use crate::discrete_log_cards::Card;
use crate::error::CardProtocolError;
use crate::Mask;
use ark_ec::CurveGroup;

use proof_essentials::homomorphic_encryption::{
    el_gamal, el_gamal::ElGamal, HomomorphicEncryptionScheme,
};

impl<C: CurveGroup> Mask<C::ScalarField, ElGamal<C>> for Card<C> {
    fn mask(
        &self,
        pp: &el_gamal::Parameters<C>,
        shared_key: &el_gamal::PublicKey<C>,
        r: &C::ScalarField,
    ) -> Result<el_gamal::Ciphertext<C>, CardProtocolError> {
        let ciphertext = ElGamal::<C>::encrypt(pp, shared_key, self, r)?;
        Ok(ciphertext)
    }
}

#[cfg(test)]
mod test {
    use crate::discrete_log_cards;
    use crate::BarnettSmartProtocol;
    use ark_ec::{AffineRepr, CurveGroup};

    use ark_ff::UniformRand;
    use ark_serialize::CanonicalDeserialize;
    use ark_serialize::CanonicalSerialize;
    use ark_std::rand::Rng;
    use proof_essentials::error::CryptoError;
    use proof_essentials::zkp::proofs::chaum_pedersen_dl_equality;
    use rand::thread_rng;

    // Choose elliptic curve setting
    type Curve = ark_bn254::G1Projective;
    type Scalar = ark_bn254::Fr;

    // Instantiate concrete type for our card protocol
    type CardProtocol<'a> = discrete_log_cards::DLCards<'a, Curve>;
    type CardParameters = discrete_log_cards::Parameters<Curve>;
    type PublicKey = discrete_log_cards::PublicKey<Curve>;
    type SecretKey = discrete_log_cards::PlayerSecretKey<Curve>;

    type Card = discrete_log_cards::Card<Curve>;
    type MaskedCard = discrete_log_cards::MaskedCard<Curve>;

    type MaskingProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;

    fn setup_players<R: Rng>(
        rng: &mut R,
        parameters: &CardParameters,
        num_of_players: usize,
    ) -> (Vec<(PublicKey, SecretKey)>, PublicKey) {
        let mut players: Vec<(PublicKey, SecretKey)> = Vec::with_capacity(num_of_players);
        let mut expected_shared_key = PublicKey::zero().into_group();

        for i in 0..parameters.n {
            players.push(CardProtocol::player_keygen(rng, &parameters).unwrap());
            expected_shared_key = expected_shared_key + players[i].0
        }

        (players, expected_shared_key.into_affine())
    }

    #[test]
    fn test_verify_masking() {
        let rng = &mut thread_rng();
        let m = 4;
        let n = 13;

        let num_of_players = 10;

        let parameters = CardProtocol::setup(rng, m, n).unwrap();

        let (_, aggregate_key) = setup_players(rng, &parameters, num_of_players);

        let some_card = Card::rand(rng);
        let some_random = Scalar::rand(rng);

        let (masked, mut masking_proof): (MaskedCard, MaskingProof) =
            CardProtocol::mask(rng, &parameters, &aggregate_key, &some_card, &some_random).unwrap();

        let mut data = Vec::with_capacity(masking_proof.compressed_size());
        masking_proof.serialize_compressed(&mut data).unwrap();
        masking_proof = CanonicalDeserialize::deserialize_compressed(data.as_slice()).unwrap();

        assert_eq!(
            Ok(()),
            CardProtocol::verify_mask(
                &parameters,
                &aggregate_key,
                &some_card,
                &masked,
                &masking_proof
            )
        );

        let wrong_masked = MaskedCard::rand(rng);

        assert_eq!(
            CardProtocol::verify_mask(
                &parameters,
                &aggregate_key,
                &some_card,
                &wrong_masked,
                &masking_proof
            ),
            Err(CryptoError::ProofVerificationError(String::from(
                "Chaum-Pedersen"
            )))
        )
    }
}
