#[cfg(test)]
mod test {
    use crate::discrete_log_cards;
    use crate::error::CardProtocolError;
    use crate::BarnettSmartProtocol;

    use ark_ff::UniformRand;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::{rand::Rng, Zero};
    use proof_essentials::error::CryptoError;
    use proof_essentials::utils::permutation::Permutation;
    use proof_essentials::utils::rand::sample_vector;
    use rand::thread_rng;
    use std::iter::Iterator;

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
    type RevealToken = discrete_log_cards::RevealToken<Curve>;

    /// Setup `n` players. We use a Scalar to represent player public information
    fn setup_players<R: Rng>(
        rng: &mut R,
        parameters: &CardParameters,
        num_of_players: usize,
    ) -> (Vec<(PublicKey, SecretKey, Scalar)>, PublicKey) {
        let mut players: Vec<(PublicKey, SecretKey, Scalar)> = Vec::with_capacity(num_of_players);
        let mut expected_shared_key = PublicKey::zero();

        for i in 0..num_of_players {
            let (pk, sk) = CardProtocol::player_keygen(rng, &parameters).unwrap();
            let player_info = Scalar::rand(rng);
            players.push((pk, sk, player_info));
            expected_shared_key = expected_shared_key + players[i].0
        }

        (players, expected_shared_key)
    }

    #[test]
    fn generate_and_verify_key() {
        let rng = &mut thread_rng();
        let m = 4;
        let n = 13;

        let parameters = CardProtocol::setup(rng, m, n).unwrap();

        let (pk, sk) = CardProtocol::player_keygen(rng, &parameters).unwrap();
        let player_name = b"Alice";

        let mut p1_keyproof =
            CardProtocol::prove_key_ownership(rng, &parameters, &pk, &sk, &player_name).unwrap();

        let mut data = Vec::with_capacity(p1_keyproof.serialized_size());
        p1_keyproof.serialize(&mut data).unwrap();
        p1_keyproof = CanonicalDeserialize::deserialize(data.as_slice()).unwrap();

        assert_eq!(
            Ok(()),
            CardProtocol::verify_key_ownership(&parameters, &pk, &player_name, &p1_keyproof)
        );

        let other_key = Scalar::rand(rng);
        let wrong_proof =
            CardProtocol::prove_key_ownership(rng, &parameters, &pk, &other_key, &player_name)
                .unwrap();

        assert_eq!(
            CardProtocol::verify_key_ownership(&parameters, &pk, &player_name, &wrong_proof),
            Err(CryptoError::ProofVerificationError(String::from(
                "Schnorr Identification"
            )))
        )
    }

    #[test]
    fn aggregate_keys() {
        let rng = &mut thread_rng();
        let m = 4;
        let n = 13;

        let num_of_players = 10;

        let parameters = CardProtocol::setup(rng, m, n).unwrap();

        let (players, expected_shared_key) = setup_players(rng, &parameters, num_of_players);

        let proofs = players
            .iter()
            .map(|player| {
                CardProtocol::prove_key_ownership(rng, &parameters, &player.0, &player.1, &player.2)
                    .unwrap()
            })
            .collect::<Vec<_>>();

        let mut key_proof_info = players
            .iter()
            .zip(proofs.iter())
            .map(|(player, &proof)| (player.0, proof.clone(), player.2))
            .collect::<Vec<(PublicKey, _, _)>>();

        let mut data = Vec::with_capacity(key_proof_info.serialized_size());
        key_proof_info.serialize(&mut data).unwrap();
        key_proof_info = CanonicalDeserialize::deserialize(data.as_slice()).unwrap();

        key_proof_info = key_proof_info
            .iter()
            .map(|vkey_proof_info| {
                let mut proof = vkey_proof_info.1;
                let mut data = Vec::with_capacity(proof.serialized_size());
                proof.serialize(&mut data).unwrap();
                proof = CanonicalDeserialize::deserialize(data.as_slice()).unwrap();
                (vkey_proof_info.0, proof.clone(), vkey_proof_info.2)
            })
            .collect();

        let test_aggregate =
            CardProtocol::compute_aggregate_key(&parameters, &key_proof_info).unwrap();

        assert_eq!(test_aggregate, expected_shared_key);

        let mut bad_key_proof_pairs = key_proof_info;
        bad_key_proof_pairs[0].0 = PublicKey::zero();

        let test_fail_aggregate =
            CardProtocol::compute_aggregate_key(&parameters, &bad_key_proof_pairs);

        assert_eq!(
            test_fail_aggregate,
            Err(CardProtocolError::ProofVerificationError(
                CryptoError::ProofVerificationError(String::from("Schnorr Identification"))
            ))
        )
    }

    #[test]
    fn test_unmask() {
        let rng = &mut thread_rng();
        let m = 4;
        let n = 13;

        let num_of_players = 10;

        let parameters = CardProtocol::setup(rng, m, n).unwrap();

        let (players, expected_shared_key) = setup_players(rng, &parameters, num_of_players);

        let card = Card::rand(rng);
        let alpha = Scalar::rand(rng);
        let (masked, _) =
            CardProtocol::mask(rng, &parameters, &expected_shared_key, &card, &alpha).unwrap();

        let decryption_key = players
            .iter()
            .map(|player| {
                let (token, proof) = CardProtocol::compute_reveal_token(
                    rng,
                    &parameters,
                    &player.1,
                    &player.0,
                    &masked,
                )
                .unwrap();

                (token, proof, player.0)
            })
            .collect::<Vec<_>>();

        let unmasked = CardProtocol::unmask(&parameters, &decryption_key, &masked).unwrap();

        assert_eq!(card, unmasked);

        let mut bad_decryption_key = decryption_key;
        bad_decryption_key[0].0 = RevealToken::rand(rng);

        let failed_decryption = CardProtocol::unmask(&parameters, &bad_decryption_key, &masked);

        assert_eq!(
            failed_decryption,
            Err(CardProtocolError::ProofVerificationError(
                CryptoError::ProofVerificationError(String::from("Chaum-Pedersen"))
            ))
        )
    }

    #[test]
    fn test_shuffle() {
        let rng = &mut thread_rng();
        let m = 4;
        let n = 13;

        let num_of_players = 10;

        let parameters = CardProtocol::setup(rng, m, n).unwrap();

        let (_, aggregate_key) = setup_players(rng, &parameters, num_of_players);

        let deck: Vec<MaskedCard> = sample_vector(rng, m * n);

        let permutation = Permutation::new(rng, m * n);
        let masking_factors: Vec<Scalar> = sample_vector(rng, m * n);

        let (shuffled_deck, mut shuffle_proof) = CardProtocol::shuffle_and_remask(
            rng,
            &parameters,
            &aggregate_key,
            &deck,
            &masking_factors,
            &permutation,
        )
        .unwrap();

        let mut data = Vec::with_capacity(shuffle_proof.serialized_size());
        shuffle_proof.serialize(&mut data).unwrap();
        shuffle_proof = CanonicalDeserialize::deserialize(data.as_slice()).unwrap();

        assert_eq!(
            Ok(()),
            CardProtocol::verify_shuffle(
                &parameters,
                &aggregate_key,
                &deck,
                &shuffled_deck,
                &shuffle_proof
            )
        );

        let wrong_output: Vec<MaskedCard> = sample_vector(rng, m * n);

        assert_eq!(
            CardProtocol::verify_shuffle(
                &parameters,
                &aggregate_key,
                &deck,
                &wrong_output,
                &shuffle_proof
            ),
            Err(CryptoError::ProofVerificationError(String::from(
                "Hadamard Product (5.1)"
            )))
        )
    }
}
