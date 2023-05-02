use anyhow::Ok;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use barnett_smart_card_protocol::discrete_log_cards;
use barnett_smart_card_protocol::BarnettSmartProtocol;

use anyhow;
use ark_ff::UniformRand;
use ark_std::cmp;
use ark_std::collections::HashMap;
use ark_std::iter::Iterator;
use ark_std::{rand::Rng, One};
use proof_essentials::homomorphic_encryption::el_gamal::ElGamal;
use proof_essentials::utils::permutation::Permutation;
use proof_essentials::utils::rand::sample_vector;
use proof_essentials::vector_commitment::pedersen::PedersenCommitment;
use proof_essentials::zkp::arguments::shuffle::proof::Proof;
use proof_essentials::zkp::proofs::{chaum_pedersen_dl_equality, schnorr_identification};
use rand::seq::SliceRandom;
use rand::thread_rng;
use thiserror::Error;

// Choose elliptic curve setting
type Curve = ark_bn254::G1Projective;
type Scalar = ark_bn254::Fr;

// Instantiate concrete type for our card protocol
type CardProtocol<'a> = discrete_log_cards::DLCards<'a, Curve>;
type CardParameters = discrete_log_cards::Parameters<Curve>;
type PublicKey = discrete_log_cards::PublicKey<Curve>;
type SecretKey = discrete_log_cards::PlayerSecretKey<Curve>;
type AggregatePublicKey = ark_bn254::G1Affine;

type Card = discrete_log_cards::Card<Curve>;
type MaskedCard = discrete_log_cards::MaskedCard<Curve>;
type RevealToken = discrete_log_cards::RevealToken<Curve>;

type ProofKeyOwnership = schnorr_identification::proof::Proof<Curve>;
type ShuffleProof = Proof<ark_bn254::Fr, ElGamal<Curve>, PedersenCommitment<Curve>>;
type RemaskingProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;
type RevealProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;

#[derive(Error, Debug, PartialEq)]
pub enum GameErrors {
    #[error("No such card in hand")]
    CardNotFound,

    #[error("Invalid card")]
    InvalidCard,
}

#[derive(PartialEq, Clone, Copy, Eq)]
pub enum Suite {
    Greet,
    Poison,
}

#[derive(PartialEq, Clone, Eq, Copy)]
pub struct MurderCard {
    suite: Suite,
}

impl MurderCard {
    pub fn new(suite: Suite) -> Self {
        Self { suite }
    }
}

impl std::fmt::Debug for MurderCard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let suite = match self.suite {
            Suite::Greet => "G",
            Suite::Poison => "P",
        };

        write!(f, "{}", suite)
    }
}

#[derive(Clone)]
pub struct Player {
    name: Vec<u8>,
    sk: SecretKey,
    pk: PublicKey,
    proof_key: ProofKeyOwnership,
    cards: Vec<MaskedCard>,
    opened_cards: Vec<Option<MurderCard>>,
}

impl Player {
    pub fn new<R: Rng>(rng: &mut R, pp: &CardParameters, name: &Vec<u8>) -> anyhow::Result<Self> {
        let (pk, sk) = CardProtocol::player_keygen(rng, pp)?;
        let proof_key = CardProtocol::prove_key_ownership(rng, pp, &pk, &sk, name)?;
        Ok(Self {
            name: name.clone(),
            sk,
            pk,
            proof_key,
            cards: vec![],
            opened_cards: vec![],
        })
    }

    pub fn cards(&self) -> Vec<MaskedCard> {
        self.cards.clone()
    }

    pub fn receive_card(&mut self, card: MaskedCard) {
        self.cards.push(card);
        self.opened_cards.push(None);
    }

    pub fn peek_at_card(
        &mut self,
        parameters: &CardParameters,
        mut reveal_tokens: Vec<(RevealToken, RevealProof, PublicKey)>,
        card_mappings: &HashMap<Card, MurderCard>,
        card: &MaskedCard,
    ) -> Result<(), anyhow::Error> {
        let i = self.cards.iter().position(|&x| x == *card);

        let i = i.ok_or(GameErrors::CardNotFound)?;

        //TODO add function to create that without the proof
        let rng = &mut thread_rng();
        let own_reveal_token = self.compute_reveal_token(rng, parameters, card)?;
        reveal_tokens.push(own_reveal_token);

        let unmasked_card = CardProtocol::unmask(&parameters, &reveal_tokens, card)?;
        let opened_card = card_mappings.get(&unmasked_card);
        let opened_card = opened_card.ok_or(GameErrors::InvalidCard)?;

        self.opened_cards[i] = Some(*opened_card);
        Ok(())
    }

    pub fn peek_my_cards(
        &mut self,
        parameters: &CardParameters,
        card_mappings: &HashMap<Card, MurderCard>,
        collection: &HashMap<MaskedCard, Vec<(RevealToken, RevealProof, PublicKey)>>,
    ) -> Result<(), anyhow::Error> {
        for card in self.cards.clone() {
            let reveal_tokens = collection.get(&card).ok_or(GameErrors::CardNotFound)?;
            self.peek_at_card(parameters, reveal_tokens.clone(), card_mappings, &card)?;
        }
        Ok(())
    }

    pub fn compute_reveal_token<R: Rng>(
        &self,
        rng: &mut R,
        pp: &CardParameters,
        card: &MaskedCard,
    ) -> anyhow::Result<(RevealToken, RevealProof, PublicKey)> {
        let (reveal_token, reveal_proof) =
            CardProtocol::compute_reveal_token(rng, &pp, &self.sk, &self.pk, card)?;

        Ok((reveal_token, reveal_proof, self.pk))
    }

    pub fn compute_my_reveal_tokens<R: Rng>(
        &self,
        rng: &mut R,
        pp: &CardParameters,
    ) -> anyhow::Result<HashMap<MaskedCard, (RevealToken, RevealProof, PublicKey)>> {
        let mut reveal_tokens = HashMap::new();
        for card in self.cards.clone() {
            let (reveal_token, reveal_proof) =
                CardProtocol::compute_reveal_token(rng, &pp, &self.sk, &self.pk, &card)?;
            reveal_tokens.insert(card, (reveal_token, reveal_proof, self.pk));
        }
        Ok(reveal_tokens)
    }

    pub fn compute_others_reveal_tokens<R: Rng>(
        &self,
        rng: &mut R,
        pp: &CardParameters,
        deck: &Vec<MaskedCard>,
    ) -> anyhow::Result<HashMap<MaskedCard, (RevealToken, RevealProof, PublicKey)>> {
        let mut reveal_tokens = HashMap::new();
        for card in deck {
            if !self.cards.contains(card) {
                let (reveal_token, reveal_proof) =
                    CardProtocol::compute_reveal_token(rng, &pp, &self.sk, &self.pk, card)?;
                reveal_tokens.insert(*card, (reveal_token, reveal_proof, self.pk));
            }
        }
        Ok(reveal_tokens)
    }
}

pub fn collect_reveal_tokens(
    deck: &Vec<MaskedCard>,
    reveal_tokens: HashMap<MaskedCard, (RevealToken, RevealProof, PublicKey)>,
    collection: &mut HashMap<MaskedCard, Vec<(RevealToken, RevealProof, PublicKey)>>,
) {
    for (card, token) in reveal_tokens {
        if deck.contains(&card) {
            let tokens = collection.entry(card).or_insert(Vec::new());
            if !tokens.contains(&token) {
                tokens.push(token);
            }
        }
    }
}

// Every player will have to calculate this function for cards that are in play
pub fn open_cards(
    parameters: &CardParameters,
    cards: Vec<MaskedCard>,
    card_mappings: &HashMap<Card, MurderCard>,
    collection: &HashMap<MaskedCard, Vec<(RevealToken, RevealProof, PublicKey)>>,
) -> Result<HashMap<MaskedCard, MurderCard>, anyhow::Error> {
    let mut opened_cards = HashMap::new();

    for card in cards {
        let reveal_tokens = collection.get(&card).ok_or(GameErrors::CardNotFound)?;
        let unmasked_card = CardProtocol::unmask(&parameters, reveal_tokens, &card)?;
        let opened_card = card_mappings.get(&unmasked_card);
        let opened_card = opened_card.ok_or(GameErrors::InvalidCard)?;
        opened_cards.insert(card, opened_card.clone());
    }
    Ok(opened_cards)
}

pub fn print_cards(
    name: String,
    cards: &Vec<MaskedCard>,
    mappings: &HashMap<MaskedCard, MurderCard>,
) {
    print!("{} ", name);
    for masked in cards {
        let opened_card = mappings.get(&masked).unwrap();
        print!(" {:?}", opened_card);
    }
    println!("");
}

fn encode_cards<R: Rng>(
    rng: &mut R,
    num_of_cards: usize,
) -> (Vec<Card>, HashMap<Card, MurderCard>) {
    let mut map: HashMap<Card, MurderCard> = HashMap::new();
    let plaintexts = (0..num_of_cards)
        .map(|_| Card::rand(rng))
        .collect::<Vec<_>>();

    // 4 guests
    for i in 0..40 {
        let greet_card = MurderCard::new(Suite::Greet);
        map.insert(plaintexts[i], greet_card);
    }

    // 2 killers
    for i in 0..2 {
        for j in 0..5 {
            // 5 poison cards
            let poison_card = MurderCard::new(Suite::Poison);
            map.insert(plaintexts[40 + i * 10 + j], poison_card);
        }
        for j in 5..10 {
            // 5 greet cards
            let greet_card = MurderCard::new(Suite::Greet);
            map.insert(plaintexts[40 + i * 10 + j], greet_card);
        }
    }

    (plaintexts, map)
}

fn chunk_permutation<R: Rng>(rng: &mut R, size: usize, chunk_size: usize) -> Vec<usize> {
    // permutation of cards
    let mut chunks = Vec::new();
    for i in (0..size).step_by(chunk_size) {
        let mut chunk: Vec<usize> = (i..i + 10).collect();
        chunk.shuffle(rng);
        chunks.push(chunk);
    }

    // permutation of chunks
    let permutation_chunk = Permutation::new(rng, size / chunk_size);
    let permuted_chunks: Vec<Vec<usize>> = permutation_chunk
        .mapping
        .iter()
        .map(|&pi| chunks[pi].clone())
        .collect();
    permuted_chunks.into_iter().flatten().collect()
}

// Shuffle cards by chunks (4 guest chunks and 2 killer chunks)
pub fn shuffle_chunks<R: Rng>(
    rng: &mut R,
    pp: &CardParameters,
    shared_key: &AggregatePublicKey,
    deck: &Vec<MaskedCard>,
    chunk_size: usize,
) -> anyhow::Result<(Vec<MaskedCard>, ShuffleProof)> {
    let permutation_vec = chunk_permutation(rng, deck.len(), chunk_size);
    let permutation = Permutation::from(&permutation_vec);
    let masking_factors: Vec<Scalar> = sample_vector(rng, deck.len());

    let (shuffled_deck, shuffle_proof) = CardProtocol::shuffle_and_remask(
        rng,
        &pp,
        &shared_key,
        &deck,
        &masking_factors,
        &permutation,
    )?;

    Ok((shuffled_deck, shuffle_proof))
}

pub fn draw_cards(player: &mut Player, deck: &Vec<MaskedCard>, amount: usize, offset: usize) {
    let end: usize = cmp::min(deck.len(), offset + amount);
    for i in offset..end {
        player.receive_card(deck[i]);
    }
}

fn main() -> anyhow::Result<()> {
    // Game coordinator prepares public parameters and encode the cards offline.
    // Game coordinator then calls `newGame()` create a game on chain with card_mapping contained.
    let m = 4;
    let n = 15;
    let chunk_size = 10;
    let num_of_cards = m * n;
    let rng = &mut thread_rng();

    let parameters = CardProtocol::setup(rng, m, n)?;
    let (encoded_cards, card_mappings) = encode_cards(rng, num_of_cards);

    // Each player creates a game key offline to `joinGame()` and smart contract run `verify_key_ownship()` on chain.
    // Note: If a game key is securely stored, it can be reused; however, if the key is leaked, it must be replaced.
    let mut andrija = Player::new(rng, &parameters, &b"Andrija".to_vec())?;
    let mut kobi = Player::new(rng, &parameters, &b"Kobi".to_vec())?;
    let mut nico = Player::new(rng, &parameters, &b"Nico".to_vec())?;
    let mut tom = Player::new(rng, &parameters, &b"Tom".to_vec())?;
    let mut jay = Player::new(rng, &parameters, &b"Jay".to_vec())?;
    let mut bob = Player::new(rng, &parameters, &b"Bob".to_vec())?;

    // Smart contract computes aggregation key on chain once all players have joined the game
    let players = vec![
        andrija.clone(),
        kobi.clone(),
        nico.clone(),
        tom.clone(),
        jay.clone(),
        bob.clone(),
    ];
    let key_proof_info = players
        .iter()
        .map(|p| (p.pk, p.proof_key, p.name.clone()))
        .collect::<Vec<_>>();
    let shared_key = CardProtocol::compute_aggregate_key(&parameters, &key_proof_info)?;

    // Smart contract creates initial deck on chain.
    // Also, each player should run this computation and verify offline so that all players agree on the initial deck.
    let mut deck_and_proofs: Vec<(MaskedCard, RemaskingProof)> = encoded_cards
        .iter()
        .map(|card| CardProtocol::mask(rng, &parameters, &shared_key, &card, &Scalar::one()))
        .collect::<Result<Vec<_>, _>>()?;

    deck_and_proofs = deck_and_proofs
        .iter()
        .map(|vdeck_and_proofs| {
            let mut proof = vdeck_and_proofs.1;
            let mut data = Vec::with_capacity(proof.compressed_size());
            proof.serialize_compressed(&mut data).unwrap();
            proof = CanonicalDeserialize::deserialize_compressed(data.as_slice()).unwrap();
            (vdeck_and_proofs.0, proof.clone())
        })
        .collect();

    let deck = deck_and_proofs
        .iter()
        .map(|x| x.0)
        .collect::<Vec<MaskedCard>>();

    // SHUFFLE CARDS --------------
    // 1.a Andrija shuffles first.
    //     Andrija shuffles deck offline and then calls `shuffleCards()` to put shuffled deck and proofs on chain.
    let (a_shuffled_deck, a_shuffle_proofs) =
        shuffle_chunks(rng, &parameters, &shared_key, &deck, chunk_size)?;

    // 1.b Smart contract checks the shuffle proofs!
    CardProtocol::verify_shuffle(
        &parameters,
        &shared_key,
        &deck,
        &a_shuffled_deck,
        &a_shuffle_proofs,
    )?;

    //2.a Kobi shuffles second
    //    Kobi shuffles deck offline and then calls `shuffleCards()` to put shuffled deck and proof on chain.
    let (k_shuffled_deck, k_shuffle_proofs) =
        shuffle_chunks(rng, &parameters, &shared_key, &a_shuffled_deck, chunk_size)?;

    //2.b Smart contract checks the shuffle proofs!
    CardProtocol::verify_shuffle(
        &parameters,
        &shared_key,
        &a_shuffled_deck,
        &k_shuffled_deck,
        &k_shuffle_proofs,
    )?;

    //3.a Nico shuffles third
    //    Nico shuffles deck offline and then calls `shuffleCards()` to put shuffled deck and proof on chain.
    let (n_shuffled_deck, n_shuffle_proofs) =
        shuffle_chunks(rng, &parameters, &shared_key, &k_shuffled_deck, chunk_size)?;

    //3.b Smart contract checks the shuffle proofs!
    CardProtocol::verify_shuffle(
        &parameters,
        &shared_key,
        &k_shuffled_deck,
        &n_shuffled_deck,
        &n_shuffle_proofs,
    )?;

    //4.a Tom shuffles fourth
    //    Tom shuffles deck offline and then calls `shuffleCards()` to put shuffled deck and proof on chain.
    let (t_shuffled_deck, t_shuffle_proofs) =
        shuffle_chunks(rng, &parameters, &shared_key, &n_shuffled_deck, chunk_size)?;

    //4.b Smart contract checks the shuffle proofs!
    CardProtocol::verify_shuffle(
        &parameters,
        &shared_key,
        &n_shuffled_deck,
        &t_shuffled_deck,
        &t_shuffle_proofs,
    )?;

    //5.a Jay shuffles fifth
    //    Jay shuffles deck offline and then calls `shuffleCards()` to put shuffled deck and proof on chain.
    let (j_shuffled_deck, j_shuffle_proofs) =
        shuffle_chunks(rng, &parameters, &shared_key, &t_shuffled_deck, chunk_size)?;

    //5.b Smart contract checks the shuffle proofs!
    CardProtocol::verify_shuffle(
        &parameters,
        &shared_key,
        &t_shuffled_deck,
        &j_shuffled_deck,
        &j_shuffle_proofs,
    )?;

    //6.a Bob shuffles last
    //    Bob shuffles deck offline and then calls `shuffleCards()` to put shuffled deck and proof on chain.
    let (b_shuffled_deck, b_shuffle_proofs) =
        shuffle_chunks(rng, &parameters, &shared_key, &j_shuffled_deck, chunk_size)?;

    //5.b Smart contract checks the shuffle proofs!
    CardProtocol::verify_shuffle(
        &parameters,
        &shared_key,
        &j_shuffled_deck,
        &b_shuffled_deck,
        &b_shuffle_proofs,
    )?;

    // CARDS ARE SHUFFLED. THE GAME CAN BEGIN
    let deck = b_shuffled_deck;

    // DRAW LOTS --------------
    // Each player `drawLots()` to get a chunk of cards in a row.
    draw_cards(&mut andrija, &deck, chunk_size, 0);
    draw_cards(&mut kobi, &deck, chunk_size, chunk_size * 1);
    draw_cards(&mut nico, &deck, chunk_size, chunk_size * 2);
    draw_cards(&mut tom, &deck, chunk_size, chunk_size * 3);
    draw_cards(&mut jay, &deck, chunk_size, chunk_size * 4);
    draw_cards(&mut bob, &deck, chunk_size, chunk_size * 5);

    // Each player computes reveal tokens offline
    let rts_andrija = andrija
        .compute_others_reveal_tokens(rng, &parameters, &deck)
        .unwrap();
    let rts_kobi = kobi
        .compute_others_reveal_tokens(rng, &parameters, &deck)
        .unwrap();
    let rts_nico = nico
        .compute_others_reveal_tokens(rng, &parameters, &deck)
        .unwrap();
    let rts_tom = tom
        .compute_others_reveal_tokens(rng, &parameters, &deck)
        .unwrap();
    let rts_jay = jay
        .compute_others_reveal_tokens(rng, &parameters, &deck)
        .unwrap();
    let rts_bob = bob
        .compute_others_reveal_tokens(rng, &parameters, &deck)
        .unwrap();

    // Each player sends 50 reveal tokens (of other players' cards) to coordinator.
    // Coordinator collects reveal tokens for each of the card.
    let mut collected_tokens: HashMap<MaskedCard, Vec<(RevealToken, RevealProof, PublicKey)>> =
        HashMap::new();
    collect_reveal_tokens(&deck, rts_andrija, &mut collected_tokens);
    collect_reveal_tokens(&deck, rts_kobi, &mut collected_tokens);
    collect_reveal_tokens(&deck, rts_nico, &mut collected_tokens);
    collect_reveal_tokens(&deck, rts_tom, &mut collected_tokens);
    collect_reveal_tokens(&deck, rts_jay, &mut collected_tokens);
    collect_reveal_tokens(&deck, rts_bob, &mut collected_tokens);

    //At this moment players privately open their cards and they only know their own cards.
    andrija.peek_my_cards(&parameters, &card_mappings, &collected_tokens)?;
    kobi.peek_my_cards(&parameters, &card_mappings, &collected_tokens)?;
    nico.peek_my_cards(&parameters, &card_mappings, &collected_tokens)?;
    tom.peek_my_cards(&parameters, &card_mappings, &collected_tokens)?;
    jay.peek_my_cards(&parameters, &card_mappings, &collected_tokens)?;
    bob.peek_my_cards(&parameters, &card_mappings, &collected_tokens)?;

    /* Here we can add custom logic of a game:
        1. play card
        2. open card
        3. ...
    */

    //At this moment players reveal their cards to each other and everything becomes public.

    //1. everyone computes reveal tokens for their own cards.
    let rts_andrija = andrija.compute_my_reveal_tokens(rng, &parameters).unwrap();
    let rts_kobi = kobi.compute_my_reveal_tokens(rng, &parameters).unwrap();
    let rts_nico = nico.compute_my_reveal_tokens(rng, &parameters).unwrap();
    let rts_tom = tom.compute_my_reveal_tokens(rng, &parameters).unwrap();
    let rts_jay = jay.compute_my_reveal_tokens(rng, &parameters).unwrap();
    let rts_bob = bob.compute_my_reveal_tokens(rng, &parameters).unwrap();

    //2. Each player sends 10 reveal tokens (of their own cards) to coordinator.
    collect_reveal_tokens(&deck, rts_andrija, &mut collected_tokens);
    collect_reveal_tokens(&deck, rts_kobi, &mut collected_tokens);
    collect_reveal_tokens(&deck, rts_nico, &mut collected_tokens);
    collect_reveal_tokens(&deck, rts_tom, &mut collected_tokens);
    collect_reveal_tokens(&deck, rts_jay, &mut collected_tokens);
    collect_reveal_tokens(&deck, rts_bob, &mut collected_tokens);

    //3. Coordinator opens cards in play on chain.
    let andrija_cards = open_cards(
        &parameters,
        andrija.cards(),
        &card_mappings,
        &collected_tokens,
    )?;
    let kobi_cards = open_cards(&parameters, kobi.cards(), &card_mappings, &collected_tokens)?;
    let nico_cards = open_cards(&parameters, nico.cards(), &card_mappings, &collected_tokens)?;
    let tom_cards = open_cards(&parameters, tom.cards(), &card_mappings, &collected_tokens)?;
    let jay_cards = open_cards(&parameters, jay.cards(), &card_mappings, &collected_tokens)?;
    let bob_cards = open_cards(&parameters, bob.cards(), &card_mappings, &collected_tokens)?;

    print_cards(String::from("Andrija: "), &andrija.cards(), &andrija_cards);
    print_cards(String::from("Kobi:    "), &kobi.cards(), &kobi_cards);
    print_cards(String::from("Nico:    "), &nico.cards(), &nico_cards);
    print_cards(String::from("Tom:     "), &tom.cards(), &tom_cards);
    print_cards(String::from("Jay:     "), &jay.cards(), &jay_cards);
    print_cards(String::from("Bob:     "), &bob.cards(), &bob_cards);

    Ok(())
}
