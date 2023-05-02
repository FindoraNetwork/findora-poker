//=====================================================================================================================
//data structs

pub struct ClassicPlayingCard {
    value: Value,
    suite: Suite,
}

pub struct ADeckofPlayingCard {
    order: Vec<Card>,
    cards: HashMap<Card, ClassicPlayingCard>,
}

pub struct ClassicPlayingCard {
    value: Value,
    suite: Suite,
}

pub struct RevealTokenInfo {
    token: RevealToken,
    proof: RevealProof,
    pubkey: PublicKey,
}

pub struct Player {
    memo: Vec<u8>,
    sk: SecretKey,
    pk: PublicKey,
    proof_key: ProofKeyOwnership,
    cards: Vec<MaskedCard>,
    opened_cards: Vec<Option<ClassicPlayingCard>>,
}

type CardParameters = discrete_log_cards::Parameters<Curve>;
type PublicKey = discrete_log_cards::PublicKey<Curve>;
type SecretKey = discrete_log_cards::PlayerSecretKey<Curve>;
type AggregatePublicKey = GroupAffine<StarkwareParameters>;

type Card = discrete_log_cards::Card<Curve>;
type MaskedCard = discrete_log_cards::MaskedCard<Curve>;
type RevealToken = discrete_log_cards::RevealToken<Curve>;

type ProofKeyOwnership = schnorr_identification::proof::Proof<Curve>;
type ShuffleProof = Proof<Fp256<FrParameters>, ElGamal<Curve>, PedersenCommitment<Curve>>;
type RemaskingProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;
type RevealProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;

//=====================================================================================================================
APIs:

// =====================================================================game setup
// off-chain API
fn setup(
    m: usize,
    n: usize,
) -> Result<Parameters, CardProtocolError>

// on-chain API
fn setup(pp: Parameters) -> Result<(), CardProtocolError>


// =====================================================================player key generation
// off-chain API
fn player_keygen(
    pp: Parameters,
) -> Result<(PlayerPublicKey, PlayerSecretKey), CardProtocolError>

// compute aggregate public key
// on-chain API
fn compute_aggregate_key(
    pp: Parameters,
    player_keys_proof_info: Vec<(PlayerPublicKey, ZKProofKeyOwnership, Vec<u8>)>,
) -> Result<AggregatePublicKey, CardProtocolError>


// =====================================================================cards encoding
// encode initial deck of 52/54 cards (in fixed order, e.g., 2,3,4,5,6,7,8,9,10,J,Q,K,A)
// off-chain API
fn encode_cards_52() -> (Vec<Card>, Vec<ClassicPlayingCard>)
fn encode_cards_54() -> (Vec<Card>, Vec<ClassicPlayingCard>)
fn compute_initial_deck(cards: Vec<Card>) -> Result<Vec<MaskedCard>, CardProtocolError>

// on-chain API
fn encode_cards(Vec<Card>, Vec<ClassicPlayingCard>) -> Result<(), CryptoError>


// =====================================================================shuffle a deck
// off-chain API
fn shuffle_and_remask(
    pp: Parameters,
    shared_key: AggregatePublicKey,
    deck: Vec<MaskedCard>,
    masking_factors: Vec<Scalar>,
    permutation: Permutation,
) -> Result<(Vec<MaskedCard>, ZKProofShuffle), CardProtocolError>

// on-chain API
fn shuffle_and_remask(
    deck: Vec<MaskedCard>,
    shuffle_proof: ZKProofShuffle,
) -> Result<(), CryptoError>


// =====================================================================reveal cards
// off-chain API
fn compute_reveal_token(
    pp: CardParameters,
    card: MaskedCard,
) -> Result<RevealTokenInfo, CardProtocolError>

// on-chain API
fn open_cards(
    cards: Vec<MaskedCard>,
    reveal_tokens: Vec<Vec<RevealTokenInfo>>,
) -> Result<Vec<MaskedCard, MurderCard>, CardProtocolError>
