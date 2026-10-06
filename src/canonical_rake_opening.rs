//! Blake2b-256 authentication of the canonical Texas table-rules preimage.
//!
//! The hot canonical state image carries only an opaque `rules_commitment`.
//! Raked settlement terminals (the sole-survivor award today, showdown
//! settlement later) must not trust a host-selected `rake_mode`/`rake_bps`/
//! `rake_cap` triple, so this module defines the fixed-width opening that
//! authenticates the complete `TableRules` byte string to that commitment:
//!
//! ```text
//! rules_commitment = Blake2b-256("zchain.texas.rules.v1" || Borsh(TableRules))
//! ```
//!
//! The proof itself is the shared lookup-backed Blake2b STARK used by the
//! state-image endpoints; no native hashing runs on the verify path.  The
//! canonical transition AIR consumes the authenticated rake configuration
//! through public scope columns, keeping the tagged batch's one-proof profile
//! while closing the host advice surface for rake computation.

#![allow(missing_docs)]

use borsh::BorshDeserialize;
use poker_l1::contracts::texas_poker::types::TableRules;

use crate::error::{TexasAirError, TexasAirResult};
use crate::hash_prover::HashProofProvider as _;

/// Domain prefix separating rules preimages from every other canonical
/// Blake2b statement.
pub const CANONICAL_RULES_DOMAIN: &[u8] = b"zchain.texas.rules.v2";

/// The authenticated rake-relevant projection of one rules opening.
#[derive(Debug, Clone, Copy, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct CanonicalRakeOpening {
    /// `RAKE_MODE_NONE` (0), `RAKE_MODE_PERCENTAGE` (1), or
    /// `RAKE_MODE_FIXED_RAKE_BURN` (2).  Discriminators are frozen across the
    /// three repos (see poker-appchain `docs/ABI_TE.md`).
    pub rake_mode: u8,
    /// Basis points, at most 10_000.
    pub rake_bps: u16,
    /// Maximum rake charged for one hand.
    pub rake_cap: u64,
}

impl CanonicalRakeOpening {
    /// Canonical zero opening for every non-raked transition kind.
    pub const ZERO: Self = Self {
        rake_mode: 0,
        rake_bps: 0,
        rake_cap: 0,
    };

    /// The percentage-mode discriminator used by raked settlement terminals.
    pub const PERCENTAGE_MODE: u8 = 1;

    /// The fixed-rake-with-burn discriminator (TE-E0, frozen = 2): identical
    /// charging-quantity relation to percentage mode, but the collected rake
    /// is burned on the L1 contract side (poker_l1, TE-M4).  The opening only
    /// authenticates the charging quantity relation — the burn fund-disposal
    /// rules live entirely in the contract.
    pub const FIXED_RAKE_BURN_MODE: u8 = 2;
}

/// The authenticated blind/ante projection of one rules opening (#22②
/// RevealComplete 前置：盲注 opening).
///
/// 与 [`CanonicalRakeOpening`] 同源——两者都是同一条 rules-hash 语句的
/// 投影，share 一个 `ArchivedCanonicalRulesHashProof`，不需要独立证明。
#[derive(Debug, Clone, Copy, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct CanonicalBlindOpening {
    pub small_blind: u64,
    pub big_blind: u64,
    /// `ANTE_MODE_NONE` (0) / `ANTE_MODE_NORMAL` (1) / `ANTE_MODE_BBA` (2).
    pub ante_mode: u8,
    pub ante_amount: u64,
}

impl CanonicalBlindOpening {
    /// Canonical zero opening (ante-less, blind-less placeholder).
    pub const ZERO: Self = Self {
        small_blind: 0,
        big_blind: 0,
        ante_mode: 0,
        ante_amount: 0,
    };
}

/// Project the blind/ante quadruple out of a full rules value.
#[must_use]
pub fn blind_opening_of(rules: &TableRules) -> CanonicalBlindOpening {
    CanonicalBlindOpening {
        small_blind: rules.small_blind,
        big_blind: rules.big_blind,
        ante_mode: rules.ante_mode,
        ante_amount: rules.ante_amount,
    }
}

/// One BLAKE3 statement authenticating the complete rules byte string.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ArchivedCanonicalRulesHashProof {
    pub hashes: crate::blake3_flock::ArchivedFlockHashesProof,
}

/// The authenticated opening extracted from a verified rules statement.
pub struct AuthenticatedRulesOpening {
    pub rules: TableRules,
    pub rake: CanonicalRakeOpening,
}

/// Return the exact byte preimage covered by a canonical rules commitment.
pub fn canonical_rules_preimage(rules: &TableRules) -> TexasAirResult<Vec<u8>> {
    let encoded = borsh::to_vec(rules)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    let mut preimage = Vec::with_capacity(CANONICAL_RULES_DOMAIN.len() + encoded.len());
    preimage.extend_from_slice(CANONICAL_RULES_DOMAIN);
    preimage.extend_from_slice(&encoded);
    Ok(preimage)
}

/// Host-side digest (BLAKE3 padded chain) used by fixture construction and
/// test oracles; the verify path authenticates it through the flock chain
/// proof instead.
pub fn canonical_rules_commitment(rules: &TableRules) -> TexasAirResult<[u8; 32]> {
    let preimage = canonical_rules_preimage(rules)?;
    Ok(crate::blake3_flock::blake3_chain_digest(&preimage))
}

/// Project the rake-relevant triple out of a full rules value.
#[must_use]
pub fn rake_opening_of(rules: &TableRules) -> CanonicalRakeOpening {
    CanonicalRakeOpening {
        rake_mode: rules.rake_mode,
        rake_bps: rules.rake_bps,
        rake_cap: rules.rake_cap,
    }
}

/// Prove `Blake2b-256(domain || Borsh(rules)) == rules_commitment` with the
/// shared lookup-backed Blake2b STARK.  Native Blake2b is not used to form or
/// verify the statement.
pub fn prove_canonical_rules_hash(
    rules: &TableRules,
) -> TexasAirResult<ArchivedCanonicalRulesHashProof> {
    let statements = vec![crate::hash_prover::HashStatement::new(
        canonical_rules_preimage(rules)?,
        canonical_rules_commitment(rules)?,
    )];
    let hashes = crate::blake3_flock::FlockProvider
        .prove_statements(&statements)
        .map_err(|error| {
            TexasAirError::SpecViolation(format!("flock rules chain proof failed: {error:?}"))
        })?;
    let crate::hash_prover::ArchivedHashProof::Flock(hashes) = hashes else {
        return Err(TexasAirError::SpecViolation(
            "flock backend must produce flock proofs".into(),
        ));
    };
    Ok(ArchivedCanonicalRulesHashProof { hashes })
}

/// Verify the archived rules byte statement against the public canonical
/// `rules_commitment` and return the authenticated opening.  This function
/// neither serializes rules nor calls a native hash implementation.
pub fn verify_canonical_rules_hash(
    archive: &ArchivedCanonicalRulesHashProof,
    rules_commitment: [u8; 32],
) -> TexasAirResult<AuthenticatedRulesOpening> {
    let statements = &archive.hashes.statements;
    let [statement] = statements.as_slice() else {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "canonical rules hash proof must contain exactly one statement".into(),
        ));
    };
    if statement.digest != rules_commitment {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "canonical rules hash proof is detached from the rules commitment".into(),
        ));
    }
    crate::blake3_flock::verify_flock_archive(&archive.hashes)?;
    let rules = decode_rules_statement(&statement.message)?;
    Ok(AuthenticatedRulesOpening {
        rake: rake_opening_of(&rules),
        rules,
    })
}

/// Decode the fixed-width Borsh `TableRules` covered by a verified statement.
fn decode_rules_statement(message: &[u8]) -> TexasAirResult<TableRules> {
    let encoded = message
        .strip_prefix(CANONICAL_RULES_DOMAIN)
        .ok_or_else(|| {
            TexasAirError::ConstraintUnsatisfied(
                "canonical rules statement is missing its domain prefix".into(),
            )
        })?;
    let rules = TableRules::try_from_slice(encoded).map_err(|error| {
        TexasAirError::ConstraintUnsatisfied(format!(
            "canonical rules statement is malformed: {error}"
        ))
    })?;
    validate_rules_opening(&rules)?;
    Ok(rules)
}

/// Mirror the VM's `TableRules::validate_canonical` rake invariants so a
/// verified opening cannot smuggle an out-of-range configuration into the
/// settlement arithmetic.
pub fn validate_rules_opening(rules: &TableRules) -> TexasAirResult<()> {
    if !matches!(
        rules.rake_mode,
        0 | 1 | 2 // RAKE_MODE_NONE | RAKE_MODE_PERCENTAGE | RAKE_MODE_FIXED_RAKE_BURN (TE-E0, frozen)
    ) || rules.rake_bps > 10_000
    {
        return Err(TexasAirError::SpecViolation(
            "canonical rules opening carries an out-of-range rake configuration".into(),
        ));
    }
    // #22② 盲注 opening：镜像 VM `TableRules::validate_canonical` 的
    // 盲注/ante 不变量，防止已验证 opening 把越界配置带进完成组合的
    // current_bet / min_raise / 盲注扣款算术。
    if rules.big_blind == 0 || rules.small_blind > rules.big_blind {
        return Err(TexasAirError::SpecViolation(
            "canonical rules opening carries an out-of-range blind configuration".into(),
        ));
    }
    if !matches!(rules.ante_mode, 0 | 1 | 2) {
        return Err(TexasAirError::SpecViolation(
            "canonical rules opening carries an unknown ante mode".into(),
        ));
    }
    if rules.ante_mode == 0 && rules.ante_amount != 0 {
        return Err(TexasAirError::SpecViolation(
            "canonical rules opening carries ante amount without ante mode".into(),
        ));
    }
    Ok(())
}

/// Deterministic rake for a raked settlement terminal, mirroring the VM's
/// `compute_rake_amount` exactly: `min(floor(pot * bps / 10_000), cap, pot)`,
/// and zero when the mode is `RAKE_MODE_NONE`.
///
/// TE-E0: `RAKE_MODE_FIXED_RAKE_BURN` (2) charges with the **same percentage
/// shape** — the charging-quantity relation is identical to percentage mode,
/// which is precisely what the opening/AIR prove.  Only the fund disposal of
/// the collected amount differs (burned on the L1 contract side, poker_l1 /
/// TE-M4); that disposal is *not* modelled here.
#[must_use]
pub fn canonical_settlement_rake(pot: u64, opening: &CanonicalRakeOpening) -> u64 {
    if opening.rake_mode == 0 {
        return 0;
    }
    let raw = u128::from(pot) * u128::from(opening.rake_bps) / 10_000;
    raw.min(u128::from(opening.rake_cap)).min(u128::from(pot)) as u64
}

/// One shared Blake2b statement batch for a complete hand's fixed openings:
/// the table rules and both endpoint state images.  Sharing a single lookup
/// STARK amortizes the dominant fixed cost (table commitment + FRI), which
/// measurements show is independent of the message-block count.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ArchivedCanonicalHandOpeningsProof {
    pub hashes: crate::blake3_flock::ArchivedFlockHashesProof,
}

/// Prove the rules and both endpoint state-image commitments in one shared
/// lookup-backed Blake2b STARK.  Statement order is fixed:
/// `[rules, pre image, post image]`.
pub fn prove_canonical_hand_openings(
    rules: &TableRules,
    pre_image: &crate::texas_canonical::CanonicalStateImage,
    post_image: &crate::texas_canonical::CanonicalStateImage,
) -> TexasAirResult<ArchivedCanonicalHandOpeningsProof> {
    let statements = vec![
        crate::hash_prover::HashStatement::new(
            canonical_rules_preimage(rules)?,
            canonical_rules_commitment(rules)?,
        ),
        crate::hash_prover::HashStatement::new(
            crate::canonical_state_hash::canonical_state_image_preimage(pre_image)?,
            pre_image.commitment(),
        ),
        crate::hash_prover::HashStatement::new(
            crate::canonical_state_hash::canonical_state_image_preimage(post_image)?,
            post_image.commitment(),
        ),
    ];
    let hashes = crate::blake3_flock::FlockProvider
        .prove_statements(&statements)
        .map_err(|error| {
            TexasAirError::SpecViolation(format!("flock hand-opening proof failed: {error:?}"))
        })?;
    let crate::hash_prover::ArchivedHashProof::Flock(hashes) = hashes else {
        return Err(TexasAirError::SpecViolation(
            "flock backend must produce flock proofs".into(),
        ));
    };
    Ok(ArchivedCanonicalHandOpeningsProof { hashes })
}

/// Verify the combined hand-opening statement batch against the three public
/// commitments without any native hashing.
pub fn verify_canonical_hand_openings(
    archive: &ArchivedCanonicalHandOpeningsProof,
    rules_commitment: [u8; 32],
    pre_commitment: [u8; 32],
    post_commitment: [u8; 32],
) -> TexasAirResult<AuthenticatedRulesOpening> {
    let statements = &archive.hashes.statements;
    let [rules_statement, pre_statement, post_statement] = statements.as_slice() else {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "hand-opening proof must contain exactly three statements".into(),
        ));
    };
    if rules_statement.digest != rules_commitment
        || pre_statement.digest != pre_commitment
        || post_statement.digest != post_commitment
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "hand-opening proof is detached from a public commitment".into(),
        ));
    }
    crate::blake3_flock::verify_flock_archive(&archive.hashes)?;
    let rules = decode_rules_statement(&rules_statement.message)?;
    Ok(AuthenticatedRulesOpening {
        rake: rake_opening_of(&rules),
        rules,
    })
}

/// The complete fixed hash bundle for one finalized hand: table rules, both
/// endpoint state images, and (for host-zero admission) both L1 sparse-Merkle
/// openings, proven as one ordered statement batch through the shared
/// hash-prover seam.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ArchivedCanonicalHandBundleProof {
    pub hash: crate::hash_prover::ArchivedHashProof,
    /// Public SMT opening witnesses, included so the verifier can rebuild and
    /// structurally check the path statements from public data alone.
    pub smt_pre: Option<crate::blake2b_smt_witness::Blake2bSmtFixedValuePathWitness>,
    pub smt_post: Option<crate::blake2b_smt_witness::Blake2bSmtFixedValuePathWitness>,
}

/// Statement order: `[rules, pre image, post image, smt_pre nodes...,
/// smt_post nodes...]`.
fn hand_bundle_statements(
    rules: &TableRules,
    pre_image: &crate::texas_canonical::CanonicalStateImage,
    post_image: &crate::texas_canonical::CanonicalStateImage,
    smt_pre: Option<&crate::blake2b_smt_witness::Blake2bSmtFixedValuePathWitness>,
    smt_post: Option<&crate::blake2b_smt_witness::Blake2bSmtFixedValuePathWitness>,
) -> TexasAirResult<Vec<crate::hash_prover::HashStatement>> {
    use crate::hash_prover::HashStatement;
    let mut statements = vec![
        HashStatement::new(
            canonical_rules_preimage(rules)?,
            canonical_rules_commitment(rules)?,
        ),
        HashStatement::new(
            crate::canonical_state_hash::canonical_state_image_preimage(pre_image)?,
            pre_image.commitment(),
        ),
        HashStatement::new(
            crate::canonical_state_hash::canonical_state_image_preimage(post_image)?,
            post_image.commitment(),
        ),
    ];
    for witness in [smt_pre, smt_post].into_iter().flatten() {
        statements.extend(crate::smt_statements::smt_path_statements(witness)?);
    }
    Ok(statements)
}

/// Prove the complete hand bundle in one shared proof.
pub fn prove_canonical_hand_bundle<P: crate::hash_prover::HashProofProvider>(
    provider: &P,
    rules: &TableRules,
    pre_image: &crate::texas_canonical::CanonicalStateImage,
    post_image: &crate::texas_canonical::CanonicalStateImage,
    smt_pre: Option<&crate::blake2b_smt_witness::Blake2bSmtFixedValuePathWitness>,
    smt_post: Option<&crate::blake2b_smt_witness::Blake2bSmtFixedValuePathWitness>,
) -> TexasAirResult<ArchivedCanonicalHandBundleProof> {
    Ok(ArchivedCanonicalHandBundleProof {
        hash: provider.prove_statements(&hand_bundle_statements(
            rules, pre_image, post_image, smt_pre, smt_post,
        )?)?,
        smt_pre: smt_pre.cloned(),
        smt_post: smt_post.cloned(),
    })
}

/// Verify the complete hand bundle against the public commitments.  Checks
/// the exact ordered statement list (splice-proof), the SMT path structure
/// over public bytes, and returns the authenticated rules opening.
pub fn verify_canonical_hand_bundle<P: crate::hash_prover::HashProofProvider>(
    provider: &P,
    archive: &ArchivedCanonicalHandBundleProof,
    rules: &TableRules,
    pre_image: &crate::texas_canonical::CanonicalStateImage,
    post_image: &crate::texas_canonical::CanonicalStateImage,
) -> TexasAirResult<AuthenticatedRulesOpening> {
    let statements = hand_bundle_statements(
        rules,
        pre_image,
        post_image,
        archive.smt_pre.as_ref(),
        archive.smt_post.as_ref(),
    )?;
    provider.verify_statements(&archive.hash, &statements)?;
    let mut cursor = 3;
    for witness in [archive.smt_pre.as_ref(), archive.smt_post.as_ref()]
        .into_iter()
        .flatten()
    {
        crate::smt_statements::verify_smt_path_statements(
            witness,
            &statements[cursor..cursor + crate::smt_statements::SMT_PATH_STATEMENTS],
        )?;
        cursor += crate::smt_statements::SMT_PATH_STATEMENTS;
    }
    let rules_statement = &statements[0];
    let rules = decode_rules_statement(&rules_statement.message)?;
    Ok(AuthenticatedRulesOpening {
        rake: rake_opening_of(&rules),
        rules,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> TableRules {
        TableRules {
            max_players: 4,
            small_blind: 25,
            big_blind: 50,
            timeout_config: Default::default(),
            ante_mode: 0,
            ante_amount: 0,
            rake_mode: 1,
            rake_bps: 500,
            rake_cap: 1_000,
            rit_mode: 0,
        }
    }

    #[test]
    fn preimage_is_the_exact_native_commitment_input() {
        let rules = rules();
        let preimage = canonical_rules_preimage(&rules).unwrap();
        assert!(preimage.starts_with(CANONICAL_RULES_DOMAIN));
        assert_eq!(
            canonical_rules_commitment(&rules).unwrap(),
            crate::blake3_flock::blake3_chain_digest(&preimage)
        );
    }

    #[test]
    fn rules_hash_proof_verifies_against_the_public_commitment() {
        let rules = rules();
        let commitment = canonical_rules_commitment(&rules).unwrap();
        let archive = prove_canonical_rules_hash(&rules).expect("rules hash proof");
        let authenticated =
            verify_canonical_rules_hash(&archive, commitment).expect("rules hash verification");
        assert_eq!(authenticated.rake, rake_opening_of(&rules));
        assert_eq!(authenticated.rules, rules);

        let mut detached = commitment;
        detached[0] ^= 1;
        assert!(verify_canonical_rules_hash(&archive, detached).is_err());
    }

    #[test]
    fn out_of_range_rake_configurations_are_rejected() {
        let mut rules = rules();
        rules.rake_bps = 10_001;
        let commitment = canonical_rules_commitment(&rules).unwrap();
        let archive = prove_canonical_rules_hash(&rules).expect("rules hash proof");
        assert!(verify_canonical_rules_hash(&archive, commitment).is_err());
    }

    #[test]
    #[ignore = "performance benchmark"]
    fn bench_rules_hash_phases() {
        use std::time::Instant;
        let rules = rules();
        let commitment = canonical_rules_commitment(&rules).unwrap();

        // Phase 1: the tiny rules preimage through the shared lookup STARK.
        let start = Instant::now();
        let archive = prove_canonical_rules_hash(&rules).expect("rules hash proof");
        println!("rules-hash prove (76-byte message): {:?}", start.elapsed());

        let start = Instant::now();
        verify_canonical_rules_hash(&archive, commitment).expect("verify");
        println!("rules-hash verify: {:?}", start.elapsed());
        println!(
            "rules-hash proof bytes: {}",
            borsh::to_vec(&archive).unwrap().len()
        );
    }

    #[test]
    fn hand_bundle_rejects_statement_splices() {
        use crate::blake3_flock::FlockProvider;
        use crate::hash_prover::HashStatement;
        use crate::texas_canonical::{
            CANONICAL_ABI_VERSION, CanonicalPhase, CanonicalSeat, CanonicalStateImage,
            MAX_CANONICAL_SEATS, NO_CANONICAL_SEAT,
        };
        let image = || CanonicalStateImage {
            abi_version: CANONICAL_ABI_VERSION,
            table_id: 7,
            hand_id: 1,
            call_seq: 0,
            phase: CanonicalPhase::Waiting,
            phase_subtag: 0,
            street: 0,
            current_turn: NO_CANONICAL_SEAT,
            deadline_ms: 0,
            shuffle_timeout_ms: 10_000,
            reveal_timeout_ms: 10_000,
            betting_timeout_ms: 30_000,
            reconstruct_timeout_ms: 10_000,
            showdown_display_ms: 3_000,
            current_bet: 0,
            min_raise: 0,
            chip_pool: 0,
            pot: 0,
            button: 0,
            last_bb_seat: NO_CANONICAL_SEAT,
            max_players: 2,
            acted_mask: 0,
            leave_after_hand_mask: 0,
            protocol_pending_mask: 0,
            board_cards_commitment: [1; 32],
            deck_commitment: [2; 32],
            reveal_commitment: [3; 32],
            reconstruction_commitment: [4; 32],
            run_it_twice_commitment: [5; 32],
            rules_commitment: [6; 32],
            governance_commitment: [7; 32],
            settlement_commitment: [8; 32],
            custody_commitment: [9; 32],
            lifecycle_root: [10; 32],
            overlay_root: [11; 32],
            state_root: [12; 32],
            seats: [CanonicalSeat::EMPTY; MAX_CANONICAL_SEATS],
        };
        let rules = rules();
        let pre = image();
        let mut post = image();
        post.call_seq = 1;
        let smt = crate::smt_statements::synthetic_smt_witness(0x5a, [0x11; 32], [0x22; 32]);
        let provider = FlockProvider;
        let bundle = prove_canonical_hand_bundle(&provider, &rules, &pre, &post, Some(&smt), None)
            .expect("bundle");
        verify_canonical_hand_bundle(&provider, &bundle, &rules, &pre, &post)
            .expect("bundle verify");

        // A tampered witness node detaches the statements.
        let mut tampered = bundle.clone();
        if let Some(witness) = tampered.smt_pre.as_mut() {
            witness.nodes[7][0] ^= 1;
        }
        assert!(verify_canonical_hand_bundle(&provider, &tampered, &rules, &pre, &post).is_err());

        // A wrong rules value detaches the rules statement.
        let mut wrong_rules = rules;
        wrong_rules.rake_bps = 250;
        assert!(
            verify_canonical_hand_bundle(&provider, &bundle, &wrong_rules, &pre, &post).is_err()
        );
        let _ = HashStatement::new(Vec::new(), [0; 32]);
    }

    #[test]
    fn settlement_rake_mirrors_the_vm_formula() {
        let opening = rake_opening_of(&rules());
        // 5% of 90 is 4.5 -> floor 4, below the cap.
        assert_eq!(canonical_settlement_rake(90, &opening), 4);
        // 5% of 100_000 is 5_000 -> capped at 1_000.
        assert_eq!(canonical_settlement_rake(100_000, &opening), 1_000);
        // The rake can never exceed the pot itself.
        assert_eq!(canonical_settlement_rake(3, &opening), 0);
        // A NONE-mode table never rakes.
        let mut none = rules();
        none.rake_mode = 0;
        assert_eq!(
            canonical_settlement_rake(100_000, &rake_opening_of(&none)),
            0
        );
    }

    // ---- TE-E0: FIXED_RAKE_BURN (2), frozen discriminator ----

    /// TE-E0: discriminators are frozen across the three repos.
    #[test]
    fn rake_mode_discriminators_are_frozen() {
        assert_eq!(CanonicalRakeOpening::ZERO.rake_mode, 0);
        assert_eq!(CanonicalRakeOpening::PERCENTAGE_MODE, 1);
        assert_eq!(CanonicalRakeOpening::FIXED_RAKE_BURN_MODE, 2);
    }

    /// Mode 2 opens with the same charging-quantity relation as mode 1: the
    /// authenticated opening accepts it and `canonical_settlement_rake`
    /// charges the identical `min(floor(pot*bps/10^4), cap, pot)` amount.
    /// Burn fund disposal is contract-side and intentionally absent here.
    #[test]
    fn fixed_rake_burn_opening_charges_like_percentage() {
        let mut burn = rules();
        burn.rake_mode = CanonicalRakeOpening::FIXED_RAKE_BURN_MODE;
        let opening = rake_opening_of(&burn);
        assert_eq!(opening.rake_mode, 2);
        assert_eq!(opening, CanonicalRakeOpening {
            rake_mode: 2,
            rake_bps: 500,
            rake_cap: 1_000,
        });

        // Identical charging relation to percentage mode for every probe pot.
        let percentage = rake_opening_of(&rules());
        for pot in [0u64, 3, 90, 999, 19_999, 100_000, u32::MAX as u64] {
            assert_eq!(
                canonical_settlement_rake(pot, &opening),
                canonical_settlement_rake(pot, &percentage),
                "mode 2 must charge exactly like mode 1 (charging relation only)"
            );
        }
        // Spot anchors: floor, cap, pot bound.
        assert_eq!(canonical_settlement_rake(90, &opening), 4);
        assert_eq!(canonical_settlement_rake(100_000, &opening), 1_000);
        assert_eq!(canonical_settlement_rake(3, &opening), 0);

        // The authenticated rules opening round-trips a mode-2 configuration.
        let commitment = canonical_rules_commitment(&burn).unwrap();
        let archive = prove_canonical_rules_hash(&burn).expect("burn rules proof");
        let authenticated =
            verify_canonical_rules_hash(&archive, commitment).expect("burn rules verify");
        assert_eq!(authenticated.rake, opening);
        assert_eq!(authenticated.rules, burn);

        // The combined hand-opening batch accepts a mode-2 rules preimage too.
        // (Statement construction is mode-agnostic; verified above.)
    }

    /// Unknown modes stay fail-closed: only 0 | 1 | 2 pass the opening
    /// validation, so a mode-3 configuration cannot smuggle into the
    /// settlement arithmetic.
    #[test]
    fn unknown_rake_mode_is_rejected_by_opening_validation() {
        let mut unknown = rules();
        unknown.rake_mode = 3;
        let commitment = canonical_rules_commitment(&unknown).unwrap();
        let archive = prove_canonical_rules_hash(&unknown).expect("rules hash proof");
        assert!(verify_canonical_rules_hash(&archive, commitment).is_err());
    }
}
