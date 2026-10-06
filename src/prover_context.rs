//! Process-local immutable data shared by independent Stwo proofs.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock, RwLock};

use stwo::core::fri::FriConfig;
use stwo::core::pcs::PcsConfig;
use stwo::core::poly::circle::CanonicCoset;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::mempool::BaseColumnPool;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::poly::twiddles::TwiddleTree;

/// Estimated-memory budget for cached twiddle trees.  A count-based cap
/// cannot distinguish one 128 MiB `log_size = 25` tree from a few KiB of
/// small-domain trees; a byte budget keeps resident memory predictable
/// regardless of which domain sizes a workload uses.
const MAX_TWIDDLE_CACHE_BYTES: usize = 512 * 1024 * 1024;

/// Conservative resident-byte estimate for one `TwiddleTree<SimdBackend>`.
///
/// `SimdBackend` packs 4 M31 lanes (4 bytes each) per element and the tree
/// stores forward and inverse twiddles for the half-coset tower, so roughly
/// `2^(log_size + 1)` bytes per direction.  The estimate intentionally errs
/// on the high side so the budget never undercounts real usage.
fn estimated_twiddle_bytes(domain_log_size: u32) -> usize {
    let shift = (domain_log_size + 2).min(usize::BITS - 1);
    1usize << shift
}

type TwiddleCache = BTreeMap<u32, Arc<TwiddleTree<SimdBackend>>>;

static TWIDDLE_CACHE: OnceLock<RwLock<TwiddleCache>> = OnceLock::new();
static BASE_COLUMN_POOL: OnceLock<BaseColumnPool<SimdBackend>> = OnceLock::new();

/// Canonical PCS profile for every production Texas AIR proof.
///
/// This is deliberately equivalent to Stwo 2.3's current default: 10 PoW
/// bits plus 30 FRI bits (`log_blowup_factor = 1`, `n_queries = 30`). Keeping
/// it local prevents an upstream default change from silently changing proof
/// compatibility or soundness. Alternative equal-security FRI configurations
/// must be benchmarked and adopted here atomically by prover and verifier.
///
/// Security budget (stwo conjectured model): `pow_bits + log_blowup ×
/// n_queries = 10 + 1×30 = 40` bits.
pub(crate) fn protocol_pcs_config() -> PcsConfig {
    PcsConfig {
        pow_bits: 10,
        fri_config: FriConfig::new(0, 1, 30, 1),
        lifting_log_size: None,
    }
}

/// 128-bit (conjectured, stwo model) PCS profile for one-hand canonical
/// proofs: `8 PoW + 4 blowup × 30 queries = 128` bits.
///
/// The 4× LDE and 2^8 PoW grinding are negligible for the fixed small
/// domains a single hand occupies (≤ 2^10 rows); the 30-query count keeps
/// verifier work at the familiar production level. Prover and verifier MUST
/// adopt the same profile atomically (the profile is mixed into the
/// Fiat--Shamir channel), so this helper is the single source both sides
/// pass to the `*_with_pcs` entry points.
pub fn security_128_pcs_config() -> PcsConfig {
    PcsConfig {
        pow_bits: 8,
        fri_config: FriConfig::new(0, 4, 30, 1),
        lifting_log_size: None,
    }
}

/// Return process-local reusable LDE column storage.
///
/// The pool contains only temporary base-field buffers. Commitment generation
/// overwrites each buffer before it is read, so reuse cannot carry witness or
/// Fiat--Shamir state between independent proofs. The underlying pool is
/// concurrent and is safe for Rayon proof workers.
pub(crate) fn simd_base_column_pool() -> &'static BaseColumnPool<SimdBackend> {
    BASE_COLUMN_POOL.get_or_init(BaseColumnPool::new)
}

/// Return immutable SIMD twiddles for a PCS evaluation domain.
///
/// Twiddles depend only on the domain, never on the trace, AIR, public
/// inputs, or Fiat--Shamir channel. Keeping a small process-local cache is
/// therefore safe across independent proofs while avoiding repeated setup on
/// the latency-sensitive single-method path.
pub(crate) fn simd_twiddles(domain_log_size: u32) -> Arc<TwiddleTree<SimdBackend>> {
    let cache = TWIDDLE_CACHE.get_or_init(|| RwLock::new(BTreeMap::new()));
    if let Some(twiddles) = cache
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&domain_log_size)
    {
        return Arc::clone(twiddles);
    }

    // Precomputation is deliberately outside the write lock. Different cold
    // domains must not block readers or serialize one another unnecessarily.
    let twiddles = Arc::new(SimdBackend::precompute_twiddles(
        CanonicCoset::new(domain_log_size).half_coset(),
    ));
    let mut cache = cache
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(existing) = cache.get(&domain_log_size) {
        return Arc::clone(existing);
    }
    cache.insert(domain_log_size, Arc::clone(&twiddles));
    // Evict smallest domains first when the budget is exceeded: they are the
    // cheapest to rebuild and typically the least contended.
    let mut total: usize = cache.keys().map(|key| estimated_twiddle_bytes(*key)).sum();
    while total > MAX_TWIDDLE_CACHE_BYTES && cache.len() > 1 {
        let smallest = *cache.keys().next().expect("cache is non-empty");
        total -= estimated_twiddle_bytes(smallest);
        cache.remove(&smallest);
    }
    twiddles
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_pcs_profile_stays_at_forty_bits() {
        assert_eq!(protocol_pcs_config().security_bits(), 40);
    }

    #[test]
    fn security_128_profile_reaches_128_bits() {
        let config = security_128_pcs_config();
        assert_eq!(config.security_bits(), 128);
        assert_eq!(config.fri_config.log_blowup_factor, 4);
        assert_eq!(config.fri_config.n_queries, 30);
        assert_eq!(config.pow_bits, 8);
    }

    #[test]
    fn twiddle_byte_estimate_grows_with_domain_and_budget_evicts_smallest() {
        // A larger domain must estimate strictly more bytes.
        assert!(estimated_twiddle_bytes(25) > estimated_twiddle_bytes(10));
        // Typical production domains fit comfortably inside the budget.
        assert!(estimated_twiddle_bytes(24) < MAX_TWIDDLE_CACHE_BYTES);
        // Even one extreme domain never evicts itself: the eviction loop
        // keeps at least the freshly inserted entry resident.
    }
}
