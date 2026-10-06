//! Host-verified administrator authorization bound into method AIRs.
//!
//! Transaction signature verification remains at the authenticated consensus
//! boundary. This module consumes that exact dispatch context and performs the
//! contract-level authorization check (`caller == table.creator`), then issues
//! a domain-separated request/receipt digest pair. The binding is projected
//! into every creator-only method AIR row, so an administrator action proof
//! cannot be detached from its caller, public key, selector, arguments,
//! table, state transition, or dispatch digest.

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use stwo::core::fields::m31::M31;

use crate::error::{TexasAirError, TexasAirResult};
use crate::method_kind::MethodKind;
use crate::precompile_binding::{DIGEST_LIMBS, digest_to_m31_limbs};
use crate::prove_task::dispatch_call_digest;
use crate::state_root::StateRoot;

/// Canonical administrator-authorization ABI version.
pub const ADMIN_AUTH_ABI_VERSION: u8 = 1;

/// AIR-visible role identifier for the table creator.
pub const TABLE_CREATOR_ROLE: u8 = 1;

/// AIR projection of a verifier-issued administrator authorization receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminAuthorizationAirBinding {
    /// Authorization request ABI version.
    pub abi_version: u8,
    /// Required administrator role.
    pub role: u8,
    /// Full canonical authorization-request digest.
    pub request_digest: [M31; DIGEST_LIMBS],
    /// Full verifier-issued successful-receipt digest.
    pub receipt_digest: [M31; DIGEST_LIMBS],
}

impl AdminAuthorizationAirBinding {
    /// Zero binding for explicitly synthetic mechanism tests only.
    #[cfg(any(test, feature = "test-helpers"))]
    #[must_use]
    pub fn synthetic_unverified() -> Self {
        Self {
            abi_version: 0,
            role: 0,
            request_digest: [M31::from(0u32); DIGEST_LIMBS],
            receipt_digest: [M31::from(0u32); DIGEST_LIMBS],
        }
    }
}

/// Verifier-issued capability proving that canonical dispatch authorization passed.
///
/// Fields are private and there is no deserializer or unchecked constructor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminAuthorizationBinding {
    abi_version: u8,
    role: u8,
    request_digest: [u8; 32],
    receipt_digest: [u8; 32],
}

impl AdminAuthorizationBinding {
    /// Verify the table-creator role and bind its complete dispatch scope.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_table_creator(
        kind: MethodKind,
        context: &poker_l1::contracts::dispatch::DispatchContext,
        selector: &[u8; 32],
        raw_args: &[u8],
        creator: poker_l1::Address,
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
        pre_version: u64,
        post_version: u64,
        pre_state_root: StateRoot,
        post_state_root: StateRoot,
        expected_dispatch_digest: [u8; 32],
    ) -> TexasAirResult<Self> {
        if !matches!(
            kind,
            MethodKind::StartHand | MethodKind::ForceFold | MethodKind::KickPlayer
        ) {
            return Err(TexasAirError::SpecViolation(format!(
                "administrator authorization is not defined for {}",
                kind.method_name()
            )));
        }
        if selector != &kind.selector() {
            return Err(TexasAirError::SpecViolation(
                "administrator authorization selector does not match method kind".into(),
            ));
        }
        if context.caller != creator {
            return Err(TexasAirError::SpecViolation(format!(
                "{}: caller is not the table creator",
                kind.method_name()
            )));
        }
        let actual_dispatch_digest = dispatch_call_digest(context, selector, raw_args)?;
        if actual_dispatch_digest != expected_dispatch_digest {
            return Err(TexasAirError::SpecViolation(
                "administrator authorization dispatch digest mismatch".into(),
            ));
        }

        let caller_pubkey = borsh::to_vec(&context.caller_pubkey).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "administrator caller public key encoding failed: {error}"
            ))
        })?;
        let mut request = Vec::with_capacity(256 + raw_args.len() + caller_pubkey.len());
        request.extend_from_slice(&[ADMIN_AUTH_ABI_VERSION, TABLE_CREATOR_ROLE, kind as u8]);
        request.extend_from_slice(&context.caller);
        request.extend_from_slice(&(caller_pubkey.len() as u32).to_le_bytes());
        request.extend_from_slice(&caller_pubkey);
        request.extend_from_slice(&creator);
        request.extend_from_slice(&context.chain_id.to_le_bytes());
        request.extend_from_slice(&context.block_height.to_le_bytes());
        request.extend_from_slice(&context.block_timestamp.to_le_bytes());
        request.extend_from_slice(selector);
        request.extend_from_slice(&(raw_args.len() as u64).to_le_bytes());
        request.extend_from_slice(raw_args);
        request.extend_from_slice(&table_id.to_le_bytes());
        request.extend_from_slice(&hand_id.to_le_bytes());
        request.extend_from_slice(&call_seq.to_le_bytes());
        request.extend_from_slice(&pre_version.to_le_bytes());
        request.extend_from_slice(&post_version.to_le_bytes());
        request.extend_from_slice(&pre_state_root.bytes());
        request.extend_from_slice(&post_state_root.bytes());
        request.extend_from_slice(&actual_dispatch_digest);

        let request_digest = hash256(b"zchain.texas_poker.admin_auth.request.v1", &request);
        let mut receipt = Vec::with_capacity(4 + 32);
        receipt.extend_from_slice(&[
            ADMIN_AUTH_ABI_VERSION,
            TABLE_CREATOR_ROLE,
            1, // canonical native dispatch authorization backend
            1, // verified-success result
        ]);
        receipt.extend_from_slice(&request_digest);
        let receipt_digest = hash256(b"zchain.texas_poker.admin_auth.receipt.v1", &receipt);
        Ok(Self {
            abi_version: ADMIN_AUTH_ABI_VERSION,
            role: TABLE_CREATOR_ROLE,
            request_digest,
            receipt_digest,
        })
    }

    /// Convert the verifier-issued capability into AIR columns.
    #[must_use]
    pub fn air_binding(&self) -> AdminAuthorizationAirBinding {
        AdminAuthorizationAirBinding {
            abi_version: self.abi_version,
            role: self.role,
            request_digest: digest_to_m31_limbs(self.request_digest),
            receipt_digest: digest_to_m31_limbs(self.receipt_digest),
        }
    }

    /// Full canonical authorization-request digest.
    #[must_use]
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }

    /// Full verifier-issued successful-receipt digest.
    #[must_use]
    pub const fn receipt_digest(&self) -> [u8; 32] {
        self.receipt_digest
    }
}

fn hash256(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
    hasher.update(domain);
    hasher.update(&(payload.len() as u64).to_le_bytes());
    hasher.update(payload);
    let mut digest = [0u8; 32];
    hasher.finalize_variable(&mut digest).expect("32 <= 64");
    digest
}

#[cfg(test)]
mod tests {
    use super::*;
    use poker_l1::signature::TaggedPubkey;
    use poker_l1::contracts::dispatch::DispatchContext;

    fn context(caller: poker_l1::Address) -> DispatchContext {
        DispatchContext {
            caller,
            caller_pubkey: TaggedPubkey {
                tag: 0x11,
                raw: vec![7; 32],
            },
            chain_id: 9,
            block_height: 10,
            block_timestamp: 11,
        }
    }

    #[test]
    fn rejects_non_creator_and_binds_scope() {
        let creator = [3; 20];
        let good_context = context(creator);
        let selector = MethodKind::ForceFold.selector();
        let raw_args = vec![0];
        let dispatch_digest = dispatch_call_digest(&good_context, &selector, &raw_args).unwrap();
        let first = AdminAuthorizationBinding::verify_table_creator(
            MethodKind::ForceFold,
            &good_context,
            &selector,
            &raw_args,
            creator,
            1,
            2,
            3,
            4,
            5,
            StateRoot::zero(),
            StateRoot::zero(),
            dispatch_digest,
        )
        .unwrap()
        .air_binding();
        let second = AdminAuthorizationBinding::verify_table_creator(
            MethodKind::ForceFold,
            &good_context,
            &selector,
            &raw_args,
            creator,
            1,
            2,
            4,
            4,
            5,
            StateRoot::zero(),
            StateRoot::zero(),
            dispatch_digest,
        )
        .unwrap()
        .air_binding();
        assert_ne!(first.request_digest, second.request_digest);

        let bad_context = context([4; 20]);
        let bad_digest = dispatch_call_digest(&bad_context, &selector, &raw_args).unwrap();
        assert!(
            AdminAuthorizationBinding::verify_table_creator(
                MethodKind::ForceFold,
                &bad_context,
                &selector,
                &raw_args,
                creator,
                1,
                2,
                3,
                4,
                5,
                StateRoot::zero(),
                StateRoot::zero(),
                bad_digest,
            )
            .is_err()
        );
    }
}
