// ABIs for the Starknet contracts the zgame client interacts with.
//
// The Cairo contracts (poker_vault.cairo, poker_settlement.cairo)
// live in poker_texas_air/poker_contracts. Only the external surface that the
// client calls is exposed here; the vault is the only entry point for chip
// buy-in, and the settlement contract is read-only from the client side.
//
// All ABIs use the CamelCase ERC20 variant (balanceOf, transferFrom, approve,
// allowance) which is the variant the contracts are written against.

/** Canonical Starknet Sepolia STRK20 token. Used for all chip buy-in. */
export const STRK20_SEPOLIA_ADDRESS =
  '0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d';

/** OpenZeppelin ERC20 + IERC20Camel (Cairo) — surface used by STRK. */
export const STRK20_ABI = [
  {
    type: 'function',
    name: 'name',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ type: 'core::byte_array::ByteArray' }],
  },
  {
    type: 'function',
    name: 'symbol',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ type: 'core::byte_array::ByteArray' }],
  },
  {
    type: 'function',
    name: 'decimals',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ type: 'core::integer::u8' }],
  },
  {
    type: 'function',
    name: 'balanceOf',
    stateMutability: 'view',
    inputs: [{ name: 'account', type: 'core::starknet::contract_address::ContractAddress' }],
    outputs: [{ type: 'core::integer::u256' }],
  },
  {
    // Cairo-native selector variant — both the canonical STRK token and the
    // deployed PokerSTRK expose snake_case entry points.
    type: 'function',
    name: 'balance_of',
    stateMutability: 'view',
    inputs: [{ name: 'account', type: 'core::starknet::contract_address::ContractAddress' }],
    outputs: [{ type: 'core::integer::u256' }],
  },
  {
    type: 'function',
    name: 'allowance',
    stateMutability: 'view',
    inputs: [
      { name: 'owner', type: 'core::starknet::contract_address::ContractAddress' },
      { name: 'spender', type: 'core::starknet::contract_address::ContractAddress' },
    ],
    outputs: [{ type: 'core::integer::u256' }],
  },
  {
    type: 'function',
    name: 'transfer',
    stateMutability: 'external',
    inputs: [
      { name: 'recipient', type: 'core::starknet::contract_address::ContractAddress' },
      { name: 'amount', type: 'core::integer::u256' },
    ],
    outputs: [{ type: 'core::bool' }],
  },
  {
    type: 'function',
    name: 'transferFrom',
    stateMutability: 'external',
    inputs: [
      { name: 'sender', type: 'core::starknet::contract_address::ContractAddress' },
      { name: 'recipient', type: 'core::starknet::contract_address::ContractAddress' },
      { name: 'amount', type: 'core::integer::u256' },
    ],
    outputs: [{ type: 'core::bool' }],
  },
  {
    type: 'function',
    name: 'approve',
    stateMutability: 'external',
    inputs: [
      { name: 'spender', type: 'core::starknet::contract_address::ContractAddress' },
      { name: 'amount', type: 'core::integer::u256' },
    ],
    outputs: [{ type: 'core::bool' }],
  },
] as const;

/** IPokerVault — chip deposit/withdraw surface. */
export const POKER_VAULT_ABI = [
  {
    type: 'function',
    name: 'token',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ type: 'core::starknet::contract_address::ContractAddress' }],
  },
  {
    type: 'function',
    name: 'total_chips',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ type: 'core::integer::u256' }],
  },
  {
    type: 'function',
    name: 'chip_balance',
    stateMutability: 'view',
    inputs: [{ name: 'player', type: 'core::starknet::contract_address::ContractAddress' }],
    outputs: [{ type: 'core::integer::u256' }],
  },
  {
    type: 'function',
    name: 'deposit',
    stateMutability: 'external',
    inputs: [{ name: 'amount', type: 'core::integer::u256' }],
    outputs: [],
  },
  {
    // P1-2 会话委托：caller（玩家钱包）为自己登记 VM 层交易签名公钥。
    // 买入 multicall 与 deposit 同笔提交；latest-wins，过期需为未来时间。
    type: 'function',
    name: 'set_session_tx_pk',
    stateMutability: 'external',
    inputs: [
      { name: 'pk', type: 'core::felt252' },
      { name: 'expires_at', type: 'core::integer::u64' },
    ],
    outputs: [],
  },
  {
    type: 'function',
    name: 'deposit_for',
    stateMutability: 'external',
    inputs: [
      { name: 'player', type: 'core::starknet::contract_address::ContractAddress' },
      { name: 'amount', type: 'core::integer::u256' },
    ],
    outputs: [],
  },
  {
    type: 'function',
    name: 'withdraw',
    stateMutability: 'external',
    inputs: [{ name: 'amount', type: 'core::integer::u256' }],
    outputs: [],
  },
  {
    type: 'function',
    name: 'paused',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ type: 'core::bool' }],
  },
] as const;

/**
 * IPokerVaultAnonymizer — STRK20 privacy-pool helper (Plan B). The privacy
 * pool calls `privacy_invoke` from inside a private transaction: it converts
 * pool-supplied STRK into chips for `player` and returns the change as an
 * open note. The client never calls it directly; the ABI is kept for
 * reference, config checks, and STRK20 wallet-API action composition.
 */
export const POKER_VAULT_ANONYMIZER_ABI = [
  {
    type: 'function',
    name: 'vault',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ type: 'core::starknet::contract_address::ContractAddress' }],
  },
  {
    type: 'function',
    name: 'pool',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ type: 'core::starknet::contract_address::ContractAddress' }],
  },
  {
    type: 'function',
    name: 'privacy_withdraw',
    stateMutability: 'external',
    inputs: [
      { name: 'player', type: 'core::starknet::contract_address::ContractAddress' },
      { name: 'amount', type: 'core::integer::u256' },
      { name: 'recipient_note_id', type: 'core::felt252' },
    ],
    outputs: [
      {
        type: 'core::array::Span::<poker_contracts::poker_vault_anonymizer::OpenNoteDeposit>',
      },
    ],
  },
  {
    type: 'function',
    name: 'privacy_invoke',
    stateMutability: 'external',
    inputs: [
      { name: 'player', type: 'core::starknet::contract_address::ContractAddress' },
      { name: 'amount', type: 'core::integer::u256' },
      { name: 'change_note_id', type: 'core::felt252' },
    ],
    outputs: [
      {
        type: 'core::array::Span::<poker_contracts::poker_vault_anonymizer::OpenNoteDeposit>',
      },
    ],
  },
] as const;

/** IPokerSettlement — read-only from the client. */
export const POKER_SETTLEMENT_ABI = [
  {
    type: 'function',
    name: 'vault',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ type: 'core::starknet::contract_address::ContractAddress' }],
  },
  {
    type: 'function',
    name: 'hand_settled',
    stateMutability: 'view',
    inputs: [{ name: 'hand_id', type: 'core::integer::u64' }],
    outputs: [{ type: 'core::bool' }],
  },
  {
    type: 'function',
    name: 'settlement_digest',
    stateMutability: 'view',
    inputs: [{ name: 'hand_id', type: 'core::integer::u64' }],
    outputs: [{ type: 'core::felt252' }],
  },
] as const;
