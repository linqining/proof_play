// Starknet Contract instances for the zgame frontend.
//
// starknet.js v8 switched to an options-object constructor: `new Contract({ abi,
// address, providerOrAccount })`. We also need the provider reference to call
// `waitForTransaction` (AccountInterface in v8 doesn't expose it).

import { Contract, RpcProvider, type Abi } from 'starknet';
import { STRK20_ABI, POKER_VAULT_ABI, POKER_SETTLEMENT_ABI } from './abis';
import { starknetConfig } from './config';
import { createFailoverProvider } from './rpc';

let _provider: RpcProvider | null = null;

/**
 * Lazy singleton RPC provider for read calls and receipt waits.
 * Plan C: wraps all configured endpoints (VITE_STARKNET_RPC_URLS + chain
 * defaults) in a failover proxy — an endpoint failure rotates to the next.
 */
export function getProvider(): RpcProvider {
  if (!_provider) {
    _provider = createFailoverProvider(starknetConfig.rpcUrls);
  }
  return _provider;
}

/** Read-only STRK20 token contract bound to the configured RPC provider. */
export function getStrk20Contract(): Contract {
  return new Contract({
    abi: STRK20_ABI as Abi,
    address: starknetConfig.strk20Address,
    providerOrAccount: getProvider(),
  });
}

/** Read-only PokerVault contract bound to the configured RPC provider. */
export function getPokerVaultReadContract(): Contract {
  if (!starknetConfig.pokerVaultAddress) {
    throw new Error(
      'PokerVault address is not configured. Set VITE_POKER_VAULT_ADDRESS.',
    );
  }
  return new Contract({
    abi: POKER_VAULT_ABI as Abi,
    address: starknetConfig.pokerVaultAddress,
    providerOrAccount: getProvider(),
  });
}

/** Read-only PokerSettlement contract bound to the configured RPC provider. */
export function getPokerSettlementReadContract(): Contract {
  if (!starknetConfig.pokerSettlementAddress) {
    throw new Error(
      'PokerSettlement address is not configured. Set VITE_POKER_SETTLEMENT_ADDRESS.',
    );
  }
  return new Contract({
    abi: POKER_SETTLEMENT_ABI as Abi,
    address: starknetConfig.pokerSettlementAddress,
    providerOrAccount: getProvider(),
  });
}