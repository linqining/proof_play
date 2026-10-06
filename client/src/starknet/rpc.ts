// 多 RPC failover provider —— Plan C 的多提交/读取入口。
//
// Proxy 包装 N 个 RpcProvider：异步调用按健康端点轮转派发；某端点抛错即熔断
// COOLDOWN_MS 并自动换下一个端点重试，全部端点失败才向上抛错（此时顺带
// 解除熔断，给端点恢复机会）。同步成员直接绑定到当前端点。
//
// 余额读取、回执等待（含 paymaster 广播交易的等待）都经由 getProvider()
// 获得该层；直签回退路径的交易本身由钱包/Controller 的 RPC 提交，不受此层
// 管辖（见 原 docs/starknet-plan-c-execution.md（git 历史） 的边界说明）。

import { RpcProvider } from 'starknet';
import { logger } from '../helpers/logger';

/** 单端点失败后的熔断时长。 */
const COOLDOWN_MS = 30_000;

export function createFailoverProvider(urls: string[]): RpcProvider {
  if (urls.length === 0) {
    throw new Error('[starknet-rpc] at least one RPC URL is required');
  }
  const providers = urls.map((nodeUrl) => new RpcProvider({ nodeUrl }));
  const blockedUntil = urls.map(() => 0);
  let cursor = 0;

  /** 健康端点下标；全熔断时退化为全列表（下次调用给所有端点重试机会）。 */
  const healthyIndexes = (): number[] => {
    const now = Date.now();
    const healthy = urls.map((_, i) => i).filter((i) => blockedUntil[i] <= now);
    return healthy.length > 0 ? healthy : urls.map((_, i) => i);
  };

  /** 依次尝试健康端点；失败端点熔断并轮转到下一个。 */
  const attempt = async (prop: string, args: unknown[]): Promise<unknown> => {
    const order = healthyIndexes();
    let lastError: unknown;
    for (const idx of order) {
      try {
        const provider = providers[idx];
        const fn = Reflect.get(provider, prop, provider) as (...a: unknown[]) => unknown;
        return await fn.apply(provider, args);
      } catch (err) {
        lastError = err;
        blockedUntil[idx] = Date.now() + COOLDOWN_MS;
        logger.warn(
          `[starknet-rpc] ${prop} failed on ${urls[idx]}; failing over (${order.length - 1} candidates left)`,
          err,
        );
      }
    }
    throw lastError;
  };

  return new Proxy(providers[0], {
    get(_target, prop) {
      if (typeof prop === 'symbol') {
        return Reflect.get(providers[0], prop, providers[0]);
      }
      cursor = (cursor + 1) % providers.length;
      const provider = providers[cursor];
      const value = Reflect.get(provider, prop, provider);
      if (typeof value !== 'function') {
        return value;
      }
      return (...args: unknown[]) => {
        const result = (value as (...a: unknown[]) => unknown).apply(provider, args);
        if (
          result !== null &&
          typeof result === 'object' &&
          typeof (result as Promise<unknown>).then === 'function'
        ) {
          // 异步成员统一改走 attempt()，失败可在端点间轮转重试。
          return attempt(prop, args);
        }
        return result;
      };
    },
  }) as RpcProvider;
}
