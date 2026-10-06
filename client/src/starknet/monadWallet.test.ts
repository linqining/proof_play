/**
 * monadWallet 纯函数单元测试——地址派生与 tx 参数编码。
 *
 * 已知向量来源（本会话 2026-09-28 实测）：
 *   - operator 地址 0xbcd7ecd68d55ca2536f3f50dcbcb44edb0d97aa6 与其 EIP-55
 *     校验和形式 0xbcD7eCD68D55ca2536F3F50dcbCB44EDb0d97aA6：
 *     `cast to-check-sum-address` 输出（跨工具核对）；
 *   - chainId 10143 = 0x279f：testnet-rpc.monad.xyz eth_chainId 实测返回；
 *   - gasPrice 102 gwei = 0x17bfac7c00：同上 eth_gasPrice 实测；
 *   - 计费模型：limit = est×11/10 + 1（scripts/deploy_wrap_monad.sh:66 同式）。
 *
 * 约束：本文件不含也不需要私钥——地址派生（EIP-55）与 tx 编码都是
 * 公开数据的纯函数；私钥侧派生属于注入钱包 / zchain monad-settlement
 * Rust signer（secp256k1）职责。
 */
import { describe, expect, it } from 'vitest';

import {
  MONAD_TESTNET_CHAIN_ID_HEX,
  buildMonadTxParams,
  formatWeiToEther,
  fromHexQuantity,
  monadLoginMessageHash,
  normalizeEvmAddress,
  parseEtherToWei,
  toEip55Address,
  toHexQuantity,
} from './monadWallet';

const OPERATOR_LOWER = '0xbcd7ecd68d55ca2536f3f50dcbcb44edb0d97aa6';
const OPERATOR_UPPER = '0xBCD7ECD68D55CA2536F3F50DCBCB44EDB0D97AA6';
const OPERATOR_CHECKSUM = '0xbcD7eCD68D55ca2536F3F50dcbCB44EDb0d97aA6';

describe('monadWallet 地址派生', () => {
  it('EIP-55 校验和派生命中 cast 已知向量（operator 地址）', () => {
    expect(toEip55Address(OPERATOR_LOWER)).toBe(OPERATOR_CHECKSUM);
  });

  it('派生幂等：对校验和形式再派生结果不变', () => {
    expect(toEip55Address(OPERATOR_CHECKSUM)).toBe(OPERATOR_CHECKSUM);
  });

  it('大写输入同样派生出唯一校验和形式', () => {
    expect(toEip55Address(OPERATOR_UPPER)).toBe(OPERATOR_CHECKSUM);
  });

  it('派生结果满足 EIP-55 全字母参与校验（换一位大小写即破坏一致性）', () => {
    // 破坏校验和后再派生，应回到正确形式（说明大小写由哈希决定，非透传）
    const tampered = OPERATOR_CHECKSUM.replace('bcD7', 'BCD7');
    expect(toEip55Address(tampered.toLowerCase())).toBe(OPERATOR_CHECKSUM);
  });

  it('normalizeEvmAddress：合法地址归一小写，非法输入返回 null', () => {
    expect(normalizeEvmAddress(OPERATOR_CHECKSUM)).toBe(OPERATOR_LOWER);
    expect(normalizeEvmAddress(` ${OPERATOR_LOWER} `)).toBe(OPERATOR_LOWER);
    expect(normalizeEvmAddress('0x1234')).toBeNull(); // 长度不足
    expect(normalizeEvmAddress(`0x${'ab'.repeat(21)}`)).toBeNull(); // 超长
    expect(normalizeEvmAddress('0xzzd7ecd68d55ca2536f3f50dcbcb44edb0d97aa6')).toBeNull(); // 非 hex
    expect(normalizeEvmAddress(OPERATOR_LOWER.slice(2))).toBeNull(); // 缺 0x
  });

  it('toEip55Address 拒绝非法地址', () => {
    expect(() => toEip55Address('0x1234')).toThrow(/invalid EVM address/);
  });
});

describe('monadWallet 数量编码', () => {
  it('toHexQuantity：0 → 0x0，无前导零；10143 → 0x279f（实测 chainId）', () => {
    expect(toHexQuantity(0n)).toBe('0x0');
    expect(toHexQuantity(10143n)).toBe(MONAD_TESTNET_CHAIN_ID_HEX);
    expect(toHexQuantity(102_000_000_000n)).toBe('0x17bfac7c00');
  });

  it('toHexQuantity 拒绝负数', () => {
    expect(() => toHexQuantity(-1n)).toThrow(/negative/);
  });

  it('fromHexQuantity 与 toHexQuantity 互逆；非法输入抛错', () => {
    expect(fromHexQuantity('0x279f')).toBe(10143n);
    expect(fromHexQuantity(toHexQuantity(1444765243886829568n))).toBe(1444765243886829568n);
    expect(() => fromHexQuantity('102')).toThrow(/invalid hex quantity/);
    expect(() => fromHexQuantity('0x')).toThrow(/invalid hex quantity/);
  });

  it('parseEtherToWei：整数/小数/实测余额', () => {
    expect(parseEtherToWei('1')).toBe(10n ** 18n);
    expect(parseEtherToWei('0.01')).toBe(10n ** 16n);
    // operator 实测余额 0x14088ab0362c6400
    expect(parseEtherToWei('1.4448')).toBe(1444800000000000000n);
  });

  it('parseEtherToWei 拒绝非法金额（负号/多小数位/空串）', () => {
    expect(() => parseEtherToWei('-1')).toThrow(/invalid ether amount/);
    expect(() => parseEtherToWei('1.2345678901234567890')).toThrow(/invalid ether amount/);
    expect(() => parseEtherToWei('')).toThrow(/invalid ether amount/);
  });

  it('formatWeiToEther：实测余额按 6 位截断展示', () => {
    expect(formatWeiToEther(1444765243886829568n)).toBe('1.444765');
    expect(formatWeiToEther(10n ** 18n, 2)).toBe('1.00');
    expect(formatWeiToEther(0n)).toBe('0.000000');
  });
});

describe('monadWallet tx 参数编码（Monad 计费纪律）', () => {
  it('自转账：est=21000 → gas=0x5a3d(23101)=est×1.1+1，gasPrice 原样（实测 102 gwei）', () => {
    const params = buildMonadTxParams(21000n, 102_000_000_000n, {
      to: OPERATOR_LOWER,
      value: 0n,
    });
    expect(params.gas).toBe('0x5a3d');
    expect(BigInt(params.gas)).toBe(21000n * 11n / 10n + 1n);
    expect(params.gasPrice).toBe('0x17bfac7c00');
    expect(params.to).toBe(OPERATOR_LOWER);
    expect(params.value).toBe('0x0');
  });

  it('非整除估计向上取整：est=21001 → ceil(23101.1)=23102', () => {
    const params = buildMonadTxParams(21001n, 1n);
    expect(BigInt(params.gas)).toBe(23102n);
  });

  it('合约调用意图：data 原样透传（batchCount() 选择子）', () => {
    const params = buildMonadTxParams(30_000n, 102_000_000_000n, {
      to: '0x60ecddd1359356a43a69de84a1cf235a69a30e71',
      data: '0x06f13056',
    });
    expect(params.data).toBe('0x06f13056');
    expect(params.to).toBe('0x60ecddd1359356a43a69de84a1cf235a69a30e71');
  });

  it('拒绝非法估计/价格（≤0）', () => {
    expect(() => buildMonadTxParams(0n, 1n)).toThrow(/bad gas estimate/);
    expect(() => buildMonadTxParams(100n, 0n)).toThrow(/bad gas price/);
  });

  it('登录消息摘要与 evmKeccak KAT 同源（monadLoginMessageHash）', () => {
    expect(monadLoginMessageHash('zgame-login')).toBe(
      '0x5320d7bb4915fc74b6e5e8dc0aab67e0f6e782379f342a76bc20ec4ac88f98b0',
    );
  });
});
