// 私密领取奖励弹窗（docs/design/SETTLEMENT_PRIVACY_PLAN.md Part C3）。
//
// 赢家筹码在 PokerVault 上，「领取」把筹码换成 STRK：
// - 私密领取（首选）：Ready 等 STRK20 钱包的两动作模式 —— 池内 burn
//   等额屏蔽 STRK + helper 烧毁 vault 筹码，产出 owner 隐藏的 open
//   note。链上只有池 envelope，看不出谁领了奖励。
// - 公开出金（回退）：vault.withdraw 直提钱包（边缘公开）。
// 私密路径需要：钱包支持 STRK20 Wallet API（capability 探测）且池内
// 屏蔽余额 ≥ 领取额（守恒在池内闭环）。
//
// UI v2（重构）：紧凑金额条 + 单个「领取条件」分组块（两张注册状态
// 行内聚，Wallet API 版本等噪音只在相关状态出现）+ 双列主行动按钮
// （按钮含义以小字注在按钮下方，不再用独立 footer 段落重复）。
// 宽度 md（480px），常规视口内不出现竖向滚动条。
import React, { useContext, useEffect, useState } from 'react';
import styled, { useTheme } from 'styled-components';
import { useAccount } from '@starknet-react/core';
import ModalShell from './ModalShell';
import Text from '../typography/Text';
import Button from '../buttons/Button';
import authContext from '../../context/auth/authContext';
import contentContext from '../../context/content/contentContext';
import { WEI_PER_CHIP, starknetConfig } from '../../starknet/config';
import {
  claimRewardsPrivate,
  claimRewardsPublic,
  detectStrk20Support,
  ensurePayoutCommitment,
  getRegisteredPayoutCommitment,
  getShieldedBalance,
  getVaultLockedBalanceWei,
  getVaultLockSession,
  unlockVaultAfterDeadline,
  getWalletApiVersions,
  shieldForPoolRegistration,
  walletErrText,
  STRK20_WALLET_API_MIN,
  compareVersions,
} from '../../starknet/strk20';
import { activeAccount } from '../../starknet/devAccount';
import { CANONICAL_STRK_ADDRESS } from '../../starknet/starknetGameActions';
import { logger } from '../../helpers/logger';

interface ClaimRewardsModalProps {
  isOpen: boolean;
  /** vault 可领筹码（服务端 chips 单位，1 chip = 1e15 wei）。 */
  chipsAmount: number | null;
  onClose: () => void;
}

// ===== 样式 =====

/** 紧凑金额条：左侧金额三行内聚为一行半，右侧收款地址，不再占半屏 */
const Hero = styled.div`
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 0.5rem;
  padding: 0.7rem 0.9rem;
  border-radius: ${({ theme }) => theme.radius.lg};
  background: linear-gradient(135deg, ${({ theme }) => theme.colors.primaryCta} 0%, ${({ theme }) => theme.colors.primaryCtaDarker} 100%);
  color: #fff;
  box-shadow: 0 6px 18px rgba(79, 70, 229, 0.3);
`;

const HeroLeft = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.1rem;
`;

const HeroLabel = styled.span`
  font-size: 0.68rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  opacity: 0.85;
`;

const HeroAmount = styled.span`
  font-size: 1.6rem;
  font-weight: 800;
  line-height: 1.15;
  font-variant-numeric: tabular-nums;
`;

const HeroSub = styled.span`
  font-size: 0.75rem;
  opacity: 0.85;
  font-variant-numeric: tabular-nums;
`;

const HeroAddr = styled.span`
  align-self: flex-end;
  flex: none;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.68rem;
  opacity: 0.75;
`;

/** 「领取条件」分组块：两张注册状态行 + 重新校验入口内聚在一个容器里 */
const CheckBlock = styled.section`
  display: flex;
  flex-direction: column;
  gap: 0.45rem;
  padding: 0.6rem 0.8rem;
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-radius: ${({ theme }) => theme.radius.md};
  background: ${({ theme }) => theme.colors.successAlpha06};
`;

const CheckHeader = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
`;

const CheckBlockTitle = styled.span`
  font-size: 0.7rem;
  font-weight: 700;
  letter-spacing: 0.05em;
  color: ${({ theme }) => theme.colors.softText};
`;

/** 单条状态行：状态点 + 名称 + 行内状态文本或一键注册按钮 */
const CheckRow = styled.div`
  display: flex;
  align-items: center;
  gap: 0.45rem;
`;

const CheckName = styled.span`
  flex: 1;
  min-width: 0;
  font-size: 0.85rem;
  font-weight: 600;
  color: ${({ theme }) => theme.colors.fontColorDark};
`;

const StatusDot = styled.span<{ $ok: boolean | null }>`
  width: 0.55rem;
  height: 0.55rem;
  border-radius: 50%;
  flex: none;
  background: ${({ $ok, theme }) =>
    $ok === null ? theme.colors.warning : $ok ? theme.colors.success : theme.colors.danger};
`;

const StatusText = styled.span<{ $ok: boolean | null }>`
  font-size: 0.75rem;
  font-weight: 600;
  flex: none;
  color: ${({ $ok, theme }) =>
    $ok === null ? theme.colors.warningDark : $ok ? theme.colors.successStrong : theme.colors.danger};
`;

/** 状态行下的次级信息行（仅在相关状态出现，避免噪音） */
const CheckDetail = styled.span`
  font-size: 0.72rem;
  line-height: 1.45;
  color: ${({ theme }) => theme.colors.mutedText};
  padding-left: 1rem;
`;

/** 行内的链接式小按钮（注册指引入口等） */
const CardLink = styled.button`
  align-self: flex-start;
  margin-left: 1rem;
  background: none;
  border: none;
  padding: 0;
  font-size: 0.72rem;
  color: ${({ theme }) => theme.colors.primaryCta};
  text-decoration: underline;
  cursor: pointer;
  &:disabled {
    opacity: 0.6;
    cursor: default;
  }
`;

/** 未注册池的引导区：钱包内 Shield 步骤（viewing key 只在钱包内，dapp 无法代注册） */
const GuideBox = styled.div`
  margin: 0.1rem 0 0 1rem;
  padding: 0.5rem 0.65rem;
  border-radius: ${({ theme }) => theme.radius.md};
  background: rgba(245, 158, 11, 0.08);
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 0.4rem;
`;

const GuideSteps = styled.ol`
  margin: 0;
  padding-left: 1.1rem;
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  font-size: 0.72rem;
  line-height: 1.5;
  color: ${({ theme }) => theme.colors.fontColorDark};
`;

const ReverifyLink = styled.button`
  background: none;
  border: none;
  padding: 0.1rem 0.3rem;
  font-size: 0.7rem;
  color: ${({ theme }) => theme.colors.mutedText};
  text-decoration: underline;
  cursor: pointer;
  &:hover:not(:disabled) {
    color: ${({ theme }) => theme.colors.fontColorDark};
  }
  &:disabled {
    opacity: 0.6;
    cursor: default;
  }
`;

/** 警告 / 错误条 */
const Notice = styled(Text)<{ $kind: 'warn' | 'error' | 'success' | 'info' }>`
  text-align: center;
  font-size: 0.78rem;
  padding: 0.5rem 0.7rem;
  border-radius: ${({ theme }) => theme.radius.md};
  word-break: break-word;
  ${({ $kind, theme }) => {
    if ($kind === 'warn')
      return `background: rgba(245, 158, 11, 0.12); color: ${theme.colors.warningDark};`;
    if ($kind === 'error')
      return `background: ${theme.colors.dangerAlpha06}; color: ${theme.colors.danger};`;
    if ($kind === 'info')
      return `background: rgba(59, 130, 246, 0.10); color: ${theme.colors.mutedText};`;
    return `background: ${theme.colors.successAlpha12}; color: ${theme.colors.successStrong};`;
  }}
`;

/** 双列主行动：按钮 + 下方一句说明（取代独立 footer 段落，说明与按钮同位） */
const ActionsGrid = styled.div`
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.6rem;

  @media screen and (max-width: 479px) {
    grid-template-columns: 1fr;
  }
`;

const ActionCell = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
`;

const ActionNote = styled.span`
  font-size: 0.68rem;
  line-height: 1.4;
  color: ${({ theme }) => theme.colors.softText};
  text-align: center;
`;

const SuccessRing = styled.div`
  width: 3.2rem;
  height: 3.2rem;
  margin: 0.2rem auto;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.6rem;
  color: ${({ theme }) => theme.colors.successStrong};
  background: ${({ theme }) => theme.colors.successAlpha12};
`;

/** '0.66' / '12' → wei（十进制字符串解析，最多 18 位小数）；非法返回 null。 */
function parseStrkToWei(s: string): bigint | null {
  const t = s.trim();
  if (!/^\d+(\.\d{1,18})?$/.test(t)) return null;
  const [int, dec = ''] = t.split('.');
  const wei = BigInt(int + dec.padEnd(18, '0'));
  return wei > 0n ? wei : null;
}

const ClaimModal: React.FC<ClaimRewardsModalProps> = ({ isOpen, chipsAmount, onClose }) => {
  const theme = useTheme();
  const { walletAddress } = useContext(authContext)!;
  const { getLocalizedString: t } = useContext(contentContext)!;
  const connected = useAccount();
  // 连接的钱包（Ready/Cartridge）优先，dev 直签兜底
  const account = activeAccount(connected.account);

  // 钱包网络守卫：Ready 重装/更新后默认主网，而 dapp 只在 Sepolia——主网
  // 语境下钱包不认 Sepolia STRK，私密操作直接被拒（151 "This token is not
  // supported for private tokens yet"）。进弹窗就明示，别等钱包给隐晦报错。
  // dev 直签账户没有 chainId 字段时视为匹配。
  const walletChainMismatch = (() => {
    const cid = (account as { chainId?: string } | null)?.chainId;
    if (!cid) return false;
    try {
      return BigInt(cid) !== BigInt(starknetConfig.chainId);
    } catch {
      return false;
    }
  })();

  const [strk20Ready, setStrk20Ready] = useState<boolean | null>(null);
  const [walletApiVersions, setWalletApiVersions] = useState<string[] | null>(null);
  const [shielded, setShielded] = useState<bigint | null>(null);
  const [pending, setPending] = useState<'private' | 'public' | null>(null);
  const [done, setDone] = useState<{ hash: string; kind: 'private' | 'public' } | null>(null);
  const [error, setError] = useState('');
  // 两份注册的真实状态（null = 检测中）。payout = 我们合约的 commitment，
  // pool = Ready 隐私池 viewing key（互不等同，各占一行）。
  const [reg, setReg] = useState<{ payout: boolean | null; pool: boolean | null; fromCache: boolean }>(
    { payout: null, pool: null, fromCache: false },
  );
  const [regPending, setRegPending] = useState(false);
  const [poolRegistering, setPoolRegistering] = useState(false);
  // 池注册指引的展开态：viewing key 只在钱包内，dapp 无法代注册——
  // 未注册用户点一键注册被钱包 118 拒绝时自动展开
  const [poolGuideOpen, setPoolGuideOpen] = useState(false);
  const [checking, setChecking] = useState(false);
  // #33 在局锁定余额（wei）：入座锁定的买入筹码，离桌后 TTL（12h）解锁；
  // 锁定部分不可领取/出金（burn_chips/withdraw 断言 spendable）
  const [lockedWei, setLockedWei] = useState<bigint | null>(null);
  // #33 解锁截止（unix 秒，0 = 无会话）+ 自助解锁 pending + 每秒走钟
  const [unlockDeadline, setUnlockDeadline] = useState<number>(0);
  // #33 解锁后全额可提，但玩家可能只想提一部分（如只取本局剩余、把
  // 其余留在 vault 备下次买入）——金额输入默认全额，可改小。
  const [amountStr, setAmountStr] = useState('');
  const [unlockPending, setUnlockPending] = useState(false);
  const [nowSec, setNowSec] = useState(() => Math.floor(Date.now() / 1000));
  useEffect(() => {
    const timer = window.setInterval(() => setNowSec(Math.floor(Date.now() / 1000)), 1000);
    return () => window.clearInterval(timer);
  }, []);

  const vaultAddr = starknetConfig.pokerVaultAddress || '';
  const flagsKey = `poker.claimReg:${(walletAddress || '').toLowerCase()}`;

  const readFlags = (): { vault: string; payout: boolean; pool: boolean } | null => {
    try {
      const raw = localStorage.getItem(flagsKey);
      if (!raw) return null;
      const f = JSON.parse(raw);
      if (f && f.vault === vaultAddr && vaultAddr !== '') return f;
    } catch { /* ignore */ }
    return null;
  };
  const writeFlags = (payout: boolean, pool: boolean) => {
    if (!walletAddress || !vaultAddr) return;
    try {
      localStorage.setItem(flagsKey, JSON.stringify({ vault: vaultAddr, payout, pool }));
    } catch { /* ignore */ }
  };
  const clearFlags = () => {
    if (!walletAddress) return;
    try { localStorage.removeItem(flagsKey); } catch { /* ignore */ }
  };

  const runChecks = React.useCallback(async (useCache: boolean) => {
    if (!account) return;
    setChecking(true);
    // cancelled 必须在下方缓存早退 return 之前初始化：锁定读取的 .then 闭包
    // 引用它，若走早退路径声明永不执行，回调必抛 TDZ ReferenceError 并被
    // .catch 吞掉 → 锁定行消失、按全额发交易撞 in-hand lock（2026-09-07）
    let cancelled = false;
    // #33 在局锁定余额随每手结算变化，不受注册缓存影响——每次打开实时查
    // （锁定量与解锁截止一起读：session_last_activity + lock_ttl）
    getVaultLockSession(account)
      .then((sess) => {
        if (cancelled) return;
        setLockedWei(sess ? sess.lockedWei : null);
        setUnlockDeadline(sess ? sess.unlockDeadlineSec : 0);
      })
      .catch((e) => {
        logger.warn('[ClaimModal] lock session read failed:', e);
        setLockedWei(null);
        setUnlockDeadline(0);
      });
    // 缓存快路径：两份注册都已确认 → 直接显示已注册态，不发任何链上查询/弹窗
    if (useCache) {
      const cached = readFlags();
      if (cached && cached.payout && cached.pool) {
        setReg({ payout: true, pool: true, fromCache: true });
        setStrk20Ready(true); // 缓存前提 = 此前钱包 API 可用（否则到不了已注册态）
        setChecking(false);
        return;
      }
    }
    let payout: boolean | null = null;
    let pool: boolean | null = null;
    // 版本先行：0.10.3 在列表里就点亮按钮（detectStrk20Support 的 V6 探测
    // 可能因 discovery 未就绪而慢一步，版本线是更快的权威信号）
    getWalletApiVersions().then((versions) => {
      if (cancelled) return;
      setWalletApiVersions(versions);
      if (versions.some((v) => compareVersions(v, STRK20_WALLET_API_MIN) >= 0)) {
        setStrk20Ready(true);
      }
    });
    await detectStrk20Support(account).then(async (ok) => {
      if (cancelled) return;
      setStrk20Ready((prev) => prev || ok);
      if (ok) {
        // 池内屏蔽余额按原生 STRK 查询（pSTRK 已弃用）
        await getShieldedBalance(account, CANONICAL_STRK_ADDRESS).then((bal) => {
          if (cancelled) return;
          // 查询成功 = 钱包在池内已注册（viewing key 可用；0 = 注册但无余额）
          if (bal !== null) pool = true;
          setShielded(bal);
        });
      }
      // 查询链上 payout commitment 注册状态（真实值，非客户端猜测）
      await getRegisteredPayoutCommitment(account).then((r) => {
        if (cancelled) return;
        payout = r !== null;
      });
      // 赔付承诺：打开弹窗时查询注册状态（已注册不发交易；未注册才可一键注册）
      try {
        const res = await ensurePayoutCommitment(account);
        if (!cancelled && res.status === 'registered') {
          payout = true;
        }
      } catch {
        if (!cancelled && payout === null) payout = false;
      }
    });
    if (!cancelled) {
      setReg({ payout: payout === true, pool: pool === true, fromCache: false });
    }
    setChecking(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [account, vaultAddr, walletAddress]);

  useEffect(() => {
    if (!isOpen || !account) return;
    setDone(null);
    setError('');
    setPoolGuideOpen(false);
    setAmountStr('');
    void runChecks(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOpen, account]);

  // 任一端完成注册后两份都齐 → 写一次性缓存（下次打开零查询）
  useEffect(() => {
    if (reg.payout === true && reg.pool === true) writeFlags(true, true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reg.payout, reg.pool]);

  const reverify = () => {
    clearFlags();
    void runChecks(false);
  };

  if (!isOpen) return null;

  const chips = Math.max(0, Math.floor(chipsAmount ?? 0));
  const fullAmountWei = BigInt(chips) * WEI_PER_CHIP;
  // #33 可提 = 余额 − 在局锁定（部分锁定时按未锁差额发交易；此前按全额
  // 发 → vault "Insufficient unlocked balance (in-hand lock)" 必拒）。
  const lockedPart = lockedWei && lockedWei > 0n ? lockedWei : 0n;
  const amountWei = fullAmountWei > lockedPart ? fullAmountWei - lockedPart : 0n;
  const claimableChips = Math.floor(Number(amountWei) / Number(WEI_PER_CHIP));
  const strkText = (Number(amountWei) / 1e18).toFixed(4);
  const lockedStrkText = (Number(lockedPart) / 1e18).toFixed(4);
  // 解锁状态：TTL 已过（任何人可自助 unlock_after_deadline）→ 展示解锁入口
  const lockExpired = unlockDeadline > 0 && nowSec >= unlockDeadline;
  const lockRemainingH = unlockDeadline > 0 ? Math.max(0, (unlockDeadline - nowSec) / 3600) : 0;
  const shieldedText = shielded !== null ? (Number(shielded) / 1e18).toFixed(4) : null;
  // 实际领取额：输入为空 = 全额可提；非空则按十进制字符串解析（避免
  // 0.66*1e18 的浮点尾差），并校验 0 < 额 ≤ 可提。
  const parsedWei = amountStr.trim() === '' ? amountWei : parseStrkToWei(amountStr);
  const amountInvalid =
    amountStr.trim() !== '' && (parsedWei === null || parsedWei <= 0n || parsedWei > amountWei);
  const claimWei = amountInvalid ? 0n : (parsedWei ?? 0n);

  const close = () => {
    setPending(null);
    setDone(null);
    setError('');
    onClose();
  };

  const handleClaim = async (kind: 'private' | 'public') => {
    if (!account || pending) return;
    if (amountInvalid || claimWei <= 0n) {
      // 全额被锁、余额为 0 或金额输入非法：锁定到期可自助解锁后全额领取
      setError(t('claim-blocked-locked'));
      return;
    }
    setPending(kind);
    setError('');
    const res =
      kind === 'private'
        ? await claimRewardsPrivate(account, { amountWei: claimWei })
        : await claimRewardsPublic(account, { amountWei: claimWei });
    setPending(null);
    if (res.success) {
      setDone({ hash: res.hash, kind });
    } else {
      setError(res.error || t('claim-error-failed'));
      logger.warn('[ClaimModal] claim failed:', res.error);
    }
  };

  // #33 到期自助解锁（无许可）：TTL 过后一键解除在局锁定
  const handleUnlock = async () => {
    if (!account || unlockPending) return;
    setUnlockPending(true);
    setError('');
    const res = await unlockVaultAfterDeadline(account);
    setUnlockPending(false);
    if (res.success) {
      setDone({ hash: res.hash, kind: 'public' });
      // 解锁落地后重读锁定（清零 → 下次打开全额可提）
      void getVaultLockSession(account).then((sess) => {
        setLockedWei(sess ? sess.lockedWei : null);
        setUnlockDeadline(sess ? sess.unlockDeadlineSec : 0);
      });
    } else {
      setError(res.error || t('claim-error-failed'));
      logger.warn('[ClaimModal] unlock failed:', res.error);
    }
  };

  // 一键注册赔付承诺（我们合约的 payout commitment，一次性链上交易）
  const registerPayout = async () => {
    if (walletChainMismatch) {
      setError(t('claim-wrong-network'));
      return;
    }
    setRegPending(true);
    setError('');
    try {
      const res = await ensurePayoutCommitment(account);
      if (res.status === 'error') {
        setError(res.error);
      } else {
        setReg((r) => ({ ...r, payout: true }));
      }
    } catch (e) {
      setError(String((e as Error)?.message || e));
    } finally {
      setRegPending(false);
    }
  };

  // 一键注册隐私池：向池 shield 0.01 STRK，钱包在首笔 shield 时自动完成
  // viewing key 注册（金额留在池内余额，后续私密领取可全额使用）。
  // 未入池的钱包会回 118 NOT_REGISTERED——自动展开钱包内注册指引。
  const registerPool = async () => {
    if (walletChainMismatch) {
      setError(t('claim-wrong-network'));
      return;
    }
    setPoolRegistering(true);
    setError('');
    try {
      const res = await shieldForPoolRegistration(
        account as unknown as Parameters<typeof shieldForPoolRegistration>[0],
        10n ** 16n,
      ); // 0.01 STRK
      if (res.success) {
        await runChecks(false);
      } else {
        setError(res.error || t('claim-error-shield'));
        if (res.notRegistered) setPoolGuideOpen(true);
      }
    } catch (e) {
      const msg = walletErrText(e);
      setError(msg);
      // 118/163（未入池）与 151（钱包网络不对/Sepolia 私密代币未开放）
      // 都自动展开钱包内注册指引——指引路径就是这些错误的解法起点。
      if (/NOT_REGISTERED|UNKNOWN_ERROR|TOKEN_NOT_SUPPORTED|not supported for private/i.test(msg)) {
        setPoolGuideOpen(true);
      }
    } finally {
      setPoolRegistering(false);
    }
  };

  // 池 viewing key 行的整体状态色：已注册绿 / 钱包不支持红 / 其余（检测中、
  // 未注册但可一键修复）黄
  const poolOk: boolean | null =
    reg.pool === true ? true : strk20Ready === false ? false : null;

  const renderPayoutRow = () => (
    <>
      <CheckRow>
        <StatusDot $ok={reg.payout} aria-hidden />
        <CheckName>{t('claim-payout-name')}</CheckName>
        {reg.payout === true ? (
          <StatusText $ok>{t('claim-status-registered')}</StatusText>
        ) : reg.payout === null ? (
          <StatusText $ok={null}>{t('claim-status-checking')}</StatusText>
        ) : (
          <Button
            type="button"
            variant="primary"
            small
            style={{ whiteSpace: 'nowrap' }}
            disabled={pending !== null || regPending || checking}
            onClick={() => void registerPayout()}
            title={t('claim-payout-tip')}
          >
            {regPending ? t('claim-registering') : t('claim-register-btn')}
          </Button>
        )}
      </CheckRow>
      {reg.payout === false && (
        <CheckDetail>{t('claim-payout-detail')}</CheckDetail>
      )}
    </>
  );

  const renderPoolRow = () => (
    <>
      <CheckRow>
        <StatusDot $ok={poolOk} aria-hidden />
        <CheckName>{t('claim-pool-name')}</CheckName>
        {reg.pool === true ? (
          <StatusText $ok>{t('claim-status-registered')}</StatusText>
        ) : strk20Ready === false ? (
          <StatusText $ok={false}>{t('claim-status-unsupported')}</StatusText>
        ) : reg.pool === false ? (
          <Button
            type="button"
            variant="primary"
            small
            style={{ whiteSpace: 'nowrap' }}
            disabled={pending !== null || poolRegistering || checking}
            onClick={() => void registerPool()}
            title={t('claim-pool-tip')}
          >
            {poolRegistering ? t('claim-registering') : t('claim-register-btn')}
          </Button>
        ) : (
          <StatusText $ok={null}>{t('claim-status-checking')}</StatusText>
        )}
      </CheckRow>
      {reg.pool === true ? (
        shieldedText !== null && (
          <CheckDetail>{t('claim-pool-balance').replace('{balance}', shieldedText)}</CheckDetail>
        )
      ) : strk20Ready === false ? (
        <>
          <CheckDetail>
            {t('claim-pool-need-api').replace('{min}', STRK20_WALLET_API_MIN)}
          </CheckDetail>
          <CheckDetail>
            {t('claim-wallet-api-label')}{' '}
            {walletApiVersions === null
              ? t('claim-status-checking')
              : walletApiVersions.length
                ? walletApiVersions.join(', ')
                : t('claim-wallet-api-none')}
          </CheckDetail>
        </>
      ) : reg.pool === false ? (
        <CheckDetail>
          {t('claim-pool-never-joined')}
        </CheckDetail>
      ) : (
        <CheckDetail>{t('claim-pool-balance-checking')}</CheckDetail>
      )}
      {reg.pool === false && strk20Ready !== false && (
        <>
          <CardLink type="button" onClick={() => setPoolGuideOpen((v) => !v)}>
            {poolGuideOpen ? t('claim-guide-collapse') : t('claim-guide-expand')}
          </CardLink>
          {poolGuideOpen && (
            <GuideBox>
              <GuideSteps>
                <li>{t('claim-guide-step1')}</li>
                <li>{t('claim-guide-step2')}</li>
                <li>{t('claim-guide-step3')}</li>
                <li>{t('claim-guide-step4')}</li>
              </GuideSteps>
              <CardLink
                type="button"
                style={{ marginLeft: 0 }}
                onClick={reverify}
                disabled={checking}
              >
                {checking ? t('claim-reverifying') : t('claim-guide-reverify')}
              </CardLink>
            </GuideBox>
          )}
        </>
      )}
    </>
  );

  const privateBlockedReason = (() => {
    if (strk20Ready === false) return t('claim-blocked-unsupported');
    if (walletApiVersions !== null && walletApiVersions.length > 0
        && !walletApiVersions.some((v) => compareVersions(v, STRK20_WALLET_API_MIN) >= 0)) {
      return t('claim-blocked-version').replace('{versions}', walletApiVersions.join(', '));
    }
    if (reg.pool === false) {
      return t('claim-blocked-pool');
    }
    if (lockedWei !== null && lockedWei > 0n && lockedWei >= amountWei) {
      return t('claim-blocked-locked');
    }
    return null;
  })();

  return (
    <ModalShell
      width="md"
      role="dialog"
      ariaLabel={t('claim-title')}
      onBackdropClick={pending ? undefined : close}
    >
      <h2
        style={{
          margin: 0,
          fontFamily: theme.fonts.fontFamilySansSerif,
          fontSize: '1.2rem',
          fontWeight: 700,
          color: theme.colors.fontColorDark,
          textAlign: 'center',
        }}
      >
        {t('claim-title')}
      </h2>

      {/* Body 容器收紧弹窗内部间距（Shell 的 1rem gap 只作用在标题边界） */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
        {done ? (
          <>
            <SuccessRing aria-hidden>✓</SuccessRing>
            <Notice $kind="success">
              {done.kind === 'private'
                ? t('claim-done-private')
                : t('claim-done-public')}
            </Notice>
            <Text
              textAlign="center"
              style={{
                fontSize: '0.72rem',
                wordBreak: 'break-all',
                color: theme.colors.mutedText,
                fontFamily: 'monospace',
                background: 'rgba(0,0,0,0.04)',
                borderRadius: theme.radius.md,
                padding: '0.5rem 0.6rem',
              }}
            >
              tx: {done.hash}
            </Text>
            <Button
              variant="secondary"
              small
              onClick={close}
              fullWidth
              style={{ marginTop: '0.5rem' }}
            >
              {t('claim-close')}
            </Button>
          </>
        ) : (
          <>
            <Hero>
              <HeroLeft>
                <HeroLabel>{t('claim-hero-label')}</HeroLabel>
                <HeroAmount>
                  {chips.toLocaleString('en-US')}{' '}
                  <span style={{ fontSize: '0.95rem', fontWeight: 600 }}>{t('claim-chips-unit')}</span>
                </HeroAmount>
                <HeroSub>≈ {strkText} STRK</HeroSub>
              </HeroLeft>
              {walletAddress && (
                <HeroAddr title={walletAddress}>
                  {walletAddress.slice(0, 6)}…{walletAddress.slice(-4)}
                </HeroAddr>
              )}
            </Hero>

            <CheckBlock aria-label={t('claim-check-title')}>
              {walletChainMismatch && <Notice $kind="warn">{t('claim-wrong-network')}</Notice>}
              {lockedPart > 0n && (
                <Notice $kind={lockExpired ? 'warn' : 'info'}>
                  {t('claim-locked-line')
                    .replace('{locked}', lockedStrkText)
                    .replace('{claimable}', strkText)}
                  {' '}
                  {lockExpired
                    ? t('claim-locked-expired')
                    : unlockDeadline > 0
                      ? t('claim-locked-until').replace(
                          '{hours}',
                          lockRemainingH >= 1
                            ? Math.ceil(lockRemainingH).toString()
                            : Math.max(1, Math.ceil(lockRemainingH * 60)).toString() + 'm',
                        )
                      : ''}
                  {lockExpired && (
                    <>
                      {' '}
                      <Button
                        variant="secondary"
                        type="button"
                        disabled={unlockPending}
                        onClick={() => void handleUnlock()}
                        style={{ marginLeft: 8, padding: '2px 10px', fontSize: '0.8rem' }}
                      >
                        {unlockPending ? t('claim-unlock-pending') : t('claim-unlock')}
                      </Button>
                    </>
                  )}
                </Notice>
              )}
              <CheckHeader>
                <CheckBlockTitle>{t('claim-check-title')}</CheckBlockTitle>
                <ReverifyLink type="button" onClick={reverify} disabled={checking}>
                  {checking ? t('claim-reverifying') : t('claim-reverify')}
                </ReverifyLink>
              </CheckHeader>
              {renderPayoutRow()}
              {renderPoolRow()}
            </CheckBlock>

            {privateBlockedReason && <Notice $kind="warn">{privateBlockedReason}</Notice>}
            {error && <Notice $kind="error">{error}</Notice>}

            {/* 领取金额：默认全额可提，可改小（部分提现） */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
              <label
                htmlFor="claim-amount"
                style={{ fontSize: '0.72rem', fontWeight: 600, color: theme.colors.softText }}
              >
                {t('claim-amount-label')}{' '}
                <span style={{ fontWeight: 400 }}>
                  ({t('claim-amount-max').replace('{max}', strkText)})
                </span>
              </label>
              <input
                id="claim-amount"
                inputMode="decimal"
                autoComplete="off"
                value={amountStr}
                placeholder={strkText}
                onChange={(e) => setAmountStr(e.target.value)}
                style={{
                  padding: '0.45rem 0.6rem',
                  borderRadius: theme.radius.md,
                  border: `1px solid ${amountInvalid ? theme.colors.danger : theme.colors.borderSubtle}`,
                  fontSize: '0.95rem',
                  fontVariantNumeric: 'tabular-nums',
                  background: 'rgba(0,0,0,0.03)',
                  color: theme.colors.fontColorDark,
                  outline: 'none',
                }}
              />
              {amountInvalid && (
                <span style={{ fontSize: '0.7rem', color: theme.colors.danger }}>
                  {t('claim-amount-invalid')}
                </span>
              )}
            </div>

            <ActionsGrid>
              <ActionCell>
                <Button
                  type="submit"
                  fullWidth
                  disabled={pending !== null || claimWei <= 0n || strk20Ready !== true}
                  onClick={() => void handleClaim('private')}
                  title={strk20Ready ? t('claim-private-tip') : t('claim-private-tip-unsupported')}
                >
                  {pending === 'private' ? t('claim-submitting') : t('claim-submit-private')}
                </Button>
                <ActionNote>{t('claim-note-private')}</ActionNote>
              </ActionCell>
              <ActionCell>
                <Button
                  variant="secondary"
                  type="button"
                  fullWidth
                  disabled={pending !== null || claimWei <= 0n}
                  onClick={() => void handleClaim('public')}
                  title={t('claim-public-tip')}
                >
                  {pending === 'public' ? t('claim-submitting') : t('claim-submit-public')}
                </Button>
                <ActionNote>{t('claim-note-public')}</ActionNote>
              </ActionCell>
            </ActionsGrid>
          </>
        )}
      </div>
    </ModalShell>
  );
};

export default ClaimModal;
