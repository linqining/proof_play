import React, { useCallback, useContext, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import Button from '../buttons/Button';
import modalContext from '../../context/modal/modalContext';
import globalContext from '../../context/global/globalContext';
import { ButtonGroup } from '../forms/ButtonGroup';
import { Form } from '../forms/Form';
import { FormGroup } from '../forms/FormGroup';
import { Input } from '../forms/Input';
import { Label } from '../forms/Label';
import gameContext from '../../context/game/gameContext';
import { PositionedUISlot } from './PositionedUISlot';
import { InfoPill } from './InfoPill';
import PokerCard from './PokerCard';
import ChipsAmountPill from './ChipsAmountPill';
import ColoredText from '../typography/ColoredText';
import Text from '../typography/Text';
import PokerChip from '../icons/PokerChip';
import { OccupiedSeat } from './OccupiedSeat';
import { Hand } from './Hand';
import { NameTag } from './NameTag';
import { PlayerName } from './PlayerName';
import contentContext from '../../context/content/contentContext';
import Markdown from 'react-markdown';
import DealerButton from '../icons/DealerButton';
import styled from 'styled-components';
import { Table } from '../../types/game';
import authContext from '../../context/auth/authContext';
import { EmptySeat } from './seatStyles';
import { getStrkBalance } from '../../starknet/starknetGameActions';  // getStrkBalance 已改读原生 STRK
import { CHIPS_PER_STRK, STRK_DECIMALS, WEI_PER_CHIP } from '../../starknet/config';
import { isZChainSession } from '../../starknet/zchainWallet';
import { logger } from '../../helpers/logger';
import { blindRoles } from '../../helpers/tableDerived';
import { evaluateBestHand, rankLabel } from '../../helpers/handEval';

// ProofPlay 钱包会话（appchain→zchain 结算的 dev 部署）不入账链上筹码，
// 入座额度按服务端结余 + 该 dev 常量放行。
const ZCHAIN_DEV_BUYIN_CHIPS = 5000;

const StyledSeat = styled.div`
  width: 200px;
  height: 200px;
  display: flex;
  justify-content: center;
  align-items: center;
`;

const BuyinInfo = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  margin-bottom: 0.75rem;
  padding: 0.75rem 1rem;
  background: ${({ theme }) => theme.colors.brandBlueAlpha08};
  border: 1px solid ${({ theme }) => theme.colors.brandBlueAlpha20};
  border-radius: ${({ theme }) => theme.radius.md};
  font-size: 0.85rem;
  color: ${({ theme }) => theme.colors.fontColorDarkLighter};
`;

const BuyinInfoRow = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 0.5rem;

  img {
    width: 16px;
    height: 16px;
    vertical-align: middle;
    margin-right: 0.25rem;
  }
`;

const ExchangeRate = styled.div`
  font-size: 0.75rem;
  color: ${({ theme }) => theme.colors.softText};
  text-align: center;
  padding-top: 0.25rem;
  border-top: 1px dashed rgba(148, 163, 184, 0.3);
`;

// 与 Modal 底部按钮（ModalButton 紫色渐变）保持视觉一致
const ConfirmButton = styled(Button)`
  background: ${({ theme }) => theme.colors.brandGradient} !important;
  color: ${({ theme }) => theme.colors.lightestBg} !important;
  border: none !important;
  border-radius: ${({ theme }) => theme.radius.md} !important;
  font-weight: 600 !important;
  padding: 0.65rem 2rem !important;
  box-shadow: 0 4px 20px rgba(102, 126, 234, 0.25) !important;
  transition:
    box-shadow 0.35s ${({ theme }) => theme.easing.easeOutCubic},
    transform 0.35s ${({ theme }) => theme.easing.easeOutCubic} !important;

  &:hover:not(:disabled) {
    box-shadow: 0 6px 24px rgba(102, 126, 234, 0.35) !important;
    transform: translateY(-1px);
  }
`;

// Faucet 按钮：次要样式（描边），与确认/取消按钮区分
const FaucetButton = styled.button`
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.4rem;
  width: 100%;
  padding: 0.55rem 1rem;
  border-radius: ${({ theme }) => theme.radius.md};
  border: 1px dashed ${({ theme }) => theme.colors.brandBlueAlpha20};
  background: ${({ theme }) => theme.colors.brandBlueAlpha08};
  color: ${({ theme }) => theme.colors.brandBlue};
  font-size: 0.85rem;
  font-weight: 500;
  cursor: pointer;
  transition:
    background-color 0.2s ease,
    border-color 0.2s ease,
    opacity 0.2s ease;
  /* Apple HIG: 44x44 touch target on mobile */
  min-height: 44px;

  img {
    width: 16px;
    height: 16px;
  }

  &:hover:not(:disabled) {
    background: ${({ theme }) => theme.colors.brandBlueAlpha08};
    border-color: ${({ theme }) => theme.colors.brandBlue};
    opacity: 0.95;
  }

  &:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
`;

interface SeatProps {
  currentTable: Table;
  seatNumber: number;
  isPlayerSeated: boolean;
  sitDown: (tableId: string, seatId: number, amount: number) => Promise<void>;
}

export interface BuyinFormProps {
  minBuyIn: number;
  maxBuyin: number;
  buyinStep: number;
  availableChips: number;
  strkCostForChips: (chips: number) => number;
  shortAddress: string;
  strkBalanceInStrk: number;
  /** 原生币符号（STRK / MON——monad 会话下余额与花费单位是 MON）。 */
  nativeSymbol?: string;
  confirmLabel: string;
  onConfirm: (amount: number) => void;
  /** T5 单据上下文：目标座位与桌名/桌号 */
  seatNumber?: number;
  tableLabel?: string;
}

// T5 单据抬头（座位/桌上下文）
const BuyinContext = styled.div`
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 9.5px;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: ${({ theme }) => theme.colors.softerText};
  margin-bottom: 0.6rem;
`;

// 琥珀「真实资产」警示条（原稿 bn-real 语言）
const RealAssetNote = styled.div`
  display: flex;
  gap: 0.5rem;
  margin-top: 0.75rem;
  padding: 0.55rem 0.75rem;
  background: ${({ theme }) => theme.colors.goldChip};
  border: 1px solid rgba(125, 83, 8, 0.35);
  border-left: 3px solid ${({ theme }) => theme.colors.gold};
  border-radius: ${({ theme }) => theme.radius.sm};
  color: ${({ theme }) => theme.colors.gold};
  font-size: 0.78rem;
  line-height: 1.5;
`;

// 页脚溯源行
const TraceFoot = styled.div`
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 9.5px;
  letter-spacing: 0.06em;
  color: ${({ theme }) => theme.colors.softerText};
  text-align: center;
  padding-top: 0.6rem;
`;

// 买入档位按钮：从 minBuyIn 起按步进取至多 4 档（设计稿 T5 的 1,000/2,000/3,000/4,000）
const PresetRow = styled.div`
  display: flex;
  gap: 0.5rem;
  margin-bottom: 0.6rem;

  button {
    flex: 1;
    padding: 0.4rem 0.5rem;
    border: 1px solid ${({ theme }) => theme.colors.brandBlueAlpha20};
    border-radius: ${({ theme }) => theme.radius.sm};
    background: transparent;
    color: ${({ theme }) => theme.colors.fontColorDark};
    font-size: 0.8rem;
    cursor: pointer;

    &.on {
      background: ${({ theme }) => theme.colors.brandBlueAlpha08};
      border-color: ${({ theme }) => theme.colors.brandBlue};
      font-weight: 600;
    }
  }
`;

/**
 * 买入/再次买入共用单据表单：受控金额输入 + 档位 + 实时「本次转换成本 /
 * 转换后余额」两行复核（设计稿 T5），替代原先的裸 number input。
 * 校验规则与原实现一致：min ≤ amount ≤ min(availableChips, maxBuyin) 且为步进整数倍。
 */
export const BuyinForm: React.FC<BuyinFormProps> = ({
  minBuyIn,
  maxBuyin,
  buyinStep,
  availableChips,
  strkCostForChips,
  shortAddress,
  strkBalanceInStrk,
  nativeSymbol = 'STRK',
  confirmLabel,
  onConfirm,
  seatNumber,
  tableLabel,
}) => {
  const { getLocalizedString } = useContext(contentContext)!;
  const [amount, setAmount] = useState<number>(minBuyIn);
  const effectiveMax = Math.min(availableChips, maxBuyin);
  // 不可成交态：超出可用额度（余额 0 / 超上限）时给出可见错误而非静默拦截
  const unaffordable = availableChips <= 0 || amount > effectiveMax;
  const presets: number[] = [];
  for (
    let v = minBuyIn;
    v <= effectiveMax && presets.length < 4;
    v += buyinStep
  ) {
    presets.push(v);
  }

  const fmtAmt = (n: number) => n.toLocaleString();

  return (
    <Form
      onSubmit={(e) => {
        e.preventDefault();
        if (
          !unaffordable &&
          amount &&
          amount >= minBuyIn &&
          amount % buyinStep === 0 &&
          amount <= availableChips &&
          amount <= maxBuyin
        ) {
          onConfirm(amount);
        }
      }}
    >
      <BuyinContext>
        {getLocalizedString('seat_buyin-ctx-label')}
        {seatNumber ? ` · SEAT ${seatNumber}` : ''}
        {tableLabel ? ` · ${tableLabel}` : ''}
      </BuyinContext>
      <BuyinInfo>
        <BuyinInfoRow>
          <span>{getLocalizedString('seat_wallet-address-label')}</span>
          <strong>{shortAddress || '-'}</strong>
        </BuyinInfoRow>
        <BuyinInfoRow>
          <span><img src="/strk-logo.svg" alt={getLocalizedString('seat_strk-logo-alt')} />{getLocalizedString('seat_strk-balance-label')}</span>
          <strong>{strkBalanceInStrk.toLocaleString(undefined, { maximumFractionDigits: 4 })} {nativeSymbol}</strong>
        </BuyinInfoRow>
        <BuyinInfoRow>
          <span>{getLocalizedString('seat_redeemable-chips-label')}</span>
          <strong>{availableChips.toLocaleString()}</strong>
        </BuyinInfoRow>
        <BuyinInfoRow>
          <span>{getLocalizedString('seat_conversion-cost-label')}</span>
          <strong>{strkCostForChips(amount || minBuyIn).toLocaleString(undefined, { maximumFractionDigits: 4 })} {nativeSymbol}</strong>
        </BuyinInfoRow>
        <BuyinInfoRow>
          <span>{getLocalizedString('seat_post-buyin-balance-label')}</span>
          <strong>{Math.max(availableChips - (amount || 0), 0).toLocaleString()}</strong>
        </BuyinInfoRow>
        <ExchangeRate>{getLocalizedString('seat_exchange-rate-label').replace('{rate}', CHIPS_PER_STRK.toLocaleString())}</ExchangeRate>
      </BuyinInfo>
      <FormGroup>
        <Label htmlFor="amount">
          {getLocalizedString('seat_buyin-amount-label')}
          <span style={{ color: '#8a8578', fontWeight: 400, marginLeft: 6 }}>
            {`${fmtAmt(minBuyIn)} – ${fmtAmt(effectiveMax || maxBuyin)} · ${getLocalizedString('seat_buyin-step-hint')} ${fmtAmt(buyinStep)}`}
          </span>
        </Label>
        <Input
          id="amount"
          type="number"
          inputMode="numeric"
          pattern="[0-9]*"
          min={minBuyIn}
          max={effectiveMax}
          step={buyinStep}
          value={amount}
          onChange={(e) => setAmount(+(e.target as HTMLInputElement).value)}
          style={unaffordable ? { borderColor: '#a83226' } : undefined}
        />
        {unaffordable && (
          <div style={{ color: '#a83226', fontSize: '0.78rem', marginTop: 4 }}>
            {getLocalizedString('seat_buyin-unaffordable')}
          </div>
        )}
      </FormGroup>
      <RealAssetNote>
        {getLocalizedString('seat_buyin-real-asset-note')}
      </RealAssetNote>
      <TraceFoot>
        {[
          seatNumber ? `SEAT ${seatNumber}` : '',
          tableLabel ?? '',
          `${getLocalizedString('seat_exchange-rate-label').replace('{rate}', CHIPS_PER_STRK.toLocaleString())}`,
        ]
          .filter(Boolean)
          .join(' · ')}
      </TraceFoot>
      {presets.length > 1 && (
        <PresetRow>
          {presets.map((v) => (
            <button
              key={v}
              type="button"
              className={amount === v ? 'on' : ''}
              onClick={() => setAmount(v)}
            >
              {v.toLocaleString()}
            </button>
          ))}
        </PresetRow>
      )}
      <ButtonGroup>
        <ConfirmButton primary type="submit" fullWidth>
          {confirmLabel}
        </ConfirmButton>
      </ButtonGroup>
    </Form>
  );
};

export const Seat: React.FC<SeatProps> = ({ currentTable, seatNumber, isPlayerSeated, sitDown }) => {
  const { openModal, closeModal } = useContext(modalContext)!;
  const navigate = useNavigate();
  const { chipsAmount } = useContext(globalContext)!;
  const { standUp, seatId, rebuy, communityCards } = useContext(gameContext)!;
  const { getLocalizedString } = useContext(contentContext)!;
  const { isLoggedIn, walletAddress } = useContext(authContext)!;
  const hasWallet = !!walletAddress;

  // Read the player's STRK balance from Starknet Sepolia. Re-fetched when the
  // wallet address changes and after a faucet claim.
  const [strkBalanceWei, setStrkBalanceWei] = useState<bigint>(0n);

  const fetchBalance = useCallback(async () => {
    if (!walletAddress || isZChainSession()) {
      setStrkBalanceWei(0n);
      return;
    }
    try {
      const bal = await getStrkBalance(walletAddress);
      setStrkBalanceWei(bal);
    } catch (err) {
      logger.error('[Seat] fetch STRK balance failed:', err);
    }
  }, [walletAddress]);

  useEffect(() => {
    fetchBalance();
  }, [fetchBalance]);

  const seat = currentTable.seats[seatNumber];
  // 买入上下限：优先用服务端下发的真值（ClientTable.minBuyIn/maxBuyIn）；
  // 旧服务端不下发时回退 limit / 盲注推导（链上同步场景 limit 可能为 0）
  const maxBuyin =
    currentTable.maxBuyIn && currentTable.maxBuyIn > 0
      ? currentTable.maxBuyIn
      : currentTable.limit > 0
        ? currentTable.limit
        : currentTable.bigBlind * 100 || 5000;
  const minBuyIn =
    currentTable.minBuyIn && currentTable.minBuyIn > 0
      ? currentTable.minBuyIn
      : Math.max(currentTable.minBet * 2 * 10, 1000);
  const BUYIN_STEP = 1000;

  // 1 STRK = 1_000 chips → 1 chip = 0.001 STRK
  const strkBalanceInStrk =
    Number(strkBalanceWei / BigInt(10) ** BigInt(STRK_DECIMALS)) +
    Number(strkBalanceWei % BigInt(10) ** BigInt(STRK_DECIMALS)) /
      10 ** STRK_DECIMALS;
  // 可买筹码 = max(服务端结余, 钱包 pSTRK 余额可兑换数量)。STRK20 模式下
  // 首次买入是链上 vault.deposit（按 WEI_PER_CHIP 换算），服务端 chipsAmount
  // 是历史结算存量（首次为 0）——只按它会永远挡住首次买入。
  const availableChips = isZChainSession()
    ? Math.max(chipsAmount ?? 0, ZCHAIN_DEV_BUYIN_CHIPS)
    : Math.max(
      chipsAmount ?? 0,
      Number(strkBalanceWei / BigInt(WEI_PER_CHIP)),
    );

  // 兑换指定筹码需要的 STRK 数量
  const strkCostForChips = (chips: number): number => chips / CHIPS_PER_STRK;

  // 格式化钱包地址用于显示（前6位...后4位）
  const shortAddress = walletAddress
    ? `${walletAddress.slice(0, 6)}...${walletAddress.slice(-4)}`
    : '';

  // Faucet 请求状态
  const [faucetLoading, setFaucetLoading] = useState(false);
  const [faucetMsg, setFaucetMsg] = useState<string | null>(null);

  // Faucet: there is no SDK-style programmatic faucet, so we open the official
  // Starknet Sepolia STRK faucet in a new
  // tab and ask the user to paste their address.
  const handleFaucetRequest = async () => {
    if (!walletAddress || faucetLoading) return;
    setFaucetLoading(true);
    setFaucetMsg(null);
    try {
      const faucetUrl = `https://starknet-faucet.vercel.app/?address=${encodeURIComponent(walletAddress)}`;
      window.open(faucetUrl, '_blank', 'noopener,noreferrer');
      setFaucetMsg(getLocalizedString('seat_claim-success'));
      // Refresh balance after a short delay to pick up the faucet transfer.
      setTimeout(() => {
        fetchBalance();
        setFaucetMsg(null);
      }, 5000);
    } catch (err: any) {
      const msg = err?.message || String(err);
      setFaucetMsg(`${getLocalizedString('seat_claim-failed-prefix')}: ${msg}`);
      openModal(
        () => <Text textAlign="center">{msg}</Text>,
        getLocalizedString('seat_claim-failed-title'),
        getLocalizedString('seat_claim-failed-ok'),
      );
    } finally {
      setFaucetLoading(false);
    }
  };

  // Debug: log hand cards for the current player's seat
  if (seat && seatId !== null && seat.id === seatId) {
    logger.log('[Seat] seatNumber:', seatNumber, 'seatId:', seatId, 'hand:', seat.hand);
  }

  // 盲注角色（小盲/大盲；BTN 已有独立图标，不重复标注）
  const roles = blindRoles(currentTable);
  const blindRoleLabel =
    roles[seatNumber] === 'sb'
      ? getLocalizedString('game_seat-sb-lbl')
      : roles[seatNumber] === 'bb'
        ? getLocalizedString('game_seat-bb-lbl')
        : null;

  // 自己手牌牌型标注（仅本人座位；底牌 + 公共牌 ≥5 张才可评）
  const isHeroSeat = seatId !== null && seat?.id === seatId;
  const handEval = (() => {
    if (!isHeroSeat || !seat) return null;
    const cards = [...seat.hand, ...(communityCards ?? [])];
    return evaluateBestHand(cards);
  })();
  const handEvalLabel = handEval
    ? `${getLocalizedString(handEval.i18nKey)}${
        handEval.category === 'flush' || handEval.category === 'royal-flush'
          ? ''
          : ` ${rankLabel(handEval.mainRank)}`
      }`
    : null;

  useEffect(() => {
    if (
      currentTable &&
      isPlayerSeated &&
      seat &&
      seat.id === seatId &&
      seat.stack === 0 &&
      seat.sittingOut
    ) {
      if (availableChips <= minBuyIn || availableChips === 0) {
        standUp().catch(e => logger.error('[Seat] standUp failed:', e));
      } else {
        // 打开 rebuy 弹窗前刷新余额，确保显示最新 STRK 余额
        fetchBalance();
        openModal(
          () => (
            <BuyinForm
              minBuyIn={minBuyIn}
              maxBuyin={maxBuyin}
              buyinStep={BUYIN_STEP}
              availableChips={availableChips}
              strkCostForChips={strkCostForChips}
              shortAddress={shortAddress}
              strkBalanceInStrk={strkBalanceInStrk}
              seatNumber={seatNumber}
              tableLabel={`${currentTable.name || currentTable.id}`}
              confirmLabel={getLocalizedString('game_rebuy-modal_confirm')}
              onConfirm={(amount) => {
                rebuy(currentTable.id, seatNumber, parseInt(String(amount)));
                closeModal();
              }}
            />
          ),
          getLocalizedString('game_rebuy-modal_header'),
          getLocalizedString('game_rebuy-modal_cancel'),
          () => {
            standUp().catch(e => logger.error('[Seat] standUp failed:', e));
            closeModal();
          },
          () => {
            standUp().catch(e => logger.error('[Seat] standUp failed:', e));
            closeModal();
          },
        );
      }
    }
    // eslint-disable-next-line
  }, [currentTable]);

  return (
    <StyledSeat>
      <AnimatePresence mode="wait">
        {!seat ? (
          <motion.div
            key="empty"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.3 }}
            style={{
              display: 'flex',
              justifyContent: 'center',
              alignItems: 'center',
            }}
          >
            {!isPlayerSeated ? (
              currentTable.closed ? (
                // 关桌终态：以空位样式的提示替代入座按钮（服务端 SIT_DOWN
                // 也会以 TABLE_CLOSED 拒绝，这里只是不打扰用户）
                <EmptySeat>
                  <Markdown>{getLocalizedString('game_table_closed')}</Markdown>
                </EmptySeat>
              ) : (
              <Button
                small
                onClick={() => {
                  if (!isLoggedIn && !hasWallet) {
                    openModal(
                      () => <Text textAlign="center">{getLocalizedString('game_login-required_text')}</Text>,
                      getLocalizedString('login_page-header_txt'),
                      getLocalizedString('navbar-login_btn'),
                      () => {
                        closeModal();
                        navigate('/', { state: { showLogin: true } });
                      },
                    );
                    return;
                  }
                  // 打开 buyin 弹窗前刷新余额，确保显示最新 STRK 余额
                  fetchBalance();
                  openModal(
                    () => (
                      <BuyinForm
                        minBuyIn={minBuyIn}
                        maxBuyin={maxBuyin}
                        buyinStep={BUYIN_STEP}
                        availableChips={availableChips}
                        strkCostForChips={strkCostForChips}
                        shortAddress={shortAddress}
                        strkBalanceInStrk={strkBalanceInStrk}
                        seatNumber={seatNumber}
                        tableLabel={`${currentTable.name || currentTable.id}`}
                        confirmLabel={getLocalizedString('game_buyin-modal_confirm')}
                        onConfirm={(amount) => {
                          sitDown(
                            currentTable.id,
                            seatNumber,
                            parseInt(String(amount)),
                          );
                          closeModal();
                        }}
                      />
                    ),
                    getLocalizedString('game_buyin-modal_header'),
                    getLocalizedString('game_buyin-modal_cancel'),
                  );
                }}
              >
                {getLocalizedString('game_sitdown-btn')}
              </Button>
              )
            ) : (
              <EmptySeat>
                <Markdown>{getLocalizedString('game_table_empty-seat')}</Markdown>
              </EmptySeat>
            )}
          </motion.div>
        ) : (
          <motion.div
            key="occupied"
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{
              opacity: 1,
              scale: 1,
              transition: { duration: 0.3, ease: 'easeOut' },
            }}
            exit={{ opacity: 0, transition: { duration: 0.3, ease: 'easeIn' } }}
            style={{
              position: 'absolute',
              display: 'flex',
              textAlign: 'center',
              justifyContent: 'center',
              alignItems: 'center',
              transformOrigin: 'center center',
              backfaceVisibility: 'hidden',
              WebkitBackfaceVisibility: 'hidden',
            }}
          >
            <PositionedUISlot top="-6.25rem" left="-75px" origin="top center">
              <NameTag>
                <ColoredText primary textAlign="center">
                  <PlayerName name={seat.player!.name} />
                  {blindRoleLabel && (
                    <span
                      style={{
                        fontSize: '0.7rem',
                        fontWeight: 600,
                        color: '#94a3b8',
                        marginLeft: '0.3rem',
                      }}
                    >
                      · {blindRoleLabel}
                    </span>
                  )}
                  <br />
                  {seat.stack && (
                    <ColoredText secondary>
                      <PokerChip width="15" height="15" />{' '}
                      {new Intl.NumberFormat(
                        document.documentElement.lang,
                      ).format(seat.stack)}
                    </ColoredText>
                  )}
                </ColoredText>
              </NameTag>
            </PositionedUISlot>
            <PositionedUISlot>
              <OccupiedSeat
                seatNumber={seatNumber}
                hasTurn={seat.turn}
                deadlineMs={
                  currentTable.bettingStartedAt && currentTable.bettingTimeoutMs
                    ? currentTable.bettingStartedAt + currentTable.bettingTimeoutMs
                    : null
                }
                totalMs={currentTable.bettingTimeoutMs ?? null}
              />
            </PositionedUISlot>
            <PositionedUISlot
              left="4vh"
              style={{
                display: 'flex',
                textAlign: 'center',
                justifyContent: 'center',
                alignItems: 'center',
              }}
              origin="center right"
            >
              <Hand>
                {seat.hand &&
                  seat.hand.map((card, index) => (
                    <PokerCard
                      key={index}
                      card={card}
                      width="5vw"
                      maxWidth="60px"
                      minWidth="30px"
                    />
                  ))}
              </Hand>
            </PositionedUISlot>

            {currentTable.button === seatNumber && (
              <PositionedUISlot
                right="35px"
                origin="center left"
                style={{ zIndex: '55' }}
              >
                <DealerButton />
              </PositionedUISlot>
            )}

            <PositionedUISlot
              top="6vh"
              style={{ minWidth: '150px', zIndex: '55' }}
              origin="bottom center"
            >
              <ChipsAmountPill chipsAmount={seat.bet} />
              {!currentTable.handOver && seat.lastAction && (
                <InfoPill>{seat.lastAction}</InfoPill>
              )}
              {handEvalLabel && <InfoPill>{handEvalLabel}</InfoPill>}
            </PositionedUISlot>
          </motion.div>
        )}
      </AnimatePresence>
    </StyledSeat>
  );
};
