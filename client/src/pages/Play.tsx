import React, { useCallback, useContext, useEffect, useRef, useState } from 'react';
import ReactDOM from 'react-dom';
import { useTheme } from 'styled-components';
import Container from '../components/layout/Container';
import Button from '../components/buttons/Button';
import ModalShell from '../components/modals/ModalShell';
import gameContext from '../context/game/gameContext';
import socketContext from '../context/websocket/socketContext';
import authContext from '../context/auth/authContext';

import { RotateDevicePrompt } from '../components/game/RotateDevicePrompt';
import Text from '../components/typography/Text';
import { useModalContext } from '../context/modal/modalContext';
import { useNavigate } from 'react-router-dom';
import { GameUI } from '../components/game/GameUI';
import { useContentContext } from '../context/content/contentContext';
import { useGlobalContext } from '../context/global/globalContext';
import { chipsToStrkText } from '../starknet/config';
import { PlayerContext } from '../context/player/PlayerContext';
import Loader from '../components/loading/Loader';
import { logger } from '../helpers/logger';
import { useTableJoin } from '../hooks/useTableJoin';
import { CryptoPanel } from '../components/game/CryptoPanel';
import { KickNotification } from '../components/game/KickNotification';
import HandHistoryPanel from '../components/game/HandHistoryPanel';
import PlayLedger from '../components/game/ledger/PlayLedger';
import TableStage from '../components/game/ledger/TableStage';
import HandReceipt from '../components/game/ledger/HandReceipt';
import { ToolButton } from '../components/game/ledger/TicketHeader';
import { BuyinForm } from '../components/game/Seat';
import { api } from '../api/secretPokerClient';
import { getStrkBalance } from '../starknet/starknetGameActions';
import { CHIPS_PER_STRK, STRK_DECIMALS, WEI_PER_CHIP } from '../starknet/config';
import { isZChainSession } from '../starknet/zchainWallet';
import { isMonadSession, monadGetBalance, monadAddress } from '../starknet/monadWallet';
import { ActionLoadingOverlay, LeavingOverlay, LeaveDeferredBanner } from './Play.styles';

// ProofPlay 钱包会话（appchain→zchain 结算的 dev 部署）不入账链上筹码，
// 入座额度按服务端结余 + 该 dev 常量放行（与 Seat.tsx 同源）。
const ZCHAIN_DEV_BUYIN_CHIPS = 5000;

const Play: React.FC = () => {
  const navigate = useNavigate();
  const theme = useTheme();
  const { socket, isConnected } = useContext(socketContext)!;
  const { openModal, closeModal } = useModalContext();
  const {
    messages,
    currentTable,
    communityCards,
    decryptedHandCards,
    isPlayerSeated,
    seatId,
    joinTable,
    leaveTable,
    sitDown,
    rebuy,
    fold,
    check,
    call,
    raise,
    kickNotification,
    clearKickNotification,
    cryptoEvents,
    settlementReceipts,
    isActionLoading,
    startActionLoading,
    leaveDeferred,
    showFoldLeaveConfirm,
    confirmFoldLeave,
    cancelFoldLeave,
    cancelDeferredLeave,
    sittingIn,
  } = useContext(gameContext)!;
  const { getLocalizedString } = useContentContext();
  const { pkHex } = useContext(PlayerContext)!;
  // 离开确认时提醒金库里还有未领取筹码（1 chip = 0.001 STRK）
  const { chipsAmount } = useGlobalContext();
  const { walletAddress } = useContext(authContext)!;
  const hasWallet = !!walletAddress;

  const [bet, setBet] = useState(0);
  const [isLeaving, setIsLeaving] = useState(false);
  // ZK 密码学事件面板开关（默认收起，避免遮挡牌桌核心区域）
  const [showCryptoPanel, setShowCryptoPanel] = useState(false);
  // 牌局记录看板开关（P0-2）
  const [showHistoryPanel, setShowHistoryPanel] = useState(false);
  // 空桌等待时的上一手结算摘要（来自 /history 末条记录）
  const [lastHandSummary, setLastHandSummary] = useState<string | null>(null);
  const lastHandFetchedRef = useRef<string>('');
  // T6 本手凭证弹窗（打开时定位最新终局手）
  const [receipt, setReceipt] = useState<{ open: boolean; seq: number }>({ open: false, seq: 1 });
  // T5 买入单据弹窗的 STRK 余额（与 Seat.tsx 同源装配）
  const [strkBalanceWei, setStrkBalanceWei] = useState<bigint>(0n);

  const fetchBalance = useCallback(async () => {
    if (!walletAddress || isZChainSession()) {
      setStrkBalanceWei(0n);
      return;
    }
    // monad 会话：读钱包原生 MON 余额（显示用；买入按服务端 note 余额差额上链）。
    if (isMonadSession()) {
      const addr = monadAddress();
      if (!addr) {
        setStrkBalanceWei(0n);
        return;
      }
      try {
        setStrkBalanceWei(await monadGetBalance(addr));
      } catch (err) {
        logger.error('[Play] fetch MON balance failed:', err);
      }
      return;
    }
    try {
      const bal = await getStrkBalance(walletAddress);
      setStrkBalanceWei(bal);
    } catch (err) {
      logger.error('[Play] fetch STRK balance failed:', err);
    }
  }, [walletAddress]);

  useEffect(() => {
    fetchBalance();
  }, [fetchBalance]);

  // T5 买入单据：空位「入座」按钮打开（字段与校验规则与 Seat.tsx 一致）
  const openBuyinModal = useCallback(
    (seatNumber: number) => {
      if (!currentTable) return;
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
      const strkBalanceInStrk =
        Number(strkBalanceWei / BigInt(10) ** BigInt(STRK_DECIMALS)) +
        Number(strkBalanceWei % BigInt(10) ** BigInt(STRK_DECIMALS)) / 10 ** STRK_DECIMALS;
      // monad 会话下 strkBalanceWei 持有的是 MON wei，同式换算（1 MON =
      // 1000 chips）；差额部分确认入座时经 L1Bridge.depositNative 上链铸 note。
      const availableChips = isZChainSession()
        ? Math.max(chipsAmount ?? 0, ZCHAIN_DEV_BUYIN_CHIPS)
        : Math.max(chipsAmount ?? 0, Number(strkBalanceWei / BigInt(WEI_PER_CHIP)));
      const nativeSymbol = isMonadSession() ? 'MON' : 'STRK';
      const strkCostForChips = (chips: number): number => chips / CHIPS_PER_STRK;
      const shortAddress = walletAddress
        ? `${walletAddress.slice(0, 6)}...${walletAddress.slice(-4)}`
        : '';
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
            nativeSymbol={nativeSymbol}
            seatNumber={seatNumber}
            tableLabel={`${currentTable.name || currentTable.id}`}
            confirmLabel={getLocalizedString('game_buyin-modal_confirm')}
            onConfirm={(amount) => {
              sitDown(currentTable.id, seatNumber, parseInt(String(amount)));
              closeModal();
            }}
          />
        ),
        getLocalizedString('game_buyin-modal_header'),
        getLocalizedString('game_buyin-modal_cancel'),
      );
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [currentTable, strkBalanceWei, chipsAmount, walletAddress],
  );

  // T6 凭证：定位最新终局手并打开三段凭证
  const openLatestReceipt = useCallback(async () => {
    if (!currentTable) return;
    try {
      const records = await api.getHandHistory(Number(currentTable.id));
      if (records.length === 0) return;
      setReceipt({ open: true, seq: records[0].handSeq });
    } catch (e) {
      logger.error('[Play] open receipt failed:', e);
    }
  }, [currentTable]);

  /**
   * Portrait detection: supplements the CSS-only <RotateDevicePrompt /> with
   * a runtime check so we can degrade the rendered tree to a minimal stub
   * when the user is in portrait. The CSS prompt is still the primary
   * deterrent (full-screen overlay), but this hook lets us short-circuit
   * the seat/socket join logic in the rare case the overlay is dismissed
   * (e.g. via DevTools) — preventing the table from running in an
   * unusable layout.
   */
  const [isPortrait, setIsPortrait] = useState<boolean>(() => {
    if (typeof window === 'undefined') return false;
    return window.matchMedia('(orientation: portrait)').matches;
  });

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const mql = window.matchMedia('(orientation: portrait)');
    const onChange = (e: MediaQueryListEvent) => setIsPortrait(e.matches);
    // matchMedia.addEventListener is the modern API; addListener is the
    // Safari < 14 fallback. Both are no-ops if already registered.
    if (mql.addEventListener) mql.addEventListener('change', onChange);
    else mql.addListener(onChange);
    return () => {
      if (mql.removeEventListener) mql.removeEventListener('change', onChange);
      else mql.removeListener(onChange);
    };
  }, []);

  useTableJoin({
    socket,
    isConnected,
    pkHex,
    currentTable,
    joinTable,
    leaveTable,
    openModal,
    navigate,
    getLocalizedString,
  });

  useEffect(() => {
    if (currentTable && seatId != null && currentTable.seats && currentTable.seats[seatId]) {
      const seatBet = currentTable.seats[seatId].bet || 0;
      const currentBet = currentTable.currentBet || 0;
      setBet(Math.max(currentBet - seatBet, 0));
    }
  }, [currentTable, seatId]);

  // 空桌等待时拉取上一手结算摘要（桌面消息条，T1）。同一手只拉一次；
  // 看板接口失败时静默降级，不影响牌桌。
  const waitingForNextHand =
    !!currentTable &&
    currentTable.roundState === 'waiting' &&
    (!currentTable.winMessages || currentTable.winMessages.length === 0);
  useEffect(() => {
    if (!currentTable || !waitingForNextHand) return;
    const fetchKey = `${currentTable.id}-${currentTable.handId ?? 0}`;
    if (lastHandFetchedRef.current === fetchKey) return;
    lastHandFetchedRef.current = fetchKey;
    let cancelled = false;
    api
      .getHandHistory(Number(currentTable.id))
      .then((records) => {
        if (cancelled) return;
        const last = records[0];
        if (!last) return;
        const parts = [`#${last.handSeq}`];
        const win = last.winMessages?.[0];
        if (win) parts.push(win);
        if (last.rakeCollected > 0) {
          parts.push(
            `${getLocalizedString('game_rake-collected_lbl')}: $${Number(last.rakeCollected).toFixed(2)}`,
          );
        }
        setLastHandSummary(`${getLocalizedString('game_last-hand-lbl')} ${parts.join(' · ')}`);
      })
      .catch(() => {
        /* 看板不可用：保留上一次摘要或空 */
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentTable?.id, currentTable?.handId, currentTable?.roundState, waitingForNextHand]);

  const wrappedFold = () => {
    startActionLoading();
    fold();
  };
  const wrappedCheck = () => {
    startActionLoading();
    check();
  };
  const wrappedCall = () => {
    startActionLoading();
    call();
  };
  const wrappedRaise = (amount: number) => {
    startActionLoading();
    raise(amount);
  };

  // Waiting for socket connection
  if (!socket) {
    return (
      <Container fullHeight contentCenteredMobile>
        <Loader />
        <Text textAlign="center" style={{ marginTop: '1rem' }}>
          {getLocalizedString('play_connecting')}
        </Text>
      </Container>
    );
  }

  // Socket exists but disconnected - show reconnecting overlay
  if (!isConnected) {
    return (
      <Container fullHeight contentCenteredMobile>
        <Loader />
        <Text textAlign="center" style={{ marginTop: '1rem' }}>
          {getLocalizedString('play_reconnecting')}
        </Text>
      </Container>
    );
  }

  // Portrait: the table is designed for landscape. The CSS-only
  // <RotateDevicePrompt /> is the primary deterrent; here we add a
  // runtime short-circuit so that the socket/table logic does not
  // continue to consume server resources / set state for a viewport
  // the user is not actually playing on. The prompt itself remains
  // rendered above the empty stub below.
  if (isPortrait) {
    return (
      <>
        <Container fullHeight contentCenteredMobile>
          <Text textAlign="center">
            {getLocalizedString('game_rotate-device-prompt')}
          </Text>
        </Container>
        <RotateDevicePrompt />
      </>
    );
  }

  const lastMessage =
    messages && messages.length > 0 ? messages[messages.length - 1].text : null;

  return (
    <>
      {isLeaving && (
        <LeavingOverlay>
          <Loader />
          <Text textAlign="center" style={{ marginTop: '1rem', color: '#fff' }}>
            {getLocalizedString('play_leaving') || '正在离开牌桌...'}
          </Text>
        </LeavingOverlay>
      )}
      {isActionLoading && (
        <ActionLoadingOverlay>
          <Loader />
          <Text textAlign="center" style={{ marginTop: '1rem', color: '#fff' }}>
            {getLocalizedString('play_action-signing') || '等待签名确认...'}
          </Text>
        </ActionLoadingOverlay>
      )}
      <KickNotification
        kickNotification={kickNotification}
        clearKickNotification={clearKickNotification}
      />
      {showFoldLeaveConfirm &&
        ReactDOM.createPortal(
          <ModalShell
            width="sm"
            role="alertdialog"
            ariaLabel={getLocalizedString('leave_confirm-title')}
            onBackdropClick={cancelFoldLeave}
          >
            <h2
              style={{
                margin: 0,
                fontFamily: theme.fonts.fontFamilySansSerif,
                fontSize: '1.4rem',
                fontWeight: 700,
                color: theme.colors.fontColorDark,
                textAlign: 'center',
              }}
            >
              {getLocalizedString('leave_confirm-title')}
            </h2>
            <Text textAlign="center" style={{ color: theme.colors.mutedText }}>
              {getLocalizedString('leave_confirm-message')}
            </Text>
            {(chipsAmount ?? 0) > 0 && (
              <Text
                textAlign="center"
                style={{
                  margin: 0,
                  padding: '0.5rem 0.75rem',
                  background: theme.colors.goldChip,
                  border: '1px solid rgba(125, 83, 8, 0.35)',
                  borderRadius: theme.radius.sm,
                  color: theme.colors.gold,
                  fontSize: '0.85rem',
                  lineHeight: 1.45,
                }}
              >
                {getLocalizedString('funds-leave_prefix')}
                {chipsToStrkText(chipsAmount ?? 0)} STRK
                {getLocalizedString('funds-leave_suffix')}
              </Text>
            )}
            <div
              style={{
                display: 'flex',
                gap: '0.75rem',
                justifyContent: 'center',
                marginTop: '0.5rem',
              }}
            >
              <Button
                variant="secondary"
                small
                onClick={cancelFoldLeave}
              >
                {getLocalizedString('leave_confirm-cancel')}
              </Button>
              <Button
                variant="danger"
                small
                onClick={() => confirmFoldLeave(true, pkHex || undefined)}
              >
                {getLocalizedString('leave_confirm-fold')}
              </Button>
            </div>
          </ModalShell>,
          document.getElementById('modal') as HTMLElement,
        )}
      {currentTable &&
        ReactDOM.createPortal(
          <>
            <HandHistoryPanel
              tableId={Number(currentTable.id)}
              visible={showHistoryPanel}
              onClose={() => setShowHistoryPanel(false)}
            />
            <HandReceipt
              tableId={Number(currentTable.id)}
              handSeq={receipt.seq}
              visible={receipt.open}
              onClose={() => setReceipt({ open: false, seq: receipt.seq })}
            />
          </>,
          document.getElementById('modal') as HTMLElement,
        )}
      <RotateDevicePrompt />
      {/* 牌桌舞台：固定设计分辨率 + 等比缩放（窗口缩放不重排，只改缩放系数）。
          CryptoPanel 的 position:fixed 以舞台为包含块，随牌桌一起缩放。 */}
      <TableStage>
      <CryptoPanel
        cryptoEvents={cryptoEvents}
        currentTable={currentTable}
        showCryptoPanel={showCryptoPanel}
        onToggle={() => setShowCryptoPanel((v) => !v)}
        settlementReceipts={settlementReceipts}
      />
      <Container
        fullHeight
        style={{
          padding: 0,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'stretch',
          justifyContent: 'flex-start',
          width: '100%',
          maxWidth: 'none',
          margin: 0,
          height: '100%',
        }}
      >
        {leaveDeferred && (
          <LeaveDeferredBanner role="status" aria-live="polite">
            <span>{getLocalizedString('leave_deferred-banner')}</span>
            <Button
              variant="secondary"
              small
              onClick={() => {
                // Re-join the table: 先中断 deferred leave（cancelled=true），
                // 再 emit SITTING_IN 让后端清除 sitting_out 标记。
                cancelDeferredLeave();
                sittingIn();
              }}
            >
              {getLocalizedString('leave_deferred-cancel')}
            </Button>
          </LeaveDeferredBanner>
        )}
        {currentTable && (
          <PlayLedger
            table={currentTable}
            communityCards={communityCards ?? []}
            decryptedHandCards={decryptedHandCards}
            lastMessage={lastMessage}
            onSitDown={openBuyinModal}
            /* 已入座用户不能再坐其他空位：隐藏全部入座钮 */
            canSit={!currentTable.closed && seatId == null}
            onOpenReceipt={() => void openLatestReceipt()}
            actionSlot={
              isPlayerSeated && seatId != null && currentTable.seats[seatId]?.turn ? (
                <div style={{ flex: 1, minWidth: 0, maxWidth: 780 }}>
                  <GameUI
                    currentTable={currentTable}
                    seatId={seatId}
                    bet={bet}
                    setBet={setBet}
                    raise={wrappedRaise}
                    fold={wrappedFold}
                    check={wrappedCheck}
                    call={wrappedCall}
                    isActionLoading={isActionLoading}
                  />
                </div>
              ) : undefined
            }
            toolbar={
              <>
                {/* /play 隐藏全局导航：此处补回 首页/大厅 入口（抬头墨线工具钮） */}
                <ToolButton onClick={() => navigate('/')}>
                  {getLocalizedString('homepage_nav-home')}
                </ToolButton>
                <ToolButton onClick={() => navigate('/lobby')}>
                  {getLocalizedString('navmenu-menu_item-lobby_txt')}
                </ToolButton>
                <ToolButton
                  onClick={async () => {
                    if (isLeaving) return;
                    setIsLeaving(true);
                    try {
                      await leaveTable(true, pkHex || undefined);
                    } catch (e) {
                      logger.error('[Play] leaveTable failed:', e);
                      setIsLeaving(false);
                    }
                  }}
                  disabled={isLeaving}
                >
                  {isLeaving
                    ? getLocalizedString('play_leaving') || '离开中...'
                    : getLocalizedString('game_leave-table-btn')}
                </ToolButton>
                <ToolButton
                  onClick={() => setShowHistoryPanel(true)}
                  aria-label={getLocalizedString('game_history-open-btn')}
                >
                  {getLocalizedString('game_history-open-btn')}
                </ToolButton>
                <ToolButton onClick={() => void openLatestReceipt()}>
                  {getLocalizedString('game_receipt-open-btn')}
                </ToolButton>
              </>
            }
          />
        )}
      </Container>
      </TableStage>
    </>
  );
};

export default Play;
