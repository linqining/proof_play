import React, { useContext, useEffect, useState, useCallback, useRef, useMemo } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import authContext from '../auth/authContext';
import socketContext from '../websocket/socketContext';
import { PlayerContext } from '../player/PlayerContext';
import GameContext from './gameContext';
import {
  Table,
  Card,
  GameMessage,
  Seat,
  CryptoEvent,
  SettlementReceipt,
} from '../../types/game';
import { SETTLEMENT_RESULT } from '../../pokergame/actions';
import { useCryptoOperations } from './useCryptoOperations';
import { useGameActions } from './useGameActions';
import { useGameSocket } from './useGameSocket';
import { useActionLoading } from '../../hooks/useActionLoading';
import { logger } from '../../helpers/logger';

const GameState: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const navigate = useNavigate();
  const { socket, socketId } = useContext(socketContext)!;
  const { loadUser } = useContext(authContext)!;
  const { playerKeys, pkHex, playerName, getPlayerKeys } = useContext(PlayerContext)!;

  const [messages, setMessages] = useState<GameMessage[]>([]);
  const [currentTable, setCurrentTable] = useState<Table | null>(null);
  const [turn, setTurn] = useState(false);
  const [turnTimeOutHandle, setHandle] = useState<ReturnType<typeof setTimeout> | null>(null);
  const [shuffleLoading, setShuffleLoading] = useState(false);
  const [revealLoading, setRevealLoading] = useState(false);
  const [decryptedHandCards, setDecryptedHandCards] = useState<string[]>([]);
  const [communityCards, setCommunityCards] = useState<Card[]>([]);
  const [kickNotification, setKickNotification] = useState<string | null>(null);
  // ZK 密码学事件流（保留最近 100 条），供主牌桌可视化面板消费
  const [cryptoEvents, setCryptoEvents] = useState<CryptoEvent[]>([]);
  // D4 结算终局回执（handId → 最新；`settlement_result` WS 事件维护，
  // T4「已上链结算」印章 / T6 托管提示的实时数据源）
  const [settlementReceipts, setSettlementReceipts] = useState<Record<number, SettlementReceipt>>({});
  // 后端因当前手牌进行中而推迟离桌时（LEAVE_DEFERRED 事件）置为 true，
  // 由 Play.tsx / useGameActions 读取并在合适时机清除
  const [leaveDeferred, setLeaveDeferred] = useState(false);

  const currentTableRef = useRef<Table | null>(null);
  const shuffleLoadingRef = useRef(false);
  const revealLoadingRef = useRef(false);

  const isPlayerSeated = !!(currentTable && pkHex && currentTable.seats && Object.values(currentTable.seats).some(
    (seat: Seat) => seat && seat.player && seat.player.pkHex === pkHex
  ));

  const seatId: number | null = currentTable && pkHex && currentTable.seats
    ? Object.values(currentTable.seats).find(
        (seat: Seat) => seat && seat.player && seat.player.pkHex === pkHex
      )?.id ?? null
    : null;

  const displayTable = useMemo(() => {
    if (!currentTable || decryptedHandCards.length === 0 || seatId === null) {
      logger.log('[displayTable] Skipping hand injection:', {
        hasTable: !!currentTable,
        decryptedCount: decryptedHandCards.length,
        seatId,
      });
      return currentTable;
    }
    const seat = currentTable.seats[seatId];
    if (!seat) {
      logger.log('[displayTable] Seat not found for seatId:', seatId, 'available keys:', Object.keys(currentTable.seats));
      return currentTable;
    }
    const handCards: Card[] = decryptedHandCards.map((cardStr) => ({
      suit: cardStr.slice(0, 1),
      rank: cardStr.slice(1),
    }));
    logger.log('[displayTable] Injecting decrypted hand cards:', handCards, 'for seatId:', seatId);
    return {
      ...currentTable,
      seats: {
        ...currentTable.seats,
        [seatId]: {
          ...seat,
          hand: handCards,
        },
      },
    };
  }, [currentTable, decryptedHandCards, seatId]);

  useEffect(() => {
    currentTableRef.current = currentTable;

    isPlayerSeated &&
      seatId && currentTable.seats &&
      currentTable.seats[seatId] &&
      turn !== currentTable.seats[seatId].turn &&
      setTurn(currentTable.seats[seatId].turn);
  }, [currentTable]); // eslint-disable-line react-hooks/exhaustive-deps

  const addMessage = useCallback((message: string) => {
    setMessages((prevMessages) => [...prevMessages, { text: message, timestamp: Date.now() }]);
    logger.log(message);
  }, []);

  const clearKickNotification = useCallback(() => {
    setKickNotification(null);
  }, []);

  const {
    handleShuffleNotice,
    handleRevealNotice,
    handleHandRevealResult,
    handleCommunityRevealResult,
    handleReconstructNotice,
    resetRevealDedup,
  } = useCryptoOperations({
    socket,
    playerKeys,
    pkHex,
    getPlayerKeys,
    addMessage,
    currentTableRef,
    setShuffleLoading,
    setRevealLoading,
    setDecryptedHandCards,
    setCommunityCards,
    shuffleLoadingRef,
    revealLoadingRef,
  });

  const gameActions = useGameActions({
    socket,
    navigate,
    playerKeys,
    pkHex,
    getPlayerKeys,
    addMessage,
    currentTableRef,
    currentTable,
    seatId,
    isPlayerSeated,
    leaveDeferred,
    setLeaveDeferred,
    authMethod: null,
  });

  const { isActionLoading, startActionLoading, stopActionLoading } = useActionLoading({ currentTable });

  // D4：结算终局事件（appchain/dual/legacy 出口成功、拒绝与终局失败都会
  // 广播）。落账 + 一条玩家可见的系统消息（binding 截断展示）。
  useEffect(() => {
    if (!socket) return;
    const onSettlement = (r: SettlementReceipt) => {
      logger.log('[SETTLEMENT_RESULT]', r);
      setSettlementReceipts((prev) => ({ ...prev, [r.handId]: r }));
      const label = r.handSeq ?? r.handId;
      const binding = r.handBinding ? ` · binding ${r.handBinding.slice(0, 12)}…` : '';
      const extra = r.blockNumber ? ` · block #${r.blockNumber}` : '';
      addMessage(
        `Hand #${label}: settlement ${r.status} (${r.exit}${binding}${extra})`,
      );
    };
    socket.on(SETTLEMENT_RESULT, onSettlement);
    return () => {
      socket.off(SETTLEMENT_RESULT, onSettlement);
    };
  }, [socket, addMessage]);

  // 真实路由离开 /play 时向服务器离桌（stand up）。
  //
  // 取代旧的 isUnmountingRef cleanup 模式：该模式用 effect cleanup 置标志、
  // 另一个 effect cleanup 读标志来触发离桌，但 React 18 StrictMode（dev）
  // 挂载即双执行 cleanup，伪卸载会把标志毒化为 true → 挂载期误发
  // LEAVE_TABLE + navigate('/')，玩家被反复弹回首页。StrictMode 重挂载
  // 不改变 pathname，只有真实导航才满足下面的 /play → 其他路径 迁移条件；
  // 页面关闭/刷新仍由 useGameSocket 的 pagehide 监听兜底。
  const location = useLocation();
  const lastPathRef = useRef(location.pathname);
  useEffect(() => {
    const prevPath = lastPathRef.current;
    lastPathRef.current = location.pathname;
    if (prevPath === '/play' && location.pathname !== '/play') {
      gameActions.leaveTable(false, pkHex || undefined).catch((e) =>
        logger.error('[GameState] leave on route change failed:', e)
      );
    }
  }, [location.pathname, pkHex, gameActions.leaveTable]);

  useEffect(() => {
    if (!turn) {
      turnTimeOutHandle && clearTimeout(turnTimeOutHandle);
      turnTimeOutHandle && setHandle(null);
      return;
    }
    // 自动弃牌定时器：始终以最新快照的回合计时锚点重排（deps 含
    // bettingStartedAt）。此前只在 turn 翻转时布防一次，若该快照携带
    // 的锚点已偏旧（回合推进广播乱序/延迟），会用过期剩余时间提前
    // 弃牌（2026-09-26 线上：15s 配置下 ~5s 即被 fold）。
    let delay = 15000;
    const t = currentTableRef.current;
    if (t?.bettingStartedAt && t?.bettingTimeoutMs && t.bettingTimeoutMs > 0) {
      const remaining = t.bettingStartedAt + t.bettingTimeoutMs - Date.now();
      delay = Math.min(Math.max(remaining, 0), t.bettingTimeoutMs);
    }
    turnTimeOutHandle && clearTimeout(turnTimeOutHandle);
    const handle = setTimeout(gameActions.fold, delay);
    setHandle(handle);
  }, [turn, currentTable?.bettingStartedAt, currentTable?.bettingTimeoutMs]); // eslint-disable-line react-hooks/exhaustive-deps

  useGameSocket({
    socket,
    addMessage,
    currentTableRef,
    setCurrentTable,
    setMessages,
    setDecryptedHandCards,
    setCommunityCards,
    setKickNotification,
    setCryptoEvents,
    setLeaveDeferred,
    pkHex,
    leaveTable: gameActions.leaveTable,
    handleShuffleNotice,
    handleRevealNotice,
    handleReconstructNotice,
    handleHandRevealResult,
    handleCommunityRevealResult,
    resetRevealDedup,
    stopActionLoading,
    shuffleLoadingRef,
  });

  return (
    <GameContext.Provider
      value={{
        messages,
        currentTable: displayTable,
        isPlayerSeated,
        seatId,
        shuffleLoading,
        revealLoading,
        decryptedHandCards,
        communityCards,
        kickNotification,
        cryptoEvents,
        settlementReceipts,
        leaveDeferred,
        setLeaveDeferred,
        showFoldLeaveConfirm: gameActions.showFoldLeaveConfirm,
        confirmFoldLeave: gameActions.confirmFoldLeave,
        cancelFoldLeave: gameActions.cancelFoldLeave,
        cancelDeferredLeave: gameActions.cancelDeferredLeave,
        joinTable: gameActions.joinTable,
        leaveTable: gameActions.leaveTable,
        sitDown: gameActions.sitDown,
        standUp: gameActions.standUp,
        addMessage,
        fold: gameActions.fold,
        check: gameActions.check,
        call: gameActions.call,
        raise: gameActions.raise,
        rebuy: gameActions.rebuy,
        sittingOut: gameActions.sittingOut,
        sittingIn: gameActions.sittingIn,
        expelInitiate: gameActions.expelInitiate,
        clearKickNotification,
        isActionLoading,
        startActionLoading,
      }}
    >
      {children}
    </GameContext.Provider>
  );
};

export default GameState;
