import React, { useEffect, useRef, useState } from 'react';
import type { Socket } from 'socket.io-client';
import type { NavigateFunction } from 'react-router-dom';
import { useLocation } from 'react-router-dom';
import { FETCH_LOBBY_INFO, RECEIVE_LOBBY_INFO } from '../pokergame/actions';
import { getToken } from '../helpers/getToken';
import { logger } from '../helpers/logger';
import type { Table } from '../types/game';
import Text from '../components/typography/Text';
import { MAX_JOIN_RETRIES, JOIN_RETRY_DELAY_MS } from '../clientConfig';

interface UseTableJoinParams {
  socket: Socket | null;
  isConnected: boolean;
  pkHex: string | null;
  currentTable: Table | null;
  joinTable: (tableId: number, pkHex: string) => void;
  leaveTable: (
    shouldNavigate?: boolean,
    pkHex?: string,
    fireAndForget?: boolean,
  ) => Promise<void>;
  openModal: (
    children: () => React.ReactNode,
    headingText: string,
    btnText: string,
    btnCallBack?: () => void,
    onCloseCallBack?: () => void,
  ) => void;
  navigate: NavigateFunction;
  getLocalizedString: (key: string) => string;
}

/**
 * Manages the table join lifecycle:
 * - Listens for RECEIVE_LOBBY_INFO to know when the server has registered the player
 * - Emits JOIN_TABLE only after lobby is ready (avoids race with FETCH_LOBBY_INFO)
 * - Retries up to MAX_JOIN_RETRIES times if currentTable remains null
 * - Handles reconnection (manual FETCH_LOBBY_INFO) and lost-connection modal
 *
 * All state managed here is internal to the join lifecycle; nothing is returned.
 */
export const useTableJoin = ({
  socket,
  isConnected,
  pkHex,
  currentTable,
  joinTable,
  leaveTable,
  openModal,
  navigate,
  getLocalizedString,
}: UseTableJoinParams): void => {
  const [hasJoined, setHasJoined] = useState(false);
  const [isReconnecting, setIsReconnecting] = useState(false);
  const [lobbyReady, setLobbyReady] = useState(false);

  const reconnectAttemptRef = useRef(0);
  const hasShownLostModalRef = useRef(false);
  // 重试计数器：进入 /play 后若 currentTable 一直为空，则重试 FETCH_LOBBY_INFO + joinTable
  const joinRetryRef = useRef(0);
  // 用 ref 在 join effect 中读取最新的 currentTable，避免将其加入依赖数组导致频繁重跑
  const currentTableRef = useRef(currentTable);

  useEffect(() => {
    currentTableRef.current = currentTable;
  }, [currentTable]);

  // 监听 RECEIVE_LOBBY_INFO：服务器处理完 FETCH_LOBBY_INFO 后会 emit 此事件，
  // 表示 player 已注册到 gs.players，此时再 emit JOIN_TABLE 才能正确触发 TABLE_UPDATED
  useEffect(() => {
    if (!socket) return;
    const handler = () => {
      logger.log('[Play] RECEIVE_LOBBY_INFO received, lobby ready');
      setLobbyReady(true);
    };
    socket.on(RECEIVE_LOBBY_INFO, handler);
    return () => {
      socket.off(RECEIVE_LOBBY_INFO, handler);
    };
  }, [socket]);

  // 断线时重置 lobbyReady，重连后重新走 FETCH_LOBBY_INFO → RECEIVE_LOBBY_INFO → JOIN_TABLE 流程
  useEffect(() => {
    if (!isConnected) {
      setLobbyReady(false);
    } else {
      joinRetryRef.current = 0;
    }
  }, [isConnected]);

  // 真实路由离开 /play 时向服务器离桌。
  // 取代旧的 isUnmountingRef cleanup 模式：StrictMode（dev）挂载即双执行
  // cleanup 会把标志毒化为 true，join effect 的依赖（socket/isConnected/
  // lobbyReady）一变就在伪卸载 cleanup 里误发 LEAVE_TABLE——服务器随即移除
  // 座位，客户端 currentTable 被清空、join 重试，形成弹回首页死循环。
  // StrictMode 重挂载不改变 pathname；页面关闭/刷新仍由 pagehide 兜底。
  const location = useLocation();
  const lastPathRef = useRef(location.pathname);
  useEffect(() => {
    const prevPath = lastPathRef.current;
    lastPathRef.current = location.pathname;
    if (prevPath === '/play' && location.pathname !== '/play') {
      void leaveTable(false, pkHex || undefined, true);
      setHasJoined(false);
    }
    // leaveTable 由调用方以稳定回调传入；仅真实路径迁移才触发动作
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.pathname, pkHex]);

  // join effect：等 lobby ready 后再 emit JOIN_TABLE。
  // 根因：WebSocketProvider 在 socket connect 时 emit FETCH_LOBBY_INFO（注册 player 到服务器），
  // 若客户端在 FETCH_LOBBY_INFO 处理完成前就 emit JOIN_TABLE，服务器端 join_table_push 会因
  // 找不到 player 的 wallet 而静默失败，客户端永远收不到 TABLE_UPDATED。
  // 修复：通过监听 RECEIVE_LOBBY_INFO 确认 player 已注册后再 emit JOIN_TABLE。
  useEffect(() => {
    if (!socket || !isConnected) return;

    // 如果 currentTable 已经存在（例如从别的页面返回 /play，GameState 仍持有 table 状态），
    // 直接跳过 joinTable 和 FETCH_LOBBY_INFO，避免每次进入都卡一下等 lobby 信息。
    if (currentTableRef.current) {
      setHasJoined(true);
      return;
    }

    if (!lobbyReady) {
      // lobby info 还没收到，主动 emit FETCH_LOBBY_INFO 触发服务器注册 player，
      // 收到 RECEIVE_LOBBY_INFO 后 lobbyReady 变 true，本 effect 会重新执行并 emit JOIN_TABLE
      const token = getToken();
      if (token) {
        logger.log('[Play] lobby not ready, emitting FETCH_LOBBY_INFO');
        socket.emit(FETCH_LOBBY_INFO, token);
      } else {
        logger.warn('[Play] No token, cannot emit FETCH_LOBBY_INFO');
      }
      return;
    }

    logger.log('[Play] lobby ready, emitting JOIN_TABLE');
    joinTable(1, pkHex || '');
    setHasJoined(true);
    // 离桌触发已迁移至上方 useLocation 路由守卫（含 pagehide 兜底）：
    // cleanup 不再做业务动作，避免 StrictMode 伪卸载误发 LEAVE_TABLE。
  }, [socket, isConnected, lobbyReady]);

  // 重试机制：lobbyReady 后若 currentTable 仍为空，重置 lobbyReady 触发重新走
  // FETCH_LOBBY_INFO → RECEIVE_LOBBY_INFO → JOIN_TABLE 流程，确保重试时不再并发。
  useEffect(() => {
    if (!hasJoined || !socket || !isConnected || currentTable || !lobbyReady) return;
    if (joinRetryRef.current >= MAX_JOIN_RETRIES) return;

    const timer = setTimeout(() => {
      joinRetryRef.current += 1;
      logger.log(
        `[Play] currentTable still null after join, retry ${joinRetryRef.current}/${MAX_JOIN_RETRIES}`,
      );
      // 重置 lobbyReady，触发 join effect 重新 emit FETCH_LOBBY_INFO → 等待 RECEIVE_LOBBY_INFO → emit JOIN_TABLE
      setLobbyReady(false);
    }, JOIN_RETRY_DELAY_MS);

    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hasJoined, socket, isConnected, currentTable, lobbyReady]);

  // Handle reconnection when connection is lost after joining
  useEffect(() => {
    if (!hasJoined) return;

    if (isConnected) {
      // Connection restored
      setIsReconnecting(false);
      reconnectAttemptRef.current = 0;
      hasShownLostModalRef.current = false;
      return;
    }

    // Connection lost - attempt manual reconnect via FETCH_LOBBY_INFO
    if (socket && !isConnected && !isReconnecting && !hasShownLostModalRef.current) {
      setIsReconnecting(true);
      reconnectAttemptRef.current += 1;

      const token = getToken();
      if (token) {
        logger.log(
          `[Reconnect] Attempt ${reconnectAttemptRef.current}, emitting FETCH_LOBBY_INFO`,
        );
        socket.emit(FETCH_LOBBY_INFO, token);
      }
    }

    // If socket is completely gone (not just disconnected), show lost modal
    if (!socket && !hasShownLostModalRef.current) {
      hasShownLostModalRef.current = true;
      openModal(
        () => <Text>{getLocalizedString('game_lost-connection-modal_text')}</Text>,
        getLocalizedString('game_lost-connection-modal_header'),
        getLocalizedString('game_lost-connection-modal_btn-txt'),
        () => navigate('/'),
      );
    }
  }, [
    hasJoined,
    isConnected,
    socket,
    isReconnecting,
    openModal,
    navigate,
    getLocalizedString,
  ]);
};
