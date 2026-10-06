import { useCallback, useEffect, useRef, useState } from 'react';
import type { Table } from '../types/game';
import { ACTION_LOADING_TIMEOUT_MS } from '../clientConfig';

interface UseActionLoadingParams {
  currentTable: Table | null;
}

interface UseActionLoadingReturn {
  isActionLoading: boolean;
  startActionLoading: () => void;
  stopActionLoading: () => void;
}

/**
 * Manages the action-loading overlay state.
 *
 * When a player action (raise/call/fold/check/all-in) is triggered, the UI shows
 * a loading overlay while waiting for the signing + TABLE_UPDATED round-trip.
 * A 30s timeout acts as a fallback in case TABLE_UPDATED never arrives.
 *
 * The overlay is cleared as soon as `currentTable` updates (TABLE_UPDATED arrived),
 * or when `stopActionLoading` is called (e.g. on backend `error` event or sponsored
 * tx execution failure), or after the 30s timeout.
 */
export const useActionLoading = ({
  currentTable,
}: UseActionLoadingParams): UseActionLoadingReturn => {
  // 玩家操作（raise/call/fold/check/all-in）签名中：点击后置 true，TABLE_UPDATED、失败或超时后置 false
  const [isActionLoading, setIsActionLoading] = useState(false);
  const actionLoadingTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // 交易失败（后端 error 或 sponsored tx 失败）时立即关闭 loading
  const stopActionLoading = useCallback(() => {
    setIsActionLoading(false);
    if (actionLoadingTimerRef.current) {
      clearTimeout(actionLoadingTimerRef.current);
      actionLoadingTimerRef.current = null;
    }
  }, []);

  // 玩家操作签名完成（TABLE_UPDATED 到达）后关闭 loading
  useEffect(() => {
    if (isActionLoading && currentTable) {
      setIsActionLoading(false);
      if (actionLoadingTimerRef.current) {
        clearTimeout(actionLoadingTimerRef.current);
        actionLoadingTimerRef.current = null;
      }
    }
  }, [currentTable, isActionLoading]);

  // 组件卸载时清理定时器
  useEffect(() => {
    return () => {
      if (actionLoadingTimerRef.current) {
        clearTimeout(actionLoadingTimerRef.current);
        actionLoadingTimerRef.current = null;
      }
    };
  }, []);

  // 包装玩家操作：点击后立即显示 loading，30 秒超时兜底
  const startActionLoading = () => {
    setIsActionLoading(true);
    if (actionLoadingTimerRef.current) {
      clearTimeout(actionLoadingTimerRef.current);
    }
    actionLoadingTimerRef.current = setTimeout(() => {
      setIsActionLoading(false);
      actionLoadingTimerRef.current = null;
    }, 30_000);
  };

  return { isActionLoading, startActionLoading, stopActionLoading };
};
