import React, { useCallback, useEffect, useState } from 'react';
import styled, { useTheme } from 'styled-components';
import ModalShell from '../modals/ModalShell';
import Text from '../typography/Text';
import Button from '../buttons/Button';
import PokerCard from './PokerCard';
import { api, type HandHistoryRecord, type HandProofResponse } from '../../api/secretPokerClient';
import { useContentContext } from '../../context/content/contentContext';
import { useLocaContext } from '../../context/localization/locaContext';

interface HandHistoryPanelProps {
  /** 桌号；null 时面板不渲染 */
  tableId: number | null;
  visible: boolean;
  onClose: () => void;
}

const List = styled.ul`
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
`;

const HandRow = styled.li`
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-radius: ${({ theme }) => theme.radius.md};
  padding: 0.6rem 0.75rem;
  background: transparent;
`;

/* 展开交互放在真 <button> 上（此前是 li onClick，键盘无法触达） */
const RowToggle = styled.button`
  display: block;
  width: 100%;
  margin: 0;
  padding: 0;
  border: none;
  background: transparent;
  color: inherit;
  font: inherit;
  text-align: left;
  cursor: pointer;
  border-radius: ${({ theme }) => theme.radius.xs};
  transition: background 0.15s ease;

  &:hover {
    background: rgba(255, 255, 255, 0.04);
  }
`;

const HandRowHeader = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
  font-size: 0.85rem;
  color: ${({ theme }) => theme.colors.fontColorDark};
`;

const HandMeta = styled.span`
  color: ${({ theme }) => theme.colors.mutedText};
  font-size: 0.75rem;
  white-space: nowrap;
`;

const Badge = styled.span<{ $showdown: boolean }>`
  font-size: 0.7rem;
  padding: 0.1rem 0.45rem;
  border-radius: ${({ theme }) => theme.radius.pill};
  border: 1px solid
    ${({ $showdown, theme }) => ($showdown ? theme.colors.borderSubtle : 'transparent')};
  background: ${({ $showdown }) => ($showdown ? 'transparent' : 'rgba(255,255,255,0.06)')};
  color: ${({ theme }) => theme.colors.mutedText};
  white-space: nowrap;
`;

const BoardRow = styled.div`
  display: flex;
  gap: 0.25rem;
  margin-top: 0.5rem;
  flex-wrap: wrap;
`;

const WinLine = styled.div`
  margin-top: 0.35rem;
  font-size: 0.8rem;
  color: ${({ theme }) => theme.colors.fontColorDark};
`;

const DetailGrid = styled.div`
  margin-top: 0.5rem;
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
  gap: 0.35rem 0.75rem;
  font-size: 0.78rem;
  color: ${({ theme }) => theme.colors.mutedText};
`;

const EmptyState = styled(Text)`
  text-align: center;
  padding: 1.5rem 0;
`;

/* D4/T4 结算印章：settled / refused / failed 三态着色 */
const SettleStamp = styled.div<{ $status: 'settled' | 'refused' | 'failed' | 'pending' }>`
  display: flex;
  align-items: center;
  gap: 0.4rem;
  flex-wrap: wrap;
  margin-top: 0.5rem;
  padding: 0.4rem 0.55rem;
  border-radius: 6px;
  font-size: 0.72rem;
  font-family: 'JetBrains Mono', monospace;
  border: 1px solid
    ${({ $status }) =>
      $status === 'settled'
        ? 'rgba(16,185,129,0.45)'
        : $status === 'pending'
          ? 'rgba(148,163,184,0.4)'
          : 'rgba(239,68,68,0.45)'};
  background: ${({ $status }) =>
    $status === 'settled'
      ? 'rgba(16,185,129,0.08)'
      : $status === 'pending'
        ? 'rgba(148,163,184,0.08)'
        : 'rgba(239,68,68,0.08)'};
  color: ${({ $status }) =>
    $status === 'settled' ? '#047857' : $status === 'pending' ? '#64748b' : '#b91c1c'};
`;

const StampMeta = styled.span`
  color: ${({ theme }) => theme.colors.mutedText};
  font-size: 0.66rem;
`;

/* T6 第三段：逐层洗牌证明事件行 */
const ProofLayerList = styled.div`
  margin-top: 0.5rem;
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
`;

const ProofLayerRow = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.72rem;
  font-family: 'JetBrains Mono', monospace;
  color: ${({ theme }) => theme.colors.mutedText};
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
`;

const truncateHex10 = (hex?: string | null) =>
  !hex ? '—' : hex.length <= 12 ? hex : `${hex.slice(0, 10)}…`;

const formatChips = (n: number) => `$${Number(n || 0).toFixed(2)}`;

const formatTime = (ms: number, lang: string) => {
  try {
    return new Date(ms).toLocaleString(lang === 'zh' ? 'zh-CN' : 'en-US', {
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return '';
  }
};

const formatDuration = (ms: number) => {
  const totalSec = Math.max(0, Math.round(ms / 1000));
  const m = Math.floor(totalSec / 60);
  const s = totalSec % 60;
  return m > 0 ? `${m}m ${s}s` : `${s}s`;
};

/**
 * 牌局记录看板（P0-2）：拉取 `/api/tables/:id/history` 最近手牌记录，
 * 行内展开公共牌/座位明细。数据来自服务器内存存储（每桌 ≤100 条，新→旧）。
 */
const HandHistoryPanel: React.FC<HandHistoryPanelProps> = ({ tableId, visible, onClose }) => {
  const theme = useTheme();
  const { getLocalizedString } = useContentContext();
  const { lang } = useLocaContext();
  const [records, setRecords] = useState<HandHistoryRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);
  // D1/D4 证明通道缓存：handSeq → 响应（'missing' = 升级前记录/暂不可用）
  const [proofCache, setProofCache] = useState<Record<number, HandProofResponse | 'missing'>>({});

  const load = useCallback(async () => {
    if (tableId == null) return;
    setLoading(true);
    setError(null);
    try {
      setRecords(await api.getHandHistory(tableId));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [tableId]);

  // 展开时拉取该手的证明 + 结算回执（T4 印章 / T6 第三段）
  useEffect(() => {
    if (tableId == null || expanded == null) return;
    if (proofCache[expanded] !== undefined) return;
    let cancelled = false;
    ;(async () => {
      try {
        const resp = await api.getHandProof(tableId, expanded);
        if (!cancelled) setProofCache((prev) => ({ ...prev, [expanded]: resp }));
      } catch {
        if (!cancelled) setProofCache((prev) => ({ ...prev, [expanded]: 'missing' }));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [tableId, expanded, proofCache]);

  useEffect(() => {
    if (visible) {
      setExpanded(null);
      void load();
    }
  }, [visible, load]);

  if (!visible) return null;

  const labels = {
    title: getLocalizedString('game_history-title'),
    hand: getLocalizedString('game_history-hand-lbl'),
    pot: getLocalizedString('game_history-pot-lbl'),
    rake: getLocalizedString('game_rake-collected_lbl'),
    showdown: getLocalizedString('game_history-showdown-badge'),
    fold: getLocalizedString('game_history-fold-badge'),
    empty: getLocalizedString('game_history-empty'),
    refresh: getLocalizedString('game_history-refresh'),
    receipt: getLocalizedString('game_history-receipt-lbl'),
    duration: getLocalizedString('game_history-duration-lbl'),
    actions: getLocalizedString('game_history-actions-lbl'),
    auto: getLocalizedString('game_history-auto-badge'),
  };

  return (
    <ModalShell
      width="lg"
      ariaLabel={labels.title}
      onBackdropClick={onClose}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <h2
          style={{
            margin: 0,
            fontFamily: theme.fonts.fontFamilySansSerif,
            fontSize: '1.3rem',
            fontWeight: 700,
            color: theme.colors.fontColorDark,
          }}
        >
          {labels.title}
        </h2>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <Button variant="secondary" small onClick={() => void load()} disabled={loading}>
            {labels.refresh}
          </Button>
          <Button variant="secondary" small onClick={onClose} aria-label="Close">
            ✕
          </Button>
        </div>
      </div>

      {error && (
        <Text style={{ color: theme.colors.danger ?? '#ff6b6b' }}>{error}</Text>
      )}
      {loading && records.length === 0 && <Text textAlign="center">…</Text>}
      {!loading && !error && records.length === 0 && <EmptyState>{labels.empty}</EmptyState>}

      <List>
        {records.map((r) => {
          const isOpen = expanded === r.handSeq;
          const proof = isOpen ? proofCache[r.handSeq] : undefined;
          const settled = proof && proof !== 'missing' ? proof.settlement : null;
          const stampStatus =
            settled == null
              ? ('pending' as const)
              : settled.status === 'settled'
                ? ('settled' as const)
                : settled.status === 'refused'
                  ? ('refused' as const)
                  : ('failed' as const);
          const stampLabel =
            stampStatus === 'settled'
              ? getLocalizedString('settlement_settled-stamp')
              : stampStatus === 'refused'
                ? getLocalizedString('settlement_refused-stamp')
                : stampStatus === 'failed'
                  ? getLocalizedString('settlement_failed-stamp')
                  : getLocalizedString('settlement_pending-stamp');
          return (
            <HandRow key={r.handSeq}>
              <RowToggle
                type="button"
                onClick={() => setExpanded(isOpen ? null : r.handSeq)}
                aria-expanded={isOpen}
              >
                <HandRowHeader>
                  <span>
                    {labels.hand} #{r.handSeq} · {labels.pot} {formatChips(r.grossPot)}
                    {r.rakeCollected > 0 && ` · ${labels.rake} ${formatChips(r.rakeCollected)}`}
                  </span>
                  <span style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                    <HandMeta>{formatTime(r.handOverAt, lang)}</HandMeta>
                    <Badge $showdown={r.wentToShowdown}>
                      {r.wentToShowdown ? labels.showdown : labels.fold}
                    </Badge>
                  </span>
                </HandRowHeader>
              </RowToggle>
              {r.winMessages.slice(0, isOpen ? undefined : 1).map((m, i) => (
                <WinLine key={i}>{m}</WinLine>
              ))}
              {isOpen && (
                <>
                  {/* T4「已上链结算」印章（D4 证明通道 settlement 段；回执未落
                      或升级前记录 = 待上链灰态） */}
                  <SettleStamp $status={stampStatus}>
                    <strong>{stampLabel}</strong>
                    {settled && (
                      <StampMeta>
                        {settled.exit}
                        {settled.handBinding
                          ? ` · binding ${truncateHex10(settled.handBinding)}`
                          : settled.aggregateDigest
                            ? ` · digest ${truncateHex10(settled.aggregateDigest)}`
                            : ''}
                        {settled.blockNumber != null
                          ? ` · block #${settled.blockNumber.toLocaleString()}`
                          : ''}
                        {settled.gasFee ? ` · ${settled.gasFee}` : ''}
                      </StampMeta>
                    )}
                    {/* 「在 starkscan 查看」：gateway attestation 入口（配置了才有） */}
                    {settled?.handBinding &&
                      proof != null &&
                      proof !== 'missing' &&
                      proof.chain?.gateway && (
                        <a
                          href={`${proof.chain.gateway.replace(/\/$/, '')}/api/v1/proof/${settled.handBinding.replace(/^0x/, '')}`}
                          target="_blank"
                          rel="noreferrer"
                          style={{ marginLeft: 'auto', fontSize: '0.66rem' }}
                          onClick={(e) => e.stopPropagation()}
                        >
                          {getLocalizedString('game_history-verify-attestation')} ↗
                        </a>
                      )}
                    {settled?.reason && (
                      <StampMeta style={{ flexBasis: '100%' }}>{settled.reason}</StampMeta>
                    )}
                  </SettleStamp>

                  {/* T6 第三段：洗牌证明（承诺值 + 逐层事件 + tx；方案 b 投影
                      的派生行由 ZK 面板展示，此处列层事实与链上锚点） */}
                  <ProofLayerList>
                    <div
                      style={{
                        fontSize: '0.7rem',
                        textTransform: 'uppercase',
                        letterSpacing: '0.05em',
                      }}
                    >
                      {getLocalizedString('game_history-proof-lbl')} (
                      {proof !== 'missing' && proof ? proof.layers.length : 0})
                    </div>
                    {proof === 'missing' || !proof ? (
                      <ProofLayerRow>
                        {getLocalizedString('game_history-proof-empty')}
                      </ProofLayerRow>
                    ) : (
                      proof.layers.map((l) => (
                        <ProofLayerRow key={`${l.round}-${l.playerPk}`}>
                          <span
                            style={{
                              color: l.verified ? '#34d399' : '#f87171',
                              fontWeight: 700,
                            }}
                          >
                            {l.verified ? '✓' : '✗'}
                          </span>
                          <span>
                            L{l.round} · V{l.proofVersion} · #{l.seat} {l.playerName}
                          </span>
                          <span>tx {l.txDigest ? truncateHex10(l.txDigest) : 'pending'}</span>
                        </ProofLayerRow>
                      ))
                    )}
                  </ProofLayerList>

                  {r.board.length > 0 && (
                    <BoardRow>
                      {r.board.map((c, i) => (
                        <PokerCard key={i} card={c} width="2rem" />
                      ))}
                    </BoardRow>
                  )}
                  {/* 凭证号 + 用时（设计稿 T6 凭证三段之一） */}
                  <WinLine>
                    {labels.receipt} R-{r.handSeq}-{tableId}
                    {r.handStartedAt
                      ? ` · ${labels.duration} ${formatDuration(r.handOverAt - r.handStartedAt)}`
                      : ''}
                    {r.actions && r.actions.length > 0
                      ? ` · ${r.actions.length}`
                      : ''}
                  </WinLine>
                  <DetailGrid>
                    {Object.entries(r.seats).map(([seatId, s]) => {
                      const cards = r.holeCards?.[seatId] ?? [];
                      const net = r.nets?.find(([seat]) => String(seat) === seatId)?.[1];
                      const rank = r.showdownHandRanks?.find(
                        (h) => String(h.seat) === seatId,
                      )?.rank;
                      return (
                        <span key={seatId} style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                          <span>
                            #{seatId} {s.player?.username || s.player?.id?.slice(0, 10) || '—'} ·{' '}
                            {labels.pot} {formatChips(s.stack)}
                            {rank && ` · ${rank}`}
                            {net != null && (
                              <span
                                style={{
                                  color: net >= 0 ? '#34d399' : '#f87171',
                                  fontWeight: 600,
                                }}
                              >
                                {' '}
                                {net >= 0 ? '+' : ''}
                                {net}
                              </span>
                            )}
                          </span>
                          {cards.length > 0 && (
                            <span style={{ display: 'inline-flex', gap: '0.15rem' }}>
                              {cards.map((c, i) => (
                                <PokerCard key={i} card={c} width="1.4rem" />
                              ))}
                            </span>
                          )}
                        </span>
                      );
                    })}
                  </DetailGrid>
                  {/* 行动流水（服务端 actions 下发时；设计稿 T6 ACTION LOG） */}
                  {r.actions && r.actions.length > 0 && (
                    <div
                      style={{
                        marginTop: '0.5rem',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '0.15rem',
                        fontSize: '0.75rem',
                        color: theme.colors.mutedText,
                      }}
                    >
                      <div style={{ fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                        {labels.actions}
                      </div>
                      {r.actions.map((a, i) => (
                        <div key={i} style={{ display: 'flex', gap: '0.5rem' }}>
                          <span style={{ minWidth: '3.5rem' }}>{a.street ?? ''}</span>
                          <span style={{ minWidth: '7rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {a.player || `#${a.seat}`}
                          </span>
                          <span>
                            {a.action}
                            {a.amount > 0 ? ` ${a.amount}` : ''}
                            {a.auto ? ` (${labels.auto})` : ''}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </>
              )}
            </HandRow>
          );
        })}
      </List>
    </ModalShell>
  );
};

export default HandHistoryPanel;
