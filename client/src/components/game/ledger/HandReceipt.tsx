import React, { useEffect, useState } from 'react';
import styled from 'styled-components';
import { api, type HandHistoryRecord, type HandProofResponse } from '../../../api/secretPokerClient';
import { StreetRailLite } from './StreetRailLite';
import { fontMono } from '../../../styles/theme';
import { ShieldCheck, CheckCircle2, AlertTriangle } from 'lucide-react';

/**
 * 本手凭证（design/table T6）：一张横向账页，三段同页——
 * ① 牌局流水（街段轨 + 逐动作）② 彩池结算（每家净结果 + 台费）③ 公平性证明
 * （洗牌层 + 结算回执 + 链上元数据，数据源 D1 证明通道）。
 */

const Overlay = styled.div`
  position: fixed;
  inset: 0;
  z-index: 500;
  background: rgba(20, 19, 15, 0.42);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 2vh 1rem;
`;

const Doc = styled.div`
  position: relative;
  width: min(1080px, 94vw);
  max-height: 86vh;
  overflow: auto;
  background: ${({ theme }) => theme.colors.lightBg};
`;

const Head = styled.div`
  display: flex;
  align-items: baseline;
  gap: 14px;
  padding: 12px 56px 12px 18px;
  background: ${({ theme }) => theme.colors.lightestBg};
  border-bottom: 1px dashed ${({ theme }) => theme.colors.borderMuted};
  flex-wrap: wrap;
`;

const Title = styled.div`
  font-size: 16px;
  font-weight: 700;
  display: flex;
  align-items: baseline;
  gap: 9px;
  flex-wrap: wrap;
  .hand {
    font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
    font-size: 11px;
    font-weight: 500;
    color: ${({ theme }) => theme.colors.softerText};
    letter-spacing: 0.06em;
  }
`;

const HeadRight = styled.div`
  margin-left: auto;
  display: flex;
  gap: 7px;
  align-items: center;
  flex-wrap: wrap;
`;

const NetChip = styled.span`
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-variant-numeric: tabular-nums;
  font-size: 10.5px;
  color: ${({ theme }) => theme.colors.mutedText};
  border: 1px solid ${({ theme }) => theme.colors.borderMuted};
  border-radius: 2px;
  padding: 2px 7px;
  background: ${({ theme }) => theme.colors.lightestBg};
  white-space: nowrap;
  b {
    color: ${({ theme }) => theme.colors.fontColorDark};
  }
`;

const Seal = styled.span<{ $ok: boolean }>`
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 9px;
  letter-spacing: 0.13em;
  text-transform: uppercase;
  padding: 3px 7px;
  border: 1.5px solid currentColor;
  border-radius: 2px;
  transform: rotate(-4deg);
  font-weight: 600;
  color: ${({ $ok, theme }) => ($ok ? theme.colors.success : theme.colors.danger)};
`;

const Body = styled.div`
  display: grid;
  grid-template-columns: 1.1fr 1fr 1.15fr;
  @media (max-width: 1023px) {
    grid-template-columns: 1fr;
  }
`;

const Col = styled.section`
  padding: 14px 16px;
  border-left: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  min-width: 0;
  &:first-child {
    border-left: none;
  }
  @media (max-width: 1023px) {
    border-left: none;
    border-top: 1px solid ${({ theme }) => theme.colors.borderSubtle};
    &:first-child {
      border-top: none;
    }
  }
`;

const SecT = styled.h3`
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 9.5px;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: ${({ theme }) => theme.colors.softerText};
  font-weight: 500;
  display: flex;
  align-items: center;
  gap: 8px;
  margin: 0 0 9px;
  &::after {
    content: '';
    flex: 1;
    height: 1px;
    background: ${({ theme }) => theme.colors.borderSubtle};
  }
`;

const LR = styled.div`
  display: flex;
  align-items: baseline;
  gap: 10px;
  padding: 6px 0;
  border-bottom: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  font-size: 12px;
  &:last-child {
    border-bottom: none;
  }
  .k {
    color: ${({ theme }) => theme.colors.mutedText};
    flex: none;
    max-width: 52%;
    font-size: 11px;
  }
  .v {
    margin-left: auto;
    font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
    font-variant-numeric: tabular-nums;
    text-align: right;
    color: ${({ theme }) => theme.colors.fontColorDark};
    font-size: 11.5px;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .v.pos {
    color: ${({ theme }) => theme.colors.success};
  }
  .v.bad {
    color: ${({ theme }) => theme.colors.danger};
  }
  .v.dim {
    color: ${({ theme }) => theme.colors.softerText};
  }
`;

const ActionList = styled.div`
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-radius: 3px;
  background: ${({ theme }) => theme.colors.lightestBg};
  padding: 2px 10px;
  max-height: 240px;
  overflow: auto;
`;

const ActionRow = styled.div`
  display: grid;
  grid-template-columns: 44px 1fr auto;
  gap: 10px;
  align-items: center;
  padding: 7px 0;
  border-bottom: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  &:last-child {
    border-bottom: none;
  }
  .tk {
    width: 22px;
    height: 22px;
    border: 1px solid ${({ theme }) => theme.colors.borderMuted};
    border-radius: 2px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
    font-size: 10px;
    font-weight: 700;
    color: ${({ theme }) => theme.colors.mutedText};
    background: ${({ theme }) => theme.colors.surfaceMutedPlain};
  }
  .n {
    font-size: 12px;
    font-weight: 600;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .s {
    font-size: 10px;
    color: ${({ theme }) => theme.colors.softerText};
    font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .r {
    font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
    font-variant-numeric: tabular-nums;
    font-size: 12px;
    font-weight: 600;
    text-align: right;
  }
`;

const LayerRow = styled.div`
  display: grid;
  grid-template-columns: 22px 1fr auto;
  gap: 9px;
  align-items: center;
  padding: 7px 0;
  border-bottom: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  &:last-child {
    border-bottom: none;
  }
  .ic {
    width: 22px;
    height: 22px;
    border: 1px solid rgba(11, 107, 69, 0.4);
    border-radius: 2px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: ${({ theme }) => theme.colors.success};
    background: rgba(11, 107, 69, 0.06);
  }
  .ic.bad {
    color: ${({ theme }) => theme.colors.danger};
    border-color: rgba(168, 50, 38, 0.4);
    background: rgba(168, 50, 38, 0.06);
  }
  b {
    display: block;
    font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
    font-size: 10.5px;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    font-weight: 600;
  }
  span {
    display: block;
    font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
    font-size: 9.5px;
    color: ${({ theme }) => theme.colors.softerText};
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .t {
    font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
    font-size: 9.5px;
    color: ${({ theme }) => theme.colors.softerText};
    text-align: right;
    flex: none;
  }
`;

const SettleCard = styled.div`
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-radius: 3px;
  background: ${({ theme }) => theme.colors.lightestBg};
  padding: 10px 12px;
  margin-bottom: 10px;
`;

const Raw = styled.div`
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 9.5px;
  color: ${({ theme }) => theme.colors.mutedText};
  background: ${({ theme }) => theme.colors.surfaceMutedPlain};
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-radius: 2px;
  padding: 8px 10px;
  word-break: break-all;
  line-height: 1.65;
`;

const fmt = (n: number) => new Intl.NumberFormat().format(n);

interface HandReceiptProps {
  tableId: number;
  handSeq: number;
  visible: boolean;
  onClose: () => void;
}

export const HandReceipt: React.FC<HandReceiptProps> = ({ tableId, handSeq, visible, onClose }) => {
  const [record, setRecord] = useState<HandHistoryRecord | null>(null);
  const [proof, setProof] = useState<HandProofResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!visible) return;
    setRecord(null);
    setProof(null);
    setError(null);
    Promise.all([
      api.getHandRecord(tableId, handSeq),
      api.getHandProof(tableId, handSeq).catch(() => null),
    ])
      .then(([r, p]) => {
        setRecord(r);
        setProof(p);
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [visible, tableId, handSeq]);

  if (!visible) return null;

  const actions = record?.actions ?? [];
  const layers = proof?.layers ?? [];
  const settlement = proof?.settlement ?? null;
  const chain = proof?.chain ?? null;
  const startedAt = record?.handStartedAt ?? 0;
  const duration =
    startedAt > 0 ? Math.max(0, Math.round((record!.handOverAt - startedAt) / 1000)) : null;
  const seats = record?.seats ?? {};
  const nets = record?.nets ?? [];
  const ranks = record?.showdownHandRanks ?? [];

  return (
    <Overlay role="dialog" aria-label="本手凭证" onClick={onClose}>
      <Doc onClick={(e) => e.stopPropagation()}>
        <button
          onClick={onClose}
          aria-label='Close'
          style={{
            position: 'absolute',
            top: 10,
            right: 12,
            width: 28,
            height: 28,
            border: '1px solid #c3bba7',
            borderRadius: 3,
            background: '#fffdf7',
            color: '#4b4840',
            fontSize: 14,
            cursor: 'pointer',
            zIndex: 2,
          }}
        >
          ✕
        </button>
        <Head>
          <Title>
            牌桌 {tableId} · 第 {handSeq} 手
            <span className="hand">
              {record
                ? new Date(record.handOverAt).toLocaleString() +
                  ` · ${Object.keys(seats).length} 家` +
                  (record.wentToShowdown ? ' · 摊牌' : '')
                : ''}
            </span>
          </Title>
          <HeadRight>
            <NetChip>
              凭证号 <b>R-{handSeq}-{tableId}</b>
            </NetChip>
            {duration != null && (
              <NetChip>
                用时 <b>{duration}s</b>
              </NetChip>
            )}
            <NetChip>
              总彩池 <b>{fmt(record?.grossPot ?? 0)}</b>
            </NetChip>
            <Seal $ok={settlement?.status === 'settled'}>
              {settlement?.status === 'settled' ? (
                <>
                  <ShieldCheck size={11} strokeWidth={2} /> 已上链结算
                </>
              ) : (
                <>
                  <AlertTriangle size={11} strokeWidth={2} /> 结算 {settlement?.status ?? '—'}
                </>
              )}
            </Seal>
          </HeadRight>
        </Head>

        {error && (
          <div style={{ padding: '12px 18px', color: '#a83226', fontSize: 12 }}>{error}</div>
        )}

        <Body>
          <Col>
            <SecT>牌局流水 · ACTION LOG</SecT>
            {record && (
              <StreetRailLite
                boardCount={record.board.length}
                showdown={record.wentToShowdown}
              />
            )}
            <div style={{ height: 8 }} />
            <ActionList>
              {actions.map((a, i) => {
                const seatKey = String(a.seat);
                const name = a.player || seats[seatKey]?.player?.username || `#${a.seat}`;
                return (
                  <ActionRow key={i}>
                    <div className="tk">{i + 1}</div>
                    <div>
                      <div className="n">{name}</div>
                      <div className="s">
                        {a.street ?? ''}
                        {a.auto ? ' · 超时代打' : ''}
                      </div>
                    </div>
                    <div className="r">
                      {a.action}
                      {a.amount > 0 ? ` ${fmt(a.amount)}` : ''}
                    </div>
                  </ActionRow>
                );
              })}
              {actions.length === 0 && (
                <ActionRow>
                  <div className="tk">—</div>
                  <div className="s">无逐动作流水（升级前旧手）</div>
                  <div />
                </ActionRow>
              )}
            </ActionList>
          </Col>

          <Col>
            <SecT>彩池结算 · SETTLEMENT</SecT>
            <LR>
              <span className="k">总彩池 GROSS POT</span>
              <span className="v">{fmt(record?.grossPot ?? 0)}</span>
            </LR>
            {(record?.sidePots ?? []).map((sp, i) => (
              <LR key={i}>
                <span className="k">边池 {i + 1}{sp.players?.length ? `（${sp.players.length} 家可争）` : ''}</span>
                <span className="v">{fmt(sp.amount)}</span>
              </LR>
            ))}
            <LR>
              <span className="k">台费 RAKE</span>
              <span className={(record?.rakeCollected ?? 0) > 0 ? 'v bad' : 'v dim'}>
                {fmt(record?.rakeCollected ?? 0)}
              </span>
            </LR>
            <div style={{ height: 10 }} />
            <SecT>各家净结果 · NETS</SecT>
            {nets.map(([seat, net]) => {
              const seatKey = String(seat);
              const name = seats[seatKey]?.player?.username || seats[seatKey]?.player?.id || `#${seat}`;
              const rank = ranks.find((h) => h.seat === seat)?.rank;
              return (
                <LR key={seat}>
                  <span className="k">
                    {name}
                    {rank ? ` · ${rank}` : ''}
                  </span>
                  <span className={net >= 0 ? 'v pos' : 'v bad'}>
                    {net >= 0 ? '+' : ''}
                    {fmt(net)}
                  </span>
                </LR>
              );
            })}
            {settlement && (
              <>
                <div style={{ height: 10 }} />
                <SecT>链上锚 · BINDING</SecT>
                <Raw>
                  hand_binding {settlement.handBinding}
                  <br />
                  batch_root {settlement.batchRoot ?? '—'} · op #{settlement.settleOpIndex ?? '—'} ·{' '}
                  {settlement.proven ? '已出证' : '未出证'}
                </Raw>
              </>
            )}
          </Col>

          <Col>
            <SecT>公平性证明 · PROOF</SecT>
            <LayerList layers={layers} />
            <div style={{ height: 10 }} />
            <SecT>链上验证 · ONCHAIN</SecT>
            <SettleCard>
              <LR>
                <span className="k">状态</span>
                <span className={settlement?.status === 'settled' ? 'v pos' : 'v bad'}>
                  {settlement?.status === 'settled' ? '已结算 SETTLED' : settlement?.status ?? '—'}
                </span>
              </LR>
              <LR>
                <span className="k">结算出口</span>
                <span className="v">{settlement?.exit ?? chain?.exit ?? '—'}</span>
              </LR>
              <LR>
                <span className="k">验证者</span>
                <span className="v">{settlement?.verifier ?? chain?.verifier ?? '—'}</span>
              </LR>
              {settlement?.contract && (
                <LR>
                  <span className="k">合约</span>
                  <span className="v" style={{ fontFamily: fontMono }}>
                    {settlement.contract.slice(0, 10)}…{settlement.contract.slice(-6)}
                  </span>
                </LR>
              )}
              {settlement?.blockNumber != null && (
                <LR>
                  <span className="k">区块</span>
                  <span className="v">#{fmt(settlement.blockNumber)}</span>
                </LR>
              )}
              {settlement?.gasFee && (
                <LR>
                  <span className="k">Gas</span>
                  <span className="v dim">{settlement.gasFee}</span>
                </LR>
              )}
              {chain?.gateway && (
                <LR>
                  <span className="k">Explorer</span>
                  <span className="v dim">gateway 已配置</span>
                </LR>
              )}
            </SettleCard>
            {layers[0]?.globalChallenge && (
              <>
                <SecT>承诺 · COMMITMENT</SecT>
                <Raw>
                  global_challenge {layers[0].globalChallenge}
                  <br />
                  aggregate_pk {proof?.aggregatePk?.slice(0, 34) ?? '—'}… · deck {proof?.deckSize ?? 52}
                </Raw>
              </>
            )}
          </Col>
        </Body>
      </Doc>
    </Overlay>
  );
};

const LayerList: React.FC<{ layers: HandProofResponse['layers'] }> = ({ layers }) => {
  if (layers.length === 0) {
    return (
      <LayerRow>
        <div className="ic bad">
          <AlertTriangle size={12} strokeWidth={2} />
        </div>
        <div>
          <b>无证明留存</b>
          <span>升级前的旧手不留存证明本体</span>
        </div>
        <div className="t">—</div>
      </LayerRow>
    );
  }
  return (
    <>
      {layers.map((l, i) => (
        <LayerRow key={i}>
          <div className={`ic ${l.verified ? '' : 'bad'}`}>
            {l.verified ? <CheckCircle2 size={12} strokeWidth={2} /> : <AlertTriangle size={12} strokeWidth={2} />}
          </div>
          <div>
            <b>
              {l.proofVersion === 2 ? 'shuffle·v2' : 'shuffle·v1'} · 层 {l.round}
            </b>
            <span>
              {l.playerName || l.playerPk.slice(0, 10)} · challenge {l.globalChallenge?.slice(0, 12) ?? '—'}…
            </span>
          </div>
          <div className="t">{l.verified ? '✓ 已验证' : '✗ 失败'}</div>
        </LayerRow>
      ))}
    </>
  );
};

export default HandReceipt;
