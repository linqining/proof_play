import React, { useContext, useEffect, useMemo, useState } from 'react';
import styled from 'styled-components';
import { ShieldCheck } from 'lucide-react';
import contentContext from '../../../context/content/contentContext';
import gameContext from '../../../context/game/gameContext';
import authContext from '../../../context/auth/authContext';
import globalContext from '../../../context/global/globalContext';
import { Table } from '../../../types/game';
import TicketHeader from './TicketHeader';
import StreetRail, { currentStreetIndex } from './StreetRail';
import PotBlock from './PotBlock';
import SeatEntry, { SeatTimer } from './SeatEntry';
import PaperCard from './PaperCard';
import { blindRoles, toCallAmount, potOdds } from '../../../helpers/tableDerived';
import { evaluateBestHand, rankLabel } from '../../../helpers/handEval';
import { fontMono } from '../../../styles/theme';

/**
 * 牌桌账簿主布局（design/table T1–T4）：
 * 票据抬头 → 街段栏 → 毡面舞台（墨皮包边椭圆毡桌 + 环桌座位 + 下注纸签 +
 * 公共牌 + 彩池合计 + 消息条）→ 页脚（玩家本人英雄卡 + 行动区）。
 *
 * 设计立意：账簿纸面（审计桌）上摆一张真实的深毡绿椭圆牌桌——
 * 桌面是全场唯一的深色实底，纸卡、筹码签、座位账卡都落在毡面上，
 * 「赌桌 × 账本」的碰撞即产品身份（可审计的牌局）。
 */

const Root = styled.div`
  display: flex;
  flex-direction: column;
  /* 牌桌舞台（TableStage 1600×900）内排版：填满舞台而非视口 */
  height: 100%;
  background: ${({ theme }) => theme.colors.lightBg};
  color: ${({ theme }) => theme.colors.fontColorDark};
  text-align: left;
`;

const StreetBar = styled.div`
  flex: none;
  display: flex;
  align-items: center;
  gap: 18px;
  padding: 8px 22px;
  border-top: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-bottom: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  background: ${({ theme }) => theme.colors.lightBg};
  flex-wrap: wrap;
`;

const Chip = styled.span<{ $tone?: 'amb' | 'play' | 'default' }>`
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 9.5px;
  letter-spacing: 0.09em;
  text-transform: uppercase;
  padding: 1.5px 6px;
  border: 1px solid ${({ theme }) => theme.colors.borderMuted};
  border-radius: 2px;
  color: ${({ theme }) => theme.colors.mutedText};
  background: ${({ theme }) => theme.colors.lightestBg};
  white-space: nowrap;
  font-weight: 500;
  ${({ $tone, theme }) => {
    if ($tone === 'amb')
      return `color: ${theme.colors.warning}; border-color: rgba(130,85,16,.4); background: rgba(130,85,16,.06); font-weight: 600;`;
    if ($tone === 'play')
      return `color: ${theme.colors.info}; border-color: rgba(21,80,127,.4); background: rgba(21,80,127,.06);`;
    return '';
  }}
`;

const BarNote = styled.span`
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  justify-content: flex-end;
`;

/* ============================================================================
 * 毡面舞台
 * ========================================================================= */

const FeltBody = styled.div`
  position: relative;
  flex: 1;
  min-height: 0;
  overflow: hidden;
`;

/* 墨皮包边：皮革深底 + 内侧高光 + 缝线，包住深毡绿桌面 */
const Rail = styled.div`
  position: absolute;
  inset: 10px 14px;
  border-radius: 50%;
  background: #241d14;
  box-shadow:
    0 24px 48px rgba(20, 19, 15, 0.22),
    0 2px 0 rgba(20, 19, 15, 0.08),
    inset 0 1px 0 rgba(245, 242, 234, 0.12),
    inset 0 -2px 6px rgba(0, 0, 0, 0.5);
`;

const Stitch = styled.div`
  position: absolute;
  inset: 6px;
  border: 1px dashed rgba(245, 242, 234, 0.22);
  border-radius: 50%;
  pointer-events: none;
`;

/* 毡面：深毡绿 + 细纹 + 内圈刻线；唯一允许的大面积深色 */
const Felt = styled.div`
  position: absolute;
  inset: 22px 26px;
  border-radius: 50%;
  background:
    repeating-linear-gradient(
      115deg,
      rgba(255, 255, 255, 0.028) 0 2px,
      transparent 2px 5px
    ),
    #0d5c3c;
  box-shadow:
    inset 0 2px 14px rgba(4, 30, 20, 0.6),
    inset 0 0 90px rgba(7, 44, 29, 0.55);

  &::before {
    content: '';
    position: absolute;
    inset: 20px;
    border: 1.5px solid rgba(245, 242, 234, 0.22);
    border-radius: 50%;
  }
  &::after {
    content: '';
    position: absolute;
    inset: 27px;
    border: 1px solid rgba(245, 242, 234, 0.1);
    border-radius: 50%;
  }
`;

/* 桌面中央钢印水印（压在公共牌之下，位于彩池与下沿座位之间的空档） */
const FeltMark = styled.div`
  position: absolute;
  left: 50%;
  top: 69%;
  transform: translate(-50%, -50%);
  text-align: center;
  color: rgba(245, 242, 234, 0.14);
  pointer-events: none;
  z-index: 0;
  white-space: nowrap;
  b {
    display: block;
    font-size: 26px;
    font-weight: 700;
    letter-spacing: 0.34em;
    text-indent: 0.34em;
    font-family: ${({ theme }) => theme.fonts.fontFamilySerif};
  }
  span {
    display: block;
    margin-top: 5px;
    font-size: 9px;
    letter-spacing: 0.3em;
    text-indent: 0.3em;
    text-transform: uppercase;
  }
`;

/* 桌沿小字：公共区归属说明 */
const FeltTag = styled.span`
  position: absolute;
  left: 50%;
  top: 4.2%;
  transform: translateX(-50%);
  font-family: ${({ theme }) => theme.fonts.fontFamilySerif};
  font-size: 8.5px;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  color: rgba(245, 242, 234, 0.45);
  white-space: nowrap;
  z-index: 1;
`;

/* 盲注指示盘：毡面左下（真实牌桌的 blind disk） */
const BlindDisks = styled.div`
  position: absolute;
  left: 14%;
  top: 74%;
  display: flex;
  gap: 7px;
  z-index: 1;
`;

const BlindDisk = styled.span`
  width: 40px;
  height: 40px;
  border-radius: 50%;
  background: ${({ theme }) => theme.colors.lightestBg};
  border: 1px solid ${({ theme }) => theme.colors.borderMuted};
  box-shadow: 0 3px 8px rgba(0, 0, 0, 0.35);
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  font-family: ${({ theme }) => theme.fonts.fontFamilySerif};
  i {
    font-style: normal;
    font-size: 7.5px;
    letter-spacing: 0.14em;
    color: ${({ theme }) => theme.colors.softerText};
    text-transform: uppercase;
  }
  b {
    font-variant-numeric: tabular-nums;
    font-size: 12px;
    font-weight: 700;
    color: ${({ theme }) => theme.colors.fontColorDark};
    line-height: 1.1;
  }
`;

/* 座位锚点层：座位按钟位环绕毡面（顺时针 1→5，本人居中下沿） */
const SeatsLayer = styled.div`
  position: absolute;
  inset: 0;
  z-index: 3;
  pointer-events: none;
`;

const SeatAnchor = styled.div<{ $x: number; $y: number }>`
  position: absolute;
  left: ${({ $x }) => $x}%;
  top: ${({ $y }) => $y}%;
  transform: translate(-50%, -50%);
  pointer-events: auto;
`;

/* 下注纸签：从座位投向桌心的中途（真实牌桌的前注位） */
const BetAnchor = styled.div<{ $x: number; $y: number }>`
  position: absolute;
  left: ${({ $x }) => $x}%;
  top: ${({ $y }) => $y}%;
  transform: translate(-50%, -50%);
  z-index: 2;
  pointer-events: none;
`;

const BetChipPill = styled.div<{ $allin: boolean }>`
  display: inline-flex;
  align-items: center;
  gap: 5px;
  background: ${({ theme }) => theme.colors.lightestBg};
  border: 1px solid
    ${({ $allin, theme }) => ($allin ? theme.colors.danger : theme.colors.fontColorDark)};
  border-radius: 2px;
  padding: 2.5px 9px;
  box-shadow: 0 3px 8px rgba(0, 0, 0, 0.3);
  font-family: ${({ theme }) => theme.fonts.fontFamilySerif};
  font-variant-numeric: tabular-nums;
  font-size: 12px;
  font-weight: 600;
  color: ${({ $allin, theme }) => ($allin ? theme.colors.danger : theme.colors.fontColorDark)};
  white-space: nowrap;
  i {
    width: 9px;
    height: 9px;
    border-radius: 50%;
    background: ${({ $allin, theme }) => ($allin ? theme.colors.danger : theme.colors.success)};
    border: 1.5px solid currentColor;
    color: ${({ $allin, theme }) => ($allin ? theme.colors.danger : theme.colors.goldDarker)};
    flex: none;
  }
`;

/* 桌心：公共牌 + 彩池合计 */
const CenterStack = styled.div`
  position: absolute;
  left: 50%;
  top: 43%;
  transform: translate(-50%, -50%);
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 9px;
  z-index: 2;
`;

const BoardRow = styled.div`
  display: flex;
  gap: 8px;
  align-items: flex-start;
  justify-content: center;
`;

const BoardLabel = styled.div`
  font-family: ${({ theme }) => theme.fonts.fontFamilySerif};
  font-size: 8.5px;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: rgba(245, 242, 234, 0.5);
  display: flex;
  align-items: center;
  gap: 6px;
  white-space: nowrap;
  justify-content: center;
`;

/* 消息条：毡面左下角内侧（避开下沿本人座位） */
const MsgStrip = styled.div`
  position: absolute;
  left: 42px;
  bottom: 28px;
  display: flex;
  gap: 8px;
  flex-direction: column;
  align-items: flex-start;
  z-index: 4;
  max-width: 44%;
`;

const Msg = styled.div<{ $ok?: boolean }>`
  background: ${({ theme }) => theme.colors.lightestBg};
  border: 1px solid ${({ theme }) => theme.colors.borderMuted};
  border-left: 3px solid ${({ $ok, theme }) => ($ok ? theme.colors.success : theme.colors.mutedText)};
  border-radius: 3px;
  padding: 6px 13px;
  font-size: 12px;
  color: ${({ theme, $ok }) => ($ok ? theme.colors.fontColorDark : theme.colors.mutedText)};
  box-shadow: 0 4px 12px rgba(20, 19, 15, 0.28);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 100%;
  b,
  .num {
    font-family: ${({ theme }) => theme.fonts.fontFamilySerif};
    font-variant-numeric: tabular-nums;
    font-weight: 600;
    color: ${({ theme }) => theme.colors.fontColorDark};
  }
`;

/* ============================================================================
 * 页脚（玩家英雄卡 + 行动区）
 * ========================================================================= */

const Footer = styled.footer`
  flex: none;
  background: ${({ theme }) => theme.colors.lightestBg};
  border-top: 1px solid ${({ theme }) => theme.colors.fontColorDark};
  padding: 12px 22px 14px;
  display: flex;
  align-items: center;
  gap: 20px;
  position: relative;
  flex-wrap: wrap;
`;

const HeroCard = styled.div<{ $accent?: 'felt' | 'ink' }>`
  width: 300px;
  flex: none;
  border: 1px solid ${({ $accent, theme }) => ($accent === 'felt' ? theme.colors.success : theme.colors.borderSubtle)};
  background: ${({ $accent, theme }) => ($accent === 'felt' ? 'rgba(11,107,69,.08)' : theme.colors.lightestBg)};
  border-radius: 3px;
  padding: 9px 11px;
`;

const HeroTop = styled.div`
  display: flex;
  align-items: center;
  gap: 8px;
  b {
    font-size: 12.5px;
    font-weight: 600;
    font-family: ${({ theme }) => theme.fonts.fontFamilySerif};
    font-variant-numeric: tabular-nums;
  }
`;

const HeroAv = styled.div`
  width: 28px;
  height: 28px;
  border-radius: 2px;
  background: ${({ theme }) => theme.colors.fontColorDark};
  color: ${({ theme }) => theme.colors.fontColorLight};
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 10px;
  font-weight: 700;
  flex: none;
`;

const HeroHand = styled.div`
  display: flex;
  align-items: center;
  gap: 0;
  margin-top: 7px;
  .note {
    font-family: ${({ theme }) => theme.fonts.fontFamilySerif};
    font-variant-numeric: tabular-nums;
    font-size: 10px;
    color: ${({ theme }) => theme.colors.success};
    font-weight: 600;
    margin-left: 9px;
  }
`;

const HeroSeal = styled.span`
  margin-left: auto;
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-family: ${({ theme }) => theme.fonts.fontFamilySerif};
  font-size: 9px;
  letter-spacing: 0.13em;
  text-transform: uppercase;
  padding: 3px 7px;
  border: 1.5px solid currentColor;
  border-radius: 2px;
  transform: rotate(-4deg);
  font-weight: 600;
  color: ${({ theme }) => theme.colors.success};
`;

const FootNote = styled.div`
  flex: 1;
  min-width: 220px;
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-left: 3px solid ${({ theme }) => theme.colors.softerText};
  border-radius: 3px;
  background: ${({ theme }) => theme.colors.lightestBg};
  font-size: 11.5px;
  color: ${({ theme }) => theme.colors.mutedText};
  padding: 10px 12px;
  line-height: 1.55;
  b {
    font-family: ${({ theme }) => theme.fonts.fontFamilySerif};
    font-variant-numeric: tabular-nums;
    color: ${({ theme }) => theme.colors.fontColorDark};
  }
`;

const fmt = (n: number) => new Intl.NumberFormat().format(n);

const streetNote = (rs: string): string => {
  const map: Record<string, string> = {
    waiting: '等待开盘',
    shuffling: '洗牌中',
    shuffleComplete: '洗牌完成',
    preFlopReveal: '翻前开牌',
    preFlop: '翻牌前下注',
    flopReveal: '翻牌开牌',
    flop: '翻牌圈',
    turnReveal: '转牌开牌',
    turn: '转牌圈',
    riverReveal: '河牌开牌',
    river: '河牌圈',
    showdownReveal: '摊牌开牌',
    showdown: '摊牌',
    handComplete: '本手结束',
  };
  return map[rs] ?? rs;
};

/* 座位钟位（FeltBody 百分比坐标，顺时针 1→5；5=本人，居中下沿）。
 * 角度：198° / 126° / 54° / 342° / 270°（数学角，y 轴向下取反）。 */
const SEAT_POS: Record<number, { x: number; y: number }> = {
  1: { x: 9.6, y: 60.5 },
  2: { x: 25.2, y: 16.5 },
  3: { x: 74.8, y: 16.5 },
  4: { x: 90.4, y: 60.5 },
  5: { x: 50, y: 86.5 },
};

/* 下注纸签位：座位→桌心连线 45% 处 */
const BET_POS: Record<number, { x: number; y: number }> = Object.fromEntries(
  Object.entries(SEAT_POS).map(([n, p]) => [
    n,
    { x: p.x + 0.45 * (50 - p.x), y: p.y + 0.45 * (46 - p.y) },
  ]),
);

export interface PlayLedgerProps {
  table: Table;
  communityCards: { suit: string; rank: string }[];
  decryptedHandCards: string[];
  lastMessage: string | null;
  onSitDown: (seatNumber: number) => void;
  canSit: boolean;
  /** 页脚右侧动作区（GameUI 或等待提示），由 Play 装配 */
  actionSlot?: React.ReactNode;
  /** 抬头右侧工具钮（离桌 / 牌局记录 / 凭证），由 Play 装配 */
  toolbar?: React.ReactNode;
  onOpenReceipt: () => void;
}

export const PlayLedger: React.FC<PlayLedgerProps> = ({
  table,
  communityCards,
  decryptedHandCards,
  lastMessage,
  onSitDown,
  canSit,
  actionSlot,
  toolbar,
  onOpenReceipt,
}) => {
  const { getLocalizedString } = useContext(contentContext)!;
  const { seatId } = useContext(gameContext)!;
  const { walletAddress } = useContext(authContext)!;
  const { chipsAmount } = useContext(globalContext)!;

  const roles = blindRoles(table);
  const heroSeat = seatId != null ? table.seats[seatId] : null;
  const heroHand = useMemo(
    () =>
      decryptedHandCards.map((cardStr) => ({
        suit: cardStr.slice(0, 1),
        rank: cardStr.slice(1),
      })),
    [decryptedHandCards],
  );

  // 自己手牌牌型标注（公共牌齐才可评）
  const heroEval = useMemo(() => {
    if (!heroSeat) return null;
    const cards = [...heroSeat.hand, ...communityCards];
    return evaluateBestHand(cards);
  }, [heroSeat, communityCards]);

  const boardCount = communityCards.length || table.board.length || 0;
  const activeCount = Object.values(table.seats).filter(
    (s) => s?.player && !s.folded && !s.sittingOut,
  ).length;

  const statusNote = table.handOver
    ? getLocalizedString('game_state-info_wait')
    : streetNote(table.roundState);

  const toCall = seatId != null ? toCallAmount(table, seatId) : 0;
  const odds = seatId != null ? potOdds(table, seatId) : null;
  const heroStack = heroSeat?.stack ?? 0;
  const heroInvested = heroSeat?.totalBet ?? 0;

  return (
    <Root>
      <TicketHeader table={table} statusNote={statusNote} toolbar={toolbar} />

      <StreetBar>
        <StreetRail table={table} />
        <BarNote>
          <Chip $tone={table.handOver ? 'default' : 'play'}>
            roundState · {table.roundState}
          </Chip>
          {!table.handOver && (
            <Chip>
              在座 {activeCount} / 5
            </Chip>
          )}
          {toCall > 0 && !table.handOver && (
            <Chip>
              待跟 <b style={{ fontFamily: fontMono }}>{fmt(toCall)}</b>
              {odds != null ? ` · 赔率 ${odds} : 1` : ''}
            </Chip>
          )}
        </BarNote>
      </StreetBar>

      <FeltBody>
        <Rail>
          <Stitch />
          <Felt />
        </Rail>
        <FeltTag>公共区 · COMMON — 不归属任何玩家</FeltTag>
        <FeltMark>
          <b>SECRET POKER</b>
          <span>PROVABLY FAIR · EVERY MOVE ON-CHAIN</span>
        </FeltMark>
        <BlindDisks>
          <BlindDisk>
            <i>SB</i>
            <b>{fmt(table.smallBlind)}</b>
          </BlindDisk>
          <BlindDisk>
            <i>BB</i>
            <b>{fmt(table.bigBlind)}</b>
          </BlindDisk>
        </BlindDisks>

        {/* 环桌座位（含本人座；空位渲染虚线待填卡） */}
        <SeatsLayer>
          {[1, 2, 3, 4, 5].map((n) => {
            const pos = SEAT_POS[n];
            const seat = table.seats[n];
            // 胜者账目行回填（T4）：牌型来自 showdownHandRanks，金额从
            // winMessages 首条解析（"X wins $200 with Two Pair"）
            const rank = table.showdownHandRanks?.find((h) => h.seat === n)?.rank;
            const isWinnerSeat =
              table.handOver && table.seats[n]?.lastAction === 'WINNER';
            const winAmount = (() => {
              if (!isWinnerSeat) return null;
              const msg = table.winMessages?.[0] ?? '';
              const m = msg.match(/\$([\d,]+)/);
              return m ? Number(m[1].replace(/,/g, '')) : null;
            })();
            const betPill = (() => {
              if (table.handOver) return null;
              if (!seat?.player || seat.folded || seat.sittingOut) return null;
              if (!(seat.bet > 0)) return null;
              return (
                <BetAnchor key={`bet-${n}`} $x={BET_POS[n].x} $y={BET_POS[n].y}>
                  <BetChipPill $allin={seat.stack === 0}>
                    <i />
                    {fmt(seat.bet)}
                  </BetChipPill>
                </BetAnchor>
              );
            })();
            return (
              <React.Fragment key={n}>
                <SeatAnchor $x={pos.x} $y={pos.y}>
                  <SeatEntry
                    table={table}
                    seatNumber={n}
                    isDealer={table.button === n || table.dealerSeatId === n}
                    winnerInfo={isWinnerSeat && rank ? { rank, amount: winAmount } : null}
                    showdownRank={table.handOver ? (rank ?? null) : null}
                    blindLabel={roles[n] === 'sb' ? getLocalizedString('game_seat-sb-lbl') : roles[n] === 'bb' ? getLocalizedString('game_seat-bb-lbl') : null}
                    onSitDown={onSitDown}
                    canSit={canSit}
                  />
                </SeatAnchor>
                {betPill}
              </React.Fragment>
            );
          })}
        </SeatsLayer>

        <CenterStack>
          <div>
            <BoardLabel>
              公共牌 {boardCount} / 5 · {boardCount === 0 ? '未发' : '已上链开牌'}
            </BoardLabel>
            <div style={{ height: 6 }} />
            <BoardRow>
              {[0, 1, 2, 3, 4].map((i) =>
                i < boardCount ? (
                  <PaperCard
                    key={i}
                    card={communityCards[i] ?? table.board[i]}
                  />
                ) : (
                  <PaperCard key={i} sealedIndex={i + 1} />
                ),
              )}
            </BoardRow>
          </div>
          <PotBlock table={table} />
        </CenterStack>

        <MsgStrip>
          {table.winMessages && table.winMessages.length > 0 && (
            <Msg $ok>{table.winMessages[table.winMessages.length - 1]}</Msg>
          )}
          {lastMessage && <Msg>{lastMessage}</Msg>}
          {table.handOver && (
            <Msg>
              <button
                onClick={onOpenReceipt}
                style={{
                  font: 'inherit',
                  border: 'none',
                  background: 'none',
                  cursor: 'pointer',
                  textDecoration: 'underline',
                  color: 'inherit',
                  padding: 0,
                }}
              >
                查看本手凭证 →
              </button>
            </Msg>
          )}
        </MsgStrip>
      </FeltBody>

      <Footer>
        {heroSeat ? (
          <HeroCard $accent={table.handOver ? 'felt' : undefined}>
            <HeroTop>
              <HeroAv>你</HeroAv>
              <b>{walletAddress ? `${walletAddress.slice(0, 6)}…${walletAddress.slice(-4)}` : '—'}</b>
              <span style={{ fontFamily: fontMono, fontWeight: 600 }}>{fmt(heroStack)}</span>
              {table.handOver && (
                <HeroSeal>
                  <ShieldCheck size={11} strokeWidth={2} /> 已结算
                </HeroSeal>
              )}
            </HeroTop>
            {/* 轮到自己行动：与对手座位同款 T-XX 倒计时（绑定服务端截止） */}
            {heroSeat?.turn && !table.handOver && table.bettingStartedAt && table.bettingTimeoutMs ? (
              <SeatTimer
                deadline={table.bettingStartedAt + table.bettingTimeoutMs}
                totalMs={table.bettingTimeoutMs}
              />
            ) : null}
            <HeroHand>
              {heroHand.map((c, i) => (
                <span key={i} style={{ marginLeft: i > 0 ? -11 : 0 }}>
                  <PaperCard card={c} small />
                </span>
              ))}
              {heroEval && (
                <span className="note">
                  {getLocalizedString(heroEval.i18nKey)}
                  {heroEval.category === 'flush' || heroEval.category === 'royal-flush'
                    ? ''
                    : ` ${rankLabel(heroEval.mainRank)}`}
                </span>
              )}
            </HeroHand>
          </HeroCard>
        ) : (
          <HeroCard>
            <HeroTop>
              <HeroAv>?</HeroAv>
              <span style={{ fontSize: 12, color: '#5f5b50' }}>
                {canSit
                  ? `${getLocalizedString('game_sitdown-prompt')}`
                  : '观战模式 · SPECTATOR'}
              </span>
            </HeroTop>
            <div style={{ fontSize: 11, color: '#5f5b50', marginTop: 6 }}>
              {walletAddress ? (
                <>
                  已登录钱包{' '}
                  <span style={{ fontFamily: fontMono }}>
                    {walletAddress.slice(0, 6)}…{walletAddress.slice(-4)}
                  </span>
                  {` · 可用 ${fmt(chipsAmount ?? 0)} 筹码`}
                </>
              ) : (
                '连接钱包后可入座参与'
              )}
            </div>
          </HeroCard>
        )}

        {actionSlot ?? (
          <FootNote>
            {heroSeat ? (
              table.handOver ? (
                <>
                  本手已结算。你本手投入 <b>{fmt(heroInvested)}</b>，台费{' '}
                  <b>{fmt(table.rakeCollected)}</b>（{table.rakeBps ? `${table.rakeBps / 100}%，上限 ${fmt(table.rakeCap ?? 0)}` : '本场免台费'}）。
                </>
              ) : (
                <>
                  等待他人行动。你已投入 <b>{fmt(heroInvested)}</b>
                  {toCall > 0 && (
                    <>
                      ，当前需跟 <b>{fmt(toCall)}</b>
                    </>
                  )}
                  ；超时将自动弃牌。
                </>
              )
            ) : (
              <>
                入座即按盲注结构锁定买入，<b>{fmt(table.minBuyIn)} – {fmt(table.maxBuyIn)}</b>{' '}
                步进 <b>1,000</b>；筹码由链上 vault 入账，余量与每一手结算都以等宽数字记账。
              </>
            )}
          </FootNote>
        )}
      </Footer>
    </Root>
  );
};

export default PlayLedger;
