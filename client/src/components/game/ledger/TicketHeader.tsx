import React from 'react';
import styled from 'styled-components';
import { Table } from '../../../types/game';

/**
 * 票据抬头（design/table .tb-hd）：桌名 + 手数 + 盲注/最小加注/上限/链上锚点。
 * 底部齿孔线（perforation）为票据共同特征。
 */
const Wrap = styled.header`
  flex: none;
  display: flex;
  align-items: flex-start;
  gap: 14px;
  padding: 10px 22px 12px;
  background: ${({ theme }) => theme.colors.lightestBg};
  position: relative;
  &::after {
    content: '';
    position: absolute;
    left: 0;
    right: 0;
    bottom: 0;
    height: 1px;
    background: ${({ theme }) => theme.colors.borderMuted};
  }
`;

const Kind = styled.div`
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 9.5px;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: ${({ theme }) => theme.colors.softerText};
`;

const Title = styled.div`
  font-size: 17px;
  font-weight: 700;
  letter-spacing: 0.01em;
  margin-top: 2px;
  display: flex;
  align-items: baseline;
  gap: 9px;
  flex-wrap: wrap;
`;

const Hand = styled.span`
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-variant-numeric: tabular-nums;
  font-size: 11px;
  font-weight: 500;
  color: ${({ theme }) => theme.colors.softerText};
  letter-spacing: 0.06em;
`;

const Right = styled.div`
  margin-left: auto;
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 5px;
  flex: none;
  padding-top: 2px;
`;

const NetsRow = styled.div`
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
  justify-content: flex-end;
`;

const Net = styled.span`
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-family: ${({ theme }) => theme.fonts.fontFamilySerif};
  font-variant-numeric: tabular-nums;
  font-size: 10.5px;
  color: ${({ theme }) => theme.colors.mutedText};
  border: 1px solid ${({ theme }) => theme.colors.borderMuted};
  border-radius: 2px;
  padding: 2px 7px;
  background: ${({ theme }) => theme.colors.lightestBg};
  white-space: nowrap;
`;

/* 抬头工具行：安静的墨线小钮（离桌 / 记录 / 凭证），不与主操作抢色 */
const ToolRow = styled.div`
  display: flex;
  align-items: center;
  gap: 6px;
  justify-content: flex-end;
  flex-wrap: wrap;
`;

export const ToolButton = styled.button`
  display: inline-flex;
  align-items: center;
  gap: 5px;
  height: 26px;
  padding: 0 10px;
  font-family: ${({ theme }) => theme.fonts.fontFamilySerif};
  font-size: 11px;
  font-weight: 500;
  letter-spacing: 0.04em;
  color: ${({ theme }) => theme.colors.mutedText};
  background: ${({ theme }) => theme.colors.lightestBg};
  border: 1px solid ${({ theme }) => theme.colors.borderMuted};
  border-radius: 3px;
  cursor: pointer;
  white-space: nowrap;
  transition:
    color ${({ theme }) => theme.timing.fast} ${({ theme }) => theme.easing.easeStandard},
    border-color ${({ theme }) => theme.timing.fast} ${({ theme }) => theme.easing.easeStandard},
    background-color ${({ theme }) => theme.timing.fast} ${({ theme }) => theme.easing.easeStandard};

  &:hover:not(:disabled) {
    color: ${({ theme }) => theme.colors.fontColorDark};
    border-color: ${({ theme }) => theme.colors.fontColorDark};
  }
  &:disabled {
    color: ${({ theme }) => theme.colors.disabledText};
    cursor: not-allowed;
    opacity: 0.6;
  }
  &:focus-visible {
    outline: none;
    box-shadow: 0 0 0 2px rgba(21, 80, 127, 0.35);
  }
`;

const fmt = (n: number) => new Intl.NumberFormat().format(n);

interface TicketHeaderProps {
  table: Table;
  /** 状态注（如「等待开盘」「轮到我行动」） */
  statusNote?: string;
  /** 右侧工具钮行（首页/大厅/离桌/记录/凭证），由 Play 装配 */
  toolbar?: React.ReactNode;
}

export const TicketHeader: React.FC<TicketHeaderProps> = ({ table, statusNote, toolbar }) => {
  const name = table.name || table.id;
  return (
    <Wrap>
      <div style={{ minWidth: 0 }}>
        <Kind>Texas Hold'em · No Limit · 5 seats</Kind>
        <Title>
          {name}
          <Hand>
            HAND #{table.handId ?? '—'}
            {statusNote ? ` · ${statusNote}` : ''}
          </Hand>
        </Title>
      </div>
      <Right>
        <ToolRow>{toolbar}</ToolRow>
        <NetsRow>
          <Net>
            盲注 {fmt(table.smallBlind)} / {fmt(table.bigBlind)}
          </Net>
          {!!table.minRaise && <Net>最小加注 {fmt(table.minRaise)}</Net>}
          <Net>最小买入 {fmt(table.minBuyIn)}</Net>
          <Net>上限 {fmt(table.maxBuyIn)}</Net>
        </NetsRow>
      </Right>
    </Wrap>
  );
};

export default TicketHeader;
