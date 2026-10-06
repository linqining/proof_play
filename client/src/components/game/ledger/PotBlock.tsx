import React from 'react';
import styled from 'styled-components';
import { Table } from '../../../types/game';

/**
 * 彩池合计块（design/table .pot）：合计大数 + 两栏拆解
 * （主池 / 边池 / 待跟 / 你已投入 / 台费），像资产负债表。
 */
const Wrap = styled.div`
  position: relative;
  background: ${({ theme }) => theme.colors.lightestBg};
  border: 1px solid ${({ theme }) => theme.colors.borderMuted};
  border-radius: 3px;
  padding: 8px 13px 9px;
  overflow: hidden;
  box-shadow: 0 8px 20px rgba(4, 30, 20, 0.4);
  width: 316px;
  max-width: 90%;
  &::before {
    content: '';
    position: absolute;
    inset: 0;
    background: repeating-linear-gradient(
      180deg,
      transparent 0 25px,
      rgba(20, 19, 15, 0.045) 25px 26px
    );
    pointer-events: none;
  }
`;

const Label = styled.div`
  position: relative;
  font-family: ${({ theme }) => theme.fonts.fontFamilySerif};
  font-size: 9px;
  letter-spacing: 0.15em;
  text-transform: uppercase;
  color: ${({ theme }) => theme.colors.softerText};
  display: flex;
  align-items: center;
  gap: 7px;
`;

const Amount = styled.div`
  position: relative;
  font-family: ${({ theme }) => theme.fonts.fontFamilySerif};
  font-variant-numeric: tabular-nums;
  font-size: 25px;
  font-weight: 700;
  letter-spacing: -0.5px;
  line-height: 1.15;
  margin: 1px 0 0;
  display: flex;
  align-items: baseline;
  gap: 5px;
  .u {
    font-size: 10.5px;
    font-weight: 500;
    letter-spacing: 0.08em;
    color: ${({ theme }) => theme.colors.softerText};
  }
`;

const Break = styled.div`
  position: relative;
  margin-top: 4px;
  border-top: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  padding-top: 1px;
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0 16px;
`;

const Row = styled.div`
  display: flex;
  align-items: baseline;
  gap: 10px;
  padding: 3px 0;
  font-size: 11px;
  .k {
    color: ${({ theme }) => theme.colors.mutedText};
    font-size: 10.5px;
    min-width: 0;
  }
  .v {
    margin-left: auto;
    font-family: ${({ theme }) => theme.fonts.fontFamilySerif};
    font-variant-numeric: tabular-nums;
    text-align: right;
    color: ${({ theme }) => theme.colors.fontColorDark};
    white-space: nowrap;
  }
  .v.dim {
    color: ${({ theme }) => theme.colors.softerText};
  }
  .v.bad {
    color: ${({ theme }) => theme.colors.danger};
  }
`;

const fmt = (n: number) => new Intl.NumberFormat().format(n);

export const PotBlock: React.FC<{ table: Table }> = ({ table }) => {
  const seatBet = table.callAmount ?? 0;
  const rows: Array<{ k: string; v: string; cls?: string }> = [];
  rows.push({ k: '主池 MAIN', v: fmt(table.mainPot ?? 0) });
  table.sidePots.forEach((sp, i) => {
    const eligible = sp.players?.length;
    rows.push({
      k: eligible ? `边池 ${i + 1}（${eligible} 家可争）` : `边池 ${i + 1}`,
      v: fmt(sp.amount),
    });
  });
  if (seatBet > 0 && !table.handOver) {
    rows.push({ k: '待跟 CALL', v: fmt(seatBet) });
  }
  rows.push({
    k: `台费 RAKE${table.rakeBps ? `（${table.rakeBps / 100}%，上限 ${fmt(table.rakeCap ?? 0)}）` : ''}`,
    v: table.rakeCollected > 0 ? fmt(table.rakeCollected) : table.rakeBps ? '摊牌时收' : '0',
    cls: table.rakeCollected > 0 ? 'bad' : 'dim',
  });

  return (
    <Wrap aria-label="total pot">
      <Label>彩池 TOTAL POT{!table.handOver && seatBet > 0 ? ' · 含当前下注轮' : ''}</Label>
      <Amount>
        {fmt(table.pot ?? 0)} <span className="u">CHIPS</span>
      </Amount>
      <Break>
        {rows.map((r) => (
          <Row key={r.k}>
            <span className="k">{r.k}</span>
            <span className={`v ${r.cls ?? ''}`}>{r.v}</span>
          </Row>
        ))}
      </Break>
    </Wrap>
  );
};

export default PotBlock;
