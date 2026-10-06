import React from 'react';
import styled from 'styled-components';
import { Table } from '../../../types/game';

/**
 * 五节点街段状态轨（design/table .rail）：翻前/翻牌/转牌/河牌/摊牌。
 * done=翡翠实心 / cur=琥珀实心（外圈光环）/ 待=空心。由 roundState + 公共牌数推导。
 */
const Rail = styled.div`
  display: flex;
  align-items: flex-start;
  padding-top: 3px;
`;

const Node = styled.div<{ $state: 'done' | 'cur' | 'todo' }>`
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 6px;
  flex: none;
  width: 64px;
  i {
    width: 11px;
    height: 11px;
    border: 1.5px solid ${({ theme }) => theme.colors.borderMuted};
    background: ${({ theme }) => theme.colors.lightestBg};
    display: block;
    flex: none;
    border-radius: 2px;
    box-shadow: ${({ $state, theme }) =>
      $state === 'cur' ? `0 0 0 3px rgba(130, 85, 16, 0.18)` : 'none'};
    ${({ $state, theme }) =>
      $state === 'done'
        ? `background: ${theme.colors.success}; border-color: ${theme.colors.success};`
        : $state === 'cur'
          ? `background: ${theme.colors.warning}; border-color: ${theme.colors.warning};`
          : ''}
  }
  span {
    font-family: ${({ theme }) => theme.fonts.fontFamilySerif};
    font-size: 9.5px;
    letter-spacing: 0.08em;
    color: ${({ theme }) => theme.colors.softerText};
    text-transform: uppercase;
    text-align: center;
    ${({ $state, theme }) =>
      $state === 'done'
        ? `color: ${theme.colors.success};`
        : $state === 'cur'
          ? `color: ${theme.colors.warning}; font-weight: 600;`
          : ''}
  }
`;

const Line = styled.div<{ $done: boolean }>`
  flex: 1;
  height: 1.5px;
  background: ${({ $done, theme }) => ($done ? theme.colors.success : theme.colors.borderMuted)};
  margin-top: 9px;
  min-width: 8px;
`;

const STREETS = ['翻前', '翻牌', '转牌', '河牌', '摊牌'] as const;

export function currentStreetIndex(table: Table): number {
  // reveal 子阶段与其下注街同节点；showdown* → 摊牌
  const rs = table.roundState;
  if (rs === 'showdown' || rs === 'showdownReveal' || rs === 'handComplete') return 4;
  const n = table.board?.length ?? 0;
  if (rs === 'preFlop' || rs === 'preFlopReveal' || n === 0) return 0;
  if (rs === 'flop' || rs === 'flopReveal' || n === 3) return 1;
  if (rs === 'turn' || rs === 'turnReveal' || n === 4) return 2;
  if (rs === 'river' || rs === 'riverReveal' || n === 5) return 3;
  return 0;
}

export const StreetRail: React.FC<{ table: Table }> = ({ table }) => {
  const cur = currentStreetIndex(table);
  return (
    <Rail aria-label="street rail">
      {STREETS.map((label, i) => {
        const state = i < cur ? 'done' : i === cur ? 'cur' : 'todo';
        return (
          <React.Fragment key={label}>
            {i > 0 && <Line $done={i <= cur} />}
            <Node $state={state}>
              <i />
              <span>{label}</span>
            </Node>
          </React.Fragment>
        );
      })}
    </Rail>
  );
};

export default StreetRail;
