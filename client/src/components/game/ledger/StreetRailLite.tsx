import React from 'react';
import styled from 'styled-components';

/**
 * 凭证内嵌街段轨（按公共牌数 + 是否摊牌推导；HandReceipt 用）。
 */
const Rail = styled.div`
  display: flex;
  align-items: center;
  gap: 0;
  margin-bottom: 8px;
`;

const Node = styled.span<{ $done: boolean }>`
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 9px;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  color: ${({ $done, theme }) => ($done ? theme.colors.success : theme.colors.softerText)};
  i {
    width: 8px;
    height: 8px;
    border: 1.5px solid currentColor;
    background: ${({ $done }) => ($done ? 'currentColor' : 'transparent')};
    display: inline-block;
  }
`;

const Line = styled.span<{ $done: boolean }>`
  flex: 1;
  height: 1px;
  margin: 0 4px;
  background: ${({ $done, theme }) => ($done ? theme.colors.success : theme.colors.borderSubtle)};
`;

const LABELS = ['翻前', '翻牌', '转牌', '河牌', '摊牌'];

export const StreetRailLite: React.FC<{ boardCount: number; showdown: boolean }> = ({
  boardCount,
  showdown,
}) => {
  const cur =
    showdown || boardCount >= 5 ? 4 : boardCount === 4 ? 3 : boardCount === 3 ? 2 : boardCount > 0 ? 1 : 0;
  return (
    <Rail>
      {LABELS.map((l, i) => (
        <React.Fragment key={l}>
          {i > 0 && <Line $done={i <= cur} />}
          <Node $done={i <= cur}>
            <i />
            {l}
          </Node>
        </React.Fragment>
      ))}
    </Rail>
  );
};

export default StreetRailLite;
