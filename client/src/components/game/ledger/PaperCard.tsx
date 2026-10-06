import React from 'react';
import styled from 'styled-components';
import { Lock } from 'lucide-react';
import type { Card } from '../../../types/game';

/**
 * 账簿纸牌（design/table zchain-table-ui.html 的 .pc）：
 * 白卡 + 等宽角标 + 中央花色 glyph，红牌用 --bad 语义色。
 * 牌背 = 密封信封：交叉细网 + 锁 + SEALED + 牌序 #idx。
 */
export const SUIT_GLYPH: Record<string, string> = {
  s: '♠',
  h: '♥',
  d: '♦',
  c: '♣',
  S: '♠',
  H: '♥',
  D: '♦',
  C: '♣',
};

const PC = styled.div<{ $red: boolean; $w: number; $h: number }>`
  width: ${({ $w }) => $w}px;
  height: ${({ $h }) => $h}px;
  background: ${({ theme }) => theme.colors.lightestBg};
  border: 1px solid ${({ theme }) => theme.colors.borderMuted};
  border-radius: 3px;
  box-shadow: ${({ theme }) => theme.other.cardDropShadow};
  position: relative;
  flex: none;
  display: block;
  color: ${({ $red, theme }) => ($red ? theme.colors.danger : theme.colors.fontColorDark)};
`;

const Ix = styled.span`
  position: absolute;
  left: 4px;
  top: 3px;
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-variant-numeric: tabular-nums;
  font-size: 11px;
  font-weight: 700;
  line-height: 1.05;
  text-align: center;
  letter-spacing: -0.02em;
  i {
    display: block;
    font-style: normal;
    font-size: 10px;
    line-height: 1;
  }
`;

const Pip = styled.span`
  position: absolute;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 26px;
  line-height: 1;
`;

const BackArt = styled.div`
  position: absolute;
  inset: 0;
  background:
    repeating-linear-gradient(45deg, rgba(11, 107, 69, 0.08) 0 3px, transparent 3px 6px),
    repeating-linear-gradient(-45deg, rgba(11, 107, 69, 0.08) 0 3px, transparent 3px 6px),
    ${({ theme }) => theme.colors.lightestBg};
  border-radius: 2px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 2px;
  color: ${({ theme }) => theme.colors.success};
  span {
    font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
    font-size: 7.5px;
    letter-spacing: 0.1em;
    font-weight: 600;
  }
`;

const BackNo = styled.span`
  position: absolute;
  right: 3px;
  top: 2px;
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 8px;
  color: ${({ theme }) => theme.colors.softerText};
`;

interface PaperCardProps {
  card?: Card | null;
  /** 牌背（未开牌）：显示牌序号 */
  sealedIndex?: number;
  small?: boolean;
}

export const PaperCard: React.FC<PaperCardProps> = ({ card, sealedIndex, small }) => {
  const w = small ? 38 : 60;
  const h = small ? 54 : 84;
  if (!card) {
    return (
      <PC $red={false} $w={w} $h={h} aria-label={`sealed card #${sealedIndex ?? ''}`}>
        <BackArt>
          <Lock size={small ? 11 : 15} strokeWidth={1.6} />
          <span>SEALED</span>
        </BackArt>
        {sealedIndex != null && <BackNo>#{sealedIndex}</BackNo>}
      </PC>
    );
  }
  const suit = SUIT_GLYPH[card.suit] ?? card.suit;
  const red = card.suit?.toLowerCase() === 'h' || card.suit?.toLowerCase() === 'd';
  const glyphSize = small ? 18 : 30;
  return (
    <PC $red={red} $w={w} $h={h} aria-label={`${card.rank}${suit}`}>
      <Ix>
        {card.rank}
        <i>{suit}</i>
      </Ix>
      <Pip style={{ fontSize: glyphSize }}>{suit}</Pip>
    </PC>
  );
};

export default PaperCard;
