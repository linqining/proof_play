import React from 'react';
import { BetSliderInput } from './BetSliderInput';
import { BetSliderWrapper } from './BetSliderWrapper';
import { Table } from '../../types/game';

interface BetSliderProps {
  currentTable: Table;
  seatId: number;
  bet: number;
  setBet: (bet: number) => void;
}

export const BetSlider: React.FC<BetSliderProps> = ({ currentTable, seatId, bet, setBet }) => {
  const seat = currentTable?.seats?.[seatId];
  const stack = seat?.stack ?? 0;
  const seatBet = seat?.bet ?? 0;
  const minRaise = currentTable?.minRaise ?? 0;
  const limit = currentTable?.limit ?? 0;
  const min = Math.max(minRaise - seatBet, 0);
  const max = Math.min(stack, limit);

  return (
    <BetSliderWrapper>
      <BetSliderInput
        type="range"
        style={{ width: '100%' }}
        step="10"
        min={min}
        max={max}
        value={isNaN(bet) ? min : bet}
        onChange={(e) => setBet(+e.target.value)}
      />
    </BetSliderWrapper>
  );
};
