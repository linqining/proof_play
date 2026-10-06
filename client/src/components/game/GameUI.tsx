import React, { useContext } from 'react';
import styled from 'styled-components';
import contentContext from '../../context/content/contentContext';
import Button from '../buttons/Button';
import { BetSlider } from './BetSlider';
import { UIWrapper } from './UIWrapper';
import { Table } from '../../types/game';
import {
  potOdds,
  percentOfStack,
  raisePresets,
  toCallAmount,
} from '../../helpers/tableDerived';

/** 跟注钮：secondaryCta 蓝实底（play 语义），与翡翠加注钮区分。 */
const CallButton = styled.button`
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border: none;
  border-radius: ${({ theme }) => theme.radius.md};
  background-color: ${({ theme }) => theme.colors.secondaryCta};
  color: #fff;
  font-family: ${({ theme }) => theme.fonts.fontFamilySerif};
  font-weight: 600;
  font-size: ${({ theme }) => theme.fontSize.sm};
  min-height: 44px;
  cursor: pointer;
  &:hover:not(:disabled) {
    background-color: ${({ theme }) => theme.colors.secondaryCtaDarker};
  }
  &:disabled {
    background-color: ${({ theme }) => theme.colors.disabled};
    color: ${({ theme }) => theme.colors.softText};
    cursor: not-allowed;
    opacity: 0.6;
  }
  &:focus-visible {
    outline: none;
    box-shadow: 0 0 0 3px rgba(21, 80, 127, 0.4);
  }
`;

interface GameUIProps {
  currentTable: Table;
  seatId: number;
  bet: number;
  setBet: (bet: number) => void;
  raise: (amount: number) => void;
  fold: () => void;
  check: () => void;
  call: () => void;
  isActionLoading?: boolean;
}

export const GameUI: React.FC<GameUIProps> = ({
  currentTable,
  seatId,
  bet,
  setBet,
  raise,
  fold,
  check,
  call,
  isActionLoading = false,
}) => {
  const { getLocalizedString } = useContext(contentContext)!;
  const seat = currentTable.seats[seatId];
  const fmt = new Intl.NumberFormat(document.documentElement.lang);

  // 决策信息（设计稿 T3）：全部由现有 Table 字段推导
  const toCall = toCallAmount(currentTable, seatId);
  const odds = potOdds(currentTable, seatId);
  const callPct = percentOfStack(currentTable, seatId, toCall);
  const invested = seat?.totalBet;
  const presets = raisePresets(currentTable, seatId);
  // 滑杆以「本轮增量」为值域（raise(bet + seat.bet) 同口径），档位为加注到总额
  const maxDelta = Math.min(seat?.stack ?? 0, currentTable.limit);
  const applyPreset = (raiseTo: number) =>
    setBet(Math.max(Math.min(raiseTo - seat.bet, maxDelta), 0));

  return (
    <UIWrapper>
      {/* 决策信息行：需跟 / 底池赔率 / 跟注占余量 / 本手已投入 */}
      <div
        style={{
          gridColumn: '1 / -1',
          display: 'flex',
          gap: '0.6rem',
          justifyContent: 'center',
          flexWrap: 'wrap',
          fontSize: '0.75rem',
          color: '#5b4a2f',
        }}
      >
        <span>
          {getLocalizedString('game_ui_to-call-lbl')}{' '}
          <strong>{fmt.format(toCall)}</strong>
        </span>
        {odds != null && (
          <span>
            · {getLocalizedString('game_ui_pot-odds-lbl')}{' '}
            <strong>{odds} : 1</strong>
          </span>
        )}
        {callPct != null && (
          <span>
            · {getLocalizedString('game_ui_call-pct-lbl')}{' '}
            <strong>{callPct}%</strong>
          </span>
        )}
        {invested != null && invested > 0 && (
          <span>
            · {getLocalizedString('game_ui_invested-lbl')}{' '}
            <strong>{fmt.format(invested)}</strong>
          </span>
        )}
      </div>

      <div style={{ gridColumn: '1 / -1' }}>
        <BetSlider
          currentTable={currentTable}
          seatId={seatId}
          bet={bet}
          setBet={setBet}
        />
      </div>

      {/* 加注四档位：最小 / 半池 / 底池 / 全下（均为「加注到」总额） */}
      {presets && maxDelta > 0 && (
        <div
          style={{
            gridColumn: '1 / -1',
            display: 'grid',
            gridTemplateColumns: 'repeat(4, 1fr)',
            gap: '0.4rem',
          }}
        >
          <Button small secondary disabled={isActionLoading} onClick={() => applyPreset(presets.min)}>
            {getLocalizedString('game_ui_preset-min')} {fmt.format(presets.min)}
          </Button>
          <Button small secondary disabled={isActionLoading} onClick={() => applyPreset(presets.halfPot)}>
            {getLocalizedString('game_ui_preset-half')} {fmt.format(presets.halfPot)}
          </Button>
          <Button small secondary disabled={isActionLoading} onClick={() => applyPreset(presets.pot)}>
            {getLocalizedString('game_ui_preset-pot')} {fmt.format(presets.pot)}
          </Button>
          <Button small secondary disabled={isActionLoading} onClick={() => applyPreset(presets.allIn)}>
            {getLocalizedString('game_ui_preset-allin')} {fmt.format(presets.allIn)}
          </Button>
        </div>
      )}

      <Button small variant="primary" disabled={isActionLoading} onClick={() => raise(bet + currentTable.seats[seatId].bet)}>
        {getLocalizedString('game_ui_bet')} {bet}
      </Button>
      <Button small variant="secondary" disabled={isActionLoading} onClick={fold}>
        {getLocalizedString('game_ui_fold')}
      </Button>
      <Button
        small
        variant="secondary"
        disabled={
          isActionLoading ||
          (currentTable.callAmount !== currentTable.seats[seatId].bet &&
          currentTable.callAmount > 0)
        }
        onClick={check}
      >
        {getLocalizedString('game_ui_check')}
      </Button>
      <CallButton
        disabled={
          isActionLoading ||
          currentTable.callAmount === 0 ||
          currentTable.seats[seatId].bet >= currentTable.callAmount
        }
        onClick={call}
      >
        {getLocalizedString('game_ui_call')}{' '}
        {currentTable.callAmount &&
        currentTable.seats[seatId].bet < currentTable.callAmount &&
        currentTable.callAmount <= currentTable.seats[seatId].stack
          ? currentTable.callAmount - currentTable.seats[seatId].bet
          : ''}
      </CallButton>
      <Button
        small
        variant="secondary"
        disabled={isActionLoading}
        onClick={() => {
          const totalPossible =
            currentTable.seats[seatId].stack + currentTable.seats[seatId].bet;
          if (totalPossible <= currentTable.callAmount) {
            call();
          } else {
            raise(totalPossible);
          }
        }}
      >
        {getLocalizedString('game_ui_all-in')} (
        {currentTable.seats[seatId].stack})
      </Button>
    </UIWrapper>
  );
};
