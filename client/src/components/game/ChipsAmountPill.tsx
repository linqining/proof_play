import React from 'react';
import PokerChip from '../icons/PokerChip';
import { Input } from '../forms/Input';
import styled from 'styled-components';

interface ChipsAmountPillProps {
  chipsAmount: number;
  style?: React.CSSProperties;
}

const Wrapper = styled.div`
  position: relative;
  display: inline-block;

  & ${Input} {
    text-align: center;
    padding: 0.5rem 1rem 0.5rem 2rem;
    background: #f7f2dc;
    opacity: 0.75;
    border-radius: 40px;
  }
`;

const IconWrapper = styled.label`
  position: absolute;
  width: 30px;
  height: 30px;
  z-index: 5;
  left: 5px;
  /* Input 基线 44px 后垂直居中 */
  top: 7px;
`;

const ChipsAmountPill: React.FC<ChipsAmountPillProps> = ({ chipsAmount, style }) => {
  return (
    <Wrapper style={style}>
      <IconWrapper htmlFor="chipsAmount">
        <PokerChip width="30" height="30" />
      </IconWrapper>
      <Input
        disabled
        type="text"
        size={10}
        value={new Intl.NumberFormat(document.documentElement.lang).format(
          chipsAmount,
        )}
        name="chipsAmount"
      />
    </Wrapper>
  );
};

export default ChipsAmountPill;
