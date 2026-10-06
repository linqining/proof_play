import React, { useContext } from 'react';
import { Input } from '../forms/Input';
import styled from 'styled-components';
import contentContext from '../../context/content/contentContext';

const Wrapper = styled.div`
  position: relative;
  display: inline-block;

  & ${Input} {
    cursor: pointer;
    text-align: right;
    padding: 0.5rem 1rem 0.5rem 2rem;
    border-radius: ${({ theme }) => theme.other.stdBorderRadius};
    border: 1px solid ${({ theme }) => theme.colors.primaryCta};
  }
`;

const IconWrapper = styled.label`
  cursor: pointer;
  position: absolute;
  width: 40px;
  height: 40px;
  left: 0;
  top: calc(50% - 40px / 2);
  display: flex;
  align-items: center;
  justify-content: center;

  img {
    width: 22px;
    height: 22px;
  }
`;

interface ChipsAmountProps {
  chipsAmount: number;
  clickHandler?: () => void;
}

const ChipsAmount: React.FC<ChipsAmountProps> = ({ chipsAmount, clickHandler }) => {
  const { getLocalizedString } = useContext(contentContext)!;
  return (
    <Wrapper onClick={clickHandler}>
      <IconWrapper htmlFor="chipsAmount">
        <img src="/strk-logo.svg" alt={getLocalizedString('seat_strk-logo-alt')} />
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

export default ChipsAmount;
