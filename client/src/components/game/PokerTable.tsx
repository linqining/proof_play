import React, { useContext } from 'react';
import styled from 'styled-components';
import table from '../../assets/game/table.svg';
import contentContext from '../../context/content/contentContext';

const StyledPokerTable = styled.img`
  display: block;
  pointer-events: none;
  width: 95%;
  margin: 0 auto;
`;

const PokerTable: React.FC = () => {
  const { getLocalizedString } = useContext(contentContext)!;
  return <StyledPokerTable src={table} alt={getLocalizedString('common_poker-table')} />;
};

export default PokerTable;
