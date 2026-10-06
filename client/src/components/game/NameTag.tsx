import styled from 'styled-components';

export const NameTag = styled.div`
  display: flex;
  justify-content: center;
  align-items: center;
  text-align: center;
  min-width: 150px;
  max-width: 200px;
  padding: 0.15rem 2rem;
  position: absolute;
  background: ${({ theme }) => theme.colors.goldChip};
  opacity: 0.75;
  border-radius: ${({ theme }) => theme.radius.sm};
  z-index: 55;
  /* Long wallet addresses / non-Latin names should truncate instead of
     pushing siblings off-seat. The tooltip on the parent shows the full
     name when needed. */
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
`;
