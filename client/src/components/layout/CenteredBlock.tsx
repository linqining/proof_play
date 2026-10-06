import styled from 'styled-components';

interface CenteredBlockProps {
  direction?: 'column' | 'row';
}

const CenteredBlock = styled.section.withConfig({
  shouldForwardProp: (prop) => prop !== 'direction',
})<CenteredBlockProps>`
  width: 100%;
  height: 100%;
  display: flex;
  flex-direction: ${({ direction }) => direction};
  justify-content: center;
  overflow-x: hidden;
`;

export default CenteredBlock;
