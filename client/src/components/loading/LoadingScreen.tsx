import React from 'react';
import styled, { keyframes } from 'styled-components';
import Loader from './Loader';

const fadeIn = keyframes`
  from { opacity: 0; }
  to { opacity: 1; }
`;

// 账簿加载屏：纸面（pg）+ 极淡账格横纹，零光晕零网格面具。
const StyledLoadingScreen = styled.div`
  width: 100%;
  min-height: 100dvh;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  overflow: hidden;
  background: ${({ theme }) => theme.colors.lightBg};
  animation: ${fadeIn} 0.3s ease-out;

  &::before {
    content: '';
    position: absolute;
    inset: 0;
    background: repeating-linear-gradient(
      180deg,
      transparent 0 27px,
      rgba(20, 19, 15, 0.035) 27px 28px
    );
    pointer-events: none;
  }
`;

const LoadingScreen: React.FC = () => (
  <StyledLoadingScreen>
    <Loader />
  </StyledLoadingScreen>
);

export default LoadingScreen;
