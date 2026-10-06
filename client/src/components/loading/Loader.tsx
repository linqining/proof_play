import React, { useContext } from 'react';
import styled, { keyframes } from 'styled-components';
import contentContext from '../../context/content/contentContext';

// 账簿加载态：一张纸牌（A♠）绕纵轴翻转 + 墨色题字。
// 零渐变、零光晕、零 emoji——牌面语言与 ledger/PaperCard 一致。
const spin = keyframes`
  0% { transform: rotateY(0deg); }
  100% { transform: rotateY(360deg); }
`;

const Wrapper = styled.div`
  perspective: 800px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
`;

const CardContainer = styled.div`
  width: clamp(56px, 14vw, 72px);
  height: clamp(78px, 20vw, 102px);
  transform-style: preserve-3d;
  animation: ${spin} 1.6s ease-in-out infinite;
`;

const CardFace = styled.div`
  width: 100%;
  height: 100%;
  background: ${({ theme }) => theme.colors.lightestBg};
  border: 1px solid ${({ theme }) => theme.colors.borderMuted};
  border-radius: 3px;
  box-shadow: ${({ theme }) => theme.other.cardDropShadow};
  position: relative;
  color: ${({ theme }) => theme.colors.fontColorDark};

  /* 内框：账簿纸牌双线桌沿 */
  &::before {
    content: '';
    position: absolute;
    inset: 5px;
    border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
    border-radius: 2px;
  }
`;

const Corner = styled.span`
  position: absolute;
  left: 7px;
  top: 5px;
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-variant-numeric: tabular-nums;
  font-size: clamp(14px, 3.4vw, 17px);
  font-weight: 700;
  line-height: 1.05;
  letter-spacing: -0.02em;
  text-align: center;

  i {
    display: block;
    font-style: normal;
    font-size: 0.85em;
    line-height: 1;
  }
`;

const Pip = styled.span`
  position: absolute;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: clamp(22px, 5.6vw, 30px);
  line-height: 1;
`;

const LogoText = styled.div`
  margin-top: 1.8rem;
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 1.35rem;
  font-weight: 700;
  color: ${({ theme }) => theme.colors.fontColorDark};
  letter-spacing: 0.06em;
`;

const Tagline = styled.div`
  margin-top: 0.45rem;
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 0.72rem;
  color: ${({ theme }) => theme.colors.softerText};
  letter-spacing: 0.18em;
  text-transform: uppercase;
`;

const Loader: React.FC = () => {
  const { getLocalizedString } = useContext(contentContext)!;
  return (
    <Wrapper>
      <CardContainer>
        <CardFace>
          <Corner>
            A
            <i>♠</i>
          </Corner>
          <Pip>♠</Pip>
        </CardFace>
      </CardContainer>
      <LogoText>ProofPlay Poker</LogoText>
      <Tagline>{getLocalizedString('common_loading')}</Tagline>
    </Wrapper>
  );
};

export default Loader;
