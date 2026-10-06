import React from 'react';
import ReactDOM from 'react-dom';
import styled, { keyframes } from 'styled-components';
import CloseButton from '../buttons/CloseButton';
import Button from '../buttons/Button';
import ModalShell from './ModalShell';

const fadeIn = keyframes`
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
`;

const StyledModalShell = styled(ModalShell)`
  animation: ${fadeIn} ${({ theme }) => theme.timing.emphasis} ${({ theme }) => theme.easing.easeStandard};
`;

const ModalContent = styled.div`
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  gap: 1.5rem;
`;

const ModalHeading = styled.h2`
  font-family: 'Inter', -apple-system, sans-serif;
  font-size: 1.4rem;
  font-weight: 700;
  color: ${({ theme }) => theme.colors.fontColorDark};
  letter-spacing: -0.02em;
  margin: 0;
`;

const IconWrapper = styled.div`
  position: absolute;
  top: 0.75rem;
  right: 0.75rem;
  z-index: 1;
`;

/**
 * ModalButton 保留为 Button variant="gradient" 的语义化别名
 * 用于模态底部主操作，与 ModalShell 配套使用。
 */
// 账簿：弹窗底部按钮为描边（felt 实底仅留给表单内主操作）
export const ModalButton = styled(Button).attrs({ variant: 'secondary' })`
  padding: 0.65rem 2rem;
`;

interface ModalProps {
  children?: React.ReactNode;
  headingText?: string;
  btnText?: string;
  onClose: () => void;
  onBtnClicked: () => void;
}

const Modal: React.FC<ModalProps> = ({
  children,
  headingText,
  btnText,
  onClose,
  onBtnClicked,
}) => {
  return ReactDOM.createPortal(
    <StyledModalShell
      width="md"
      onBackdropClick={onClose}
      ariaLabel={headingText}
    >
      <IconWrapper>
        <CloseButton clickHandler={onClose} ariaLabel="Close modal" />
      </IconWrapper>
      <ModalContent>
        {headingText && <ModalHeading>{headingText}</ModalHeading>}
        {children && children}
        {btnText && (
          <ModalButton onClick={onBtnClicked}>
            {btnText}
          </ModalButton>
        )}
      </ModalContent>
    </StyledModalShell>,
    document.getElementById('modal') as HTMLElement,
  );
};

export default Modal;
