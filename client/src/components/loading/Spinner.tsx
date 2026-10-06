import React from 'react';
import styled, { keyframes, useTheme } from 'styled-components';

const spin = keyframes`
  to { transform: rotate(360deg); }
`;

interface SpinnerProps {
  size?: number;
  /** 圆环颜色（默认 primaryCta felt） */
  color?: string;
  /** 圆环底色（默认 borderSubtle） */
  trackColor?: string;
  /** 圆环宽度（px） */
  thickness?: number;
  ariaLabel?: string;
}

const Ring = styled.div<{ $size: number; $thickness: number; $color: string; $track: string }>`
  display: inline-block;
  width: ${({ $size }) => $size}px;
  height: ${({ $size }) => $size}px;
  border: ${({ $thickness }) => $thickness}px solid ${({ $track }) => $track};
  border-top-color: ${({ $color }) => $color};
  border-radius: 50%;
  animation: ${spin} 0.8s linear infinite;
`;

/**
 * 统一 Spinner 组件（账簿配色：felt 主色 + 淡纸轨道）
 * 替代 SecretPokerGameTable / ZkLoginCallback / Spinner styled 中的 4 套实现
 */
const Spinner: React.FC<SpinnerProps> = ({
  size = 36,
  color,
  trackColor,
  thickness = 3,
  ariaLabel = 'Loading',
}) => {
  const theme = useTheme();
  return (
    <Ring
      role="status"
      aria-label={ariaLabel}
      $size={size}
      $thickness={thickness}
      $color={color ?? theme.colors.primaryCta}
      $track={trackColor ?? theme.colors.borderSubtle}
    />
  );
};

export default Spinner;
