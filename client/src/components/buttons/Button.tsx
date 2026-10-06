import styled, { css } from 'styled-components';

export type ButtonVariant = 'default' | 'primary' | 'secondary' | 'gradient' | 'danger';

interface ButtonProps {
  /** 视觉变体（向后兼容：'default' = 金色，'primary' = primaryCta 实色，'secondary' = 描边，'gradient' = 紫色渐变，'danger' = 灰+hover红） */
  variant?: ButtonVariant;
  /** 已弃用别名，等价 variant="primary" */
  primary?: boolean;
  /** 已弃用别名，等价 variant="secondary" */
  secondary?: boolean;
  /** 已弃用别名，等价 variant="gradient" */
  dark?: boolean;
  /** 已弃用别名，等价 variant="default" + 玻璃拟态 */
  darkSecondary?: boolean;
  small?: boolean;
  large?: boolean;
  fullWidth?: boolean;
  fullWidthOnMobile?: boolean;
  to?: string;
  autoFocus?: boolean;
}

/**
 * Button 基类
 * - variant="default"     : 金色（向后兼容 default 行为）
 * - variant="primary"     : primaryCta 实色
 * - variant="secondary"   : 透明 + primaryCta 描边
 * - variant="gradient"    : 品牌紫色渐变（合并 ModalButton/ConfirmButton/GradientButton/BtnPrimary/ActionButton）
 * - variant="danger"      : 灰底 + hover 变红（合并 DangerButton/LogoutButton/BackButton）
 */
const Button = styled.button.withConfig({
  shouldForwardProp: (prop) =>
    ![
      'variant',
      'primary',
      'secondary',
      'dark',
      'darkSecondary',
      'small',
      'large',
      'fullWidth',
      'fullWidthOnMobile',
    ].includes(prop as string),
})<ButtonProps>`
  display: inline-flex;
  align-items: center;
  justify-content: center;
  text-align: center;
  padding: 0.75rem 1.5rem;
  outline: none;
  /* Use box-shadow instead of transparent border to avoid extra GPU layer */
  border: none;
  box-shadow: 0 0 0 2px transparent;
  border-radius: ${({ theme }) => theme.radius.md};
  background-color: ${({ theme }) => theme.colors.goldenColor};
  color: ${({ theme }) => theme.colors.fontColorDark};
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-weight: 500;
  font-size: ${({ theme }) => theme.fontSize.lg};
  line-height: 1.3;
  min-width: 90px;
  min-height: 44px;
  cursor: pointer;
  transition:
    background-color ${({ theme }) => theme.timing.fast} ${({ theme }) => theme.easing.easeStandard},
    box-shadow ${({ theme }) => theme.timing.fast} ${({ theme }) => theme.easing.easeStandard},
    transform ${({ theme }) => theme.timing.fast} ${({ theme }) => theme.easing.easeStandard},
    color ${({ theme }) => theme.timing.fast} ${({ theme }) => theme.easing.easeStandard};

  &:visited {
    background-color: ${({ theme }) => theme.colors.goldenColorDarker};
    color: ${({ theme }) => theme.colors.fontColorDark};
  }

  &:hover:not(:disabled),
  &:active:not(:disabled) {
    background-color: ${({ theme }) => theme.colors.goldenColorDarker};
    color: ${({ theme }) => theme.colors.fontColorDark};
  }

  &:focus-visible {
    outline: none;
    box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.5);
  }

  &:disabled {
    background-color: ${({ theme }) => theme.colors.disabled};
    /* 账簿亮色主题：禁用态文字用弱墨（纸白在浅底上不可读） */
    color: ${({ theme }) => theme.colors.softText};
    cursor: not-allowed;
    opacity: 0.6;
  }

  /* === variant="primary" === */
  ${({ variant, primary }) => {
    const isPrimary = variant === 'primary' || (primary && variant === undefined);
    return isPrimary
      ? css`
          color: ${({ theme }) => theme.colors.primaryCta};
          &,
          &:visited {
            background-color: ${({ theme }) => theme.colors.primaryCta};
            color: ${({ theme }) => theme.colors.fontColorLight};
          }
          &:hover:not(:disabled),
          &:active:not(:disabled) {
            background-color: ${({ theme }) => theme.colors.primaryCtaDarker};
            color: ${({ theme }) => theme.colors.fontColorLight};
          }
          &:focus-visible {
            color: ${({ theme }) => theme.colors.fontColorLight};
            box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.5);
          }
        `
      : null;
  }}

  /* === variant="secondary" === */
  ${({ variant, secondary }) => {
    const isSecondary = variant === 'secondary' || (secondary && variant === undefined);
    return isSecondary
      ? css`
          color: ${({ theme }) => theme.colors.primaryCta};
          &,
          &:visited {
            background-color: transparent;
            border: 2px solid ${({ theme }) => theme.colors.primaryCta};
            color: ${({ theme }) => theme.colors.primaryCta};
          }
          &:hover:not(:disabled),
          &:active:not(:disabled) {
            background-color: transparent;
            border-color: ${({ theme }) => theme.colors.primaryCtaDarker};
            color: ${({ theme }) => theme.colors.primaryCtaDarker};
          }
          &:focus-visible {
            border-color: ${({ theme }) => theme.colors.primaryCtaDarker};
            color: ${({ theme }) => theme.colors.primaryCtaDarker};
          }
        `
      : null;
  }}

  /* === variant="gradient" (品牌紫色渐变) === */
  ${({ variant, dark }) => {
    const isGradient = variant === 'gradient' || (dark && variant === undefined);
    return isGradient
      ? css`
          background: ${({ theme }) => theme.colors.brandGradient};
          color: ${({ theme }) => theme.colors.lightestBg};
          box-shadow: none;
          &,
          &:visited {
            background: ${({ theme }) => theme.colors.brandGradient};
            color: ${({ theme }) => theme.colors.lightestBg};
          }
          &:hover:not(:disabled),
          &:active:not(:disabled) {
            background: ${({ theme }) => theme.colors.brandGradientHover};
            transform: translateY(-2px);
            box-shadow: none;
            color: ${({ theme }) => theme.colors.lightestBg};
          }
          &:focus-visible {
            color: ${({ theme }) => theme.colors.lightestBg};
            box-shadow: 0 0 0 3px rgba(11, 107, 69, 0.35);
          }
          &:disabled {
            background: ${({ theme }) => theme.colors.disabled};
            color: ${({ theme }) => theme.colors.softText};
            box-shadow: none;
            transform: none;
          }
        `
      : null;
  }}

  /* === variant="danger" (灰底 + hover 红) === */
  ${({ variant }) =>
    variant === 'danger'
      ? css`
          background: ${({ theme }) => theme.colors.surfaceMuted};
          color: ${({ theme }) => theme.colors.mutedText};
          border: 1px solid ${({ theme }) => theme.colors.borderMuted};
          &,
          &:visited {
            background: ${({ theme }) => theme.colors.surfaceMuted};
            color: ${({ theme }) => theme.colors.mutedText};
            border-color: ${({ theme }) => theme.colors.borderMuted};
          }
          &:hover:not(:disabled),
          &:active:not(:disabled) {
            background: ${({ theme }) => theme.colors.dangerAlpha06};
            color: ${({ theme }) => theme.colors.dangerStrong};
            border-color: ${({ theme }) => theme.colors.danger};
          }
          &:focus-visible {
            border-color: ${({ theme }) => theme.colors.danger};
            box-shadow: 0 0 0 3px rgba(239, 68, 68, 0.3);
          }
        `
      : null}

  /* === 兼容 darkSecondary：玻璃拟态灰色按钮 === */
  ${({ variant, darkSecondary }) => {
    const isDarkSecondary = darkSecondary && variant === undefined;
    return isDarkSecondary
      ? css`
          background: ${({ theme }) => theme.colors.surfaceMuted};
          color: ${({ theme }) => theme.colors.fontColorDark};
          border: 1px solid ${({ theme }) => theme.colors.borderMuted};
          backdrop-filter: blur(10px);
          &,
          &:visited {
            background: ${({ theme }) => theme.colors.surfaceMuted};
            color: ${({ theme }) => theme.colors.fontColorDark};
            border-color: ${({ theme }) => theme.colors.borderMuted};
          }
          &:hover:not(:disabled),
          &:active:not(:disabled) {
            background: ${({ theme }) => theme.colors.borderSubtle};
            border-color: ${({ theme }) => theme.colors.info};
            color: ${({ theme }) => theme.colors.fontColorDark};
            transform: translateY(-2px);
          }
          &:focus-visible {
            border-color: ${({ theme }) => theme.colors.secondaryCta};
            box-shadow: 0 0 0 3px rgba(11, 107, 69, 0.3);
            color: ${({ theme }) => theme.colors.fontColorDark};
          }
        `
      : null;
  }}

  ${({ large }) =>
    large &&
    css`
      font-size: 1.6rem;
      line-height: 1.6rem;
      min-width: 250px;
      padding: 1rem 2rem;
    `}

  ${({ small }) =>
    small &&
    css`
      font-size: ${({ theme }) => theme.fontSize.md};
      line-height: 1.1;
      min-width: 90px;
      padding: 0.5rem 1rem;
    `}

  ${({ fullWidth }) =>
    fullWidth &&
    css`
      width: 100%;
    `}

  /* Mobile adjustments */
  @media screen and (max-width: 1023px) {
    ${({ large }) =>
      large &&
      css`
        font-size: 1.4rem;
        line-height: 1.4rem;
        min-width: 0;
        width: 100%;
        padding: 0.75rem 1.5rem;
      `}

    ${({ fullWidthOnMobile, fullWidth }) =>
      (fullWidthOnMobile || fullWidth) &&
      css`
        width: 100%;
      `}
  }

  /* Small phones: tighten padding */
  @media screen and (max-width: 479px) {
    min-width: 0;
    ${({ small }) =>
      !small &&
      css`
        padding: 0.6rem 1rem;
        font-size: 1rem;
      `}
  }
`;

export default Button;
