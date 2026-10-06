import React, { useEffect, useRef } from 'react';
import styled, { css } from 'styled-components';

export interface ModalShellProps {
  /** 模态内容（React 节点） */
  children: React.ReactNode;
  /** 模态宽度：sm=320px, md=480px, lg=560px，或自定义 CSS 字符串 */
  width?: 'sm' | 'md' | 'lg' | string;
  /** 关闭回调（点击遮罩时触发，可选） */
  onBackdropClick?: () => void;
  /**
   * 是否在 mobile（< 480px）占用全屏。默认 true。
   * 注意:此 prop **不影响桌面宽度** — 桌面下弹窗始终按 `width` 渲染。
   */
  fullScreenOnMobile?: boolean;
  /** ARIA 角色，默认 dialog */
  role?: 'dialog' | 'alertdialog';
  ariaLabel?: string;
  ariaLabelledBy?: string;
  className?: string;
}

const Backdrop = styled.div`
  position: fixed;
  inset: 0;
  z-index: ${({ theme }) => theme.zIndex.modal};
  background-color: rgba(20, 19, 15, 0.42);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 1rem;
  /* Prevent scroll chaining when modal scroll hits boundary */
  overscroll-behavior: contain;
`;

/**
 * Shell design:
 * - On viewports >= 480px (desktop / tablet landscape / large phone
 *   landscape), the modal always uses the caller-supplied $width. No
 *   full-screen override is applied, regardless of $fullScreen.
 * - On viewports < 480px (small phone portrait), if $fullScreen is
 *   true the modal goes full-bleed (100% of the available space inside
 *   the backdrop's 1rem padding). Otherwise the $width still applies,
 *   but capped at 100% so it never overflows the viewport.
 *
 * This is the fix for the regression where `$fullScreen=true` on
 * desktop made the dialog 100% wide — see the comment in the styled
 * template below.
 */
const Shell = styled.div<{ $width: string; $fullScreen: boolean }>`
  position: relative;
  display: flex;
  flex-direction: column;
  gap: 1rem;
  /* Desktop / larger viewports: use the caller-supplied width as both
     the width and the max-width floor. $fullScreen is intentionally
     IGNORED here so the desktop dialog stays compact. */
  width: ${({ $width }) => $width};
  max-width: ${({ $width }) => $width};
  max-height: calc(100dvh - 2rem);
  padding: 1.5rem 1.25rem;
  background: ${({ theme }) => theme.colors.surfaceGlass};
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-radius: ${({ theme }) => theme.radius.xl};
  box-shadow: ${({ theme }) => theme.other.cardDropShadow};
  overflow-y: auto;
  overscroll-behavior: contain;

  @media screen and (max-width: 479px) {
    ${({ $fullScreen, $width }) =>
      $fullScreen
        ? css`
            width: 100%;
            max-width: 100%;
            max-height: 100dvh;
            border-radius: 0;
            padding: 1.25rem 1rem;
          `
        : css`
            /* Don't overflow the small viewport: cap at 100% of the
               backdrop's content area (which has 1rem padding on each
               side). */
            max-width: min(${$width}, 100%);
          `}
  }
`;

const SIZE_MAP: Record<string, string> = {
  sm: '320px',
  md: '480px',
  lg: '560px',
};

const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/* 嵌套弹窗（如弹窗内再开弹窗）时只在最后一个实例关闭时恢复 body 滚动 */
let openShellCount = 0;
let savedBodyOverflow = '';

/**
 * 统一模态容器
 * 替代 Modal.tsx 与 LoginModal.tsx 中重复的 ModalWrapper + StyledModal 容器。
 * 提供遮罩点击、ARIA、焦点陷阱、Esc 关闭、body 滚动锁定、焦点还原。
 */
const ModalShell: React.FC<ModalShellProps> = ({
  children,
  width = 'md',
  onBackdropClick,
  fullScreenOnMobile = true,
  role = 'dialog',
  ariaLabel,
  ariaLabelledBy,
  className,
}) => {
  const resolvedWidth = SIZE_MAP[width] ?? width;
  const shellRef = useRef<HTMLDivElement>(null);
  const onBackdropClickRef = useRef(onBackdropClick);
  onBackdropClickRef.current = onBackdropClick;

  useEffect(() => {
    const shell = shellRef.current;
    const previouslyFocused =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;

    if (openShellCount === 0) {
      savedBodyOverflow = document.body.style.overflow;
      document.body.style.overflow = 'hidden';
    }
    openShellCount += 1;

    // 初始聚焦弹窗内部第一个可聚焦元素（无则聚焦 shell 本体）
    const focusables = shell
      ? (Array.from(shell.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)) as HTMLElement[]).filter(
          (el) => el.offsetParent !== null || el === document.activeElement,
        )
      : [];
    (focusables[0] ?? shell)?.focus();

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        // 与遮罩点击同一出口；调用方（如 pending 中）可不传即禁用
        if (onBackdropClickRef.current) {
          e.stopPropagation();
          onBackdropClickRef.current();
        }
        return;
      }
      if (e.key !== 'Tab' || !shell) return;
      // 焦点陷阱：Tab 循环限制在弹窗内
      const items = (
        Array.from(shell.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)) as HTMLElement[]
      ).filter((el) => !el.hasAttribute('disabled') && el.offsetParent !== null);
      if (items.length === 0) {
        e.preventDefault();
        shell.focus();
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      const active = document.activeElement;
      if (e.shiftKey && (active === first || active === shell)) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && active === last) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener('keydown', onKeyDown, true);

    return () => {
      document.removeEventListener('keydown', onKeyDown, true);
      openShellCount -= 1;
      if (openShellCount === 0) {
        document.body.style.overflow = savedBodyOverflow;
      }
      previouslyFocused?.focus();
    };
  }, []);

  return (
    <Backdrop
      onClick={(e) => {
        if (e.target === e.currentTarget && onBackdropClick) {
          onBackdropClick();
        }
      }}
    >
      <Shell
        ref={shellRef}
        $width={resolvedWidth}
        $fullScreen={fullScreenOnMobile}
        role={role}
        aria-modal="true"
        aria-label={ariaLabel}
        aria-labelledby={ariaLabelledBy}
        className={className}
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
      >
        {children}
      </Shell>
    </Backdrop>
  );
};

export default ModalShell;
