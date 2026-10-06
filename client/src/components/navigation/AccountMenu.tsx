import React, { useEffect, useRef, useState } from 'react';
import styled from 'styled-components';

/**
 * 账户菜单：地址触发器 + 下拉面板（复制地址 / 断开连接）。
 * 替代旧的"地址 chip 即登出按钮"——登出收进菜单，杜绝误触。
 */

interface AccountMenuProps {
  /** 完整钱包地址（复制用） */
  address: string;
  copyLabel: string;
  copiedLabel: string;
  logoutLabel: string;
  onLogout?: () => void;
}

const shortAddress = (addr: string): string =>
  addr.length > 12 ? `${addr.slice(0, 6)}…${addr.slice(-4)}` : addr;

const Wrapper = styled.div`
  position: relative;
  display: inline-flex;
`;

const Trigger = styled.button<{ $open: boolean }>`
  display: inline-flex;
  align-items: center;
  gap: 0.45rem;
  height: 40px;
  padding: 0 0.75rem;
  background: ${({ theme }) => theme.colors.surfaceMuted};
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-radius: ${({ theme }) => theme.radius.sm};
  color: ${({ theme }) => theme.colors.mutedText};
  font-family: 'JetBrains Mono', monospace;
  font-weight: 600;
  font-size: ${({ theme }) => theme.fontSize.sm};
  cursor: pointer;
  white-space: nowrap;
  transition:
    color 0.15s ease,
    border-color 0.15s ease,
    background-color 0.15s ease;

  &:hover {
    color: ${({ theme }) => theme.colors.fontColorDark};
    border-color: ${({ theme }) => theme.colors.borderMuted};
    background: ${({ theme }) => theme.colors.lightBg};
  }

  &:focus-visible {
    outline: none;
    box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.3);
  }

  .chevron {
    transition: transform 0.15s ease;
    transform: rotate(${({ $open }) => ($open ? '180deg' : '0deg')});
  }
`;

const StatusDot = styled.span`
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: ${({ theme }) => theme.colors.success};
  flex-shrink: 0;
`;

const Panel = styled.div`
  position: absolute;
  top: calc(100% + 0.5rem);
  right: 0;
  min-width: 250px;
  padding: 0.4rem;
  background: ${({ theme }) => theme.colors.lightestBg};
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-radius: ${({ theme }) => theme.radius.md};
  box-shadow: 0 10px 30px rgba(15, 23, 42, 0.14);
  z-index: 30;
`;

const AddressRow = styled.div`
  padding: 0.5rem 0.55rem;
  margin-bottom: 0.25rem;
  background: ${({ theme }) => theme.colors.surfaceSubtle};
  border-radius: ${({ theme }) => theme.radius.xs};
  font-family: 'JetBrains Mono', monospace;
  font-size: ${({ theme }) => theme.fontSize.xs};
  color: ${({ theme }) => theme.colors.fontColorDarkLighter};
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
`;

const MenuItem = styled.button<{ $danger?: boolean }>`
  display: flex;
  align-items: center;
  gap: 0.45rem;
  width: 100%;
  padding: 0.5rem 0.55rem;
  border: none;
  border-radius: ${({ theme }) => theme.radius.xs};
  background: transparent;
  color: ${({ theme, $danger }) => ($danger ? theme.colors.danger : theme.colors.fontColorDarkLighter)};
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: ${({ theme }) => theme.fontSize.sm};
  font-weight: 500;
  text-align: left;
  cursor: pointer;
  transition: background-color 0.15s ease;

  &:hover {
    background: ${({ theme, $danger }) =>
      $danger ? theme.colors.dangerAlpha06 : theme.colors.lightBg};
  }

  &:focus-visible {
    outline: none;
    box-shadow: 0 0 0 2px rgba(79, 70, 229, 0.3);
  }
`;

const ChevronIcon = () => (
  <svg className="chevron" width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path
      d="M6 9l6 6 6-6"
      stroke="currentColor"
      strokeWidth="2.2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

const CopyIcon = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true" style={{ flexShrink: 0 }}>
    <rect x="9" y="9" width="11" height="11" rx="2" stroke="currentColor" strokeWidth="2" />
    <path d="M5 15V5a2 2 0 012-2h10" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
  </svg>
);

const LogoutIcon = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true" style={{ flexShrink: 0 }}>
    <path
      d="M15 4h3a2 2 0 012 2v12a2 2 0 01-2 2h-3M10 17l-5-5 5-5M5 12h11"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

const AccountMenu: React.FC<AccountMenuProps> = ({
  address,
  copyLabel,
  copiedLabel,
  logoutLabel,
  onLogout,
}) => {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const wrapperRef = useRef<HTMLDivElement>(null);
  const copiedTimerRef = useRef<number | null>(null);

  // 点击面板外或按 Escape 关闭
  useEffect(() => {
    if (!open) return;
    const onPointerDown = (e: MouseEvent) => {
      if (wrapperRef.current && !wrapperRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('mousedown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [open]);

  useEffect(
    () => () => {
      if (copiedTimerRef.current !== null) window.clearTimeout(copiedTimerRef.current);
    },
    [],
  );

  const handleCopy = async (): Promise<void> => {
    try {
      await navigator.clipboard.writeText(address);
      setCopied(true);
      if (copiedTimerRef.current !== null) window.clearTimeout(copiedTimerRef.current);
      copiedTimerRef.current = window.setTimeout(() => setCopied(false), 2000);
    } catch {
      // 剪贴板不可用（非安全上下文等）：静默失败，菜单保持打开
    }
  };

  return (
    <Wrapper ref={wrapperRef}>
      <Trigger
        type="button"
        $open={open}
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
        title={address}
      >
        <StatusDot />
        {shortAddress(address)}
        <ChevronIcon />
      </Trigger>
      {open && (
        <Panel role="menu" aria-label={shortAddress(address)}>
          <AddressRow title={address}>{address}</AddressRow>
          <MenuItem
            type="button"
            role="menuitem"
            onClick={() => {
              void handleCopy();
            }}
          >
            <CopyIcon />
            {copied ? copiedLabel : copyLabel}
          </MenuItem>
          <MenuItem
            type="button"
            role="menuitem"
            $danger
            onClick={() => {
              setOpen(false);
              onLogout?.();
            }}
          >
            <LogoutIcon />
            {logoutLabel}
          </MenuItem>
        </Panel>
      )}
    </Wrapper>
  );
};

export default AccountMenu;
