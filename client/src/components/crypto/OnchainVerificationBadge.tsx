import type { CSSProperties } from 'react'
import { ExternalLink, ShieldCheck, Clock } from 'lucide-react'
import { useContentContext } from '../../context/content/contentContext'

interface OnchainVerificationBadgeProps {
  txDigest: string | null
  verified?: boolean // 是否验证通过，影响颜色
  network?: 'testnet' | 'mainnet' // 默认 testnet
  compact?: boolean // 紧凑模式，只显示图标
}

// 基础徽章样式：圆角 6px 小徽章，与 SecretPokerGameTable 内联风格一致
const baseStyle: CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  gap: '0.3rem',
  padding: '0.25rem 0.5rem',
  borderRadius: '6px',
  fontSize: '0.78rem',
  fontFamily: 'monospace',
  lineHeight: 1.2,
  whiteSpace: 'nowrap',
  textDecoration: 'none',
  userSelect: 'none',
}

// 三种状态颜色 — 选用 WCAG AA 4.5:1 对比的色值，避免在浅色背景上看不清。
// 同时为链接态设置 minHeight=44px 满足 Apple HIG 触控目标。
const greenStyle: CSSProperties = {
  background: 'rgba(16,185,129,0.18)',
  color: '#047857',
  fontWeight: 600,
}
const redStyle: CSSProperties = {
  background: 'rgba(239,68,68,0.18)',
  color: '#b91c1c',
  fontWeight: 600,
}
const grayStyle: CSSProperties = {
  background: 'rgba(100,116,139,0.18)',
  color: '#334155',
  fontWeight: 600,
}

// 截断 digest：前 6 + 后 4 字符
function truncateDigest(digest: string): string {
  if (digest.length <= 10) return digest
  return `${digest.slice(0, 6)}…${digest.slice(-4)}`
}

export function OnchainVerificationBadge({
  txDigest,
  verified = false,
  network = 'testnet',
  compact = false,
}: OnchainVerificationBadgeProps) {
  const { getLocalizedString: t } = useContentContext()
  // 无 txDigest：显示灰色 pending 状态，不可点击
  if (!txDigest) {
    return (
      <span
        style={{ ...baseStyle, ...grayStyle, cursor: 'default' }}
        title={t('crypto_pending-onchain')}
      >
        <Clock size={12} />
        {!compact && <span>{t('crypto_pending-onchain')}</span>}
      </span>
    )
  }

  // Starknet block explorer (Starkscan). Transaction hashes are 0x-prefixed
  // 64-hex (32-byte) values.
  const href = `https://${network === 'mainnet' ? '' : 'sepolia.'}starkscan.co/tx/${txDigest}`
  // verified=true 用 ShieldCheck 图标 + 绿色；verified=false 用 ExternalLink 图标 + 红色
  const Icon = verified ? ShieldCheck : ExternalLink
  const colorStyle = verified ? greenStyle : redStyle

  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      title={txDigest}
      /* Min-height ensures the tap target meets the 44x44 Apple HIG
         guideline, even on the compact icon-only variant. */
      style={{ ...baseStyle, ...colorStyle, cursor: 'pointer', minHeight: 28 }}
    >
      <Icon size={12} />
      {!compact && <span>{truncateDigest(txDigest)}</span>}
    </a>
  )
}

export default OnchainVerificationBadge
