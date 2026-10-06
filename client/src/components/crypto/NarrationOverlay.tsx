import { Info } from 'lucide-react'
import { useContentContext } from '../../context/content/contentContext'

interface NarrationOverlayProps {
  phase: string
  cryptoEventCount?: number
}

export default function NarrationOverlay({
  phase,
  cryptoEventCount = 0,
}: NarrationOverlayProps) {
  const { getLocalizedString: t } = useContentContext()

  const NARRATION_KEYS: Record<string, string> = {
    waiting: 'narration_waiting',
    shuffling: 'narration_shuffling',
    shuffleComplete: 'narration_shuffle-complete',
    preFlopReveal: 'narration_pre-flop-reveal',
    preFlop: 'narration_pre-flop',
    flopReveal: 'narration_flop-reveal',
    flop: 'narration_flop',
    turnReveal: 'narration_turn-reveal',
    turn: 'narration_turn',
    riverReveal: 'narration_river-reveal',
    river: 'narration_river',
    showdownReveal: 'narration_showdown-reveal',
    showdown: 'narration_showdown',
    handComplete: 'narration_hand-complete',
  }

  const key = NARRATION_KEYS[phase]
  const narration = key
    ? t(key)
    : t('narration_default').replace('{phase}', phase)
  const hasCryptoCount = cryptoEventCount > 0

  return (
    <div
      style={{
        position: 'relative',
        display: 'flex',
        alignItems: 'flex-start',
        gap: '0.6rem',
        // 账簿语言：play 语义（进行中）淡章 + 左侧 3px 边线，方角
        background: 'rgba(21, 80, 127, 0.06)',
        border: '1px solid rgba(21, 80, 127, 0.25)',
        borderLeft: '3px solid #15507f',
        borderRadius: '3px',
        padding: '0.7rem 1rem',
        paddingBottom: hasCryptoCount ? '1.5rem' : '0.7rem',
      }}
    >
      <Info
        size={18}
        color="#15507f"
        style={{ flexShrink: 0, marginTop: 2 }}
      />
      <p
        key={phase}
        style={{
          flex: 1,
          margin: 0,
          color: '#14130f',
          fontWeight: 700,
          fontSize: '0.9rem',
          lineHeight: 1.5,
          animation: 'fadeIn 0.4s ease-out',
        }}
      >
        {narration}
      </p>
      {hasCryptoCount && (
        <span
          style={{
            position: 'absolute',
            bottom: '0.3rem',
            right: '0.8rem',
            fontSize: '0.72rem',
            color: '#0b6b45',
            fontWeight: 600,
          }}
        >
          {t('narration_verified-count').replace('{count}', String(cryptoEventCount))}
        </span>
      )}
      <style>{`@keyframes fadeIn { from { opacity: 0; transform: translateY(-2px); } to { opacity: 1; transform: translateY(0); } }`}</style>
    </div>
  )
}
