import { useState, useEffect, useContext } from 'react'
import styled, { keyframes, css } from 'styled-components'
import { Lock } from 'lucide-react'
import contentContext from '../../context/content/contentContext'

interface EncryptedCardProps {
  // 密文摘要（ElGamal c1/c2 的 hex 前 8 字符）
  ciphertextPreview?: { c1: string; c2: string } | null
  // 解密后的明文牌面（如 "A♥" "K♠" "10♦"），为 null/undefined 表示尚未解密
  decryptedValue: string | null
  // 解密者玩家标识（pk 截断或名字）
  decryptedBy?: string | null
  // 卡片索引
  cardIndex?: number
  size?: 'sm' | 'md' // 默认 md
}

// 尺寸配置：md 56x80 / sm 40x56
const SIZE_MAP = {
  sm: { w: 40, h: 56, fontMain: '0.72rem', fontSub: '0.48rem', lockSize: 12 },
  md: { w: 56, h: 80, fontMain: '1.05rem', fontSub: '0.6rem', lockSize: 16 },
} as const

// 卡片所处阶段：密文态 / 翻转中 / 解密态
type CardPhase = 'encrypted' | 'flipping' | 'decrypted'

// 将 hex 截断为前 8 字符，超出则追加 ".."，统一带 0x 前缀
function truncateHex(hex: string): string {
  const v = hex.startsWith('0x') ? hex : `0x${hex}`
  return v.length > 8 ? `${v.slice(0, 8)}..` : v
}

/* ===================== Styled components ===================== */

const encCardFlip = keyframes`
  0% { transform: rotateY(0deg); }
  100% { transform: rotateY(180deg); }
`;

const Perspective = styled.div`
  perspective: 600px;
`;

const Flipper = styled.div<{ $phase: CardPhase; $w: number; $h: number }>`
  position: relative;
  width: ${({ $w }) => $w}px;
  height: ${({ $h }) => $h}px;
  transform-style: preserve-3d;
  ${({ $phase }) =>
    $phase === 'flipping'
      ? css`
          animation: ${encCardFlip} 0.6s ease-in-out forwards;
        `
      : $phase === 'decrypted'
      ? css`
          transform: rotateY(180deg);
        `
      : null}
`;

const Face = styled.div`
  position: absolute;
  inset: 0;
  border-radius: ${({ theme }) => theme.radius.sm};
  backface-visibility: hidden;
  -webkit-backface-visibility: hidden;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  box-shadow: 0 3px 12px rgba(0, 0, 0, 0.12);
  overflow: hidden;
  box-sizing: border-box;
`;

const FaceFront = styled(Face)`
  background: linear-gradient(145deg, #1a3050, #0d1f35);
  border: 2px solid #2a4a70;
  color: rgba(255, 255, 255, 0.85);
`;

const FaceBack = styled(Face)`
  transform: rotateY(180deg);
  background: linear-gradient(145deg, ${({ theme }) => theme.colors.lightestBg}, #f0f0f0);
  border: 1px solid rgba(0, 0, 0, 0.08);
  color: ${({ $isRed, theme }: { $isRed?: boolean; theme?: any }) =>
    $isRed ? theme?.colors?.dangerStrong ?? '#dc2626' : '#1a1a1a'};
`;

// 注：styled-components 的 FaceBack 类型推断对可选 theme prop 不友好，
// 上述简化为直接传 theme prop，但更稳妥的做法是套 ThemeProvider + 默认 theme。
// 这里改用普通 styled with props 解构:
const FaceBackColored = styled(Face).attrs<{ $isRed: boolean }>((p) => ({
  $isRed: p.$isRed,
}))<{ $isRed: boolean }>`
  transform: rotateY(180deg);
  background: linear-gradient(145deg, ${({ theme }) => theme.colors.lightestBg}, #f0f0f0);
  border: 1px solid rgba(0, 0, 0, 0.08);
  color: ${({ $isRed, theme }) =>
    $isRed ? theme.colors.dangerStrong : theme.colors.fontColorDark};
`;

const IndexLabel = styled.span<{ $back: boolean }>`
  position: absolute;
  top: 2px;
  left: 4px;
  color: ${({ $back }) =>
    $back ? 'rgba(0, 0, 0, 0.35)' : 'rgba(255, 255, 255, 0.45)'};
  font-family: 'JetBrains Mono', monospace;
  line-height: 1;
`;

const CipherRow = styled.div`
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
`;

const CipherBox = styled.div`
  position: absolute;
  bottom: 2px;
  left: 0;
  right: 0;
  text-align: center;
  font-family: 'JetBrains Mono', monospace;
  color: rgba(255, 255, 255, 0.45);
  line-height: 1.1;
  padding: 0 3px;
`;

const DecryptedByLabel = styled.span`
  position: absolute;
  bottom: 3px;
  left: 0;
  right: 0;
  text-align: center;
  color: ${({ theme }) => theme.colors.successStrong};
  line-height: 1.15;
  padding: 0 3px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
`;

const EncText = styled.span`
  font-weight: 700;
  letter-spacing: 0.08em;
  margin-top: 2px;
  line-height: 1;
`;

const DecryptedValue = styled.span`
  font-weight: 800;
  line-height: 1;
`;

/* ===================== Component ===================== */

export default function EncryptedCard({
  ciphertextPreview,
  decryptedValue,
  decryptedBy,
  cardIndex,
  size = 'md',
}: EncryptedCardProps) {
  const { getLocalizedString: t } = useContext(contentContext)!
  const s = SIZE_MAP[size]
  const [phase, setPhase] = useState<CardPhase>(decryptedValue ? 'decrypted' : 'encrypted')
  const [prevValue, setPrevValue] = useState<string | null>(decryptedValue ?? null)

  useEffect(() => {
    // 从密文态切换到解密态：触发翻转动画
    if (prevValue == null && decryptedValue != null) {
      setPhase('flipping')
      const timer = setTimeout(() => setPhase('decrypted'), 600)
      setPrevValue(decryptedValue)
      return () => clearTimeout(timer)
    }
    if (prevValue !== decryptedValue) {
      setPrevValue(decryptedValue ?? null)
      setPhase(decryptedValue ? 'decrypted' : 'encrypted')
    }
  }, [decryptedValue, prevValue])

  const isRed = !!(decryptedValue && (decryptedValue.includes('♥') || decryptedValue.includes('♦')))

  return (
    <Perspective>
      <Flipper $phase={phase} $w={s.w} $h={s.h}>
        {/* 正面：密文态 */}
        <FaceFront>
          {cardIndex != null && <IndexLabel $back={false}>#{cardIndex}</IndexLabel>}
          <Lock size={s.lockSize} strokeWidth={2} style={{ opacity: 0.85 }} />
          <EncText style={{ fontSize: s.fontMain }}>{t('crypto_enc')}</EncText>
          {ciphertextPreview && (
            <CipherBox style={{ fontSize: s.fontSub }}>
              <CipherRow>c1:{truncateHex(ciphertextPreview.c1)}</CipherRow>
              <CipherRow>c2:{truncateHex(ciphertextPreview.c2)}</CipherRow>
            </CipherBox>
          )}
        </FaceFront>

        {/* 背面：解密态 */}
        <FaceBackColored $isRed={isRed}>
          {cardIndex != null && <IndexLabel $back={true}>#{cardIndex}</IndexLabel>}
          <DecryptedValue style={{ fontSize: s.fontMain }}>
            {decryptedValue ?? ''}
          </DecryptedValue>
          {decryptedBy && (
            <DecryptedByLabel style={{ fontSize: s.fontSub }}>
              {t('crypto_decrypted-by')}{decryptedBy}
            </DecryptedByLabel>
          )}
        </FaceBackColored>
      </Flipper>
    </Perspective>
  );
}
