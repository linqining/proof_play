import type { ReactNode } from 'react'
import { ShieldCheck, CheckCircle2, AlertTriangle } from 'lucide-react'
import styled, { useTheme } from 'styled-components'
import { useContentContext } from '../../context/content/contentContext'
import { isV2Proof } from '../../api/secretPokerClient'
import type {
  ShuffleLayerRecord,
  HandSettleReceipt,
  ChainMeta,
} from '../../api/secretPokerClient'

interface ShuffleProofVisualizerProps {
  /** D1 证明通道下发的单层留存记录（含 V1/V2 证明本体 + 方案 b 投影） */
  layer?: ShuffleLayerRecord | null
  /** 手级上下文（aggregate_pk / deck_size / 总轮次） */
  meta?: {
    aggregatePk?: string | null
    deckSize?: number | null
    totalRounds?: number | null
  } | null
  /** D2/D3 链上验证卡（结算回执 + 合约元数据）；链下验证时为 null */
  settlement?: HandSettleReceipt | null
  chain?: ChainMeta | null
  verified?: boolean | null
  /** 验证失败原因（crypto_event message；FAILED 态展开） */
  failureReason?: string | null
}

function truncateHex(hex: string | undefined | null, prefix = 10): string {
  if (!hex) return '—'
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex
  if (clean.length <= prefix) return `0x${clean}`
  return `0x${clean.slice(0, prefix)}…`
}

/* ===================== styled components ===================== */

const Card = styled.div<{ $borderColor: string }>`
  background: ${({ theme }) => theme.colors.lightestBg};
  border-radius: ${({ theme }) => theme.radius.md};
  padding: 1rem;
  border: 1px solid ${({ $borderColor }) => $borderColor};
  box-shadow: 0 3px 12px rgba(0, 0, 0, 0.05);
  font-family: 'Inter', sans-serif;
  color: ${({ theme }) => theme.colors.fontColorDarkLighter};
`;

const Title = styled.h3`
  margin: 0;
  font-size: 1.05rem;
  font-weight: 700;
  color: ${({ theme }) => theme.colors.fontColorDarkLighter};
`;

const Subtitle = styled.p`
  margin: 0.2rem 0 0;
  font-size: 0.78rem;
  color: ${({ theme }) => theme.colors.info};
  font-weight: 600;
`;

const SectionLabel = styled.div`
  font-size: 0.7rem;
  color: ${({ theme }) => theme.colors.softerText};
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-bottom: 0.4rem;
  font-weight: 600;
`;

const Empty = styled.div`
  padding: 1.2rem 0.5rem;
  text-align: center;
  color: ${({ theme }) => theme.colors.softerText};
  font-style: italic;
  font-size: 0.85rem;
`;

const HexRowContainer = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
  background: rgba(248, 250, 252, 0.8);
  border-radius: 6px;
  padding: 0.35rem 0.55rem;
`;

const HexRowLabel = styled.span`
  font-size: 0.75rem;
  color: ${({ theme }) => theme.colors.mutedText};
  font-weight: 500;
  flex-shrink: 0;
`;

const HexRowValue = styled.span`
  font-size: 0.75rem;
  font-family: 'JetBrains Mono', monospace;
  color: ${({ theme }) => theme.colors.softText};
`;

const DerivedTag = styled.span`
  font-size: 0.62rem;
  color: #8b5cf6;
  border: 1px solid rgba(139, 92, 246, 0.4);
  border-radius: 4px;
  padding: 0 0.25rem;
  margin-left: 0.35rem;
  white-space: nowrap;
`;

const ProofRowContainer = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  background: rgba(248, 250, 252, 0.8);
  border-radius: 6px;
  padding: 0.35rem 0.55rem;
`;

const ProofIconWrap = styled.span`
  display: inline-flex;
  flex-shrink: 0;
`;

const ProofName = styled.span`
  font-size: 0.75rem;
  font-family: 'JetBrains Mono', monospace;
  color: ${({ theme }) => theme.colors.fontColorDarkLighter};
  font-weight: 600;
`;

const ProofDesc = styled.span`
  font-size: 0.72rem;
  color: ${({ theme }) => theme.colors.softText};
  margin-left: auto;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
`;

const HighlightsDivider = styled.div`
  margin-top: 0.5rem;
  padding-top: 0.75rem;
  border-top: 1px dashed ${({ theme }) => theme.colors.borderSubtle};
`;

const HighlightsList = styled.ul`
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
`;

const HighlightItemRow = styled.li`
  display: flex;
  align-items: center;
  gap: 0.4rem;
`;

const HighlightItemText = styled.span`
  font-size: 0.75rem;
  color: ${({ theme }) => theme.colors.mutedText};
`;

const SectionStack = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
`;

const SectionBlock = styled.div`
  margin-bottom: 0.75rem;
`;

const FailureBanner = styled.div`
  display: flex;
  align-items: flex-start;
  gap: 0.4rem;
  margin-bottom: 0.6rem;
  padding: 0.45rem 0.6rem;
  border-radius: 6px;
  background: rgba(239, 68, 68, 0.08);
  border: 1px solid rgba(239, 68, 68, 0.35);
  font-size: 0.72rem;
  color: #b91c1c;
`;

/* ===================== component ===================== */

export default function ShuffleProofVisualizer({
  layer,
  meta,
  settlement,
  chain,
  verified,
  failureReason,
}: ShuffleProofVisualizerProps) {
  const { getLocalizedString: t } = useContentContext()
  const theme = useTheme()

  const failed = verified === false || layer?.verified === false
  const borderColor = failed
    ? theme.colors.danger
    : verified === true || layer?.verified === true
      ? theme.colors.success
      : theme.colors.borderSubtle

  const isV2 = layer ? isV2Proof(layer.proof) : false
  const v2 = layer && isV2Proof(layer.proof) ? layer.proof.proof : null
  const totalRounds = meta?.totalRounds ?? null

  return (
    <Card $borderColor={borderColor}>
      <div style={{ marginBottom: '0.75rem' }}>
        <Title>{t('shuffle-proof_title')}</Title>
        <Subtitle>
          {t('shuffle-proof_subtitle')}
          {layer
            ? ` · ${t('shuffle-proof_layer')} ${layer.round}${totalRounds ? `/${totalRounds}` : ''} · V${layer.proofVersion}`
            : ''}
        </Subtitle>
      </div>

      {failed && (
        <FailureBanner>
          <AlertTriangle size={14} style={{ flexShrink: 0, marginTop: 1 }} />
          <div>
            <strong>{t('shuffle-proof_verify-failed')}</strong>
            {failureReason ? ` — ${failureReason}` : ''}
          </div>
        </FailureBanner>
      )}

      {layer === null || layer === undefined ? (
        <Empty>{t('shuffle-proof_placeholder')}</Empty>
      ) : (
        <>
          {/* ① 承诺层：V1 字段名布局；V2 行为服务端派生摘要（诚实标注） */}
          <SectionBlock>
            <SectionLabel>{t('shuffle-proof_commitment-layer')}</SectionLabel>
            <SectionStack>
              <HexRow
                label="sum_c1_commit"
                value={truncateHex(layer.display.sumC1Commit)}
                derived={layer.display.derived}
                derivedText={t('shuffle-proof_derived')}
              />
              <HexRow
                label="sum_c2_commit"
                value={truncateHex(layer.display.sumC2Commit)}
                derived={layer.display.derived}
                derivedText={t('shuffle-proof_derived')}
              />
              <HexRow label="aggregate_pk" value={truncateHex(meta?.aggregatePk, 12)} />
              <HexRow label="deck_size" value={meta?.deckSize ? String(meta.deckSize) : '—'} />
            </SectionStack>
          </SectionBlock>

          {/* ② 证明层：V1 = 三个 Schnorr 子证明；V2 = Bayer-Groth 结构 */}
          <SectionBlock>
            <SectionLabel>
              {t('shuffle-proof_proof-layer')}
              {isV2 ? ` · ${t('shuffle-proof_v2-native')}` : ''}
            </SectionLabel>
            <SectionStack>
              {v2
                ? (
                    <>
                      <ProofRow icon={<ShieldCheck size={16} color={theme.colors.info} />} name="c_permutation" desc={truncateHex(v2.c_permutation_hex)} />
                      <ProofRow icon={<ShieldCheck size={16} color={theme.colors.info} />} name="multi_exponentiation" desc={truncateHex(v2.multi_exponentiation.c_alpha_hex)} />
                      <ProofRow icon={<ShieldCheck size={16} color={theme.colors.info} />} name="product_argument" desc={truncateHex(v2.product.c_d_hex)} />
                    </>
                  )
                : (
                    <>
                      <ProofRow icon={<ShieldCheck size={16} color={theme.colors.info} />} name="combined_schnorr_proof" desc={truncateHex(layer.display.combinedSchnorrProof)} />
                      <ProofRow icon={<ShieldCheck size={16} color={theme.colors.info} />} name="sum_c1_schnorr_proof" desc={truncateHex(layer.display.sumC1SchnorrProof)} />
                      <ProofRow icon={<ShieldCheck size={16} color={theme.colors.info} />} name="sum_c2_schnorr_proof" desc={truncateHex(layer.display.sumC2SchnorrProof)} />
                    </>
                  )}
            </SectionStack>
          </SectionBlock>

          {/* ③ 防重放：V1 nonce / V2 transcript 全局挑战 + 轮次 */}
          <SectionBlock>
            <SectionLabel>{t('shuffle-proof_anti-replay')}</SectionLabel>
            <SectionStack>
              {isV2
                ? (
                    <HexRow
                      label="global_challenge"
                      value={truncateHex(layer.globalChallenge)}
                      derived
                      derivedText={t('shuffle-proof_transcript-derived')}
                    />
                  )
                : (
                    <HexRow label="nonce" value={truncateHex(layer.display.nonce)} />
                  )}
              <HexRow
                label={t('shuffle-proof_round')}
                value={totalRounds ? `${layer.round}/${totalRounds}` : String(layer.round)}
              />
            </SectionStack>
          </SectionBlock>

          {/* ④ 链上验证（D2/D3）：仅已上链时展示区块/Gas/合约 */}
          {settlement && settlement.status === 'settled' && (
            <SectionBlock>
              <SectionLabel>{t('shuffle-proof_onchain-meta')}</SectionLabel>
              <SectionStack>
                {settlement.blockNumber !== undefined && settlement.blockNumber !== null && (
                  <HexRow label={t('shuffle-proof_block')} value={`#${settlement.blockNumber.toLocaleString()}`} />
                )}
                {settlement.gasFee && (
                  <HexRow label={t('shuffle-proof_gas')} value={settlement.gasFee} />
                )}
                {(settlement.contract ?? chain?.contract) && (
                  <HexRow label={t('shuffle-proof_contract')} value={truncateHex(settlement.contract ?? chain?.contract ?? undefined, 12)} />
                )}
                {settlement.handBinding && (
                  <HexRow label={t('shuffle-proof_binding')} value={truncateHex(settlement.handBinding, 12)} />
                )}
              </SectionStack>
            </SectionBlock>
          )}
        </>
      )}

      <HighlightsDivider>
        <SectionLabel>{t('shuffle-proof_highlights')}</SectionLabel>
        <HighlightsList>
          <Highlight text={t('shuffle-proof_highlight-1')} />
          <Highlight text={t('shuffle-proof_highlight-2')} />
          <Highlight text={t('shuffle-proof_highlight-3')} />
        </HighlightsList>
      </HighlightsDivider>
    </Card>
  )
}

function HexRow({
  label,
  value,
  derived,
  derivedText,
}: {
  label: string
  value: string
  derived?: boolean
  derivedText?: string
}) {
  return (
    <HexRowContainer>
      <HexRowLabel>
        {label}
        {derived && derivedText && <DerivedTag>{derivedText}</DerivedTag>}
      </HexRowLabel>
      <HexRowValue>{value}</HexRowValue>
    </HexRowContainer>
  )
}

function ProofRow({ icon, name, desc }: { icon: ReactNode; name: string; desc: string }) {
  return (
    <ProofRowContainer>
      <ProofIconWrap>{icon}</ProofIconWrap>
      <ProofName>{name}</ProofName>
      <ProofDesc>{desc}</ProofDesc>
    </ProofRowContainer>
  )
}

function Highlight({ text }: { text: string }) {
  const theme = useTheme()
  return (
    <HighlightItemRow>
      <CheckCircle2 size={14} color={theme.colors.success} style={{ flexShrink: 0 }} />
      <HighlightItemText>{text}</HighlightItemText>
    </HighlightItemRow>
  )
}
