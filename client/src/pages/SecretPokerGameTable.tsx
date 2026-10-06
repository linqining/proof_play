import { useState, useEffect, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, RefreshCw, AlertCircle, ChevronRight, ChevronDown, X, Eye } from 'lucide-react'
import api, { GameState } from '../api/secretPokerClient'
import type { HandProofResponse } from '../api/secretPokerClient'
import { PlayerName } from '../components/game/PlayerName'
import { gameWsClient } from '../api/wsClient'
import { CryptoEvent } from '../types/game'
import { useContentContext } from '../context/content/contentContext'
import NarrationOverlay from '../components/crypto/NarrationOverlay'
import CryptoEventStream from '../components/crypto/CryptoEventStream'
import { OnchainVerificationBadge } from '../components/crypto/OnchainVerificationBadge'
import EncryptedCard from '../components/crypto/EncryptedCard'
import ShuffleProofVisualizer from '../components/crypto/ShuffleProofVisualizer'
import { logger } from '../helpers/logger'
import Spinner from '../components/loading/Spinner'
import {
  CenteredMessageContainer,
  GradientButton,
  MainContainer,
  TopBar,
  SecondaryActionButton,
  TopBarCenter,
  PhaseBadge,
  PotDisplay,
  TopBarRight,
  DrawerToggleButton,
  MainLayout,
  TableCard,
  GameTitle,
  PlayersGrid,
  PlayerSeat,
  PlayerNameDisplay,
  PlayerChips,
  PlayerBet,
  CommunityCardsSection,
  SectionLabel,
  SectionLabelTight,
  SectionLabelDetail,
  CardsRow,
  CardDisplay,
  WinnerBanner,
  ZkPanel,
  PanelInner,
  PanelHeader,
  PanelTitle,
  PanelSubtitle,
  PanelCloseButton,
  EventStreamContainer,
  EventDetailColumn,
  EventTypeRow,
  EventTypeLabel,
  RevealTokenCards,
  EventMessage,
  EmptyDetailPlaceholder,
  RawLogSection,
  RawLogToggleButton,
  RawLogContent,
  EmptyLog,
  LogEntry,
  ErrorToast,
} from './SecretPokerGameTable.styles'

export default function GameTable() {
  const { gameId } = useParams<{ gameId: string }>()
  const navigate = useNavigate()
  const { getLocalizedString: t } = useContentContext()
  const [game, setGame] = useState<GameState | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [logs, setLogs] = useState<string[]>([])
  const [cryptoEvents, setCryptoEvents] = useState<CryptoEvent[]>([])
  const [selectedEvent, setSelectedEvent] = useState<CryptoEvent | null>(null)
  const [showPanel, setShowPanel] = useState(false)
  const [showRawLog, setShowRawLog] = useState(false)
  // D1 证明通道：当前手的证明留存（layers + settlement + chain 元数据）
  const [handProof, setHandProof] = useState<HandProofResponse | null>(null)

  const addLog = useCallback((msg: string) => {
    setLogs(prev => [...prev.slice(-19), `[${new Date().toLocaleTimeString()}] ${msg}`])
  }, [])

  const fetchState = useCallback(async () => {
    if (!gameId) return
    try {
      const state = await api.getGame(gameId)
      setGame(state)
      setError(null)
    } catch (e) {
      const msg = e instanceof Error ? e.message : t('gametable_failed-fetch-state')
      setError(msg)
      addLog(`Error: ${msg}`)
    } finally {
      setLoading(false)
    }
  }, [gameId, addLog])

  useEffect(() => {
    if (!gameId) return
    addLog('Connecting to game...')
    fetchState()

    gameWsClient.connect(gameId, {
      onMessage: (data) => {
        setGame(data)
        addLog(`[WS] State update: ${data.phase ?? 'Unknown'}`)
      },
      onCryptoEvent: (ev) => {
        setCryptoEvents(prev => [...prev.slice(-99), ev])
        logger.log('[CryptoEvent]', ev)
      },
      onError: () => addLog(t('gametable_ws-connection-error')),
      onClose: () => addLog(t('gametable_ws-disconnected-reconnecting')),
    })

    return () => {
      gameWsClient.disconnect()
    }
  }, [gameId, fetchState, addLog])

  // Esc 关闭 ZK 抽屉（与遮罩点击等价的键盘路径）
  useEffect(() => {
    if (!showPanel) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setShowPanel(false)
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [showPanel])

  // D1 证明通道：shuffle 事件流入/选中时拉取本手证明留存。
  // 先查当前手（hand_seq=0 = 进行中），无则回退最新终局记录。
  useEffect(() => {
    if (!gameId) return
    let cancelled = false
    ;(async () => {
      try {
        let resp: HandProofResponse | null = null
        try {
          resp = await api.getHandProof(gameId, 0)
          if (resp.layers.length === 0) resp = null
        } catch {
          resp = null
        }
        if (!resp) {
          const records = await api.getHandHistory(gameId)
          const latest = records[0]
          if (latest) {
            resp = await api.getHandProof(gameId, latest.handSeq)
          }
        }
        if (!cancelled) setHandProof(resp)
      } catch (e) {
        if (!cancelled) setHandProof(null)
        logger.log('[HandProof] unavailable:', e)
      }
    })()
    return () => {
      cancelled = true
    }
    // cryptoEvents.length：新一层洗牌验证落账后重拉（当前手层增量）
  }, [gameId, cryptoEvents.length])

  function formatPhase(phase: string) {
    return phase.replace(/([A-Z])/g, ' $1').trim()
  }

  if (loading) {
    return (
      <CenteredMessageContainer>
        <Spinner />
        <p>{t('gametable_loading')}</p>
        <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
      </CenteredMessageContainer>
    )
  }

  if (!game) {
    return (
      <CenteredMessageContainer>
        <AlertCircle size={48} strokeWidth={1} />
        <p>{error || t('gametable_not-found')}</p>
        <GradientButton onClick={() => navigate('/lobby')}>
          ← {t('gametable_back-lobby')}
        </GradientButton>
      </CenteredMessageContainer>
    )
  }

  const players = Array.isArray(game.players) ? game.players : []

  return (
    <MainContainer>
      <style>{`
        .zk-layout { display: flex; flex-direction: row; gap: 1.5rem; }
        .zk-left { flex: 0 0 60%; min-width: 0; }
        .zk-panel { position: relative; flex: 0 0 40%; min-width: 0; }
        .zk-drawer-btn { display: none; }
        .zk-panel-close { display: none; }
        .zk-backdrop { display: none; }
        @media (max-width: 1023px) {
          .zk-layout { flex-direction: column; gap: 1rem; }
          .zk-left { flex: 1 1 auto; width: 100%; }
          .zk-panel {
            position: fixed;
            top: 0; right: 0; bottom: 0;
            width: 380px; max-width: 85vw;
            background: var(--zk-panel-bg, #ffffff);
            z-index: var(--zk-drawer-z, 200);
            box-shadow: -8px 0 24px rgba(0,0,0,0.15);
            transform: translateX(100%);
            transition: transform 0.3s ease;
            overflow-y: auto;
            flex: none;
          }
          .zk-panel.is-open { transform: translateX(0); }
          .zk-drawer-btn { display: inline-flex; }
          .zk-panel-close { display: inline-flex; }
          .zk-backdrop { display: block; position: fixed; inset: 0; background: rgba(0,0,0,0.3); z-index: var(--zk-overlay-z, 150); border: none; padding: 0; cursor: pointer; }
        }
      `}</style>

      <TopBar>
        <SecondaryActionButton onClick={() => navigate('/lobby')}>
          <ArrowLeft size={16} /> {t('gametable_lobby')}
        </SecondaryActionButton>
        <TopBarCenter>
          <PhaseBadge>
            {formatPhase(game.phase)}
          </PhaseBadge>
          <PotDisplay>
            {t('gametable_pot')}{(game.pot ?? 0).toLocaleString()}
          </PotDisplay>
        </TopBarCenter>
        <TopBarRight>
          <DrawerToggleButton
            className="zk-drawer-btn"
            onClick={() => setShowPanel(v => !v)}
          >
            <Eye size={14} /> {showPanel ? t('gametable_collapse') : t('gametable_zk-visual')}
          </DrawerToggleButton>
          <SecondaryActionButton onClick={() => { setLogs([]); fetchState(); }}>
            <RefreshCw size={14} /> {t('gametable_refresh')}
          </SecondaryActionButton>
        </TopBarRight>
      </TopBar>

      <MainLayout className="zk-layout">
        <div className="zk-left">
          <TableCard>
            <GameTitle>
              {t('gametable_game')}{gameId}
            </GameTitle>

            <PlayersGrid>
              {players.map((p, i) => (
                <PlayerSeat
                  key={p.player_pk || p.id}
                  $active={game.current_player_index === i}
                >
                  <PlayerNameDisplay $folded={p.folded}>
                    <PlayerName name={p.name} />
                  </PlayerNameDisplay>
                  <PlayerChips>
                    ${p.chips.toLocaleString()}
                  </PlayerChips>
                  {p.current_bet > 0 && !p.folded && (
                    <PlayerBet>
                      Bet: ${p.current_bet.toLocaleString()}
                    </PlayerBet>
                  )}
                </PlayerSeat>
              ))}
            </PlayersGrid>

            <CommunityCardsSection>
              <SectionLabel>
                {t('gametable_community-cards')}{game.community_cards_revealed ?? 0}/{game.config?.community_cards ?? 5})
              </SectionLabel>
              <CardsRow>
                {Array.from({ length: game.config?.community_cards ?? 5 }).map((_, i) => {
                  const isRevealed = i < (game.community_cards_revealed ?? 0)
                  const cardValue = Array.isArray(game.community_cards) ? game.community_cards[i] : null
                  const revealed = !!(isRevealed && cardValue)
                  const isRed = !!(cardValue && (cardValue.includes('♥') || cardValue.includes('♦')))
                  return (
                    <CardDisplay key={i} $revealed={revealed} $isRed={isRed}>
                      {isRevealed && cardValue ? cardValue : '🂠'}
                    </CardDisplay>
                  )
                })}
              </CardsRow>
            </CommunityCardsSection>

            {game.winner && (
              <WinnerBanner>
                🏆 {t('gametable_winner')}{game.winner}
              </WinnerBanner>
            )}
          </TableCard>
        </div>

        {showPanel && (
        <button
          type="button"
          className="zk-backdrop"
          aria-label={t('gametable_zk-panel-close')}
          onClick={() => setShowPanel(false)}
        />
      )}

        <ZkPanel className={`zk-panel ${showPanel ? 'is-open' : ''}`}>
          <PanelInner>
            <PanelHeader>
              <div>
                <PanelTitle>
                  {t('gametable_zk-panel-title')}
                </PanelTitle>
                <PanelSubtitle>
                  {t('gametable_zk-panel-subtitle')}
                </PanelSubtitle>
              </div>
              <PanelCloseButton
                className="zk-panel-close"
                onClick={() => setShowPanel(false)}
                title={t('gametable_zk-panel-close')}
              >
                <X size={16} />
              </PanelCloseButton>
            </PanelHeader>

            <NarrationOverlay phase={game.phase} cryptoEventCount={cryptoEvents.length} />

            <div>
              <SectionLabelTight>
                {t('gametable_crypto-event-stream')}
              </SectionLabelTight>
              <EventStreamContainer>
                <CryptoEventStream
                  events={cryptoEvents}
                  onSelect={(ev) => setSelectedEvent(ev)}
                  selectedTimestamp={selectedEvent?.timestamp}
                />
              </EventStreamContainer>
            </div>

            <div>
              <SectionLabelDetail>
                {t('gametable_event-detail')}
              </SectionLabelDetail>
              {selectedEvent ? (
                <EventDetailColumn>
                  <EventTypeRow>
                    <EventTypeLabel>
                      {selectedEvent.event_type.toUpperCase()}
                    </EventTypeLabel>
                    <OnchainVerificationBadge
                      txDigest={selectedEvent.tx_digest}
                      verified={selectedEvent.verified}
                    />
                  </EventTypeRow>

                  {selectedEvent.event_type === 'shuffle' && (
                    <ShuffleProofVisualizer
                      layer={
                        handProof?.layers.find(
                          l =>
                            selectedEvent.player_pk &&
                            l.playerPk.toLowerCase() === selectedEvent.player_pk.toLowerCase(),
                        ) ?? handProof?.layers[handProof.layers.length - 1] ?? null
                      }
                      meta={{
                        aggregatePk: handProof?.aggregatePk ?? null,
                        deckSize: handProof?.deckSize ?? null,
                        totalRounds: handProof?.layers.length ?? null,
                      }}
                      settlement={handProof?.settlement ?? null}
                      chain={handProof?.chain ?? null}
                      verified={selectedEvent.verified}
                      failureReason={selectedEvent.message}
                    />
                  )}

                  {selectedEvent.event_type === 'reveal_token' && (
                    <RevealTokenCards>
                      {[0, 1, 2].map((offset) => (
                        <EncryptedCard
                          key={offset}
                          cardIndex={(selectedEvent.card_index ?? 0) + offset}
                          decryptedValue={null}
                          ciphertextPreview={null}
                          size="md"
                        />
                      ))}
                    </RevealTokenCards>
                  )}

                  {selectedEvent.event_type !== 'shuffle' && selectedEvent.event_type !== 'reveal_token' && selectedEvent.message && (
                    <EventMessage>
                      {selectedEvent.message}
                    </EventMessage>
                  )}
                </EventDetailColumn>
              ) : (
                <EmptyDetailPlaceholder>
                  {t('gametable_event-detail-empty')}
                </EmptyDetailPlaceholder>
              )}
            </div>
          </PanelInner>
        </ZkPanel>
      </MainLayout>

      <RawLogSection>
        <RawLogToggleButton onClick={() => setShowRawLog(v => !v)}>
          {showRawLog ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
          {t('gametable_raw-log')}
        </RawLogToggleButton>
        {showRawLog && (
          <RawLogContent>
            {logs.length === 0 ? (
              <EmptyLog>
                {t('gametable_no-events')}
              </EmptyLog>
            ) : (
              logs.map((log, i) => (
                <LogEntry key={i}>
                  {log}
                </LogEntry>
              ))
            )}
          </RawLogContent>
        )}
      </RawLogSection>

      {error && (
        <ErrorToast type="button" onClick={() => setError(null)}>
          <AlertCircle size={16} style={{ display: 'inline', verticalAlign: 'middle', marginRight: '0.3rem' }} />
          {error} {t('gametable_click-dismiss')}
        </ErrorToast>
      )}
    </MainContainer>
  )
}
