import { GameState } from './secretPokerClient'
import { CryptoEvent } from '../types/game'
import { logger } from '../helpers/logger'

// WS 消息联合类型：GameState（无顶层 type 字段）或 CryptoEvent（type === 'crypto_event'）
export type CryptoMessage = GameState | CryptoEvent

type MessageHandler = (data: GameState) => void
type CryptoEventHandler = (data: CryptoEvent) => void
type ErrorHandler = (error: Event) => void
type CloseHandler = () => void

// 类型守卫：判断 WS 消息是否为 crypto_event
function isCryptoEvent(msg: CryptoMessage): msg is CryptoEvent {
  return (msg as CryptoEvent).type === 'crypto_event'
}

export class GameWsClient {
  private ws: WebSocket | null = null
  private gameId: string = ''
  private baseUrl: string = ''
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private onMessage: MessageHandler | null = null
  private onCryptoEvent: CryptoEventHandler | null = null
  private onError: ErrorHandler | null = null
  private onClose: CloseHandler | null = null
  private intentionalClose = false

  constructor(baseUrl?: string) {
    this.baseUrl = baseUrl || ''
  }

  connect(gameId: string, handlers: {
    onMessage: MessageHandler
    onCryptoEvent?: CryptoEventHandler
    onError?: ErrorHandler
    onClose?: CloseHandler
  }) {
    this.disconnect()
    this.gameId = gameId
    this.onMessage = handlers.onMessage
    this.onCryptoEvent = handlers.onCryptoEvent || null
    this.onError = handlers.onError || (() => {})
    this.onClose = handlers.onClose || (() => {})
    this.intentionalClose = false

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = this.baseUrl || `${window.location.host}`
    const url = `${protocol}//${host}/api/games/${gameId}/ws`

    this.ws = new WebSocket(url)

    this.ws.onopen = () => {
      logger.log(`[WS] Connected to game ${gameId}`)
    }

    this.ws.onmessage = (event) => {
      try {
        const parsed = JSON.parse(event.data) as CryptoMessage
        // 区分两种消息：crypto_event 有顶层 type 字段，GameState 没有
        if (isCryptoEvent(parsed)) {
          if (this.onCryptoEvent) {
            this.onCryptoEvent(parsed)
          } else {
            // 未注册 crypto handler 时仅打印日志，保持向后兼容
            logger.log('[WS] Crypto event (no handler):', parsed)
          }
        } else {
          // 默认当作 GameState 处理
          if (this.onMessage) {
            this.onMessage(parsed as GameState)
          }
        }
      } catch (e) {
        logger.error(`[WS] Failed to parse message:`, e)
      }
    }

    this.ws.onerror = (event) => {
      if (this.onError) this.onError(event)
    }

    this.ws.onclose = () => {
      if (!this.intentionalClose && this.onClose) {
        this.onClose()
      }
      this.scheduleReconnect()
    }
  }

  send(data: object) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data))
    }
  }

  disconnect() {
    this.intentionalClose = true
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
    if (this.ws) {
      this.ws.close(1000, 'Client disconnecting')
      this.ws = null
    }
  }

  get isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN
  }

  private scheduleReconnect() {
    if (this.intentionalClose) return
    this.reconnectTimer = setTimeout(() => {
      if (!this.intentionalClose && !this.isConnected) {
        this.connect(this.gameId, {
          onMessage: this.onMessage!,
          onCryptoEvent: this.onCryptoEvent ?? undefined,
          onError: this.onError!,
          onClose: this.onClose!,
        })
      }
    }, 3000)
  }
}

export const gameWsClient = new GameWsClient()
