export const FOLD = 'FOLD' as const;
export const CHECK = 'CHECK' as const;
export const CALL = 'CALL' as const;
export const RAISE = 'RAISE' as const;
export const WINNER = 'WINNER' as const;
export const FETCH_LOBBY_INFO = 'FETCH_LOBBY_INFO' as const;
export const RECEIVE_LOBBY_INFO = 'RECEIVE_LOBBY_INFO' as const;
export const PLAYERS_UPDATED = 'PLAYERS_UPDATED' as const;
export const JOIN_TABLE = 'JOIN_TABLE' as const;
export const TABLE_JOINED = 'TABLE_JOINED' as const;
export const LEAVE_TABLE = 'LEAVE_TABLE' as const;
export const LEAVE_DEFERRED = 'LEAVE_DEFERRED' as const;
export const TABLE_LEFT = 'TABLE_LEFT' as const;
export const TABLES_UPDATED = 'TABLES_UPDATED' as const;
export const TABLE_UPDATED = 'TABLE_UPDATED' as const;
export const TABLE_MESSAGE = 'TABLE_MESSAGE' as const;
export const REBUY = 'REBUY' as const;
export const SIT_DOWN = 'SIT_DOWN' as const;
export const SIT_DOWN_V2 = 'SIT_DOWN_V2' as const;
export const STAND_UP = 'STAND_UP' as const;
export const SITTING_OUT = 'SITTING_OUT' as const;
export const SITTING_IN = 'SITTING_IN' as const;
export const DISCONNECT = 'DISCONNECT' as const;
export const SHUFFLE_SUBMIT = 'SHUFFLE_SUBMIT' as const;
export const SHUFFLE_NOTICE = 'SHUFFLE_NOTICE' as const;
export const REVEAL_SUBMIT = 'REVEAL_SUBMIT' as const;
export const REVEAL_NOTICE = 'REVEAL_NOTICE' as const;
export const RECONSTRUCT_INITIATE = 'RECONSTRUCT_INITIATE' as const;
export const RECONSTRUCT_NOTICE = 'RECONSTRUCT_NOTICE' as const;
export const RECONSTRUCT_VOTE = 'RECONSTRUCT_VOTE' as const;
export const RECONSTRUCT_SUBMIT = 'RECONSTRUCT_SUBMIT' as const;
export const RECONSTRUCT_RESULT = 'RECONSTRUCT_RESULT' as const;
export const HAND_REVEAL_RESULT = 'HAND_REVEAL_RESULT' as const;
export const COMMUNITY_REVEAL_RESULT = 'COMMUNITY_REVEAL_RESULT' as const;
export const REDEAL_NOTICE = 'REDEAL_NOTICE' as const;
export const REDEAL_RESULT = 'REDEAL_RESULT' as const;
export const REDEAL_REQUEST = 'REDEAL_REQUEST' as const;

// ZK 密码学事件（与后端 actions::CRYPTO_EVENT 对应的 socket.io 事件名）
export const CRYPTO_EVENT = 'crypto_event' as const;

// D4 结算终局事件（settled / refused / failed + hand_binding + 区块/gas；
// 与后端 actions::SETTLEMENT_RESULT 对应的 socket.io 事件名）
export const SETTLEMENT_RESULT = 'settlement_result' as const;

// 后端在 on-chain 模式下 emit 的签名请求事件，前端收到后执行 sponsored tx 签名流程
export const ACTION_SIGNING_REQUEST = 'action_signing_request' as const;

