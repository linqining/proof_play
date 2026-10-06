interface Config {
  isProduction: boolean;
  contentfulSpaceId: string | undefined;
  contentfulAccessToken: string | undefined;
  googleAnalyticsTrackingId: string | undefined;
  socketURI: string;
}

const config: Config = {
  isProduction: import.meta.env.PROD,
  contentfulSpaceId: import.meta.env.VITE_CONTENTFUL_SPACE_ID,
  contentfulAccessToken: import.meta.env.VITE_CONTENTFUL_ACCESS_TOKEN,
  googleAnalyticsTrackingId: import.meta.env.VITE_GOOGLE_ANALYTICS_TRACKING_ID,
  // dev 与 prod 统一支持 VITE_SERVER_URI 绝对地址（远程联调：游戏服务器
  // 与前端不同源时必须直连绝对地址）；未提供时 dev 回退到
  // http://<页面host>:VITE_SERVER_PORT（本地 9001，scripts/dev.sh 注入）。
  socketURI:
    import.meta.env.VITE_SERVER_URI ??
    (import.meta.env.PROD
      ? import.meta.env.VITE_SERVER_URI
      : `http://${window.location.hostname}:${import.meta.env.VITE_SERVER_PORT ?? 9001}/`),
};

export default config;

// ========== 游戏相关命名常量 ==========
// 1 chip = 1e15 wei of STRK (1 STRK = 1_000 chips)。与 starknet/config.ts 的
// WEI_PER_CHIP 一致；pSTRK/swap 已下线。
export const WEI_PER_CHIP = 1_000_000_000_000_000n;
// StandUp（离开牌桌）等待服务器响应的超时时间
export const STAND_UP_TIMEOUT_MS = 60_000;
// 进入 /play 后若 currentTable 一直为空，重试 join 的最大次数
export const MAX_JOIN_RETRIES = 3;
// 玩家操作（raise/call/fold/check/all-in）loading overlay 的超时兜底时间
export const ACTION_LOADING_TIMEOUT_MS = 30_000;
// join 重试之间的延迟
export const JOIN_RETRY_DELAY_MS = 1500;
// 踢出通知自动消失时间
export const KICK_NOTIFICATION_DISMISS_MS = 5000;
