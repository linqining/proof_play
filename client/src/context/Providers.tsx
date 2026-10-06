import React from 'react';
import GlobalState from './global/GlobalState';
import AuthProvider from './auth/AuthProvider';
import LocaProvider from './localization/LocaProvider';
import ContentProvider from './content/ContentProvider';
import ModalProvider from './modal/ModalProvider';
import { ThemeProvider } from 'styled-components';
import theme from '../styles/theme';
import Normalize from '../styles/Normalize';
import GlobalStyles from '../styles/Global';
import { BrowserRouter } from 'react-router-dom';
import OfflineProvider from './offline/OfflineProvider';
import WebSocketProvider from './websocket/WebsocketProvider';
import PlayerProvider from './player/PlayerContext';
import GameState from './game/GameState';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MotionConfig } from 'framer-motion';
import {
  StarknetConfig,
  starkscan,
  jsonRpcProvider,
  injected,
} from '@starknet-react/core';
import { sepolia, mainnet } from '@starknet-react/chains';
import { starknetConfig } from '../starknet/config';

const queryClient = new QueryClient();

// Connector list（docs/design/SETTLEMENT_PRIVACY_PLAN.md Part C：Ready 唯一钱包）：
// Ready Wallet（注入钱包，STRK20 Wallet API 的官方测试基线）承担登录验证、
// swap 兑换、买入扣款、私密领取奖励。Ready 的注入 id 历史上是 'argentX'，
// 改版后可能注册 'ready'——两个都挂，LoginModal 按 available() 过滤。
// Cartridge 已整体移除：其 #controller 覆盖层曾拦截全页点击、买入后强制
// 弹初始化窗；游戏交互签名由 plain join + 服务器会话承担，无需 session key。
const connectors = [
  injected({ id: 'argentX' }),
  injected({ id: 'ready' }),
];

// Per-chain RPC endpoints：配置链（VITE_STARKNET_CHAIN_ID）的端点来自
// starknetConfig（VITE_STARKNET_RPC_URL[S]）——dev 模式指向本地 devnet
// http://127.0.0.1:5051，未配置时回退公共端点（行为与硬编码时代一致）。
// 非配置链保留公共端点（钱包在另一条链上时 dApp 读取仍可用）。
const DEFAULT_RPC_URLS: Record<string, string> = {
  [sepolia.id.toString()]: 'https://starknet-sepolia-rpc.publicnode.com',
  [mainnet.id.toString()]: 'https://starknet-rpc.publicnode.com',
};
const RPC_URLS: Record<string, string> = {
  ...DEFAULT_RPC_URLS,
  [starknetConfig.chainId]: starknetConfig.rpcUrl,
};

const provider = jsonRpcProvider({
  rpc: (chain) => {
    const url = RPC_URLS[chain.id.toString()];
    return url ? { nodeUrl: url } : null;
  },
});

// starknet-react 以数组首项为默认链：按构建时 chainId 排序，
// 主网构建默认 mainnet，否则 dApp 会反过来要求钱包切到 Sepolia。
const chains =
  starknetConfig.chainId === '0x534e5f4d41494e'
    ? [mainnet, sepolia]
    : [sepolia, mainnet];

interface ProvidersProps {
  children: React.ReactNode;
}

const Providers: React.FC<ProvidersProps> = ({ children }) => (
  <BrowserRouter future={{ v7_relativeSplatPath: true, v7_startTransition: true }}>
    <QueryClientProvider client={queryClient}>
      <StarknetConfig
        chains={chains}
        provider={provider}
        connectors={connectors}
        explorer={starkscan}
        autoConnect
      >
        <ThemeProvider theme={theme}>
          {/* reducedMotion="user"：跟随系统 prefers-reduced-motion，
              framer-motion 自动只保留 opacity 类过渡、跳过 transform 动画 */}
          <MotionConfig reducedMotion="user">
            <GlobalState>
              <LocaProvider>
                <ContentProvider>
                  <AuthProvider>
                    <ModalProvider>
                      <OfflineProvider>
                        <WebSocketProvider>
                          <PlayerProvider>
                            <GameState>
                              <Normalize />
                              <GlobalStyles />
                              {children}
                            </GameState>
                          </PlayerProvider>
                        </WebSocketProvider>
                      </OfflineProvider>
                    </ModalProvider>
                  </AuthProvider>
                </ContentProvider>
              </LocaProvider>
            </GlobalState>
          </MotionConfig>
        </ThemeProvider>
      </StarknetConfig>
    </QueryClientProvider>
  </BrowserRouter>
);

export default Providers;