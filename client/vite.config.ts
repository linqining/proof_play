import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

// 游戏服务器地址（vite 代理目标）。解析顺序：
//   1. 进程环境 GAME_SERVER_URL（scripts/dev.sh 用 PORT=xxxx 拉起时同步导出）
//   2. .env 系文件的 GAME_SERVER_URL / VITE_SERVER_URI / VITE_SERVER_PORT
//      （loadEnv 读取 .env.development.local 等，无需 export）
//   3. 默认本地 9001。
// 注意 socket（clientConfig.socketURI）与 /api 代理必须指向同一台服务器，
// 否则会出现「页面能开、登录 500 / 牌桌重连」的劈叉状态。
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, __dirname, '');
  const gameServer =
    process.env.GAME_SERVER_URL ??
    env.GAME_SERVER_URL ??
    env.VITE_SERVER_URI ??
    (env.VITE_SERVER_PORT ? `http://127.0.0.1:${env.VITE_SERVER_PORT}` : undefined) ??
    'http://127.0.0.1:9001';

  return {
    plugins: [react()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, './src'),
      },
    },
    server: {
      proxy: {
        '/api': gameServer,
        '/socket.io': {
          target: gameServer,
          ws: true,
        },
      },
    },
    assetsInclude: ['**/*.wasm'],
  };
});
