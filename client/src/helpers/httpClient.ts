import axios from 'axios';
import { getToken } from './getToken';

const baseURL = '/api';

export const httpClient = axios.create({
  baseURL,
  headers: {
    'Content-Type': 'application/json',
  },
});

httpClient.interceptors.request.use(
  (config) => {
    const token = getToken();
    if (token) {
      config.headers['x-auth-token'] = token;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// 会话过期统一广播：API 返回 401 且**失败请求携带的 token 就是当前存储的
// token** 时，派发事件由 useAuth 清理登录态。
// 必须比对 token：页面加载时旧 token 的在途请求迟到 401，而自动重登已经
// 换了新 token 并登录成功——若不比对，迟到的 401 会把新登录态清掉（闪退）。
httpClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error?.response?.status === 401) {
      const failedToken: string | undefined =
        error?.config?.__zgameToken ?? error?.config?.headers?.['x-auth-token'];
      const current = getToken();
      if (failedToken && current && failedToken === current) {
        window.dispatchEvent(new Event('zgame:session-expired'));
      }
    }
    return Promise.reject(error);
  }
);

export default httpClient;
