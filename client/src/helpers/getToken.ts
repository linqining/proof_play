/**
 * 统一的 token 访问器
 * 所有需要读取 auth token 的地方都应使用此函数，避免散落的 localStorage.getItem('token')
 */
export function getToken(): string | null {
  return localStorage.getItem('token');
}

/**
 * 设置 auth token
 */
export function setToken(token: string | null): void {
  if (token) {
    localStorage.setItem('token', token);
  } else {
    localStorage.removeItem('token');
  }
}
