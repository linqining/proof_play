import { css } from 'styled-components';

// 响应式断点：屏幕越窄，scale 越小。
// 在传入的 base scale 基础上，按断点逐级递减偏移：
//   1068px → +0.3
//   968px  → +0.25
//   868px  → +0.2
//   812px  → +0.15
//   668px  → +0.1
//   648px  → +0.05
//   568px  → +0   (使用 base 本身)
const RESPONSIVE_BREAKPOINTS = [
  { maxWidth: 1068, offset: 0.3 },
  { maxWidth: 968, offset: 0.25 },
  { maxWidth: 868, offset: 0.2 },
  { maxWidth: 812, offset: 0.15 },
  { maxWidth: 668, offset: 0.1 },
  { maxWidth: 648, offset: 0.05 },
  { maxWidth: 568, offset: 0 },
] as const;

// base 可以是静态数值（如 UIWrapper 的 0.5），也可以是读取组件 prop 的函数
// （如 PositionedUISlot 的 scale prop，缺省为 1）。
export const responsiveScale = <Props extends object>(
  base: number | ((props: Props) => string | number | undefined),
) => css<Props>`
  ${RESPONSIVE_BREAKPOINTS.map(({ maxWidth, offset }) => css<Props>`
    @media screen and (max-width: ${maxWidth}px) {
      transform: ${(props) => {
        const resolved = typeof base === 'function' ? base(props) : base;
        return `scale(${+(resolved ?? 1) + offset})`;
      }};
    }
  `)}
`;
