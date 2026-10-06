import { createGlobalStyle } from 'styled-components';

const GlobalStyles = createGlobalStyle`
  :root {
    box-sizing: border-box;
    font-size: ${(props) => props.theme.fonts.fontSizeRoot};
  }

  /* Cartridge Controller 的挂载层 #controller 是一个铺满视口的 div
     （pointer-events:auto），内部只有一个 0x0 的隐藏 keychain iframe——
     不可见却吞掉全页点击（登出/入座等按钮全部点不动）。让容器不再拦截；
     iframe 自身恢复 auto：空闲时 0x0 无面积不影响页面，弹窗打开时自身
     尺寸展开且可正常接收点击。 */
  #controller {
    pointer-events: none;
  }
  #controller iframe {
    pointer-events: auto;
  }

  *,
  *::before,
  *::after {
    margin: 0;
    padding: 0;
    scrollbar-width: thin;
    scrollbar-color: ${(props) => props.theme.colors.secondaryCta} ${(props) =>
  props.theme.colors.lightBg};
    box-sizing: inherit;
  }

  /* Use :focus-visible (keyboard-only) so touch users don't get rings.
     iOS / Android still get visual focus via :focus-visible when an
     external keyboard / assistive switch is connected. */
  *:focus-visible {
    outline: 2px solid ${(props) => props.theme.colors.primaryCta};
    outline-offset: 2px;
  }

  *::-webkit-scrollbar {
    width: 0.75rem;
    transition: background-color ${(props) => props.theme.timing.base} ${(props) =>
  props.theme.easing.easeStandard};
  }

  *::-webkit-scrollbar-track {
    background: ${(props) => props.theme.colors.lightBg};
  }

  *::-webkit-scrollbar-thumb {
    background-color: ${(props) => props.theme.colors.secondaryCta};
    border-radius: ${(props) => props.theme.radius.pill};
  }

  *::-webkit-scrollbar-thumb:hover {
    background-color: ${(props) => props.theme.colors.primaryCta};
  }

  ::-moz-selection {
    background: ${(props) => props.theme.colors.primaryCta};
    color: #ffffff;
  }

  ::selection {
    background: ${(props) => props.theme.colors.primaryCta};
    color: #ffffff;
  }

  html {
    /* Prevent rubber-band scroll chaining and accidental pull-to-refresh */
    overscroll-behavior-y: contain;
    /* Better touch behavior on iOS */
    -webkit-text-size-adjust: 100%;
    /* 平滑滚动（锚点跳转/程序滚动）。曾经的文档级 scroll-snap 已移除：
       hero 是 100dvh 首屏，上方还有条件渲染的资金横幅，snap 锚点几何
       随视口/内容变化经常不可达——Chrome 的重吸附会劫持程序滚动并在
       窗口 resize 后落在几十 px 的杂散偏移上（导航栏被顶出、内容错位，
       2026-09-06 两次线上排版事故同源）。各 section 保留
       scroll-margin-top 仅供锚点定位使用。 */
    scroll-behavior: smooth;
    /* 吸顶导航栏（theme.other.navHeight）悬于页面最上层——锚点定位
       与滚动统一预留导航高度 + 一档呼吸位。 */
    scroll-padding-top: calc(${(props) => props.theme.other.navHeight} + 0.5rem);
  }

  body {
    background-color: ${(props) => props.theme.colors.lightestBg};
    color: ${(props) => props.theme.colors.fontColorDark};
    font-family: ${(props) => props.theme.fonts.fontFamilySansSerif};
    line-height: ${(props) => props.theme.fonts.fontLineHeight};
    font-weight: 400;
    /* Prevent horizontal scroll bleed when fixed positioned UI overflows */
    overflow-x: hidden;
    /* Better touch behavior — disable double-tap zoom and other gestures */
    touch-action: manipulation;
    /* Safe area support (iPhone notch) */
    padding-top: ${(props) => props.theme.other.safeAreaTop};
    padding-bottom: ${(props) => props.theme.other.safeAreaBottom};
    padding-left: ${(props) => props.theme.other.safeAreaLeft};
    padding-right: ${(props) => props.theme.other.safeAreaRight};
  }

  /* 前庭障碍用户（WCAG 2.3.3）：系统声明减弱动态效果时，把装饰性
     动画/过渡收敛为瞬时完成。framer-motion 部分由 Providers 里的
     <MotionConfig reducedMotion="user"> 负责豁免 transform 动画。 */
  @media (prefers-reduced-motion: reduce) {
    *,
    *::before,
    *::after {
      animation-duration: 0.01ms !important;
      animation-iteration-count: 1 !important;
      transition-duration: 0.01ms !important;
      scroll-behavior: auto !important;
    }
  }

  hr {
    background-color: ${(props) => props.theme.colors.darkBg};
    height: 1px;
  }

  a {
    text-decoration: none;
    color: ${(props) => props.theme.colors.primaryCta};
    font-weight: bold;

    &:visited {
      color: ${(props) => props.theme.colors.primaryCta};
    }

    &:hover {
      color: ${(props) => props.theme.colors.primaryCtaDarker};
    }

    &:active {
      color: ${(props) => props.theme.colors.primaryCtaDarker};
    }
  }

  h1,
  h2,
  h3,
  h4,
  h5,
  h5 {
    font-family: ${(props) => props.theme.fonts.fontFamilySerif};
    font-weight: 400;
    margin-bottom: 1.5rem;
  }

  h1,
  .h1 {
    font-size: ${(props) => props.theme.fonts.fontSizeH1};
  }

  h2,
  .h2 {
    font-size: ${(props) => props.theme.fonts.fontSizeH2};
  }

  h3,
  .h3 {
    font-size: ${(props) => props.theme.fonts.fontSizeH3};
  }

  h4,
  .h4 {
    font-size: ${(props) => props.theme.fonts.fontSizeH4};
  }

  h5,
  .h5 {
    font-size: ${(props) => props.theme.fonts.fontSizeH5};
  }

  h6,
  .h6 {
    font-size: ${(props) => props.theme.fonts.fontSizeH6};
  }

  p {
    font-family: ${(props) => props.theme.fonts.fontFamilySansSerif};
    font-size: ${(props) => props.theme.fonts.fontSizeParagraph};
    font-weight: 400;
    line-height: ${(props) => props.theme.fonts.fontLineHeight};
    margin-bottom: 1rem;
  }

  input,
  textarea,
  button,
  div,
  select,
  a {
    -webkit-tap-highlight-color: rgba(0,0,0,0);
  }

  img {
    max-width: 100%;
  }

  @media screen and (max-width: 1023px) {
    :root {
      font-size: ${(props) => props.theme.fonts.fontSizeRootMobile};
    }
  }
`;

export default GlobalStyles;
