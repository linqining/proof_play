import 'styled-components';

export interface ThemeColors {
  // === Primary Brand Colors ===
  primaryCta: string;
  primaryCtaDarker: string;
  secondaryCta: string;
  secondaryCtaDarker: string;
  secondaryCtaDarkest: string;

  // === Brand Purple (formerly hardcoded #764ba2) ===
  brandPurple: string;
  brandPurpleHover: string;
  brandPurpleLight: string;
  brandPurpleRgb: string; // '118, 75, 162' (for rgba())
  brandPurpleAlpha04: string; // rgba(118,75,162,0.04)
  brandPurpleAlpha10: string; // rgba(118,75,162,0.10)
  brandPurpleAlpha15: string; // rgba(118,75,162,0.15)
  brandGradient: string;
  brandGradientHover: string;

  // === Brand Indigo (secondary CTA #667eea) ===
  brandIndigo: string;     // #667eea
  brandIndigoRgb: string;  // '102, 126, 234' (for rgba())
  brandIndigoAlpha06: string; // rgba(102,126,234,0.06)
  brandIndigoAlpha10: string; // rgba(102,126,234,0.10)
  brandIndigoAlpha12: string; // rgba(102,126,234,0.12)
  brandIndigoAlpha15: string; // rgba(102,126,234,0.15)
  brandIndigoAlpha20: string; // rgba(102,126,234,0.20)
  brandIndigoAlpha25: string; // rgba(102,126,234,0.25)
  brandIndigoAlpha35: string; // rgba(102,126,234,0.35)

  // === Brand Blue ===
  brandBlue: string;
  brandBlueAlpha08: string;
  brandBlueAlpha20: string;

  // === Backgrounds ===
  darkBg: string;
  lightBg: string;
  lightestBg: string;

  // === Font Colors ===
  fontColorLight: string;
  fontColorDark: string;
  fontColorDarkLighter: string;
  mutedText: string;       // #475569
  softText: string;        // #64748b
  softerText: string;      // #94a3b8

  // === Surfaces (glass / muted) ===
  surfaceGlass: string;    // rgba(255,255,255,0.95)
  surfaceMuted: string;    // rgba(241,245,249,0.8)
  surfaceSubtle: string;   // rgba(241,245,249,0.9)
  surfaceMutedPlain: string; // #f1f5f9
  surfaceMutedPlainRgb: string; // '241, 245, 249' (for rgba())

  // === Borders ===
  borderSubtle: string;    // rgba(226,232,240,0.9)
  borderSubtleRgb: string; // '226, 232, 240'
  borderMuted: string;     // rgba(203,213,225,0.8)
  borderMutedRgb: string;  // '203, 213, 225'

  // === Status Colors ===
  success: string;         // #10b981
  successStrong: string;   // #059669
  successAlpha06: string;  // rgba(16,185,129,0.06)
  successAlpha12: string;  // rgba(16,185,129,0.12)
  successAlpha20: string;  // rgba(16,185,129,0.20)
  danger: string;          // #ef4444
  dangerStrong: string;    // #dc2626
  dangerLighter: string;   // hsl(0,100%,56%) — legacy
  dangerBase: string;      // hsl(0,100%,46%) — legacy
  dangerAlpha06: string;   // rgba(239,68,68,0.06)
  dangerAlpha95: string;   // rgba(239,68,68,0.95)
  warning: string;         // #f59e0b
  warningDark: string;     // #b45309
  gold: string;            // #ffd700
  goldDarker: string;      // #d4a843
  goldChip: string;        // #f7f2dc (chip background)
  goldChipAlpha80: string; // rgba(247,242,220,0.8) (empty seat)
  info: string;            // #3b82f6
  infoCyan: string;        // #06b6d4

  // === Other legacy ===
  playingCardBg: string;
  playingCardBgLighter: string;
  goldenColorDarker: string;
  goldenColor: string;
  dangerColorLighter: string;
  dangerColor: string;

  // === Pill (chip) colors ===
  pillDark: string;        // #282215
  pillDarkText: string;    // #fffefc
  pillBorder: string;      // #5b96b5
  pillBackgroundLight: string; // #245069

  // === Disabled ===
  disabled: string;        // rgba(0,0,0,0.3) — used for greyed state
  disabledText: string;    // #94a3b8

  // === Tooltip ===
  tooltipBg: string;       // #1e293b
  tooltipText: string;     // #f8fafc
}

interface ThemeFonts {
  fontFamilySerif: string;
  fontFamilySansSerif: string;
  fontLineHeight: string;
  fontSizeRoot: string;
  fontSizeRootMobile: string;
  fontSizeH1: string;
  fontSizeH2: string;
  fontSizeH3: string;
  fontSizeH4: string;
  fontSizeH5: string;
  fontSizeH6: string;
  fontSizeParagraph: string;
}

interface ThemeRadius {
  pill: string;
  xxl: string;
  xl: string;
  lg: string;
  md: string;
  sm: string;
  xs: string;
  xxs: string;
}

interface ThemeFontSize {
  xxs: string;
  xs: string;
  sm: string;
  base: string;
  md: string;
  lg: string;
  xl: string;
  '2xl': string;
}

interface ThemeTiming {
  fast: string;
  base: string;
  slow: string;
  emphasis: string;
  critical: string;
}

interface ThemeEasing {
  easeOutCubic: string;
  easeStandard: string;
}

interface ThemeZIndex {
  base: number;        // 0
  hidden: number;      // -1
  watermark: number;   // -99
  backdrop: number;    // 100
  nav: number;         // 300
  overlay: number;     // 400
  modal: number;       // 500
  drawer: number;      // 600
  popover: number;     // 700
  toast: number;       // 800
  loading: number;     // 900
  critical: number;    // 1000
}

interface ThemeBreakpoints {
  sm: number;          // 480
  md: number;          // 768
  lg: number;          // 1024
  xl: number;          // 1280
  /** 媒体查询字符串（min-width） */
  up: { sm: string; md: string; lg: string; xl: string };
  /** 媒体查询字符串（max-width） */
  down: { sm: string; md: string; lg: string; xl: string };
}

interface ThemeOther {
  stdBorderRadius: string;
  cardDropShadow: string;
  navMenuDropShadow: string;
  /** 吸顶导航栏高度——fixed 定位后所有页面顶部内容/吸附锚点的
   * 唯一避让依据（Navbar min-height 与此保持一致）。 */
  navHeight: string;
  /** iOS safe-area helpers */
  safeAreaTop: string;
  safeAreaBottom: string;
  safeAreaLeft: string;
  safeAreaRight: string;
}

export interface Theme {
  colors: ThemeColors;
  fonts: ThemeFonts;
  radius: ThemeRadius;
  fontSize: ThemeFontSize;
  timing: ThemeTiming;
  easing: ThemeEasing;
  zIndex: ThemeZIndex;
  breakpoints: ThemeBreakpoints;
  other: ThemeOther;
}

declare module 'styled-components' {
  // eslint-disable-next-line @typescript-eslint/no-empty-interface
  export interface DefaultTheme extends Theme {}
}

const up = (bp: number) => `@media (min-width: ${bp}px)`;
const down = (bp: number) => `@media (max-width: ${bp - 1}px)`;

// ============================================================================
// 账簿 Ledger 主题（design/figma/tokens.json paper 逐字同源）。
//
// 映射原则：保持既有 Theme 接口形状（全部存量 styled-components 零改动编译），
// 把牌桌稿/客户端稿的账簿令牌映射到语义槽位：
//   primaryCta   紫 #4f46e5 → felt 翡翠 #0b6b45（一屏只允许一个实底）
//   brandGradient → felt 实底（账簿无渐变）
//   surfaceGlass → cd 纸白 #fffdf7（零玻璃拟态）
//   radius 2rem  → 3px/6px 方角
//   success/danger/warning/info → felt/bad/amb/play 四个语义色
//   gold（筹码）→ real 托管金（--real 只用于托管/真实资产语义）
// 零 webfont：system-ui 栈 + ui-monospace（tokens.json font.ui / font.mono）。
// ============================================================================
const theme: Theme = {
  // Colors
  colors: {
    // Primary Brand Colors（felt = 确认/主操作，唯一实底色）
    primaryCta: '#0b6b45',
    primaryCtaDarker: '#095a3a',
    secondaryCta: '#15507f',
    secondaryCtaDarker: '#10416a',
    secondaryCtaDarkest: '#0b3352',
    // Brand Purple → felt 语义（渐变槽位 = 实底；账簿零渐变）
    brandPurple: '#0b6b45',
    brandPurpleHover: '#0d7a4f',
    brandPurpleLight: '#a8c8b6',
    brandPurpleRgb: '11, 107, 69',
    brandPurpleAlpha04: 'rgba(11, 107, 69, 0.04)',
    brandPurpleAlpha10: 'rgba(11, 107, 69, 0.10)',
    brandPurpleAlpha15: 'rgba(11, 107, 69, 0.15)',
    brandGradient: '#0b6b45',
    brandGradientHover: '#0d7a4f',
    // Brand Indigo → play 进行中语义
    brandIndigo: '#15507f',
    brandIndigoRgb: '21, 80, 127',
    brandIndigoAlpha06: 'rgba(21, 80, 127, 0.06)',
    brandIndigoAlpha10: 'rgba(21, 80, 127, 0.10)',
    brandIndigoAlpha12: 'rgba(21, 80, 127, 0.12)',
    brandIndigoAlpha15: 'rgba(21, 80, 127, 0.15)',
    brandIndigoAlpha20: 'rgba(21, 80, 127, 0.20)',
    brandIndigoAlpha25: 'rgba(21, 80, 127, 0.25)',
    brandIndigoAlpha35: 'rgba(21, 80, 127, 0.35)',
    // Brand Blue → play
    brandBlue: '#15507f',
    brandBlueAlpha08: 'rgba(21, 80, 127, 0.08)',
    brandBlueAlpha20: 'rgba(21, 80, 127, 0.20)',
    // Backgrounds（pg / cd / cd-2）
    darkBg: '#eae5d9',
    lightBg: '#f5f2ea',
    lightestBg: '#fffdf7',
    // Font Colors（ink / ink-2 / ink-3）
    fontColorLight: '#f5f2ea',
    fontColorDark: '#14130f',
    fontColorDarkLighter: '#4b4840',
    mutedText: '#4b4840',
    softText: '#5f5b50',
    softerText: '#8a8578',
    // Surfaces（纸白，零玻璃）
    surfaceGlass: '#fffdf7',
    surfaceMuted: 'rgba(248, 245, 236, 0.9)',
    surfaceSubtle: 'rgba(248, 245, 236, 0.95)',
    surfaceMutedPlain: '#f8f5ec',
    surfaceMutedPlainRgb: '248, 245, 236',
    // Borders（rl / rl-2）
    borderSubtle: '#ddd6c6',
    borderSubtleRgb: '221, 214, 198',
    borderMuted: '#c3bba7',
    borderMutedRgb: '195, 187, 167',
    // Status Colors（felt / bad / amb / play 语义）
    success: '#0b6b45',
    successStrong: '#095a3a',
    successAlpha06: 'rgba(11, 107, 69, 0.06)',
    successAlpha12: '#e6efe8',
    successAlpha20: 'rgba(11, 107, 69, 0.20)',
    danger: '#a83226',
    dangerStrong: '#8f2a20',
    dangerLighter: '#c4473a',
    dangerBase: '#a83226',
    dangerAlpha06: 'rgba(168, 50, 38, 0.06)',
    dangerAlpha95: 'rgba(168, 50, 38, 0.95)',
    warning: '#825510',
    warningDark: '#6b450d',
    gold: '#7d5308',
    goldDarker: '#6a4607',
    goldChip: '#f6ebd4',
    goldChipAlpha80: 'rgba(246, 235, 212, 0.8)',
    info: '#15507f',
    infoCyan: '#15507f',
    // Other legacy（牌面纸卡）
    playingCardBg: '#fffdf7',
    playingCardBgLighter: '#fffdf7',
    goldenColorDarker: '#6a4607',
    goldenColor: '#7d5308',
    dangerColorLighter: '#c4473a',
    dangerColor: '#a83226',
    // Pill（chip）→ 墨底等宽
    pillDark: '#14130f',
    pillDarkText: '#f5f2ea',
    pillBorder: '#c3bba7',
    pillBackgroundLight: '#4b4840',
    // Disabled
    disabled: 'rgba(20, 19, 15, 0.12)',
    disabledText: '#8a8578',
    // Tooltip（墨底白字反转）
    tooltipBg: '#14130f',
    tooltipText: '#f5f2ea',
  },
  // Fonts（零 webfont：system-ui 栈；等宽走 fontMono）
  fonts: {
    fontFamilySerif: "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', Roboto, Arial, sans-serif",
    fontFamilySansSerif: "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', Roboto, Arial, sans-serif",
    // Use clamp() so portrait phones don't blow up H1
    fontLineHeight: '1.55',
    fontSizeRoot: '1em',
    fontSizeRootMobile: '0.9em',
    fontSizeH1: 'clamp(1.6rem, 4.5vmin + 1rem, 2.5rem)',
    fontSizeH2: 'clamp(1.4rem, 4vmin + 0.9rem, 2.1rem)',
    fontSizeH3: 'clamp(1.25rem, 3.5vmin + 0.85rem, 1.85rem)',
    fontSizeH4: 'clamp(1.15rem, 3vmin + 0.8rem, 1.6rem)',
    fontSizeH5: 'clamp(1.05rem, 2.5vmin + 0.75rem, 1.4rem)',
    fontSizeH6: 'clamp(1rem, 2vmin + 0.7rem, 1.2rem)',
    fontSizeParagraph: '1.2rem',
  },
  // Radius（账簿方角：3px / 6px；pill 保留给徽章胶囊）
  radius: {
    pill: '2px',
    xxl: '6px',
    xl: '6px',
    lg: '6px',
    md: '3px',
    sm: '3px',
    xs: '2px',
    xxs: '2px',
  },
  // Font size scale
  fontSize: {
    xxs: '0.7rem',
    xs: '0.75rem',
    sm: '0.85rem',
    base: '1rem',
    md: '1.1rem',
    lg: '1.3rem',
    xl: '1.5rem',
    '2xl': '1.6rem',
  },
  // Animation timing tokens
  timing: {
    fast: '0.2s',
    base: '0.3s',
    slow: '0.4s',
    emphasis: '0.6s',
    critical: '1s',
  },
  // Easing curves
  easing: {
    easeOutCubic: 'cubic-bezier(0.22, 1, 0.36, 1)',
    easeStandard: 'ease',
  },
  // Z-index scale
  zIndex: {
    base: 0,
    hidden: -1,
    watermark: -99,
    backdrop: 100,
    nav: 300,
    overlay: 400,
    modal: 500,
    drawer: 600,
    popover: 700,
    toast: 800,
    loading: 900,
    critical: 1000,
  },
  // Breakpoints
  breakpoints: {
    sm: 480,
    md: 768,
    lg: 1024,
    xl: 1280,
    up: {
      sm: up(480),
      md: up(768),
      lg: up(1024),
      xl: up(1280),
    },
    down: {
      sm: down(480),
      md: down(768),
      lg: down(1024),
      xl: down(1280),
    },
  },
  // Other styles（零大圆角；阴影降到账簿级 1px 底线）
  other: {
    stdBorderRadius: '3px',
    cardDropShadow: '0 1px 0 rgba(20, 19, 15, 0.04)',
    navMenuDropShadow: '-6px 0 24px rgba(20, 19, 15, 0.06)',
    navHeight: '5.5rem',
    safeAreaTop: 'env(safe-area-inset-top, 0px)',
    safeAreaBottom: 'env(safe-area-inset-bottom, 0px)',
    safeAreaLeft: 'env(safe-area-inset-left, 0px)',
    safeAreaRight: 'env(safe-area-inset-right, 0px)',
  },
};

/** 账簿等宽字体（哈希/地址/金额专用；tokens.json font.mono 同源）。 */
export const fontMono =
  "ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace";

export default theme;
