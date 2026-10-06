import styled, { keyframes, css } from 'styled-components';
import type { ThemeColors } from '../styles/theme';
import { motion } from 'framer-motion';

/* ===== Keyframes ===== */

const particleFloat = keyframes`
  0% { transform: translateY(100vh); opacity: 0; }
  10% { opacity: 1; }
  90% { opacity: 1; }
  100% { transform: translateY(-10vh); opacity: 0; }
`;

const orbFloat = keyframes`
  0%, 100% { transform: translate(0, 0); }
  50% { transform: translate(30px, -20px); }
`;

const gradientShift = keyframes`
  0%, 100% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
`;

/* ===== Particles ===== */

export const Particles = styled.div`
  position: fixed;
  inset: 0;
  pointer-events: none;
  z-index: 0;
  overflow: hidden;
`;

export const Particle = styled.div`
  position: absolute;
  width: 2px;
  height: 2px;
  background: ${({ theme }) => theme.colors.brandIndigoAlpha12};
  border-radius: 50%;
  animation: ${particleFloat} linear infinite;
`;

/* ===== Buttons ===== */

export const BtnPrimary = styled(motion.button)<{ $lg?: boolean }>`
  background: ${({ theme }) => theme.colors.primaryCta};
  color: #fffdf7;
  border: none;
  padding: 0.65rem 1.6rem;
  border-radius: ${({ theme }) => theme.radius.sm};
  font-weight: 500;
  font-size: 0.9rem;
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  cursor: pointer;
  transition:
    box-shadow 0.35s cubic-bezier(0.22, 1, 0.36, 1),
    transform 0.35s cubic-bezier(0.22, 1, 0.36, 1);
  box-shadow: ${({ theme }) => theme.other.cardDropShadow};

  &:hover:not(:disabled) {
    box-shadow: 0 6px 24px ${({ theme }) => theme.colors.brandIndigoAlpha35};
  }
  &:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  ${(props) =>
    props.$lg &&
    css`
      padding: 0.85rem 2rem;
      font-size: 0.95rem;
    `}
`;

export const BtnSecondary = styled(motion.button)<{ $lg?: boolean }>`
  background: transparent;
  color: ${({ theme }) => theme.colors.mutedText};
  border: 1px solid rgba(${({ theme }) => theme.colors.borderSubtleRgb}, 0.35);
  padding: 0.65rem 1.6rem;
  border-radius: 10px;
  font-weight: 400;
  font-size: 0.9rem;
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  cursor: pointer;
  transition:
    border-color 0.35s cubic-bezier(0.22, 1, 0.36, 1),
    color 0.35s cubic-bezier(0.22, 1, 0.36, 1),
    background-color 0.35s cubic-bezier(0.22, 1, 0.36, 1);

  &:hover:not(:disabled) {
    border-color: rgba(${({ theme }) => theme.colors.borderSubtleRgb}, 0.6);
    color: ${(props) => props.theme.colors.fontColorDark};
  }
  ${(props) =>
    props.$lg &&
    css`
      padding: 0.85rem 2rem;
      font-size: 0.95rem;
    `}
`;

/* ===== Home ===== */

export const Home = styled.div`
  min-height: 100dvh;
  position: relative;
  background: ${(props) => props.theme.colors.lightestBg};
  color: ${(props) => props.theme.colors.fontColorDark};
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  /* 普通块级流布局：文档级 scroll-snap 已移除（hero 首屏 + 条件横幅
     让 snap 锚点几何不可达，Chrome 重吸附会劫持滚动——见 Global.ts），
     页面走浏览器原生滚动链。 */
  overflow-x: clip;
`;

/* 未领取资金横幅槽位：吸顶导航栏（theme.other.navHeight）悬于页面最
   上层，槽位作为 S.Home 的直接子元素承担两件事——
   1. margin-top 让出导航高度（横幅首屏不被盖住）；
   2. sticky 吸附：滚动时横幅贴在导航栏正下方不消失（"处理前一直
      看得见"）。sticky 只能在父容器范围内吸附，所以必须放在横跨
      整页的槽位上、而不是横幅组件自己的小 wrapper 里。
   横幅组件因未登录/已关闭/无筹码返回 null 时，:empty 归零边距避免
   首屏出现幻影空隙。 */
export const FundsBannerSlot = styled.div`
  position: sticky;
  top: calc(${(props) => props.theme.other.navHeight} + 0.5rem);
  margin-top: calc(${(props) => props.theme.other.navHeight} + 0.75rem);
  /* 高于各 section 的 z-index(1-2)，低于侧边圆点(50)/导航栏(300) */
  z-index: 3;

  &:empty {
    margin-top: 0;
  }
`;

/* ===== Hero ===== */

export const Hero = styled.section`
  position: relative;
  min-height: 100dvh;
  display: flex;
  align-items: center;
  justify-content: center;
  overflow: hidden;
  padding: calc(${(props) => props.theme.other.navHeight} + 1.5rem) 2rem 2rem;
  scroll-margin-top: 5rem;

  @media (max-width: 1023px) {
    padding: 1.5rem;
    padding-top: calc(${(props) => props.theme.other.navHeight} + 1.5rem);
    padding-bottom: 4rem;
  }
`;

export const HeroBg = styled.div`
  position: absolute;
  inset: 0;
`;

// 账簿硬规则「零渐变」：hero 背景为平色纸白（原径向光晕废除）
export const HeroGradient = styled.div`
  position: absolute;
  inset: 0;
  background: ${({ theme }) => theme.colors.lightBg};
`;

export const HeroOrb = styled.div<{ $variant: 1 | 2 }>`
  position: absolute;
  border-radius: 50%;
  filter: blur(120px);
  opacity: 0.25;
  animation: ${orbFloat} 12s ease-in-out infinite;

  ${(props) =>
    props.$variant === 1 &&
    css`
      width: 500px;
      height: 500px;
      background: ${({ theme }) => theme.colors.brandIndigoAlpha15};
      top: 10%;
      left: 10%;
    `}
  ${(props) =>
    props.$variant === 2 &&
    css`
      width: 400px;
      height: 400px;
      background: ${({ theme }) => theme.colors.brandPurpleAlpha10};
      bottom: 20%;
      right: 15%;
      animation-delay: -6s;
    `}
`;

export const HeroContent = styled(motion.div)`
  position: relative;
  max-width: 800px;
  text-align: center;
  z-index: 1;
  padding-top: 2rem;
`;

// 账簿还原（design/client C1 .badge）：felt 方角章，非胶囊
export const HeroBadge = styled(motion.div)`
  display: inline-flex;
  align-items: center;
  gap: 8px;
  background: ${({ theme }) => theme.colors.successAlpha12};
  border: 1px solid ${({ theme }) => theme.colors.successAlpha20};
  color: ${({ theme }) => theme.colors.success};
  padding: 4px 10px;
  border-radius: 2px;
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 10.5px;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  margin-bottom: 2rem;
`;

export const HeroTitle = styled(motion.h1)`
  font-size: clamp(3.2rem, 7vw, 5.5rem);
  line-height: 1.1;
  font-weight: 700;
  margin-bottom: 1.5rem;
  letter-spacing: -0.03em;

  @media (max-width: 1023px) {
    font-size: clamp(2.2rem, 8vw, 3.5rem);
  }
`;

// 账簿硬规则「零渐变/零发光」：hero 强调行改翡翠实色（原蓝绿渐变文字废除）
export const GradientText = styled.span`
  color: ${({ theme }) => theme.colors.success};
`;

export const HeroDesc = styled(motion.p)`
  font-size: 1.15rem;
  color: ${({ theme }) => theme.colors.mutedText};
  max-width: 520px;
  margin: 0 auto 2.5rem;
  line-height: 1.7;
  font-weight: 400;

  @media (max-width: 1023px) {
    font-size: 1rem;
  }
`;

export const HeroActions = styled(motion.div)`
  display: flex;
  gap: 0.75rem;
  justify-content: center;
  flex-wrap: wrap;
  margin-bottom: 4rem;
`;

export const HeroStats = styled(motion.div)`
  display: flex;
  justify-content: center;
  gap: 3.5rem;
  flex-wrap: wrap;

  @media (max-width: 1023px) {
    gap: 1.5rem;
  }
`;

export const Stat = styled.div`
  text-align: center;
  padding: 0.5rem 1rem;
`;

export const StatValue = styled.span`
  display: block;
  font-size: 1.2rem;
  font-weight: 600;
  color: ${(props) => props.theme.colors.fontColorDark};
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-variant-numeric: tabular-nums;
  margin-bottom: 0.3rem;
`;

export const StatLabel = styled.span`
  font-size: 0.7rem;
  color: ${({ theme }) => theme.colors.softerText};
  text-transform: uppercase;
  letter-spacing: 0.12em;
`;

export const StatDivider = styled.div`
  width: 1px;
  background: ${({ theme }) => theme.colors.borderSubtle};
  align-self: stretch;
  margin: 0.5rem 0;

  @media (max-width: 1023px) {
    display: none;
  }
`;

/* ===== Sections ===== */

export const Section = styled.section<{ $variant?: 'default' | 'alt' | 'how' | 'cta' }>`
  padding: 5.5rem 2rem 4rem;
  position: relative;
  z-index: 1;
  scroll-margin-top: 5rem;
  min-height: 100dvh;
  display: flex;
  flex-direction: column;
  justify-content: center;

  ${(props) =>
    props.$variant === 'alt' &&
    css`
      background: ${props.theme.colors.lightestBg};
    `}
  ${(props) =>
    props.$variant === 'how' &&
    css`
      background: ${props.theme.colors.lightBg};

      /* Real felt texture overlay (Transparent Textures, ~129KB) gives
         the 'how it works' section the look of a poker table surface.
         The pseudo-element ::before keeps the texture below all card
         content (which sits in the normal flow), and pointer-events
         none ensures it never intercepts clicks. */
      &::before {
        content: '';
        position: absolute;
        inset: 0;
        background-image: url('/textures/felt.png');
        background-repeat: repeat;
        background-size: 320px 320px;
        opacity: 0.06;
        mix-blend-mode: multiply;
        pointer-events: none;
        z-index: -1;
      }
    `}
  ${(props) =>
    props.$variant === 'cta' &&
    css`
      /* 原稿 C1 尾段：墨底 band，纸白文字 */
      background: ${({ theme }) => theme.colors.fontColorDark};
    `}

  @media (max-width: 1023px) {
    padding: 7rem 1.5rem 5rem;
  }
`;

export const Container = styled.div`
  max-width: 1100px;
  margin: 0 auto;
`;

export const SectionHeader = styled.div`
  text-align: center;
  margin-bottom: 3rem;
`;

export const SectionTag = styled.span`
  display: inline-block;
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 10.5px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: ${({ theme }) => theme.colors.success};
  margin-bottom: 1rem;
  padding: 4px 10px;
  border-radius: 2px;
  background: ${({ theme }) => theme.colors.successAlpha12};
  border: 1px solid ${({ theme }) => theme.colors.successAlpha20};
`;

export const SectionTitle = styled.h2`
  font-size: clamp(2rem, 4vw, 3rem);
  font-weight: 700;
  text-align: center;
  margin-bottom: 0.75rem;
  letter-spacing: -0.02em;
  line-height: 1.2;

  @media (max-width: 1023px) {
    font-size: clamp(1.6rem, 5vw, 2.2rem);
  }
`;

export const SectionSubtitle = styled.p`
  font-size: 1.05rem;
  color: ${({ theme }) => theme.colors.mutedText};
  max-width: 480px;
  margin: 0 auto;
  line-height: 1.7;
`;

/* ===== Stagger Grid (shared by feature & value grids) ===== */

export const StaggerGrid = styled(motion.div)`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1.75rem;

  @media (max-width: 1023px) {
    grid-template-columns: 1fr;
  }
`;

/* ===== Features ===== */

type IconTone = 'felt' | 'play' | 'real' | 'amb';
// 原稿 grid4 四色左条语义：felt=公平/加密 play=洗牌/即时 real=金库 amb=密钥/时间
const toneOf = (theme: { colors: ThemeColors }, tone: IconTone = 'felt'): string => {
  const key = { felt: 'success', play: 'info', real: 'gold', amb: 'warning' }[tone] as keyof ThemeColors;
  return theme.colors[key];
};

export const FeatureIcon = styled.div<{ $tone?: IconTone }>`
  margin-bottom: 1.25rem;
  color: ${({ $tone, theme }) => toneOf(theme, $tone)};
  transition: transform 0.4s ease;
`;

export const FeatureCard = styled(motion.div)`
  background: ${({ theme }) => theme.colors.lightestBg};
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-radius: ${({ theme }) => theme.radius.sm};
  padding: 2rem;
  /* 等高卡片：填满网格 item（StaggerItem 拉伸），标题行齐、正文自然对齐 */
  flex: 1;
  display: flex;
  flex-direction: column;
  transition:
    border-color 0.4s cubic-bezier(0.22, 1, 0.36, 1),
    background-color 0.4s cubic-bezier(0.22, 1, 0.36, 1),
    box-shadow 0.4s cubic-bezier(0.22, 1, 0.36, 1),
    transform 0.4s cubic-bezier(0.22, 1, 0.36, 1);
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05), 0 1px 2px rgba(0, 0, 0, 0.03);

  &:hover {
    border-color: ${({ theme }) => theme.colors.borderMuted};
    background: ${({ theme }) => theme.colors.lightestBg};
    box-shadow: 0 2px 8px rgba(20, 19, 15, 0.06);
    transform: translateY(-4px);
  }
  &:hover ${FeatureIcon} {
    transform: translateY(-2px);
  }

  h3 {
    font-size: 1.1rem;
    margin-bottom: 0.6rem;
    font-weight: 600;
    color: ${(props) => props.theme.colors.fontColorDark};
  }
  p {
    color: ${({ theme }) => theme.colors.mutedText};
    font-size: 0.92rem;
    line-height: 1.65;
  }
`;

/* ===== Value Section ===== */

export const ValueHeader = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 1.25rem;
`;

export const ValueIcon = styled.div<{ $tone?: IconTone }>`
  color: ${({ $tone, theme }) => toneOf(theme, $tone)};
  transition: transform 0.4s ease;
`;

export const ValueCard = styled(motion.div)`
  background: ${({ theme }) => theme.colors.lightestBg};
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-radius: ${({ theme }) => theme.radius.sm};
  padding: 1.75rem;
  /* 等高卡片：与 FeatureCard 同款填满逻辑 */
  flex: 1;
  display: flex;
  flex-direction: column;
  transition:
    border-color 0.4s cubic-bezier(0.22, 1, 0.36, 1),
    background-color 0.4s cubic-bezier(0.22, 1, 0.36, 1),
    box-shadow 0.4s cubic-bezier(0.22, 1, 0.36, 1),
    transform 0.4s cubic-bezier(0.22, 1, 0.36, 1);
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05), 0 1px 2px rgba(0, 0, 0, 0.03);

  &:hover {
    border-color: ${({ theme }) => theme.colors.borderMuted};
    background: ${({ theme }) => theme.colors.lightestBg};
    box-shadow: 0 2px 8px rgba(20, 19, 15, 0.06);
    transform: translateY(-4px);
  }
  &:hover ${ValueIcon} {
    transform: translateY(-2px);
  }

  h3 {
    font-size: 1.1rem;
    margin-bottom: 0.5rem;
    font-weight: 600;
    color: ${(props) => props.theme.colors.fontColorDark};
  }
  p {
    color: ${({ theme }) => theme.colors.mutedText};
    font-size: 0.9rem;
    line-height: 1.6;
  }
`;

export const ValueStat = styled.div`
  text-align: right;
`;

export const StatNumber = styled.span`
  display: block;
  font-size: 1.6rem;
  font-weight: 600;
  font-family: 'JetBrains Mono', monospace;
  line-height: 1;
`;

export const StatDesc = styled.span`
  font-size: 0.7rem;
  color: ${({ theme }) => theme.colors.softerText};
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-top: 0.3rem;
`;

/* ===== Protocol Flow ===== */

export const ProtocolFlow = styled.div`
  max-width: 640px;
  margin: 0 auto;
`;

export const ProtocolStep = styled.div`
  display: flex;
  align-items: flex-start;
  gap: 1.25rem;
  position: relative;
  padding-bottom: 1.25rem;

  @media (max-width: 1023px) {
    gap: 1rem;
    padding-bottom: 1.5rem;
  }
`;

export const StepNumber = styled.div`
  width: 48px;
  height: 48px;
  border-radius: ${({ theme }) => theme.radius.sm};
  background: ${({ theme }) => theme.colors.successAlpha12};
  border: 1px solid ${({ theme }) => theme.colors.successAlpha20};
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  position: relative;
  z-index: 2;
`;

export const StepNum = styled.span`
  position: absolute;
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 0.6rem;
  font-weight: 700;
  color: ${({ theme }) => theme.colors.success};
  top: 6px;
  left: 8px;
  letter-spacing: 0.08em;
`;

export const StepIcon = styled.span`
  color: ${({ theme }) => theme.colors.softText};
`;

export const StepContent = styled.div`
  flex: 1;
  padding-top: 0.25rem;

  /* h3：修正标题层级跳跃（h2 之后直接出现 h4 被 Lighthouse 判不合规） */
  h3 {
    font-size: 1.1rem;
    font-weight: 600;
    margin: 0 0 0.4rem;
    color: ${(props) => props.theme.colors.fontColorDark};
  }
  p {
    color: ${({ theme }) => theme.colors.mutedText};
    font-size: 0.92rem;
    line-height: 1.6;
    margin: 0;
  }
`;

export const StepLine = styled.div`
  position: absolute;
  left: 24px;
  top: 48px;
  bottom: 0;
  width: 1px;
  background: ${({ theme }) => theme.colors.borderSubtle};
  z-index: 1;
`;

/* ===== CTA Section ===== */

export const CTAContent = styled.div`
  text-align: center;
  max-width: 500px;
  margin: 0 auto;

  h2 {
    font-size: clamp(2rem, 4vw, 3rem);
    font-weight: 700;
    margin-bottom: 0.75rem;
    letter-spacing: -0.02em;
    color: ${({ theme }) => theme.colors.fontColorLight};
  }
  p {
    font-size: 1rem;
    margin: 0 auto 2rem;
    line-height: 1.7;
    color: ${({ theme }) => theme.colors.fontColorDarkLighter};
  }
`;

/* ===== Footer ===== */

export const Footer = styled.footer`
  border-top: 1px solid ${({ theme }) => theme.colors.borderMuted};
  padding: 3rem 2rem;
  background: ${({ theme }) => theme.colors.surfaceMutedPlain};
  position: relative;
  z-index: 1;
  scroll-margin-top: 5rem;
  min-height: 50vh;
  display: flex;
  flex-direction: column;
  justify-content: center;
`;

export const FooterContent = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 1.5rem;
  max-width: 1100px;
  margin: 0 auto;
`;

export const FooterBrand = styled.div`
  span:first-child {
    font-size: 1.2rem;
    font-weight: 600;
    color: ${(props) => props.theme.colors.fontColorDark};
  }
  p {
    color: ${({ theme }) => theme.colors.mutedText};
    font-size: 0.8rem;
    margin-top: 0.3rem;
  }
`;

export const FooterLinks = styled.div`
  display: flex;
  gap: 0.75rem;
  align-items: center;
`;

export const FooterLink = styled(motion.button)`
  background: transparent;
  color: ${({ theme }) => theme.colors.mutedText};
  border: 1px solid rgba(${({ theme }) => theme.colors.borderSubtleRgb}, 0.25);
  padding: 0.4rem 1rem;
  border-radius: 8px;
  font-size: 0.8rem;
  font-weight: 500;
  cursor: pointer;
  transition:
    border-color 0.25s ease,
    color 0.25s ease;

  &:hover {
    border-color: rgba(${({ theme }) => theme.colors.borderSubtleRgb}, 0.45);
    color: ${(props) => props.theme.colors.fontColorDark};
  }
`;

export const FooterTech = styled.div`
  span {
    display: block;
    font-size: 0.75rem;
    /* mutedText：浅底对比度 ≥ 6.9:1（原 softText 被 Lighthouse 判 AA 不达标） */
    color: ${({ theme }) => theme.colors.mutedText};
    margin-bottom: 0.4rem;
  }
`;

export const TechTags = styled.div`
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;

  span {
    background: rgba(${({ theme }) => theme.colors.surfaceMutedPlainRgb}, 0.6);
    border: 1px solid rgba(${({ theme }) => theme.colors.borderSubtleRgb}, 0.8);
    padding: 0.25rem 0.6rem;
    border-radius: 6px;
    font-size: 0.72rem;
    color: ${({ theme }) => theme.colors.mutedText};
    transition:
      border-color 0.2s ease,
      color 0.2s ease;
    cursor: default;

    &:hover {
      border-color: ${(props) => props.theme.colors.secondaryCta};
      color: ${(props) => props.theme.colors.secondaryCta};
    }
  }
`;

export const FooterRef = styled.div`
  span {
    display: block;
    font-size: 0.75rem;
    /* mutedText：对比度修复，同 FooterTech */
    color: ${({ theme }) => theme.colors.mutedText};
    margin-bottom: 0.2rem;
  }
  a {
    /* primaryCta：浅底 5.7:1+（原 secondaryCta 仅 ~3.3:1） */
    color: ${(props) => props.theme.colors.primaryCta};
    font-size: 0.8rem;
    transition: color 0.2s ease;

    &:hover {
      color: ${({ theme }) => theme.colors.primaryCtaDarker};
    }
  }
`;

/* ===== Scroll Nav ===== */

export const ScrollNav = styled.nav`
  position: fixed;
  right: 1.5rem;
  top: 50%;
  transform: translateY(-50%);
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 1rem;
  z-index: 50;

  @media (max-width: 1023px) {
    display: none;
  }
`;

export const ScrollLabel = styled.span`
  position: absolute;
  right: 1.25rem;
  top: 50%;
  transform: translateY(-50%) translateX(4px);
  white-space: nowrap;
  font-size: 0.7rem;
  font-weight: 500;
  color: ${({ theme }) => theme.colors.mutedText};
  background: ${({ theme }) => theme.colors.surfaceGlass};
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  padding: 0.25rem 0.6rem;
  border-radius: 6px;
  opacity: 0;
  pointer-events: none;
  transition: opacity 0.25s ease, transform 0.25s ease;
`;

export const ScrollDot = styled.button<{ $active?: boolean }>`
  position: relative;
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: ${({ theme }) => theme.colors.brandIndigoAlpha25};
  border: none;
  cursor: pointer;
  padding: 0;
  transition:
    background-color 0.3s ease,
    transform 0.3s ease,
    box-shadow 0.3s ease;

  &:hover ${ScrollLabel} {
    opacity: 1;
    transform: translateY(-50%) translateX(0);
  }

  ${(props) =>
    props.$active &&
    css`
      background: ${({ theme }) => theme.colors.success};
      transform: scale(1.3);
      box-shadow: 0 0 0 4px ${({ theme }) => theme.colors.successAlpha20};
    `}
`;
