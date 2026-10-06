import styled, { css } from 'styled-components';

/**
 * Whitepaper design tokens
 * ------------------------------------------------------------------
 * Derives from the global theme but normalises the long-form reading
 * experience: a soft glassy card surface, indigo→purple brand gradient
 * for emphasis (matching SecretPokerHomePage), and ample line-height
 * for prose. The palette is light-mode consistent with the rest of the
 * app; nothing is hardcoded outside the constants below — every value
 * here can be swapped to a theme token at the call site.
 */

export const WP_MAX_WIDTH = '920px';
export const WP_RADIUS = '16px';
export const WP_RADIUS_SM = '10px';
export const WP_BODY_FONT_SIZE = '1rem';
export const WP_LINE_HEIGHT = '1.75';

/**
 * Light-mode visual palette. All values are pulled from theme.ts via
 * styled-component template literals below; this object just gives the
 * styled components a single place to document their dependency on
 * the global palette.
 */
export const PageRoot = styled.article`
  background: ${({ theme }) => theme.colors.lightestBg};
  color: ${({ theme }) => theme.colors.fontColorDark};
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  line-height: ${WP_LINE_HEIGHT};
  padding-bottom: 4rem;
`;

export const Content = styled.div`
  max-width: ${WP_MAX_WIDTH};
  margin: 0 auto;
  padding: 0 1.5rem;
`;

/* ------------------------- Sticky back bar ------------------------- */

export const BackTopBar = styled.div`
  position: sticky;
  top: 0;
  z-index: 10;
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.75rem 1.5rem;
  background: ${({ theme }) => theme.colors.surfaceGlass};
  border-bottom: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
`;

const navLink = css`
  color: ${({ theme }) => theme.colors.secondaryCta};
  text-decoration: none;
  font-size: 0.9rem;
  font-weight: 500;
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.4rem 0.8rem;
  border-radius: ${WP_RADIUS_SM};
  transition:
    background-color ${({ theme }) => theme.timing.base} ${({ theme }) => theme.easing.easeStandard},
    color ${({ theme }) => theme.timing.base} ${({ theme }) => theme.easing.easeStandard};

  &:hover {
    background: ${({ theme }) => theme.colors.brandIndigoAlpha10};
    color: ${({ theme }) => theme.colors.secondaryCtaDarker};
  }
`;

export const BackLink = styled.a`
  ${navLink}
`;

export const TopBarGroup = styled.div`
  display: flex;
  align-items: center;
  gap: 0.75rem;
`;

/* --------------------------- Cover block --------------------------- */

export const Cover = styled.section`
  text-align: center;
  padding: 5rem 1.5rem 3rem;
  max-width: ${WP_MAX_WIDTH};
  margin: 0 auto;
  position: relative;
`;

export const CoverBadge = styled.div`
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  background: ${({ theme }) => theme.colors.brandIndigoAlpha10};
  color: ${({ theme }) => theme.colors.secondaryCtaDarker};
  border: 1px solid ${({ theme }) => theme.colors.brandIndigoAlpha20};
  padding: 0.35rem 0.9rem;
  border-radius: 999px;
  font-size: 0.75rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  font-weight: 600;
  margin-bottom: 1.75rem;
`;

export const CoverTitle = styled.h1`
  font-family: ${({ theme }) => theme.fonts.fontFamilySerif};
  font-size: ${({ theme }) => theme.fonts.fontSizeH1};
  font-weight: 700;
  line-height: 1.15;
  margin: 0 0 1.25rem;
  color: ${({ theme }) => theme.colors.fontColorDark};
  letter-spacing: -0.01em;
`;

export const CoverTitleAccent = styled.span`
  background: ${({ theme }) => theme.colors.brandGradient};
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
  display: inline-block;
`;

export const CoverSubtitle = styled.p`
  font-size: 1.1rem;
  color: ${({ theme }) => theme.colors.mutedText};
  max-width: 620px;
  margin: 0 auto 2rem;
  line-height: 1.65;
`;

export const CoverMeta = styled.div`
  font-size: 0.8rem;
  color: ${({ theme }) => theme.colors.softText};
  letter-spacing: 0.05em;
`;

/* -------------------------- Abstract block -------------------------- */

export const Abstract = styled.section`
  background: ${({ theme }) => theme.colors.surfaceGlass};
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-radius: ${WP_RADIUS};
  padding: 1.75rem 2rem;
  margin: 2.5rem auto;
  max-width: ${WP_MAX_WIDTH};
  box-shadow: ${({ theme }) => theme.other.cardDropShadow};
  position: relative;
  overflow: hidden;

  &::before {
    content: '';
    position: absolute;
    left: 0;
    top: 0;
    bottom: 0;
    width: 4px;
    background: ${({ theme }) => theme.colors.brandGradient};
  }

  p {
    margin-bottom: 0.85rem;
    color: ${({ theme }) => theme.colors.fontColorDarkLighter};
    font-size: 0.98rem;
    line-height: 1.7;
  }
  p:last-child { margin-bottom: 0; }
  strong {
    color: ${({ theme }) => theme.colors.fontColorDark};
    font-weight: 600;
  }
`;

/* ---------------------------- Sections ----------------------------- */

export const Section = styled.section`
  margin: 3rem 0;
`;

export const ChapterTitle = styled.h2`
  font-family: ${({ theme }) => theme.fonts.fontFamilySerif};
  font-size: ${({ theme }) => theme.fonts.fontSizeH2};
  font-weight: 700;
  color: ${({ theme }) => theme.colors.fontColorDark};
  margin: 4rem 0 1.5rem;
  display: flex;
  align-items: baseline;
  gap: 0.75rem;
  position: relative;
  padding-bottom: 0.6rem;
  border-bottom: 1px solid ${({ theme }) => theme.colors.borderSubtle};
`;

export const ChapterNumber = styled.span`
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 0.85rem;
  font-weight: 700;
  background: ${({ theme }) => theme.colors.brandGradient};
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
  letter-spacing: 0.05em;
`;

export const SubTitle = styled.h3`
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 1.15rem;
  font-weight: 600;
  color: ${({ theme }) => theme.colors.fontColorDark};
  margin: 2rem 0 0.75rem;
  letter-spacing: -0.005em;
`;

export const SubSubTitle = styled.h4`
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 1rem;
  font-weight: 600;
  color: ${({ theme }) => theme.colors.fontColorDarkLighter};
  margin: 1.25rem 0 0.5rem;
`;

export const Paragraph = styled.p`
  margin-bottom: 1rem;
  color: ${({ theme }) => theme.colors.fontColorDarkLighter};
  font-size: ${WP_BODY_FONT_SIZE};
  line-height: ${WP_LINE_HEIGHT};
`;

export const Mark = styled.mark`
  background: ${({ theme }) => theme.colors.brandIndigoAlpha10};
  color: ${({ theme }) => theme.colors.secondaryCtaDarker};
  font-weight: 600;
  padding: 0.05em 0.3em;
  border-radius: 4px;
`;

export const InlineLink = styled.a`
  color: ${({ theme }) => theme.colors.secondaryCta};
  text-decoration: none;
  border-bottom: 1px solid ${({ theme }) => theme.colors.brandIndigoAlpha20};
  transition: border-color ${({ theme }) => theme.timing.base} ${({ theme }) => theme.easing.easeStandard};

  &:hover {
    border-color: ${({ theme }) => theme.colors.secondaryCta};
  }
`;

/* ----------------------------- Lists ------------------------------- */

export const List = styled.ul`
  list-style: none;
  padding-left: 0;
  margin-bottom: 1.25rem;

  li {
    position: relative;
    padding-left: 1.6rem;
    margin-bottom: 0.55rem;
    color: ${({ theme }) => theme.colors.fontColorDarkLighter};
    line-height: ${WP_LINE_HEIGHT};

    &::before {
      content: '';
      position: absolute;
      left: 0;
      top: 0.65em;
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: ${({ theme }) => theme.colors.brandGradient};
    }
  }
`;

export const OrderedList = styled.ol`
  list-style: none;
  padding-left: 0;
  margin-bottom: 1.25rem;
  counter-reset: wp-ol;

  li {
    position: relative;
    padding-left: 2.4rem;
    margin-bottom: 0.55rem;
    color: ${({ theme }) => theme.colors.fontColorDarkLighter};
    line-height: ${WP_LINE_HEIGHT};
    counter-increment: wp-ol;

    &::before {
      content: counter(wp-ol, decimal-leading-zero);
      position: absolute;
      left: 0;
      top: 0.05em;
      font-size: 0.78rem;
      font-weight: 700;
      background: ${({ theme }) => theme.colors.brandGradient};
      -webkit-background-clip: text;
      background-clip: text;
      color: transparent;
      letter-spacing: 0.05em;
    }
  }
`;

/* ----------------------------- Tables ------------------------------ */

export const TableWrap = styled.div`
  overflow-x: auto;
  margin: 1.5rem 0;
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-radius: ${WP_RADIUS};
  -webkit-overflow-scrolling: touch;
  background: ${({ theme }) => theme.colors.lightestBg};
`;

export const Table = styled.table`
  width: 100%;
  border-collapse: collapse;
  margin: 0;
  font-size: 0.9rem;
  min-width: 600px;

  th, td {
    padding: 0.75rem 1rem;
    text-align: left;
    border-bottom: 1px solid ${({ theme }) => theme.colors.borderSubtle};
    color: ${({ theme }) => theme.colors.fontColorDarkLighter};
    vertical-align: top;
  }
  th {
    font-weight: 600;
    color: ${({ theme }) => theme.colors.fontColorDark};
    background: ${({ theme }) => theme.colors.surfaceMuted};
    border-bottom-color: ${({ theme }) => theme.colors.borderMuted};
  }
  tr:last-child td { border-bottom: none; }
  tr:hover td {
    background: ${({ theme }) => theme.colors.surfaceSubtle};
  }
`;

export const TableCompare = styled(Table)`
  font-size: 0.88rem;
  td:first-child {
    font-weight: 600;
    color: ${({ theme }) => theme.colors.fontColorDark};
  }
`;

/* --------------------------- Card grid ----------------------------- */

export const CardGrid = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 1rem;
  margin: 1.5rem 0;

  @media ${({ theme }) => theme.breakpoints.down.md} {
    grid-template-columns: 1fr;
  }
`;

export const Card = styled.div`
  background: ${({ theme }) => theme.colors.surfaceGlass};
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-radius: ${WP_RADIUS};
  padding: 1.25rem 1.4rem;
  box-shadow: ${({ theme }) => theme.other.cardDropShadow};
  transition: transform ${({ theme }) => theme.timing.base} ${({ theme }) => theme.easing.easeOutCubic};

  &:hover {
    transform: translateY(-2px);
  }

  h4 {
    margin: 0 0 0.5rem;
    color: ${({ theme }) => theme.colors.fontColorDark};
    font-size: 0.95rem;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 0.4rem;
  }
  p {
    font-size: 0.9rem;
    margin: 0;
    color: ${({ theme }) => theme.colors.mutedText};
    line-height: 1.55;
  }
`;

export const ProofCard = styled.div`
  background: ${({ theme }) => theme.colors.surfaceGlass};
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-radius: ${WP_RADIUS};
  padding: 1.1rem 1.4rem;
  margin: 0.75rem 0;
  box-shadow: ${({ theme }) => theme.other.cardDropShadow};
  position: relative;

  &::before {
    content: '';
    position: absolute;
    left: 0;
    top: 0.6rem;
    bottom: 0.6rem;
    width: 3px;
    border-radius: 0 3px 3px 0;
    background: ${({ theme }) => theme.colors.brandGradient};
  }

  h4 {
    margin: 0 0 0.4rem;
    color: ${({ theme }) => theme.colors.fontColorDark};
    font-size: 1rem;
    font-weight: 600;
  }
  p {
    font-size: 0.92rem;
    margin: 0;
    color: ${({ theme }) => theme.colors.mutedText};
    line-height: 1.6;
  }
`;

export const VisionCard = styled.div`
  background: ${({ theme }) => theme.colors.surfaceGlass};
  border: 1px solid ${({ theme }) => theme.colors.brandIndigoAlpha25};
  border-radius: ${WP_RADIUS};
  padding: 1.5rem 1.75rem;
  margin: 1rem 0;
  box-shadow: ${({ theme }) => theme.other.cardDropShadow};

  h4 {
    margin: 0 0 0.5rem;
    color: ${({ theme }) => theme.colors.secondaryCtaDarker};
    font-size: 1.05rem;
    font-weight: 600;
  }
  p {
    margin: 0;
    color: ${({ theme }) => theme.colors.fontColorDarkLighter};
    font-size: 0.95rem;
    line-height: 1.6;
  }
`;

/* ----------------------------- Timeline ---------------------------- */

export const Timeline = styled.div`
  position: relative;
  padding: 0.5rem 0 0.5rem 1.75rem;
  margin: 1.5rem 0;
  border-left: 2px solid ${({ theme }) => theme.colors.borderMuted};
`;

export const TimelineItem = styled.div`
  position: relative;
  padding: 0 0 1.25rem 1rem;

  &::before {
    content: '';
    position: absolute;
    left: -1.95rem;
    top: 0.45rem;
    width: 0.85rem;
    height: 0.85rem;
    border-radius: 50%;
    background: ${({ theme }) => theme.colors.lightestBg};
    border: 3px solid transparent;
    background-image: ${({ theme }) => theme.colors.brandGradient};
    background-origin: border-box;
    background-clip: padding-box, border-box;
  }

  h4 {
    margin: 0 0 0.3rem;
    color: ${({ theme }) => theme.colors.fontColorDark};
    font-size: 0.98rem;
    font-weight: 600;
  }
  p {
    margin: 0;
    color: ${({ theme }) => theme.colors.mutedText};
    font-size: 0.9rem;
    line-height: 1.55;
  }
`;

/* ----------------------------- Divider ----------------------------- */

export const Divider = styled.hr`
  border: none;
  height: 1px;
  background: ${({ theme }) => theme.colors.borderSubtle};
  margin: 3rem auto;
  max-width: 240px;
`;

/* ----------------------------- Code -------------------------------- */

export const Code = styled.code`
  font-family: 'JetBrains Mono', 'SF Mono', Menlo, monospace;
  font-size: 0.85em;
  background: ${({ theme }) => theme.colors.surfaceMutedPlain};
  padding: 0.1rem 0.4rem;
  border-radius: 4px;
  color: ${({ theme }) => theme.colors.secondaryCtaDarker};
`;

export const Pre = styled.pre`
  background: ${({ theme }) => theme.colors.surfaceMuted};
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  padding: 1rem 1.25rem;
  border-radius: ${WP_RADIUS_SM};
  overflow-x: auto;
  margin: 1rem 0;
  font-size: 0.85rem;
  line-height: 1.55;
  color: ${({ theme }) => theme.colors.fontColorDarkLighter};
`;

/* ------------------------------ Footer ----------------------------- */

export const Footer = styled.footer`
  margin-top: 4rem;
  padding: 2.5rem 0;
  background: ${({ theme }) => theme.colors.surfaceMuted};
  border-top: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  font-size: 0.85rem;
  color: ${({ theme }) => theme.colors.mutedText};
  border-radius: ${WP_RADIUS} ${WP_RADIUS} 0 0;

  h3 {
    font-family: ${({ theme }) => theme.fonts.fontFamilySerif};
    font-size: 1.05rem;
    color: ${({ theme }) => theme.colors.fontColorDark};
    margin: 0 0 1rem;
  }
  ol {
    padding-left: 1.2rem;
    margin: 0 0 1.5rem;
  }
  li {
    margin-bottom: 0.5rem;
  }
  a {
    color: ${({ theme }) => theme.colors.secondaryCta};
  }
`;
