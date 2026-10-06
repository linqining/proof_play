import styled, { css } from 'styled-components';

interface ContainerProps {
  contentCenteredMobile?: boolean;
  fluid?: boolean;
  fullHeight?: boolean;
  justifyContent?: string;
  alignItems?: string;
  flexDirection?: string;
  display?: string;
  margin?: string;
  padding?: string;
}

const Container = styled.div.withConfig({
  shouldForwardProp: (prop) => !['contentCenteredMobile', 'fluid', 'fullHeight', 'justifyContent', 'alignItems', 'flexDirection', 'display', 'margin', 'padding'].includes(prop),
})<ContainerProps>`
  display: ${({ display }) => display};
  position: relative;
  flex-direction: ${({ flexDirection }) => flexDirection};
  justify-content: ${({ justifyContent }) => justifyContent};
  align-items: ${({ alignItems }) => alignItems};
  max-width: 1440px;
  margin: ${({ margin }) => margin};
  padding: ${({ padding }) => padding};

  @media screen and (max-width: 1024px) {
    justify-content: ${({ contentCenteredMobile }) =>
      contentCenteredMobile ? 'center' : 'space-between'};
    padding-left: 1rem;
    padding-right: 1rem;
  }

  ${({ fluid }) =>
    fluid &&
    css`
      max-width: 100%;
      width: 100%;
      padding: 0 3rem;
    `}

  ${({ fullHeight }) =>
    fullHeight &&
    css`
      min-height: 100dvh;
    `}
`;

Container.defaultProps = {
  contentCenteredMobile: false,
  fluid: false,
  fullHeight: false,
  margin: '0 auto',
  justifyContent: 'space-between',
  alignItems: 'center',
  flexDirection: 'row',
  padding: '0 2rem',
  display: 'flex',
};

export default Container;
