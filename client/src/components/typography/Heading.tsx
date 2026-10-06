import styled from 'styled-components';
import type { Theme } from '../../styles/theme';

type HeadingClass = 'h1' | 'h2' | 'h3' | 'h4' | 'h5' | 'h6';

interface HeadingProps {
  headingClass?: HeadingClass;
  textCentered?: boolean;
  textCenteredOnMobile?: boolean;
}

const fontSizeKey = (headingClass: HeadingClass): keyof Theme['fonts'] =>
  `fontSize${headingClass.toUpperCase()}` as keyof Theme['fonts'];

const Heading = styled.h1.withConfig({
  shouldForwardProp: (prop) => !['headingClass', 'textCentered', 'textCenteredOnMobile'].includes(prop),
})<HeadingProps>`
  font-size: ${({ headingClass, theme }) =>
    headingClass
      ? theme.fonts[fontSizeKey(headingClass)]
      : theme.fonts.fontSizeH1};

  text-align: ${({ textCentered }) => (textCentered ? 'center' : 'left')};

  @media screen and (max-width: 1024px) {
    text-align: ${({ textCenteredOnMobile, textCentered }) =>
      textCenteredOnMobile || textCentered ? 'center' : 'left'};
  }
`;

Heading.defaultProps = {
  textCentered: false,
  textCenteredOnMobile: false,
};

export default Heading;
