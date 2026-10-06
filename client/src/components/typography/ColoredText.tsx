import styled from 'styled-components';

interface ColoredTextProps {
  primary?: boolean;
  emphazised?: boolean;
  secondary?: boolean;
  textAlign?: string;
}

const ColoredText = styled.span.withConfig({
  shouldForwardProp: (prop) => !['primary', 'emphazised', 'secondary', 'textAlign'].includes(prop),
})<ColoredTextProps>`
  color: ${({ primary, secondary, theme }) => {
    if (primary) {
      return theme.colors.fontColorDark;
    } else if (secondary) {
      return theme.colors.secondaryCta;
    } else {
      return theme.colors.primaryCta;
    }
  }};
  font-weight: ${({ emphazised }) => (emphazised ? 'bold' : 'normal')};
  text-align: ${({ textAlign }) => textAlign || 'inherit'};
`;

export default ColoredText;
