import styled from 'styled-components';

interface TextProps {
  fontSize?: string;
  textAlign?: 'left' | 'center' | 'right';
}

const Text = styled.p.withConfig({
  shouldForwardProp: (prop) => !['fontSize', 'textAlign'].includes(prop),
})<TextProps>`
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  text-align: ${({ textAlign }) => textAlign};
  font-size: ${({ fontSize, theme }) =>
    fontSize ? fontSize : theme.fonts.fontSizeParagraph};
  font-weight: 400;
  line-height: ${({ theme }) => theme.fonts.fontLineHeight};
  margin-bottom: 1rem;
`;

export default Text;
