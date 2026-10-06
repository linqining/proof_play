import styled from 'styled-components';
import { responsiveScale } from './responsiveScale';

interface PositionedUISlotProps {
  width?: string;
  height?: string;
  top?: string;
  right?: string;
  bottom?: string;
  left?: string;
  origin?: string;
  scale?: string;
}

export const PositionedUISlot = styled.div.withConfig({
  shouldForwardProp: (prop) => !['width', 'height', 'top', 'right', 'bottom', 'left', 'origin', 'scale'].includes(prop),
})<PositionedUISlotProps>`
  width: ${({ width }) => width || 'auto'};
  height: ${({ height }) => height || 'auto'};
  position: absolute;
  top: ${({ top }) => top};
  right: ${({ right }) => right};
  bottom: ${({ bottom }) => bottom};
  left: ${({ left }) => left};
  transform-origin: ${({ origin }) => origin || 'top left'};
  -webkit-backface-visibility: hidden;
  backface-visibility: hidden;

  ${responsiveScale<PositionedUISlotProps>((props) => props.scale)}
`;
