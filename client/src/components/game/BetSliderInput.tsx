import styled from 'styled-components';

const TRACK_COLOR = 'rgba(245, 242, 234, 0.28)';
const THUMB_COLOR = '#f5f2ea';

export const BetSliderInput = styled.input`
  width: 100%;
  background-color: transparent;
  -webkit-appearance: none;
  /* The thumb is the touch target — keep it as large as the track allows;
     the visible focus ring below restores keyboard affordance. */
  cursor: pointer;

  /* 下注是资金操作：键盘焦点必须可见（此前的 outline:none 无替代样式） */
  &:focus-visible::-webkit-slider-thumb {
    box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.5);
  }

  &:focus-visible::-moz-range-thumb {
    box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.5);
  }

  &:focus-visible::-ms-thumb {
    box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.5);
  }

  &::-webkit-slider-runnable-track {
    background: ${TRACK_COLOR};
    border: none;
    border-radius: 40px;
    width: 100%;
    height: 0.25rem;
    cursor: pointer;
  }

  &::-webkit-slider-thumb {
    margin-top: -4px;
    width: 1.5rem;
    height: 1.5rem;
    background: ${THUMB_COLOR};
    border: 0;
    border-radius: 40px;
    cursor: pointer;
    -webkit-appearance: none;
  }

  &:focus-visible::-webkit-slider-runnable-track {
    background: ${TRACK_COLOR};
  }

  &::-moz-range-track {
    background: ${TRACK_COLOR};
    border: none;
    border-radius: 40px;
    width: 100%;
    height: 0.25rem;
    cursor: pointer;
  }

  &::-moz-range-thumb {
    width: 1.5rem;
    height: 1.5rem;
    background: ${THUMB_COLOR};
    border: 0;
    border-radius: 40px;
    cursor: pointer;
  }

  &::-ms-track {
    background: transparent;
    border-color: transparent;
    border-width: 4.8px 0;
    color: transparent;
    width: 100%;
    height: 0.25rem;
    cursor: pointer;
  }

  &::-ms-fill-lower {
    background: ${TRACK_COLOR};
    border: none;
    border-radius: 40px;
  }

  &::-ms-fill-upper {
    background: ${TRACK_COLOR};
    border: none;
    border-radius: 40px;
  }

  &::-ms-thumb {
    width: 1.5rem;
    height: 1.5rem;
    background: ${THUMB_COLOR};
    border: 0;
    border-radius: 40px;
    cursor: pointer;
    margin-top: 0;
  }

  &:focus-visible::-ms-fill-lower {
    background: ${TRACK_COLOR};
  }

  &:focus-visible::-ms-fill-upper {
    background: ${TRACK_COLOR};
  }

  @supports (-ms-ime-align: auto) {
    & {
      margin: 0;
    }
  }
`;
