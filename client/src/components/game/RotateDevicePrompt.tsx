import React, { useContext } from 'react';
import Text from '../typography/Text';
import rotateGif from '../../assets/game/rotate.gif';
import styled from 'styled-components';
import contentContext from '../../context/content/contentContext';

const Wrapper = styled.div`
  display: none;
  position: fixed;
  z-index: ${({ theme }) => theme.zIndex.critical};
  /* 账簿墨底（tokens ink），与牌桌页脚同源 */
  background-color: ${({ theme }) => theme.colors.fontColorDark};
  padding: 2rem;
  width: 100%;
  height: 100%;
  inset: 0;

  & ${Text} {
    color: ${(props) => props.theme.colors.fontColorLight};
    word-break: break-all;
  }

  /* Show on portrait phones (the table needs landscape room) and on
     very narrow landscape windows where the 5-seat table would not
     fit comfortably. */
  @media screen and (orientation: portrait), (max-height: 480px) and (orientation: landscape) {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
  }
`;

export const RotateDevicePrompt: React.FC = () => {
  const { getLocalizedString } = useContext(contentContext)!;
  return (
    <Wrapper role="alertdialog" aria-live="polite">
      <img
        src={rotateGif}
        width="140"
        height="140"
        style={{ width: '140px', height: 'auto' }}
        alt={getLocalizedString('rotate-device_alt')}
      />
      <br />
      <Text textAlign="center">
        {getLocalizedString('game_rotate-device-prompt')}
      </Text>
    </Wrapper>
  );
};
