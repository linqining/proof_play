import React, { useEffect } from 'react';
import styled from 'styled-components';
import { KICK_NOTIFICATION_DISMISS_MS } from '../../clientConfig';

interface KickNotificationProps {
  kickNotification: string | null;
  clearKickNotification: () => void;
}

/* role="alert" 让读屏用户即时获知被踢；关闭动作用真 <button>，
   键盘可触达（此前是无键盘等价物的 div onClick）。 */
const AlertRegion = styled.div`
  position: fixed;
  top: 1.5rem;
  left: 0;
  width: 100%;
  display: flex;
  justify-content: center;
  z-index: ${({ theme }) => theme.zIndex.toast};
  pointer-events: none;
`;

const Notification = styled.button`
  pointer-events: auto;
  appearance: none;
  display: inline-block;
  background: ${({ theme }) => theme.colors.dangerAlpha95};
  color: #fff;
  border: none;
  font-family: inherit;
  padding: 0.8rem 1.5rem;
  border-radius: 10px;
  font-size: 0.95rem;
  font-weight: 600;
  cursor: pointer;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
  max-width: 90vw;
  text-align: center;
`;

export const KickNotification: React.FC<KickNotificationProps> = ({
  kickNotification,
  clearKickNotification,
}) => {
  // Auto-dismiss kick notification after 5 seconds
  useEffect(() => {
    if (kickNotification) {
      const timer = setTimeout(() => {
        clearKickNotification();
      }, KICK_NOTIFICATION_DISMISS_MS);
      return () => clearTimeout(timer);
    }
  }, [kickNotification, clearKickNotification]);

  if (!kickNotification) return null;

  return (
    <AlertRegion role="alert">
      <Notification type="button" onClick={clearKickNotification}>
        {kickNotification}
      </Notification>
    </AlertRegion>
  );
};
