import { createContext } from 'react';
import { Socket } from 'socket.io-client';

export interface SocketContextType {
  socket: Socket | null;
  socketId: string | null;
  isConnected: boolean;
  cleanUp: () => void;
}

const socketContext = createContext<SocketContextType | undefined>(undefined);

export default socketContext;
