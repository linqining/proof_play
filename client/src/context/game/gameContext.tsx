import { createContext } from 'react';
import { GameContextType } from '../../types/game';

const gameContext = createContext<GameContextType | undefined>(undefined);

export default gameContext;
