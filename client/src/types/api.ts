// API 请求/响应类型

import { Card, Table } from './game';

export interface JoinGameRequest {
  pk_hex: string;
  pk_proof: string;
}

export interface JoinGameResponse {
  gameId: string;
}

export interface ShuffleRequest {
  pk_hex: string;
  output_cards: string[][];
  shuffle_proof: string;
}

export interface JoinAndShuffleRequest {
  pk_hex: string;
  pk_proof: string;
  mask_and_shuffle_round: {
    mask_cards: string[][];
    output_cards: string[][];
    remask_proof: string;
    shuffle_proof: string;
  };
}

export interface PlayerActionRequest {
  action: string;
  amount?: number;
}

export interface RevealTokenRequest {
  pk_hex: string;
  reveal_tokens: string[];
}

export interface AuthWalletRequest {
  address: string;
  signature: string;
  message: string;
}

export interface AuthWalletResponse {
  token: string;
  user: {
    _id: string;
    name: string;
    walletAddress: string;
  };
}

export interface FreeChipsResponse {
  chipsAmount: number;
}
