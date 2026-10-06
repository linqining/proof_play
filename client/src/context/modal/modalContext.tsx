import { createContext, useContext } from 'react';
import React from 'react';

export interface ModalData {
  children: () => React.ReactNode;
  headingText: string;
  btnText: string;
  btnCallBack: () => void;
  onCloseCallBack: () => void;
}

export interface ModalContextType {
  showModal: boolean;
  modalData: ModalData;
  openModal: (
    children: () => React.ReactNode,
    headingText: string,
    btnText: string,
    btnCallBack?: () => void,
    onCloseCallBack?: () => void,
  ) => void;
  closeModal: () => void;
}

const modalContext = createContext<ModalContextType | undefined>(undefined);

export const useModalContext = (): ModalContextType => {
  const context = useContext(modalContext);
  if (context === undefined) {
    throw new Error('useModalContext must be used within a ModalProvider');
  }
  return context;
};

export default modalContext;
