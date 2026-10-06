import { useState } from 'react';

type UseNavMenuReturn = [
  boolean,
  () => void,
  () => void,
];

const useNavMenu = (): UseNavMenuReturn => {
  const [showNavMenu, setShowNavMenu] = useState(false);

  // 账簿语言：遮罩只用纯色暗纱（NavMenuWrapper），不再对背景内容做
  // filter: blur 毛玻璃处理——零玻璃拟态。
  const openNavMenu = (): void => {
    document.body.style.overflow = 'hidden';
    setShowNavMenu(true);
  };

  const closeNavMenu = (): void => {
    document.body.style.overflow = 'initial';
    setShowNavMenu(false);
  };

  return [showNavMenu, openNavMenu, closeNavMenu];
};

export default useNavMenu;
