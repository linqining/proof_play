import React, { useLayoutEffect, useState } from 'react';
import styled from 'styled-components';

/**
 * 牌桌舞台 —— 游戏引擎 stage 模型的 DOM 等价物：
 * - 固定设计分辨率（1600×900）排版，内部元素用设计像素定位，
 *   窗口缩放不再触发牌桌重排/折行；
 * - 整体按 min(w/W, h/H) 等比缩放（FIT 模式）+ 居中留边（letterbox）；
 * - transform 缩放后浏览器自动处理命中测试，按钮/表单交互不受影响；
 * - 舞台内的 position:fixed 子元素（如 ZK 面板）以舞台为包含块，
 *   随舞台一起等比缩放。
 *
 * 不引入 canvas/游戏引擎的原因：账簿牌桌是文本密集型 UI（纸卡、等宽
 * 数字、按钮、表单、模态），DOM 渲染的文字清晰度与可访问性远优于
 * canvas 精灵；舞台化已完整获得引擎的缩放语义，引擎仅剩动画收益。
 */
const DESIGN_W = 1600;
const DESIGN_H = 900;

const Backdrop = styled.div`
  position: fixed;
  inset: 0;
  overflow: hidden;
  display: flex;
  align-items: center;
  justify-content: center;
  background: ${({ theme }) => theme.colors.lightBg};
`;

const Stage = styled.div<{ $scale: number }>`
  width: ${DESIGN_W}px;
  height: ${DESIGN_H}px;
  flex: none;
  transform: scale(${({ $scale }) => $scale});
  transform-origin: center center;
`;

export const TableStage: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [scale, setScale] = useState(1);

  useLayoutEffect(() => {
    const compute = () => {
      setScale(Math.min(window.innerWidth / DESIGN_W, window.innerHeight / DESIGN_H));
    };
    compute();
    window.addEventListener('resize', compute);
    window.visualViewport?.addEventListener('resize', compute);
    return () => {
      window.removeEventListener('resize', compute);
      window.visualViewport?.removeEventListener('resize', compute);
    };
  }, []);

  return (
    <Backdrop>
      <Stage $scale={scale}>{children}</Stage>
    </Backdrop>
  );
};

export default TableStage;
