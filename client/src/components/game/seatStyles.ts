import styled from 'styled-components';

/**
 * 空座位的基础样式组件。
 * 从 Seat.tsx 抽出独立文件，避免 Seat.tsx 与 OccupiedSeat.tsx 之间的循环依赖
 * （Seat 导入 OccupiedSeat，OccupiedSeat 又需要 EmptySeat 做 styled 继承）。
 */
export const EmptySeat = styled.div`
  display: flex;
  justify-content: center;
  align-items: center;
  text-align: center;
  width: 120px;
  height: 120px;
  padding: 1rem;
  border-radius: 100%;
  background: rgba(247, 242, 220, 0.8);
  border: 5px solid #6297b5;
  transition:
    background-color 0.1s ease,
    border-color 0.1s ease,
    transform 0.1s ease;

  p {
    margin-bottom: 0;
  }
`;
