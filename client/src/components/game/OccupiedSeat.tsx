import React, { useEffect, useState } from 'react';
import styled from 'styled-components';
import userImages from './userImages';
import { EmptySeat } from './seatStyles';

interface OccupiedSeatProps {
  hasTurn: boolean;
  seatNumber: number;
  /** 回合截止时间（epoch ms，服务端 bettingStartedAt + bettingTimeoutMs）；
   * 缺省回退旧的 15s CSS 无限环（与服务端未下发计时时钟的旧行为一致）。 */
  deadlineMs?: number | null;
  /** 回合计时总长（ms），用于计算环的进度比例 */
  totalMs?: number | null;
}

interface StyledOccupiedSeatProps {
  seatNumber: number;
  hasTurn: boolean;
}

const RING_RADIUS = 58;
const RING_CIRCUMFERENCE = 2 * Math.PI * RING_RADIUS;

/** 线性读数 + SVG 进度环：与真实剩余时间绑定（T-09 等宽读数，设计稿 T2/T3） */
const TurnCountdown: React.FC<{ deadlineMs: number; totalMs: number }> = ({
  deadlineMs,
  totalMs,
}) => {
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const iv = setInterval(() => setNow(Date.now()), 200);
    return () => clearInterval(iv);
  }, [deadlineMs]);

  const total = totalMs > 0 ? totalMs : 15000;
  const remaining = Math.max(deadlineMs - now, 0);
  const frac = Math.min(remaining / total, 1);
  const secs = Math.ceil(remaining / 1000);
  const color = frac > 0.33 ? '#219653' : frac > 0.15 ? '#f39c12' : '#c0392b';

  return (
    <div className="circle-timer">
      <svg width="130" height="130" viewBox="0 0 130 130">
        <circle
          cx="65"
          cy="65"
          r={RING_RADIUS}
          fill="none"
          stroke="rgba(33, 150, 83, 0.25)"
          strokeWidth="10"
        />
        <circle
          cx="65"
          cy="65"
          r={RING_RADIUS}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeDasharray={RING_CIRCUMFERENCE}
          strokeDashoffset={RING_CIRCUMFERENCE * (1 - frac)}
          transform="rotate(-90 65 65)"
        />
        <text
          x="65"
          y="74"
          textAnchor="middle"
          fill="#fff"
          stroke="rgba(0,0,0,0.55)"
          strokeWidth="3"
          style={{ paintOrder: 'stroke' }}
          fontSize="30"
          fontFamily="'JetBrains Mono', ui-monospace, monospace"
          fontWeight="700"
        >
          T-{String(Math.min(secs, 99)).padStart(2, '0')}
        </text>
      </svg>
    </div>
  );
};

const StyledOccupiedSeat = styled(EmptySeat).withConfig({
  shouldForwardProp: (prop) => !['seatNumber', 'hasTurn'].includes(prop),
})<StyledOccupiedSeatProps>`
  position: relative;
  background-image: ${({ seatNumber }) => `url(${userImages[seatNumber]})`};
  background-position: center;
  background-size: cover;
  background-repeat: no-repeat;
  padding: 0;
  border: ${({ hasTurn }) => (hasTurn ? `none` : `5px solid #6297b5`)};
  transition:
    border-color 0.3s ease,
    transform 0.3s ease;
  transform-origin: center center;
  -webkit-backface-visibility: hidden;
  backface-visibility: hidden;

  &.hasTurn {
    animation: double-pulse 0.5s forwards;
  }

  .circle-timer {
    display: flex;
    justify-content: center;
    align-items: center;
    width: 130px;
    height: 130px;
    text-align: center;
    position: absolute;
    z-index: 4;

    .timer-slot {
      position: relative;
      width: 130px;
      height: 130px;
      display: inline-block;
      overflow: hidden;

      .timer-lt,
      .timer-rt {
        border-radius: 50%;
        position: relative;
        top: 50%;
        left: 0;
        z-index: 15;
        border: 10px solid #219653;
        width: 120px;
        height: 120px;
        margin-left: -60px;
        margin-top: -60px;
        border-left-color: transparent;
        border-top-color: transparent;
        z-index: 5;
      }
      .timer-lt {
        animation: 15s linear infinite timer-slide-lt;
        left: 100%;
      }
      .timer-rt {
        animation: 15s linear infinite timer-slide-rt;
      }
    }
  }

  @keyframes double-pulse {
    0% {
      transform: scale(1);
    }

    25% {
      transform: scale(1.5);
    }

    50% {
      transform: scale(1);
    }

    75% {
      transform: scale(1.5);
    }

    100% {
      transform: scale(1.1);
    }
  }

  @keyframes timer-slide-lt {
    0% {
      transform: rotate(135deg);
    }
    50% {
      transform: rotate(135deg);
    }
    100% {
      transform: rotate(315deg);
    }
  }
  @keyframes timer-slide-rt {
    0% {
      transform: rotate(-45deg);
    }
    50% {
      transform: rotate(135deg);
    }
    100% {
      transform: rotate(135deg);
    }
  }
`;

export const OccupiedSeat: React.FC<OccupiedSeatProps> = ({
  hasTurn,
  seatNumber,
  deadlineMs,
  totalMs,
}) => (
  <StyledOccupiedSeat
    hasTurn={hasTurn}
    seatNumber={seatNumber}
    className={hasTurn ? 'hasTurn' : ''}
  >
    {hasTurn &&
      (deadlineMs && deadlineMs > 0 ? (
        <TurnCountdown deadlineMs={deadlineMs} totalMs={totalMs ?? 15000} />
      ) : (
        // 服务端未下发计时：回退旧的表现环（不与真实时间绑定）
        <div className="circle-timer">
          <div className="timer-slot">
            <div className="timer-lt"></div>
          </div>
          <div className="timer-slot">
            <div className="timer-rt"></div>
          </div>
        </div>
      ))}
  </StyledOccupiedSeat>
);
