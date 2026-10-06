import { useMemo, useEffect, useState } from 'react'
import styled, { keyframes, css } from 'styled-components'
import { Spade, Club, Heart, Diamond } from 'lucide-react'

/* ============================================================
   HeroBackdrop
   ------------------------------------------------------------
   Decorative layer that sits inside the Hero <S.HeroBg> tree.
   Renders 3 stacked visual elements behind the hero copy:

     1. <TextureLayer>  — full-bleed tiled bubbles.svg at low
        opacity, mixed via multiply so the gradient below it
        stays legible.
     2. <SuitParticles> — 4 lucide-react playing-card suit icons
        (Spade/Heart/Diamond/Club) that drift slowly in the
        background corners. They are pointer-events:none and
        aria-hidden, so they don't interfere with content.
     3. <Vignette>      — soft radial overlay that draws the
        eye toward the center copy.

   All assets are local (no network requests at runtime):
     - /textures/bubbles.svg  (inline-authored, brand-tinted)
     - lucide-react (already a project dep, MIT-licensed)
   ============================================================ */

const floatA = keyframes`
  0%   { transform: translate3d(0, 0, 0) rotate(0deg); }
  50%  { transform: translate3d(20px, -25px, 0) rotate(8deg); }
  100% { transform: translate3d(0, 0, 0) rotate(0deg); }
`

const floatB = keyframes`
  0%   { transform: translate3d(0, 0, 0) rotate(0deg); }
  50%  { transform: translate3d(-25px, 18px, 0) rotate(-10deg); }
  100% { transform: translate3d(0, 0, 0) rotate(0deg); }
`

const floatC = keyframes`
  0%   { transform: translate3d(0, 0, 0) rotate(0deg); }
  50%  { transform: translate3d(15px, 20px, 0) rotate(12deg); }
  100% { transform: translate3d(0, 0, 0) rotate(0deg); }
`

const floatD = keyframes`
  0%   { transform: translate3d(0, 0, 0) rotate(0deg); }
  50%  { transform: translate3d(-18px, -22px, 0) rotate(-7deg); }
  100% { transform: translate3d(0, 0, 0) rotate(0deg); }
`

const TextureLayer = styled.div`
  position: absolute;
  inset: 0;
  pointer-events: none;
  background-image: url('/textures/bubbles.svg');
  background-repeat: repeat;
  background-size: 80px 80px;
  opacity: 0.07;
  mix-blend-mode: multiply;
  z-index: 0;

  /* Hide the texture entirely for users who request reduced motion
     and on very small viewports where the particles also disappear —
     keeps first paint cheap on low-end devices. */
  @media (prefers-reduced-motion: reduce) {
    opacity: 0.05;
  }
`

const SuitParticle = styled.span<{
  $anim: ReturnType<typeof keyframes>
  $top: string
  $left: string
  $size: number
  $delay: string
  $color: string
  $duration: string
}>`
  position: absolute;
  top: ${({ $top }) => $top};
  left: ${({ $left }) => $left};
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: ${({ $size }) => `${$size}px`};
  height: ${({ $size }) => `${$size}px`};
  color: ${({ $color }) => $color};
  opacity: 0.22;
  pointer-events: none;
  user-select: none;
  filter: none;
  animation: ${({ $anim }) => $anim} ${({ $duration }) => $duration} ease-in-out infinite;
  animation-delay: ${({ $delay }) => $delay};
  will-change: transform;

  svg {
    width: 100%;
    height: 100%;
  }

  /* Mobile: hide the suit particles — the texture alone is enough. */
  @media screen and (max-width: 1023px) {
    display: none;
  }

  @media (prefers-reduced-motion: reduce) {
    animation: none;
  }
`

const Vignette = styled.div`
  position: absolute;
  inset: 0;
  pointer-events: none;
  z-index: 0;
  background: radial-gradient(
    ellipse at center,
    transparent 50%,
    rgba(15, 23, 42, 0.06) 100%
  );
`

interface SuitSpec {
  Icon: typeof Spade
  $anim: ReturnType<typeof keyframes>
  $top: string
  $left: string
  $size: number
  $delay: string
  $duration: string
  $color: string
}

const SUIT_SPECS: SuitSpec[] = [
  // Spade — top-left, ledger real-gold
  {
    Icon: Spade,
    $anim: floatA,
    $top: '12%',
    $left: '8%',
    $size: 64,
    $delay: '0s',
    $duration: '14s',
    $color: 'rgba(125, 83, 8, 0.55)',
  },
  // Heart — top-right, indigo
  {
    Icon: Heart,
    $anim: floatB,
    $top: '18%',
    $left: '82%',
    $size: 56,
    $delay: '-3s',
    $duration: '16s',
    $color: 'rgba(11, 107, 69, 0.5)',
  },
  // Diamond — bottom-right, ledger real-gold light
  {
    Icon: Diamond,
    $anim: floatC,
    $top: '72%',
    $left: '78%',
    $size: 52,
    $delay: '-6s',
    $duration: '18s',
    $color: 'rgba(125, 83, 8, 0.35)',
  },
  // Club — bottom-left, indigo
  {
    Icon: Club,
    $anim: floatD,
    $top: '70%',
    $left: '10%',
    $size: 60,
    $delay: '-9s',
    $duration: '15s',
    $color: 'rgba(75, 72, 64, 0.45)',
  },
]

export default function HeroBackdrop() {
  // Memoize spec list so the four SuitParticles don't re-mount on every
  // parent re-render (which would restart their CSS animations).
  const suits = useMemo(() => SUIT_SPECS, [])

  // Avoid hydration mismatches if SSR is ever added — only render the
  // floating suits after the first client mount.
  const [mounted, setMounted] = useState(false)
  useEffect(() => {
    setMounted(true)
  }, [])

  return (
    <>
      <TextureLayer aria-hidden="true" />
      {mounted &&
        suits.map((s, i) => {
          const { Icon, ...rest } = s
          return (
            <SuitParticle key={i} {...rest} aria-hidden="true">
              <Icon strokeWidth={1.4} aria-hidden="true" />
            </SuitParticle>
          )
        })}
      <Vignette aria-hidden="true" />
    </>
  )
}

// Re-export keyframes for tests / future reuse; suppressed by tree-shake
// in production builds.
export const heroBackdropKeyframes = css`
  ${floatA}
  ${floatB}
  ${floatC}
  ${floatD}
`
