import { useNavigate } from 'react-router-dom'
import * as S from './SecretPokerHomePage.styles'
import HeroBackdrop from '../components/decoration/HeroBackdrop'
import {
  Lock, Users, Zap, Eye, Shuffle, ArrowRight,
  Award, TrendingUp, Globe, Clock, Sparkles, CheckCircle2, Wallet, Gamepad2
} from 'lucide-react'
import { motion, useInView, useScroll, useTransform } from 'framer-motion'
import { useRef, useState, useEffect, useCallback, useMemo } from 'react'
import { useContentContext } from '../context/content/contentContext'
import UnclaimedFundsBanner from '../components/funds/UnclaimedFundsBanner'

function FadeIn({ children, delay = 0, direction = 'up' }: { children: React.ReactNode; delay?: number; direction?: 'up' | 'down' | 'left' | 'right' }) {
  const ref = useRef(null)
  const isInView = useInView(ref, { once: true, margin: '-100px' })

  const directions = {
    up: { y: 60, x: 0 },
    down: { y: -60, x: 0 },
    left: { y: 0, x: 60 },
    right: { y: 0, x: -60 },
  }

  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, ...directions[direction] }}
      animate={isInView ? { opacity: 1, y: 0, x: 0 } : {}}
      transition={{ duration: 1, delay, ease: [0.22, 1, 0.36, 1] }}
    >
      {children}
    </motion.div>
  )
}

function StaggerContainer({ children }: { children: React.ReactNode }) {
  const ref = useRef(null)
  const isInView = useInView(ref, { once: true, margin: '-80px' })

  return (
    <S.StaggerGrid
      ref={ref}
      initial="hidden"
      animate={isInView ? 'visible' : 'hidden'}
      variants={{
        hidden: {},
        visible: { transition: { staggerChildren: 0.12 } },
      }}
    >
      {children}
    </S.StaggerGrid>
  )
}

function StaggerItem({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return (
    <motion.div
      variants={{
        hidden: { opacity: 0, y: 30 },
        visible: { opacity: 1, y: 0, transition: { duration: 0.8, ease: [0.22, 1, 0.36, 1] } },
      }}
      className={className}
      style={{ height: '100%', display: 'flex', flexDirection: 'column' }}
    >
      {children}
    </motion.div>
  )
}

export default function SecretPokerHomePage() {
  const navigate = useNavigate()
  const { getLocalizedString: t } = useContentContext()
  const heroRef = useRef<HTMLElement | null>(null)
  const sectionRefs = useRef<(HTMLElement | null)[]>([])
  const [activeIndex, setActiveIndex] = useState(0)

  const sections = [
    { id: 'hero', label: t('homepage_nav-home') },
    { id: 'features', label: t('homepage_nav-features') },
    { id: 'value', label: t('homepage_nav-benefits') },
    { id: 'how', label: t('homepage_nav-how') },
    { id: 'cta', label: t('homepage_nav-play') },
    { id: 'footer', label: t('homepage_nav-footer') },
  ]

  const { scrollYProgress } = useScroll({
    target: heroRef,
    offset: ['start start', 'end start'],
  })
  const heroOpacity = useTransform(scrollYProgress, [0, 0.8], [1, 0])
  const heroY = useTransform(scrollYProgress, [0, 1], [0, 80])

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            const index = sectionRefs.current.findIndex((el) => el === entry.target)
            if (index !== -1) {
              setActiveIndex(index)
            }
          }
        })
      },
      { threshold: 0.5 }
    )

    sectionRefs.current.forEach((el) => {
      if (el) observer.observe(el)
    })

    return () => observer.disconnect()
  }, [])

  const handleNavigate = useCallback((index: number) => {
    const el = sectionRefs.current[index]
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' })
    }
  }, [])

  const setSectionRef = useCallback((index: number) => (el: HTMLElement | null) => {
    sectionRefs.current[index] = el
  }, [])

  // Particle positions are randomized once on mount; without useMemo they
  // would be re-randomized on every render, causing the particles to jump.
  const particles = useMemo(() => (
    Array.from({ length: 12 }).map((_, i) => ({
      key: i,
      left: `${15 + Math.random() * 70}%`,
      top: `${15 + Math.random() * 70}%`,
      animationDelay: `${Math.random() * 15}s`,
      animationDuration: `${12 + Math.random() * 16}s`,
      opacity: 0.15 + Math.random() * 0.2,
    }))
  ), [])

  return (
    <S.Home>
      {/* 未领取资金提醒（登录且金库有筹码时常驻）。吸顶导航栏悬于页面
          最上层，槽位负责让出导航高度（Lobby 宿主自带顶部 padding，
          不需要此槽位）。 */}
      <S.FundsBannerSlot>
        <UnclaimedFundsBanner />
      </S.FundsBannerSlot>
      {/* Subtle ambient particles */}
      <S.Particles>
        {particles.map((p) => (
          <S.Particle
            key={p.key}
            style={{
              left: p.left,
              top: p.top,
              animationDelay: p.animationDelay,
              animationDuration: p.animationDuration,
              opacity: p.opacity,
            }}
          />
        ))}
      </S.Particles>

      {/* Hero */}
      <S.Hero ref={(el) => { heroRef.current = el; setSectionRef(0)(el) }}>
        <S.HeroBg>
          <HeroBackdrop />
          <S.HeroGradient />
          <S.HeroOrb $variant={1} />
          <S.HeroOrb $variant={2} />
        </S.HeroBg>
        <S.HeroContent
          style={{ opacity: heroOpacity, y: heroY }}
        >
          <S.HeroBadge
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.1 }}
          >
            <Sparkles size={14} strokeWidth={1.5} />
            <span>{t('homepage_hero-badge')}</span>
          </S.HeroBadge>

          <S.HeroTitle
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 1, delay: 0.2 }}
          >
            {t('homepage_hero-title-1')}<br />
            <S.GradientText>{t('homepage_hero-title-2')}</S.GradientText>
          </S.HeroTitle>

          <S.HeroDesc
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.4 }}
          >
            {t('homepage_hero-desc-1')}{' '}
            {t('homepage_hero-desc-2')}
          </S.HeroDesc>

          <S.HeroActions
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.55 }}
          >
            <S.BtnPrimary
              $lg
              onClick={() => navigate('/lobby')}
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.97 }}
            >
              <Zap size={18} strokeWidth={1.5} />
              {t('homepage_hero-btn-join')}
            </S.BtnPrimary>
            <S.BtnSecondary
              $lg
              onClick={() => handleNavigate(3)}
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.97 }}
            >
              {t('homepage_hero-btn-how')}
              <ArrowRight size={16} strokeWidth={1.5} />
            </S.BtnSecondary>
          </S.HeroActions>

          <S.HeroStats
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 1, delay: 0.8 }}
          >
            <S.Stat>
              <S.StatValue>{t('homepage_stat-server-blind')}</S.StatValue>
              <S.StatLabel>{t('homepage_stat-hidden')}</S.StatLabel>
            </S.Stat>
            <S.StatDivider />
            <S.Stat>
              <S.StatValue>{t('homepage_stat-256bit')}</S.StatValue>
              <S.StatLabel>{t('homepage_stat-e2e')}</S.StatLabel>
            </S.Stat>
            <S.StatDivider />
            <S.Stat>
              <S.StatValue>{t('homepage_stat-100pct')}</S.StatValue>
              <S.StatLabel>{t('homepage_stat-fair')}</S.StatLabel>
            </S.Stat>
          </S.HeroStats>
        </S.HeroContent>
      </S.Hero>

      {/* Features */}
      <S.Section id="features" ref={setSectionRef(1)}>
        <S.Container>
          <FadeIn>
            <S.SectionHeader>
              <S.SectionTag>{t('homepage_features-tag')}</S.SectionTag>
              <S.SectionTitle>{t('homepage_features-title')}</S.SectionTitle>
              <S.SectionSubtitle>
                {t('homepage_features-subtitle-1')}{' '}
                {t('homepage_features-subtitle-2')}
              </S.SectionSubtitle>
            </S.SectionHeader>
          </FadeIn>
          <StaggerContainer>
            {[
              {
                icon: <Lock size={24} strokeWidth={1.5} />,
                title: t('homepage_feature-encrypted-title'),
                desc: t('homepage_feature-encrypted-desc'),
                color: 'felt' as const,
              },
              {
                icon: <Shuffle size={24} strokeWidth={1.5} />,
                title: t('homepage_feature-shuffle-title'),
                desc: t('homepage_feature-shuffle-desc'),
                color: 'play' as const,
              },
              {
                icon: <Eye size={24} strokeWidth={1.5} />,
                title: t('homepage_feature-unlock-title'),
                desc: t('homepage_feature-unlock-desc'),
                color: 'real' as const,
              },
              {
                icon: <Wallet size={24} strokeWidth={1.5} />,
                title: t('homepage_feature-keys-title'),
                desc: t('homepage_feature-keys-desc'),
                color: 'amb' as const,
              },
            ].map((f, i) => (
              <StaggerItem key={i}>
                <S.FeatureCard
                  whileHover={{ y: -6 }}
                  transition={{ duration: 0.4 }}
                >
                  <S.FeatureIcon $tone={f.color}>
                    {f.icon}
                  </S.FeatureIcon>
                  <h3>{f.title}</h3>
                  <p>{f.desc}</p>
                </S.FeatureCard>
              </StaggerItem>
            ))}
          </StaggerContainer>
        </S.Container>
      </S.Section>

      {/* Benefits */}
      <S.Section id="value" $variant="alt" ref={setSectionRef(2)}>
        <S.Container>
          <FadeIn>
            <S.SectionHeader>
              <S.SectionTag>{t('homepage_benefits-tag')}</S.SectionTag>
              <S.SectionTitle>{t('homepage_benefits-title')}</S.SectionTitle>
              <S.SectionSubtitle>
                {t('homepage_benefits-subtitle')}
              </S.SectionSubtitle>
            </S.SectionHeader>
          </FadeIn>
          <StaggerContainer>
            {[
              {
                icon: <Award size={28} strokeWidth={1.5} />,
                title: t('homepage_benefit-auditable-title'),
                desc: t('homepage_benefit-auditable-desc'),
                stat: t('homepage_benefit-auditable-stat'),
                statLabel: t('homepage_benefit-auditable-label'),
                color: 'amb' as const,
              },
              {
                icon: <Globe size={28} strokeWidth={1.5} />,
                title: t('homepage_benefit-instant-title'),
                desc: t('homepage_benefit-instant-desc'),
                stat: t('homepage_benefit-instant-stat'),
                statLabel: t('homepage_benefit-instant-label'),
                color: 'play' as const,
              },
              {
                icon: <TrendingUp size={28} strokeWidth={1.5} />,
                title: t('homepage_benefit-fee-title'),
                desc: t('homepage_benefit-fee-desc'),
                stat: t('homepage_benefit-fee-stat'),
                statLabel: t('homepage_benefit-fee-label'),
                color: 'felt' as const,
              },
              {
                icon: <Clock size={28} strokeWidth={1.5} />,
                title: t('homepage_benefit-uptime-title'),
                desc: t('homepage_benefit-uptime-desc'),
                stat: t('homepage_benefit-uptime-stat'),
                statLabel: t('homepage_benefit-uptime-label'),
                color: 'real' as const,
              },
            ].map((item, i) => (
              <StaggerItem key={i}>
                <S.ValueCard
                  whileHover={{ y: -4 }}
                  transition={{ duration: 0.4 }}
                >
                  <S.ValueHeader>
                    <S.ValueIcon $tone={item.color}>
                      {item.icon}
                    </S.ValueIcon>
                    <S.ValueStat>
                      <S.StatNumber style={{ color: item.color }}>{item.stat}</S.StatNumber>
                      <S.StatDesc>{item.statLabel}</S.StatDesc>
                    </S.ValueStat>
                  </S.ValueHeader>
                  <h3>{item.title}</h3>
                  <p>{item.desc}</p>
                </S.ValueCard>
              </StaggerItem>
            ))}
          </StaggerContainer>
        </S.Container>
      </S.Section>

      {/* How It Works */}
      <S.Section id="how" $variant="how" ref={setSectionRef(3)}>
        <S.Container>
          <FadeIn>
            <S.SectionHeader>
              <S.SectionTag>{t('homepage_how-tag')}</S.SectionTag>
              <S.SectionTitle>{t('homepage_how-title')}</S.SectionTitle>
              <S.SectionSubtitle>
                {t('homepage_how-subtitle')}
              </S.SectionSubtitle>
            </S.SectionHeader>
          </FadeIn>
          <S.ProtocolFlow>
            {[
              {
                step: '01',
                title: t('homepage_step-lock-title'),
                desc: t('homepage_step-lock-desc'),
                icon: <Lock size={18} strokeWidth={1.5} />,
              },
              {
                step: '02',
                title: t('homepage_step-shuffle-title'),
                desc: t('homepage_step-shuffle-desc'),
                icon: <Shuffle size={18} strokeWidth={1.5} />,
              },
              {
                step: '03',
                title: t('homepage_step-deal-title'),
                desc: t('homepage_step-deal-desc'),
                icon: <Gamepad2 size={18} strokeWidth={1.5} />,
              },
              {
                step: '04',
                title: t('homepage_step-reveal-title'),
                desc: t('homepage_step-reveal-desc'),
                icon: <Eye size={18} strokeWidth={1.5} />,
              },
              {
                step: '05',
                title: t('homepage_step-community-title'),
                desc: t('homepage_step-community-desc'),
                icon: <Users size={18} strokeWidth={1.5} />,
              },
              {
                step: '06',
                title: t('homepage_step-verify-title'),
                desc: t('homepage_step-verify-desc'),
                icon: <CheckCircle2 size={18} strokeWidth={1.5} />,
              },
            ].map((s, i) => (
              <FadeIn key={i} delay={i * 0.1} direction="up">
                <S.ProtocolStep>
                  <S.StepNumber>
                    <S.StepNum>{s.step}</S.StepNum>
                    <S.StepIcon>{s.icon}</S.StepIcon>
                  </S.StepNumber>
                  <S.StepContent>
                    <h3>{s.title}</h3>
                    <p>{s.desc}</p>
                  </S.StepContent>
                  {i < 5 && <S.StepLine />}
                </S.ProtocolStep>
              </FadeIn>
            ))}
          </S.ProtocolFlow>
        </S.Container>
      </S.Section>

      {/* CTA */}
      <S.Section $variant="cta" ref={setSectionRef(4)}>
        <S.Container>
          <FadeIn>
            <S.CTAContent>
              <h2>{t('homepage_cta-title')}</h2>
              <p>{t('homepage_cta-desc')}</p>
              <S.BtnPrimary
                $lg
                onClick={() => navigate('/lobby')}
                whileHover={{ scale: 1.03 }}
                whileTap={{ scale: 0.97 }}
              >
                <Sparkles size={18} strokeWidth={1.5} />
                {t('homepage_cta-btn')}
              </S.BtnPrimary>
            </S.CTAContent>
          </FadeIn>
        </S.Container>
      </S.Section>

      <S.Footer ref={setSectionRef(5)}>
        <S.Container>
          <S.FooterContent>
            <S.FooterBrand>
              <span>🃏 {t('homepage_footer-brand')}</span>
              <p>{t('homepage_footer-tagline')}</p>
            </S.FooterBrand>
            <S.FooterLinks>
              <S.FooterLink
                onClick={() => navigate('/lobby')}
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                {t('homepage_footer-lobby')}
              </S.FooterLink>
              <S.FooterLink
                onClick={() => navigate('/whitepaper')}
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                {t('homepage_footer-whitepaper')}
              </S.FooterLink>
            </S.FooterLinks>
            <S.FooterTech>
              <span>{t('homepage_footer-built-with')}</span>
              <S.TechTags>
                {['Rust', 'React', 'WebAssembly', 'Cryptography'].map((tag) => (
                  <motion.span
                    key={tag}
                    whileHover={{ scale: 1.1, y: -2 }}
                    transition={{ duration: 0.2 }}
                  >
                    {tag}
                  </motion.span>
                ))}
              </S.TechTags>
            </S.FooterTech>
            <S.FooterRef>
              <span>{t('homepage_footer-based-on')}</span>
              <a href="https://github.com/linqining/mental-poker-rust" target="_blank" rel="noopener noreferrer">
                {t('homepage_footer-ref-text')}
              </a>
            </S.FooterRef>
          </S.FooterContent>
        </S.Container>
      </S.Footer>

      <S.ScrollNav>
        {sections.map((s, i) => (
          <S.ScrollDot
            key={s.id}
            $active={i === activeIndex}
            onClick={() => handleNavigate(i)}
            aria-label={s.label}
          >
            <S.ScrollLabel>{s.label}</S.ScrollLabel>
          </S.ScrollDot>
        ))}
      </S.ScrollNav>
    </S.Home>
  )
}
