import { useContext } from 'react';
import { useNavigate } from 'react-router-dom';
import styled from 'styled-components';
import { useGlobalContext } from '../context/global/globalContext';
import { useContentContext } from '../context/content/contentContext';
import { useModalContext } from '../context/modal/modalContext';
import authContext from '../context/auth/authContext';
import Text from '../components/typography/Text';
import { PlayerName } from '../components/game/PlayerName';
import UnclaimedFundsBanner from '../components/funds/UnclaimedFundsBanner';

/* ===== Styled Components ===== */

const PageWrapper = styled.div`
  min-height: 100dvh;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: flex-end;
  background: ${({ theme }) => theme.colors.fontColorLight};
  /* 顶部避让吸顶导航栏（theme.other.navHeight） */
  padding: calc(${({ theme }) => theme.other.navHeight} + 0.75rem) 1.5rem 2rem;

  @media screen and (max-width: 468px) {
    padding: calc(${({ theme }) => theme.other.navHeight} + 0.5rem) 1rem 2rem;
  }

  @media screen and (max-width: 900px) and (max-height: 450px) and (orientation: landscape) {
    justify-content: center;
  }
`;

const WelcomeHeading = styled.h2`
  font-family: 'Inter', -apple-system, sans-serif;
  font-size: 1.6rem;
  font-weight: 700;
  text-align: center;
  color: ${({ theme }) => theme.colors.fontColorDark};
  margin: 2rem auto;
  letter-spacing: -0.02em;

  span {
    background: ${({ theme }) => theme.colors.primaryCta};
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }

  @media screen and (max-width: 468px) {
    font-size: 1.3rem;
  }

  @media screen and (max-width: 900px) and (max-height: 450px) and (orientation: landscape) {
    display: none;
  }
`;

const MenuGrid = styled.div`
  margin: 0 0 auto 0;
  display: grid;
  justify-content: center;
  align-content: center;
  grid-template-columns: repeat(2, minmax(250px, auto));
  grid-template-rows: repeat(2, minmax(250px, auto));
  grid-gap: 1.5rem;
  max-width: 600px;

  @media screen and (max-width: 900px) and (max-height: 450px) and (orientation: landscape) {
    grid-template-columns: repeat(4, 140px);
    grid-template-rows: repeat(1, minmax(140px, auto));
    grid-gap: 1rem;
  }

  @media screen and (max-width: 590px) and (max-height: 420px) and (orientation: landscape) {
    grid-template-columns: repeat(4, 120px);
    grid-template-rows: repeat(1, minmax(120px, auto));
    grid-gap: 1rem;
  }

  @media screen and (max-width: 468px) {
    grid-template-columns: repeat(1, auto);
    grid-template-rows: repeat(4, auto);
    grid-gap: 1rem;
  }
`;

/* button 而非 div onClick：键盘/读屏用户也能进入游戏（WCAG 2.1.1）。
   reset 浏览器默认按钮样式以保持原视觉。 */
const MenuCard = styled.button`
  appearance: none;
  display: flex;
  flex-direction: column;
  justify-content: flex-start;
  align-items: center;
  text-align: center;
  font-family: inherit;
  cursor: pointer;
  background: ${({ theme }) => theme.colors.lightestBg};
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-radius: ${({ theme }) => theme.radius.sm};
  padding: 1.5rem 2rem;
  box-shadow: none;
  transition:
    border-color 0.35s cubic-bezier(0.22, 1, 0.36, 1),
    transform 0.35s cubic-bezier(0.22, 1, 0.36, 1),
    box-shadow 0.35s cubic-bezier(0.22, 1, 0.36, 1);

  &,
  & > * {
    user-select: none;
    -moz-user-select: none;
    -khtml-user-select: none;
    -webkit-user-select: none;
    -o-user-select: none;
  }

  &:hover {
    border-color: rgba(11, 107, 69, 0.4);
    transform: translateY(-3px);
    box-shadow: 0 12px 40px rgba(0, 0, 0, 0.08);
  }

  h3 {
    font-family: 'Inter', -apple-system, sans-serif;
    font-size: 1rem;
    font-weight: 700;
    color: ${({ theme }) => theme.colors.secondaryCta};
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin: 0;
    word-wrap: break-word;
  }

  img {
    margin: 1rem;
    width: 75%;
    max-width: 170px;
    height: auto;
    opacity: 0.9;
  }

  @media screen and (min-width: 648px) {
    font-size: 3rem;
  }

  @media screen and (max-width: 648px) {
    padding: 0.5rem;
  }

  @media screen and (max-width: 468px) {
    flex-direction: row;
    justify-content: space-between;
    border-radius: 90px 40px 40px 90px;
    padding: 0 1rem 0 0;

    h3 {
      text-align: right;
      margin: 0 1rem;
      font-size: 0.9rem;
    }

    img {
      max-width: 80px;
      margin: 0;
    }
  }
`;


/* 大厅菜单图形（design/client C2 改动 #1）：人物 PNG → 牌面字面。
   A♠ K♠ Q♠ J♠ 与牌桌稿同一套符号——零图片、零加载、零版权资产。 */
const CardFaceWrap = styled.span<{ $red: boolean }>`
  display: inline-flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  width: 120px;
  height: 128px;
  margin: 1rem;
  background: ${({ theme }) => theme.colors.lightestBg};
  border: 1px solid ${({ theme }) => theme.colors.borderMuted};
  border-radius: 6px;
  box-shadow: ${({ theme }) => theme.other.cardDropShadow};
  color: ${({ $red, theme }) => ($red ? theme.colors.danger : theme.colors.fontColorDark)};
  flex: none;

  @media screen and (max-width: 468px) {
    width: 64px;
    height: 72px;
    margin: 0.4rem;
    .rank {
      font-size: 1.5rem;
    }
    .suit {
      font-size: 1.1rem;
    }
  }
`;
const CardRank = styled.span`
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-variant-numeric: tabular-nums;
  font-size: 2.6rem;
  font-weight: 700;
  line-height: 1;
`;
const CardSuit = styled.span`
  font-size: 1.8rem;
  line-height: 1.15;
`;

const CardDesc = styled.p`
  margin: 0.25rem 0 0;
  font-size: 0.8rem;
  color: ${({ theme }) => theme.colors.mutedText};
  line-height: 1.5;
`;

const CardFoot = styled.span`
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 9.5px;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: ${({ theme }) => theme.colors.success};
  border-top: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  margin-top: 0.75rem;
  padding-top: 0.55rem;
  width: 100%;
`;

const LobbyMeta = styled.div`
  margin-top: 1.5rem;
  text-align: center;
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 9.5px;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: ${({ theme }) => theme.colors.softerText};
`;

const MenuCardFace: React.FC<{ rank: string; suit: string; red?: boolean }> = ({ rank, suit, red }) => (
  <CardFaceWrap $red={!!red} aria-hidden>
    <CardRank className="rank">{rank}</CardRank>
    <CardSuit className="suit">{suit}</CardSuit>
  </CardFaceWrap>
);

/* ===== Component ===== */

export default function Lobby() {
  const navigate = useNavigate();
  const { userName } = useGlobalContext();
  const { getLocalizedString } = useContentContext();
  const { openModal, closeModal } = useModalContext();
  const { isLoggedIn, walletAddress } = useContext(authContext)!;
  const hasWallet = !!walletAddress;

  const requireAuthAndNavigate = () => {
    if (!isLoggedIn && !hasWallet) {
      openModal(
        () => <Text textAlign="center">{getLocalizedString('game_login-required_text')}</Text>,
        getLocalizedString('login_page-header_txt'),
        getLocalizedString('navbar-login_btn'),
        () => {
          closeModal();
          navigate('/', { state: { showLogin: true } });
        },
      );
      return;
    }
    navigate('/play');
  };

  return (
    <PageWrapper>
      <UnclaimedFundsBanner />
      <WelcomeHeading>
        {getLocalizedString('main_page-salutation')}{' '}
        <span><PlayerName name={userName ?? getLocalizedString('main_page-guest-name')} />!</span>
      </WelcomeHeading>

      <MenuGrid>
        <MenuCard type="button" onClick={requireAuthAndNavigate}>
          <MenuCardFace rank="A" suit="♠" />
          <h3>{getLocalizedString('main_page-join_table').toUpperCase()}</h3>
          <CardDesc>{getLocalizedString('lobby_desc-join_table')}</CardDesc>
          <CardFoot>{getLocalizedString('lobby_foot-join_table')}</CardFoot>
        </MenuCard>

        <MenuCard type="button" onClick={requireAuthAndNavigate}>
          <MenuCardFace rank="K" suit="♠" />
          <h3>{getLocalizedString('main_page-quick_game').toUpperCase()}</h3>
          <CardDesc>{getLocalizedString('lobby_desc-quick_game')}</CardDesc>
          <CardFoot>{getLocalizedString('lobby_foot-quick_game')}</CardFoot>
        </MenuCard>

        <MenuCard
          type="button"
          onClick={() => {
            openModal(
              () => (
                <Text textAlign="center">
                  {getLocalizedString('main_page-modal_text')}
                </Text>
              ),
              getLocalizedString('main_page-modal_heading'),
              getLocalizedString('main_page-modal_button_text'),
            );
          }}
        >
          <MenuCardFace rank="Q" suit="♥" red />
          <h3>{getLocalizedString('main_page-open_shop').toUpperCase()}</h3>
          <CardDesc>{getLocalizedString('lobby_desc-open_shop')}</CardDesc>
          <CardFoot>{getLocalizedString('lobby_foot-open_shop')}</CardFoot>
        </MenuCard>

        <MenuCard type="button" onClick={() => navigate('/game-rules')}>
          <MenuCardFace rank="J" suit="♣" />
          <h3>{getLocalizedString('main_page-open_rules').toUpperCase()}</h3>
          <CardDesc>{getLocalizedString('lobby_desc-open_rules')}</CardDesc>
          <CardFoot>{getLocalizedString('lobby_foot-open_rules')}</CardFoot>
        </MenuCard>
      </MenuGrid>
      <LobbyMeta>{getLocalizedString('lobby_meta-connected')} · {window.location.host}</LobbyMeta>
    </PageWrapper>
  );
}
