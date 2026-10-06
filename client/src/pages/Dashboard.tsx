import React, { useContext } from 'react';
import { Link } from 'react-router-dom';
import Button from '../components/buttons/Button';
import { Input } from '../components/forms/Input';
import styled from 'styled-components';
import LogoWithText from '../components/logo/LogoWithText';
import { useGlobalContext } from '../context/global/globalContext';
import { useContentContext } from '../context/content/contentContext';

const PageWrapper = styled.div`
  min-height: 100dvh;
  display: flex;
  align-items: center;
  justify-content: center;
  /* 账簿纸白（原冷灰 #f1f5f9 残留清除） */
  background: ${({ theme }) => theme.colors.lightBg};
  padding: 2rem;
`;

const DashboardCard = styled.div`
  width: 100%;
  max-width: 600px;
  background: ${({ theme }) => theme.colors.lightestBg};
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-radius: ${({ theme }) => theme.radius.sm};
  padding: 2.5rem 2rem;
`;

const LogoWrapper = styled.div`
  display: flex;
  justify-content: center;
  margin-bottom: 2rem;
`;

const FormTitle = styled.h2`
  font-family: 'Inter', -apple-system, sans-serif;
  font-size: 1.5rem;
  font-weight: 700;
  text-align: center;
  color: ${({ theme }) => theme.colors.fontColorDark};
  margin-bottom: 2rem;
  letter-spacing: -0.02em;
`;

const Wrapper = styled.div`
  display: grid;
  grid-template-columns: 1fr 1fr;
  grid-gap: 1.25rem;
  margin-bottom: 1.5rem;

  @media screen and (max-width: 624px) {
    display: flex;
    flex-direction: column;
    gap: 1.25rem;
  }
`;

const FormGroup = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
`;

const StyledLabel = styled.label`
  font-size: 0.85rem;
  color: #475569;
  font-weight: 500;
`;

const StyledInput = styled(Input)`
  background: ${({ theme }) => theme.colors.lightestBg} !important;
  border: 1px solid rgba(203, 213, 225, 0.8) !important;
  border-radius: 10px !important;
  color: ${({ theme }) => theme.colors.fontColorDark} !important;
  height: 44px;
  font-size: 1rem;

  &:focus {
    border-color: ${({ theme }) => theme.colors.secondaryCta} !important;
    box-shadow: 0 0 0 3px rgba(11, 107, 69, 0.15);
  }
`;

/* 改昵称/改邮箱/重置密码/删除账户按钮曾在此渲染，但从未接入任何后端
   动作（纯死按钮，删除账户甚至是危险误导）。待对应 API 落地后再以
   Button variant 补回。 */
const BackButton = styled(Button)`
  background: transparent !important;
  color: #64748b !important;
  border: 1px solid rgba(203, 213, 225, 0.8) !important;
  border-radius: 10px !important;
  font-weight: 500 !important;
  height: 40px;
  transition:
    border-color 0.25s ease,
    color 0.25s ease !important;

  &:hover {
    border-color: rgba(11, 107, 69, 0.4) !important;
    color: ${({ theme }) => theme.colors.secondaryCta} !important;
  }
`;

const FullWidthGroup = styled.div`
  grid-column: 1 / -1;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
`;

const Dashboard: React.FC = () => {
  const { getLocalizedString } = useContentContext();
  const { userName, email } = useGlobalContext();

  return (
    <PageWrapper>
      <DashboardCard>
        <LogoWrapper>
          <LogoWithText />
        </LogoWrapper>
        <FormTitle>{getLocalizedString('dashboard-heading_txt')}</FormTitle>
        <Wrapper>
          <FormGroup>
            <StyledLabel>{getLocalizedString('dashboard-nickname_lbl_txt')}</StyledLabel>
            <StyledInput value={userName ?? ''} readOnly />
          </FormGroup>
          <FormGroup>
            <StyledLabel>{getLocalizedString('dashboard-email_lbl_txt')}</StyledLabel>
            <StyledInput type="email" value={email ?? ''} readOnly />
          </FormGroup>
          <FullWidthGroup>
            <BackButton as={Link} to="/">
              {getLocalizedString('static_page-back_btn_txt')}
            </BackButton>
          </FullWidthGroup>
        </Wrapper>
      </DashboardCard>
    </PageWrapper>
  );
};

export default Dashboard;
