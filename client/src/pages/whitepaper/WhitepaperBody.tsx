import React from 'react';
import * as S from './styles';
import LanguageSwitcher from '../../components/navigation/LanguageSwitcher';

/**
 * WhitepaperBody
 * ------------------------------------------------------------------
 * Pure presentational component. All visible text comes from the
 * `t` function the caller provides, so the same body tree is reused
 * across en / zh / de by simply binding `t` to a different locale.
 *
 * AUTH-FREE: this body intentionally never imports `authContext` and
 * uses plain `<a href>` anchors (not `navigate()`) for all in-page
 * navigation. Anonymous visitors can read the entire document without
 * being redirected to the home page with the login modal.
 *
 * The two-page app pattern (three locale files → three components) is
 * the convention the rest of the client uses; see Play.tsx, Dashboard.tsx
 * for similar dot-notation t() lookups.
 */
export interface WhitepaperBodyProps {
  t: (key: string) => string;
}

const WhitepaperBody: React.FC<WhitepaperBodyProps> = ({ t }) => {
  return (
    <S.PageRoot>
      <S.BackTopBar>
        <S.BackLink href="/">← {t('whitepaper.nav.back')}</S.BackLink>
        <S.TopBarGroup>
          <LanguageSwitcher />
          <S.BackLink href="#top">{t('whitepaper.nav.top')}</S.BackLink>
        </S.TopBarGroup>
      </S.BackTopBar>

      <S.Cover id="top">
        <S.CoverBadge>{t('whitepaper.cover.badge')}</S.CoverBadge>
        <S.CoverTitle>
          ZGame
          <br />
          <S.CoverTitleAccent>Zero-Knowledge</S.CoverTitleAccent>
          <br />
          {t('whitepaper.cover.title-line3')}
        </S.CoverTitle>
        <S.CoverSubtitle>{t('whitepaper.cover.subtitle')}</S.CoverSubtitle>
        <S.CoverMeta>{t('whitepaper.cover.meta')}</S.CoverMeta>
      </S.Cover>

      <S.Content>
        <S.Abstract>
          <p>
            <strong>{t('whitepaper.abstract.label')}</strong> — {t('whitepaper.abstract.p1')}
          </p>
          <p>{t('whitepaper.abstract.p2')}</p>
          <p>{t('whitepaper.abstract.p3')}</p>
        </S.Abstract>

        {/* ==================== CHAPTER 1 ==================== */}
        <S.Section>
          <S.ChapterTitle>
            <S.ChapterNumber>01</S.ChapterNumber>
            {t('whitepaper.ch1.title')}
          </S.ChapterTitle>
          <S.SubTitle>{t('whitepaper.ch1.s1.title')}</S.SubTitle>
          <S.Paragraph>{t('whitepaper.ch1.s1.p1')}</S.Paragraph>
          <S.Paragraph>
            <S.Mark>{t('whitepaper.ch1.s1.mark')}</S.Mark>
          </S.Paragraph>
          <S.SubTitle>{t('whitepaper.ch1.s2.title')}</S.SubTitle>
          <S.Paragraph>{t('whitepaper.ch1.s2.p1')}</S.Paragraph>
          <S.Paragraph>{t('whitepaper.ch1.s2.p2')}</S.Paragraph>
          <S.SubTitle>{t('whitepaper.ch1.s3.title')}</S.SubTitle>
          <S.Paragraph>{t('whitepaper.ch1.s3.p1')}</S.Paragraph>
        </S.Section>

        <S.Divider />

        {/* ==================== CHAPTER 2 ==================== */}
        <S.Section>
          <S.ChapterTitle>
            <S.ChapterNumber>02</S.ChapterNumber>
            {t('whitepaper.ch2.title')}
          </S.ChapterTitle>
          <S.SubTitle>{t('whitepaper.ch2.s1.title')}</S.SubTitle>
          <S.Paragraph>{t('whitepaper.ch2.s1.p1')}</S.Paragraph>
          <S.Paragraph>
            <S.Mark>{t('whitepaper.ch2.s1.mark')}</S.Mark>
          </S.Paragraph>
          <S.SubTitle>{t('whitepaper.ch2.s2.title')}</S.SubTitle>
          <S.Paragraph>{t('whitepaper.ch2.s2.p1')}</S.Paragraph>
          <S.Paragraph>
            <S.Mark>{t('whitepaper.ch2.s2.mark')}</S.Mark>
          </S.Paragraph>
          <S.SubTitle>{t('whitepaper.ch2.s3.title')}</S.SubTitle>
          <S.Paragraph>{t('whitepaper.ch2.s3.p1')}</S.Paragraph>
          <S.List>
            <li>
              <strong>{t('whitepaper.ch2.s3.l1.title')}</strong> — {t('whitepaper.ch2.s3.l1.desc')}
            </li>
            <li>
              <strong>{t('whitepaper.ch2.s3.l2.title')}</strong> — {t('whitepaper.ch2.s3.l2.desc')}
            </li>
            <li>
              <strong>{t('whitepaper.ch2.s3.l3.title')}</strong> — {t('whitepaper.ch2.s3.l3.desc')}
            </li>
            <li>
              <strong>{t('whitepaper.ch2.s3.l4.title')}</strong> — {t('whitepaper.ch2.s3.l4.desc')}
            </li>
          </S.List>
          <S.Paragraph>
            <S.Mark>{t('whitepaper.ch2.s3.conclusion')}</S.Mark>
          </S.Paragraph>
          <S.SubTitle>{t('whitepaper.ch2.s4.title')}</S.SubTitle>
          <S.Paragraph>{t('whitepaper.ch2.s4.p1')}</S.Paragraph>
          <S.CardGrid>
            <S.Card>
              <h4>{t('whitepaper.ch2.s4.c1.title')}</h4>
              <p>{t('whitepaper.ch2.s4.c1.desc')}</p>
            </S.Card>
            <S.Card>
              <h4>{t('whitepaper.ch2.s4.c2.title')}</h4>
              <p>{t('whitepaper.ch2.s4.c2.desc')}</p>
            </S.Card>
            <S.Card>
              <h4>{t('whitepaper.ch2.s4.c3.title')}</h4>
              <p>{t('whitepaper.ch2.s4.c3.desc')}</p>
            </S.Card>
          </S.CardGrid>
        </S.Section>

        <S.Divider />

        {/* ==================== CHAPTER 3 ==================== */}
        <S.Section>
          <S.ChapterTitle>
            <S.ChapterNumber>03</S.ChapterNumber>
            {t('whitepaper.ch3.title')}
          </S.ChapterTitle>
          <S.SubTitle>{t('whitepaper.ch3.s1.title')}</S.SubTitle>
          <S.Paragraph>{t('whitepaper.ch3.s1.p1')}</S.Paragraph>
          <S.Pre>
            <S.Code>{t('whitepaper.ch3.s1.code')}</S.Code>
          </S.Pre>
          <S.Paragraph>{t('whitepaper.ch3.s1.p2')}</S.Paragraph>
          <S.SubTitle>{t('whitepaper.ch3.s2.title')}</S.SubTitle>
          <S.Paragraph>{t('whitepaper.ch3.s2.p1')}</S.Paragraph>
          <S.OrderedList>
            <li>
              <strong>{t('whitepaper.ch3.s2.l1.title')}</strong> — {t('whitepaper.ch3.s2.l1.desc')}
            </li>
            <li>
              <strong>{t('whitepaper.ch3.s2.l2.title')}</strong> — {t('whitepaper.ch3.s2.l2.desc')}
            </li>
          </S.OrderedList>
          <S.Paragraph>{t('whitepaper.ch3.s2.p2')}</S.Paragraph>
          <S.SubTitle>{t('whitepaper.ch3.s3.title')}</S.SubTitle>
          <S.Paragraph>{t('whitepaper.ch3.s3.p1')}</S.Paragraph>
          <S.Paragraph>{t('whitepaper.ch3.s3.p2')}</S.Paragraph>
          <S.Pre>
            <S.Code>{t('whitepaper.ch3.s3.code')}</S.Code>
          </S.Pre>
          <S.Paragraph>{t('whitepaper.ch3.s3.p3')}</S.Paragraph>
          <S.SubTitle>{t('whitepaper.ch3.s4.title')}</S.SubTitle>
          <S.Paragraph>{t('whitepaper.ch3.s4.p1')}</S.Paragraph>
          <S.List>
            <li>
              <strong>{t('whitepaper.ch3.s4.l1.title')}</strong> — {t('whitepaper.ch3.s4.l1.desc')}
            </li>
            <li>
              <strong>{t('whitepaper.ch3.s4.l2.title')}</strong> — {t('whitepaper.ch3.s4.l2.desc')}
            </li>
            <li>
              <strong>{t('whitepaper.ch3.s4.l3.title')}</strong> — {t('whitepaper.ch3.s4.l3.desc')}
            </li>
          </S.List>
        </S.Section>

        <S.Divider />

        {/* ==================== CHAPTER 4 ==================== */}
        <S.Section>
          <S.ChapterTitle>
            <S.ChapterNumber>04</S.ChapterNumber>
            {t('whitepaper.ch4.title')}
          </S.ChapterTitle>
          <S.Paragraph>
            <S.Mark>{t('whitepaper.ch4.intro.mark')}</S.Mark>
            {t('whitepaper.ch4.intro.tail')}
          </S.Paragraph>
          <S.ProofCard>
            <h4>1. {t('whitepaper.ch4.p1.title')}</h4>
            <p>{t('whitepaper.ch4.p1.desc')}</p>
          </S.ProofCard>
          <S.ProofCard>
            <h4>2. {t('whitepaper.ch4.p2.title')}</h4>
            <p>{t('whitepaper.ch4.p2.desc')}</p>
          </S.ProofCard>
          <S.ProofCard>
            <h4>3. {t('whitepaper.ch4.p3.title')}</h4>
            <p>{t('whitepaper.ch4.p3.desc')}</p>
          </S.ProofCard>
          <S.ProofCard>
            <h4>4. {t('whitepaper.ch4.p4.title')}</h4>
            <p>{t('whitepaper.ch4.p4.desc')}</p>
          </S.ProofCard>
          <S.ProofCard>
            <h4>5. {t('whitepaper.ch4.p5.title')}</h4>
            <p>{t('whitepaper.ch4.p5.desc')}</p>
          </S.ProofCard>
          <S.ProofCard>
            <h4>6. {t('whitepaper.ch4.p6.title')}</h4>
            <p>{t('whitepaper.ch4.p6.desc')}</p>
          </S.ProofCard>
          <S.SubTitle>{t('whitepaper.ch4.security.title')}</S.SubTitle>
          <S.List>
            <li>{t('whitepaper.ch4.security.l1')}</li>
            <li>{t('whitepaper.ch4.security.l2')}</li>
            <li>{t('whitepaper.ch4.security.l3')}</li>
            <li>{t('whitepaper.ch4.security.l4')}</li>
            <li>{t('whitepaper.ch4.security.l5')}</li>
          </S.List>
        </S.Section>

        <S.Divider />

        {/* ==================== CHAPTER 5 ==================== */}
        <S.Section>
          <S.ChapterTitle>
            <S.ChapterNumber>05</S.ChapterNumber>
            {t('whitepaper.ch5.title')}
          </S.ChapterTitle>
          <S.Paragraph>{t('whitepaper.ch5.p1')}</S.Paragraph>
          <S.TableWrap>
            <S.Table>
              <thead>
                <tr>
                  <th>{t('whitepaper.ch5.table.col1')}</th>
                  <th>{t('whitepaper.ch5.table.col2')}</th>
                  <th>{t('whitepaper.ch5.table.col3')}</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>{t('whitepaper.ch5.table.r1.c1')}</td>
                  <td>{t('whitepaper.ch5.table.r1.c2')}</td>
                  <td>{t('whitepaper.ch5.table.r1.c3')}</td>
                </tr>
                <tr>
                  <td>{t('whitepaper.ch5.table.r2.c1')}</td>
                  <td>{t('whitepaper.ch5.table.r2.c2')}</td>
                  <td>{t('whitepaper.ch5.table.r2.c3')}</td>
                </tr>
                <tr>
                  <td>{t('whitepaper.ch5.table.r3.c1')}</td>
                  <td>{t('whitepaper.ch5.table.r3.c2')}</td>
                  <td>{t('whitepaper.ch5.table.r3.c3')}</td>
                </tr>
                <tr>
                  <td>{t('whitepaper.ch5.table.r4.c1')}</td>
                  <td>{t('whitepaper.ch5.table.r4.c2')}</td>
                  <td>{t('whitepaper.ch5.table.r4.c3')}</td>
                </tr>
                <tr>
                  <td>{t('whitepaper.ch5.table.r5.c1')}</td>
                  <td>{t('whitepaper.ch5.table.r5.c2')}</td>
                  <td>{t('whitepaper.ch5.table.r5.c3')}</td>
                </tr>
                <tr>
                  <td>{t('whitepaper.ch5.table.r6.c1')}</td>
                  <td>{t('whitepaper.ch5.table.r6.c2')}</td>
                  <td>{t('whitepaper.ch5.table.r6.c3')}</td>
                </tr>
                <tr>
                  <td>{t('whitepaper.ch5.table.r7.c1')}</td>
                  <td>{t('whitepaper.ch5.table.r7.c2')}</td>
                  <td>{t('whitepaper.ch5.table.r7.c3')}</td>
                </tr>
                <tr>
                  <td>{t('whitepaper.ch5.table.r8.c1')}</td>
                  <td>{t('whitepaper.ch5.table.r8.c2')}</td>
                  <td>{t('whitepaper.ch5.table.r8.c3')}</td>
                </tr>
                <tr>
                  <td>{t('whitepaper.ch5.table.r9.c1')}</td>
                  <td>{t('whitepaper.ch5.table.r9.c2')}</td>
                  <td>{t('whitepaper.ch5.table.r9.c3')}</td>
                </tr>
                <tr>
                  <td>{t('whitepaper.ch5.table.r10.c1')}</td>
                  <td>{t('whitepaper.ch5.table.r10.c2')}</td>
                  <td>{t('whitepaper.ch5.table.r10.c3')}</td>
                </tr>
                <tr>
                  <td>{t('whitepaper.ch5.table.r11.c1')}</td>
                  <td>{t('whitepaper.ch5.table.r11.c2')}</td>
                  <td>{t('whitepaper.ch5.table.r11.c3')}</td>
                </tr>
                <tr>
                  <td>{t('whitepaper.ch5.table.r12.c1')}</td>
                  <td>{t('whitepaper.ch5.table.r12.c2')}</td>
                  <td>{t('whitepaper.ch5.table.r12.c3')}</td>
                </tr>
              </tbody>
            </S.Table>
          </S.TableWrap>
          <S.SubTitle>{t('whitepaper.ch5.timeout.title')}</S.SubTitle>
          <S.List>
            <li>{t('whitepaper.ch5.timeout.l1')}</li>
            <li>{t('whitepaper.ch5.timeout.l2')}</li>
            <li>{t('whitepaper.ch5.timeout.l3')}</li>
          </S.List>
        </S.Section>

        <S.Divider />

        {/* ==================== CHAPTER 6 ==================== */}
        <S.Section>
          <S.ChapterTitle>
            <S.ChapterNumber>06</S.ChapterNumber>
            {t('whitepaper.ch6.title')}
          </S.ChapterTitle>
          <S.SubTitle>{t('whitepaper.ch6.s1.title')}</S.SubTitle>
          <S.Paragraph>{t('whitepaper.ch6.s1.p1')}</S.Paragraph>
          <S.SubTitle>{t('whitepaper.ch6.s2.title')}</S.SubTitle>
          <S.Paragraph>{t('whitepaper.ch6.s2.p1')}</S.Paragraph>
          <S.OrderedList>
            <li>{t('whitepaper.ch6.s2.l1')}</li>
            <li>{t('whitepaper.ch6.s2.l2')}</li>
            <li>{t('whitepaper.ch6.s2.l3')}</li>
            <li>{t('whitepaper.ch6.s2.l4')}</li>
          </S.OrderedList>
          <S.SubTitle>{t('whitepaper.ch6.s3.title')}</S.SubTitle>
          <S.Paragraph>{t('whitepaper.ch6.s3.p1')}</S.Paragraph>
        </S.Section>

        <S.Divider />

        {/* ==================== CHAPTER 7 ==================== */}
        <S.Section>
          <S.ChapterTitle>
            <S.ChapterNumber>07</S.ChapterNumber>
            {t('whitepaper.ch7.title')}
          </S.ChapterTitle>
          <S.SubTitle>{t('whitepaper.ch7.s1.title')}</S.SubTitle>
          <S.Paragraph>{t('whitepaper.ch7.s1.p1')}</S.Paragraph>
          <S.SubTitle>{t('whitepaper.ch7.s2.title')}</S.SubTitle>
          <S.Paragraph>{t('whitepaper.ch7.s2.p1')}</S.Paragraph>
          <S.SubTitle>{t('whitepaper.ch7.s3.title')}</S.SubTitle>
          <S.Paragraph>{t('whitepaper.ch7.s3.p1')}</S.Paragraph>
          <S.SubTitle>{t('whitepaper.ch7.s4.title')}</S.SubTitle>
          <S.Paragraph>{t('whitepaper.ch7.s4.p1')}</S.Paragraph>
          <S.SubTitle>{t('whitepaper.ch7.s5.title')}</S.SubTitle>
          <S.Paragraph>{t('whitepaper.ch7.s5.p1')}</S.Paragraph>
          <S.SubTitle>{t('whitepaper.ch7.s6.title')}</S.SubTitle>
          <S.Paragraph>{t('whitepaper.ch7.s6.p1')}</S.Paragraph>
        </S.Section>

        <S.Divider />

        {/* ==================== CHAPTER 8 ==================== */}
        <S.Section>
          <S.ChapterTitle>
            <S.ChapterNumber>08</S.ChapterNumber>
            {t('whitepaper.ch8.title')}
          </S.ChapterTitle>
          <S.CardGrid>
            <S.Card>
              <h4>{t('whitepaper.ch8.c1.title')}</h4>
              <p>
                {t('whitepaper.ch8.c1.l1')}
                <br />
                {t('whitepaper.ch8.c1.l2')}
                <br />
                {t('whitepaper.ch8.c1.l3')}
                <br />
                {t('whitepaper.ch8.c1.l4')}
              </p>
            </S.Card>
            <S.Card>
              <h4>{t('whitepaper.ch8.c2.title')}</h4>
              <p>
                {t('whitepaper.ch8.c2.l1')}
                <br />
                {t('whitepaper.ch8.c2.l2')}
                <br />
                {t('whitepaper.ch8.c2.l3')}
                <br />
                {t('whitepaper.ch8.c2.l4')}
              </p>
            </S.Card>
            <S.Card>
              <h4>{t('whitepaper.ch8.c3.title')}</h4>
              <p>
                {t('whitepaper.ch8.c3.l1')}
                <br />
                {t('whitepaper.ch8.c3.l2')}
                <br />
                {t('whitepaper.ch8.c3.l3')}
                <br />
                {t('whitepaper.ch8.c3.l4')}
              </p>
            </S.Card>
            <S.Card>
              <h4>{t('whitepaper.ch8.c4.title')}</h4>
              <p>
                {t('whitepaper.ch8.c4.l1')}
                <br />
                {t('whitepaper.ch8.c4.l2')}
                <br />
                {t('whitepaper.ch8.c4.l3')}
                <br />
                {t('whitepaper.ch8.c4.l4')}
              </p>
            </S.Card>
          </S.CardGrid>
        </S.Section>

        <S.Divider />

        {/* ==================== CHAPTER 9 ==================== */}
        <S.Section>
          <S.ChapterTitle>
            <S.ChapterNumber>09</S.ChapterNumber>
            {t('whitepaper.ch9.title')}
          </S.ChapterTitle>
          <S.TableWrap>
            <S.Table>
              <thead>
                <tr>
                  <th>{t('whitepaper.ch9.table.col1')}</th>
                  <th>{t('whitepaper.ch9.table.col2')}</th>
                  <th>{t('whitepaper.ch9.table.col3')}</th>
                  <th>{t('whitepaper.ch9.table.col4')}</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td rowSpan={3}>{t('whitepaper.ch9.table.r1.c1')}</td>
                  <td>{t('whitepaper.ch9.table.r1.c2')}</td>
                  <td>{t('whitepaper.ch9.table.r1.c3')}</td>
                  <td>{t('whitepaper.ch9.table.r1.c4')}</td>
                </tr>
                <tr>
                  <td>{t('whitepaper.ch9.table.r2.c2')}</td>
                  <td>{t('whitepaper.ch9.table.r2.c3')}</td>
                  <td>{t('whitepaper.ch9.table.r2.c4')}</td>
                </tr>
                <tr>
                  <td>{t('whitepaper.ch9.table.r3.c2')}</td>
                  <td>{t('whitepaper.ch9.table.r3.c3')}</td>
                  <td>{t('whitepaper.ch9.table.r3.c4')}</td>
                </tr>
                <tr>
                  <td rowSpan={4}>{t('whitepaper.ch9.table.r4.c1')}</td>
                  <td>{t('whitepaper.ch9.table.r4.c2')}</td>
                  <td>{t('whitepaper.ch9.table.r4.c3')}</td>
                  <td>{t('whitepaper.ch9.table.r4.c4')}</td>
                </tr>
                <tr>
                  <td>{t('whitepaper.ch9.table.r5.c2')}</td>
                  <td>{t('whitepaper.ch9.table.r5.c3')}</td>
                  <td>{t('whitepaper.ch9.table.r5.c4')}</td>
                </tr>
                <tr>
                  <td>{t('whitepaper.ch9.table.r6.c2')}</td>
                  <td>{t('whitepaper.ch9.table.r6.c3')}</td>
                  <td>{t('whitepaper.ch9.table.r6.c4')}</td>
                </tr>
                <tr>
                  <td>{t('whitepaper.ch9.table.r7.c2')}</td>
                  <td>{t('whitepaper.ch9.table.r7.c3')}</td>
                  <td>{t('whitepaper.ch9.table.r7.c4')}</td>
                </tr>
                <tr>
                  <td rowSpan={5}>{t('whitepaper.ch9.table.r8.c1')}</td>
                  <td>{t('whitepaper.ch9.table.r8.c2')}</td>
                  <td>{t('whitepaper.ch9.table.r8.c3')}</td>
                  <td>{t('whitepaper.ch9.table.r8.c4')}</td>
                </tr>
                <tr>
                  <td>{t('whitepaper.ch9.table.r9.c2')}</td>
                  <td>{t('whitepaper.ch9.table.r9.c3')}</td>
                  <td>{t('whitepaper.ch9.table.r9.c4')}</td>
                </tr>
                <tr>
                  <td>{t('whitepaper.ch9.table.r10.c2')}</td>
                  <td>{t('whitepaper.ch9.table.r10.c3')}</td>
                  <td>{t('whitepaper.ch9.table.r10.c4')}</td>
                </tr>
                <tr>
                  <td>{t('whitepaper.ch9.table.r11.c2')}</td>
                  <td>{t('whitepaper.ch9.table.r11.c3')}</td>
                  <td>{t('whitepaper.ch9.table.r11.c4')}</td>
                </tr>
                <tr>
                  <td>{t('whitepaper.ch9.table.r12.c2')}</td>
                  <td>{t('whitepaper.ch9.table.r12.c3')}</td>
                  <td>{t('whitepaper.ch9.table.r12.c4')}</td>
                </tr>
              </tbody>
            </S.Table>
          </S.TableWrap>
        </S.Section>

        <S.Divider />

        {/* ==================== CHAPTER 10 ==================== */}
        <S.Section>
          <S.ChapterTitle>
            <S.ChapterNumber>10</S.ChapterNumber>
            {t('whitepaper.ch10.title')}
          </S.ChapterTitle>
          <S.SubTitle>{t('whitepaper.ch10.s1.title')}</S.SubTitle>
          <S.Paragraph>{t('whitepaper.ch10.s1.p1')}</S.Paragraph>
          <S.SubTitle>{t('whitepaper.ch10.s2.title')}</S.SubTitle>
          <S.Paragraph>{t('whitepaper.ch10.s2.p1')}</S.Paragraph>
          <S.List>
            <li>
              <strong>{t('whitepaper.ch10.s2.l1.title')}</strong> — {t('whitepaper.ch10.s2.l1.desc')}
            </li>
            <li>
              <strong>{t('whitepaper.ch10.s2.l2.title')}</strong> — {t('whitepaper.ch10.s2.l2.desc')}
            </li>
            <li>
              <strong>{t('whitepaper.ch10.s2.l3.title')}</strong> — {t('whitepaper.ch10.s2.l3.desc')}
            </li>
          </S.List>
          <S.Paragraph>{t('whitepaper.ch10.s2.p2')}</S.Paragraph>
          <S.SubTitle>{t('whitepaper.ch10.s3.title')}</S.SubTitle>
          <S.Paragraph>{t('whitepaper.ch10.s3.p1')}</S.Paragraph>
          <S.CardGrid>
            <S.Card>
              <h4>{t('whitepaper.ch10.s3.c1.title')}</h4>
              <p>{t('whitepaper.ch10.s3.c1.desc')}</p>
            </S.Card>
            <S.Card>
              <h4>{t('whitepaper.ch10.s3.c2.title')}</h4>
              <p>{t('whitepaper.ch10.s3.c2.desc')}</p>
            </S.Card>
            <S.Card>
              <h4>{t('whitepaper.ch10.s3.c3.title')}</h4>
              <p>{t('whitepaper.ch10.s3.c3.desc')}</p>
            </S.Card>
          </S.CardGrid>
          <S.SubTitle>{t('whitepaper.ch10.s4.title')}</S.SubTitle>
          <S.TableWrap>
            <S.TableCompare>
              <thead>
                <tr>
                  <th>{t('whitepaper.ch10.s4.table.col1')}</th>
                  <th>{t('whitepaper.ch10.s4.table.col2')}</th>
                  <th>{t('whitepaper.ch10.s4.table.col3')}</th>
                  <th>{t('whitepaper.ch10.s4.table.col4')}</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>{t('whitepaper.ch10.s4.table.r1.c1')}</td>
                  <td>{t('whitepaper.ch10.s4.table.r1.c2')}</td>
                  <td>{t('whitepaper.ch10.s4.table.r1.c3')}</td>
                  <td>{t('whitepaper.ch10.s4.table.r1.c4')}</td>
                </tr>
                <tr>
                  <td>{t('whitepaper.ch10.s4.table.r2.c1')}</td>
                  <td>{t('whitepaper.ch10.s4.table.r2.c2')}</td>
                  <td>{t('whitepaper.ch10.s4.table.r2.c3')}</td>
                  <td>{t('whitepaper.ch10.s4.table.r2.c4')}</td>
                </tr>
                <tr>
                  <td>{t('whitepaper.ch10.s4.table.r3.c1')}</td>
                  <td>{t('whitepaper.ch10.s4.table.r3.c2')}</td>
                  <td>{t('whitepaper.ch10.s4.table.r3.c3')}</td>
                  <td>{t('whitepaper.ch10.s4.table.r3.c4')}</td>
                </tr>
                <tr>
                  <td>{t('whitepaper.ch10.s4.table.r4.c1')}</td>
                  <td>{t('whitepaper.ch10.s4.table.r4.c2')}</td>
                  <td>{t('whitepaper.ch10.s4.table.r4.c3')}</td>
                  <td>{t('whitepaper.ch10.s4.table.r4.c4')}</td>
                </tr>
                <tr>
                  <td>{t('whitepaper.ch10.s4.table.r5.c1')}</td>
                  <td>{t('whitepaper.ch10.s4.table.r5.c2')}</td>
                  <td>{t('whitepaper.ch10.s4.table.r5.c3')}</td>
                  <td>{t('whitepaper.ch10.s4.table.r5.c4')}</td>
                </tr>
                <tr>
                  <td>{t('whitepaper.ch10.s4.table.r6.c1')}</td>
                  <td>{t('whitepaper.ch10.s4.table.r6.c2')}</td>
                  <td>{t('whitepaper.ch10.s4.table.r6.c3')}</td>
                  <td>{t('whitepaper.ch10.s4.table.r6.c4')}</td>
                </tr>
              </tbody>
            </S.TableCompare>
          </S.TableWrap>
          <S.Paragraph>{t('whitepaper.ch10.s4.conclusion')}</S.Paragraph>
        </S.Section>

        <S.Divider />

        {/* ==================== CHAPTER 11 ==================== */}
        <S.Section>
          <S.ChapterTitle>
            <S.ChapterNumber>11</S.ChapterNumber>
            {t('whitepaper.ch11.title')}
          </S.ChapterTitle>
          <S.SubTitle>{t('whitepaper.ch11.s1.title')}</S.SubTitle>
          <S.Paragraph>{t('whitepaper.ch11.s1.p1')}</S.Paragraph>
          <S.SubTitle>{t('whitepaper.ch11.s2.title')}</S.SubTitle>
          <S.Paragraph>{t('whitepaper.ch11.s2.p1')}</S.Paragraph>
          <S.List>
            <li>
              <strong>{t('whitepaper.ch11.s2.l1.title')}</strong> — {t('whitepaper.ch11.s2.l1.desc')}
            </li>
            <li>
              <strong>{t('whitepaper.ch11.s2.l2.title')}</strong> — {t('whitepaper.ch11.s2.l2.desc')}
            </li>
            <li>
              <strong>{t('whitepaper.ch11.s2.l3.title')}</strong> — {t('whitepaper.ch11.s2.l3.desc')}
            </li>
          </S.List>
          <S.SubTitle>{t('whitepaper.ch11.s3.title')}</S.SubTitle>
          <S.Paragraph>{t('whitepaper.ch11.s3.p1')}</S.Paragraph>
          <S.CardGrid>
            <S.Card>
              <h4>{t('whitepaper.ch11.s3.c1.title')}</h4>
              <p>{t('whitepaper.ch11.s3.c1.desc')}</p>
            </S.Card>
            <S.Card>
              <h4>{t('whitepaper.ch11.s3.c2.title')}</h4>
              <p>{t('whitepaper.ch11.s3.c2.desc')}</p>
            </S.Card>
            <S.Card>
              <h4>{t('whitepaper.ch11.s3.c3.title')}</h4>
              <p>{t('whitepaper.ch11.s3.c3.desc')}</p>
            </S.Card>
          </S.CardGrid>
        </S.Section>

        <S.Divider />

        {/* ==================== CHAPTER 12 ==================== */}
        <S.Section>
          <S.ChapterTitle>
            <S.ChapterNumber>12</S.ChapterNumber>
            {t('whitepaper.ch12.title')}
          </S.ChapterTitle>
          <S.Paragraph>
            <S.Mark>{t('whitepaper.ch12.intro.mark')}</S.Mark>
            {t('whitepaper.ch12.intro.tail')}
          </S.Paragraph>
          <S.SubTitle>{t('whitepaper.ch12.s1.title')}</S.SubTitle>
          <S.Paragraph>{t('whitepaper.ch12.s1.p1')}</S.Paragraph>
          <S.List>
            <li>
              <strong>{t('whitepaper.ch12.s1.l1.title')}</strong> — {t('whitepaper.ch12.s1.l1.desc')}
            </li>
            <li>
              <strong>{t('whitepaper.ch12.s1.l2.title')}</strong> — {t('whitepaper.ch12.s1.l2.desc')}
            </li>
            <li>
              <strong>{t('whitepaper.ch12.s1.l3.title')}</strong> — {t('whitepaper.ch12.s1.l3.desc')}
            </li>
            <li>
              <strong>{t('whitepaper.ch12.s1.l4.title')}</strong> — {t('whitepaper.ch12.s1.l4.desc')}
            </li>
          </S.List>
          <S.SubTitle>{t('whitepaper.ch12.s2.title')}</S.SubTitle>
          <S.Paragraph>{t('whitepaper.ch12.s2.p1')}</S.Paragraph>
          <S.VisionCard>
            <h4>{t('whitepaper.ch12.s2.v1.title')}</h4>
            <p>{t('whitepaper.ch12.s2.v1.desc')}</p>
          </S.VisionCard>
          <S.VisionCard>
            <h4>{t('whitepaper.ch12.s2.v2.title')}</h4>
            <p>{t('whitepaper.ch12.s2.v2.desc')}</p>
          </S.VisionCard>
          <S.VisionCard>
            <h4>{t('whitepaper.ch12.s2.v3.title')}</h4>
            <p>{t('whitepaper.ch12.s2.v3.desc')}</p>
          </S.VisionCard>
          <S.SubTitle>{t('whitepaper.ch12.s3.title')}</S.SubTitle>
          <S.Timeline>
            <S.TimelineItem>
              <h4>{t('whitepaper.ch12.s3.p1.title')}</h4>
              <p>{t('whitepaper.ch12.s3.p1.desc')}</p>
            </S.TimelineItem>
            <S.TimelineItem>
              <h4>{t('whitepaper.ch12.s3.p2.title')}</h4>
              <p>{t('whitepaper.ch12.s3.p2.desc')}</p>
            </S.TimelineItem>
            <S.TimelineItem>
              <h4>{t('whitepaper.ch12.s3.p3.title')}</h4>
              <p>{t('whitepaper.ch12.s3.p3.desc')}</p>
            </S.TimelineItem>
            <S.TimelineItem>
              <h4>{t('whitepaper.ch12.s3.p4.title')}</h4>
              <p>{t('whitepaper.ch12.s3.p4.desc')}</p>
            </S.TimelineItem>
            <S.TimelineItem>
              <h4>{t('whitepaper.ch12.s3.p5.title')}</h4>
              <p>{t('whitepaper.ch12.s3.p5.desc')}</p>
            </S.TimelineItem>
            <S.TimelineItem>
              <h4>{t('whitepaper.ch12.s3.p6.title')}</h4>
              <p>{t('whitepaper.ch12.s3.p6.desc')}</p>
            </S.TimelineItem>
            <S.TimelineItem>
              <h4>{t('whitepaper.ch12.s3.p7.title')}</h4>
              <p>{t('whitepaper.ch12.s3.p7.desc')}</p>
            </S.TimelineItem>
          </S.Timeline>
        </S.Section>

        <S.Divider />

        {/* ==================== CHAPTER 13 ==================== */}
        <S.Section>
          <S.ChapterTitle>
            <S.ChapterNumber>13</S.ChapterNumber>
            {t('whitepaper.ch13.title')}
          </S.ChapterTitle>
          <S.Paragraph>
            <S.Mark>{t('whitepaper.ch13.intro.mark')}</S.Mark>
            {t('whitepaper.ch13.intro.tail')}
          </S.Paragraph>
          <S.Paragraph>{t('whitepaper.ch13.p2')}</S.Paragraph>
          <S.Paragraph>{t('whitepaper.ch13.p3')}</S.Paragraph>
        </S.Section>

        <S.Footer>
          <S.Content>
            <h3>{t('whitepaper.footer.title')}</h3>
            <ol>
              <li>{t('whitepaper.footer.c1')}</li>
              <li>{t('whitepaper.footer.c2')}</li>
              <li>{t('whitepaper.footer.c3')}</li>
              <li>{t('whitepaper.footer.c4')}</li>
              <li>{t('whitepaper.footer.c5')}</li>
              <li>{t('whitepaper.footer.c6')}</li>
              <li>{t('whitepaper.footer.c7')}</li>
            </ol>
            <p style={{ textAlign: 'center' }}>{t('whitepaper.footer.signoff')}</p>
          </S.Content>
        </S.Footer>
      </S.Content>
    </S.PageRoot>
  );
};

export default WhitepaperBody;
