// 牌桌身份密钥面板（docs/design/SETTLEMENT_PRIVACY_PLAN.md Part B / B1.5）。
//
// 展示当前密钥模式与 pk 前缀，提供两种身份来源切换：
// - 口令派生（可恢复）：同一口令在任何设备派生出同一 pk；口令即备份，
//   忘记口令 = 身份永久丢失。禁止使用钱包助记词/恢复短语作为口令。
// - 随机密钥（默认）：CSPRNG 生成，与钱包零派生关系，无跨设备恢复。
//
// 切换身份会使当前座位的 reveal/fold 义务失效（服务器按已有超时/踢出
// 路径降级），建议在牌局间歇操作——面板常驻提示这一点。
import React, { useContext, useState } from 'react';
import styled from 'styled-components';
import { useTheme } from 'styled-components';
import Text from '../typography/Text';
import Button from '../buttons/Button';
import { Input } from '../forms/Input';
import { Label } from '../forms/Label';
import authContext from '../../context/auth/authContext';
import contentContext from '../../context/content/contentContext';
import { PlayerContext as playerContext } from '../../context/player/PlayerContext';
import { logger } from '../../helpers/logger';

const Panel = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  padding: 0.75rem;
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-radius: ${({ theme }) => theme.radius.sm};
  margin: 0.5rem;
  background: ${({ theme }) => theme.colors.lightestBg};
`;

// 账簿章（原稿 .ch 语言）：passphrase=felt / random=play / legacy=灰，方角 2px
const ModeTag = styled.span<{ $mode: string }>`
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 9px;
  font-weight: 600;
  padding: 1.5px 6px;
  border-radius: 2px;
  border: 1px solid;
  ${({ $mode, theme }) => {
    if ($mode === 'passphrase')
      return `color: ${theme.colors.success}; border-color: rgba(11,107,69,.4); background: rgba(11,107,69,.06);`;
    if ($mode === 'random')
      return `color: ${theme.colors.info}; border-color: rgba(21,80,127,.4); background: rgba(21,80,127,.06);`;
    return `color: ${theme.colors.softerText}; border-color: ${theme.colors.borderMuted}; background: ${theme.colors.surfaceMutedPlain};`;
  }}
`;

const PlayerKeyPanel: React.FC = () => {
  const theme = useTheme();
  const { isLoggedIn } = useContext(authContext)!;
  const { getLocalizedString: t } = useContext(contentContext)!;
  const { pkHex, keyMode, switchToPassphraseKey, switchToRandomKey } = useContext(playerContext)!;
  const [pass, setPass] = useState('');
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  if (!isLoggedIn) return null;

  const modeLabel = (mode: string): string =>
    mode === 'passphrase'
      ? t('playerkey-mode-passphrase')
      : mode === 'random'
        ? t('playerkey-mode-random')
        : mode === 'legacy'
          ? t('playerkey-mode-legacy')
          : mode;

  const handleSwitch = (kind: 'passphrase' | 'random') => {
    setBusy(true);
    setMsg(null);
    try {
      const res =
        kind === 'passphrase' ? switchToPassphraseKey(pass) : switchToRandomKey();
      if (res.ok) {
        setPass('');
        setMsg({
          ok: true,
          text:
            kind === 'passphrase'
              ? t('playerkey-msg-switched-passphrase')
              : t('playerkey-msg-switched-random'),
        });
      } else {
        setMsg({ ok: false, text: res.error || t('playerkey-msg-failed') });
      }
    } catch (e) {
      logger.error('[PlayerKeyPanel] switch failed:', e);
      setMsg({ ok: false, text: t('playerkey-msg-failed-console') });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <Text style={{ fontWeight: 700, margin: 0 }}>{t('playerkey-title')}</Text>
        {keyMode && <ModeTag $mode={keyMode}>{modeLabel(keyMode)}</ModeTag>}
      </div>
      <Text style={{ fontSize: '0.72rem', margin: 0, wordBreak: 'break-all', fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace' }}>
        {t('playerkey-current-pk')}
        {pkHex ? `${pkHex.slice(0, 18)}…` : t('playerkey-no-key')}
      </Text>
      <div>
        <Label htmlFor="playerkey-passphrase">{t('playerkey-passphrase-label')}</Label>
        <Input
          id="playerkey-passphrase"
          type="password"
          placeholder={t('playerkey-passphrase-placeholder')}
          value={pass}
          onChange={(e: React.ChangeEvent<HTMLInputElement>) => setPass(e.target.value)}
          disabled={busy}
        />
      </div>
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <Button
          small
          primary
          type="button"
          disabled={busy || pass.length < 8}
          onClick={() => handleSwitch('passphrase')}
          title={t('playerkey-tip-passphrase')}
        >
          {t('playerkey-btn-passphrase')}
        </Button>
        <Button
          small
          variant="secondary"
          type="button"
          disabled={busy}
          onClick={() => handleSwitch('random')}
          title={t('playerkey-tip-random')}
        >
          {t('playerkey-btn-random')}
        </Button>
      </div>
      {msg && (
        <Text
          style={{
            fontSize: '0.72rem',
            margin: 0,
            color: msg.ok ? '#0b6b45' : '#a83226',
            wordBreak: 'break-word',
          }}
        >
          {msg.text}
        </Text>
      )}
      <Text style={{ fontSize: '0.68rem', margin: 0, color: theme.colors.mutedText }}>
        {t('playerkey-warning')}
      </Text>
    </Panel>
  );
};

export default PlayerKeyPanel;
