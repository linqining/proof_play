import { useState, useEffect } from 'react';
import { logger } from '../helpers/logger';

type UseCookieReturn = [
  boolean,
  (cookieValue: string, expirationDays: number) => void,
  () => string | undefined,
];

const useCookie = (cookieName: string, initialState: boolean): UseCookieReturn => {
  const [isCookieSet, setIsCookieSet] = useState(initialState);

  useEffect(() => {
    setIsCookieSet(checkCookies());
    // eslint-disable-next-line
  }, []);

  const getCookieValue = (): string | undefined => {
    const allStoredCookies = document.cookie.split('; ');
    const foundCookie = allStoredCookies.filter((cookie) =>
      cookie.split('=').includes(cookieName),
    )[0];
    return foundCookie;
  };

  const checkCookies = (): boolean => {
    return getCookieValue() ? true : false;
  };

  const setCookie = (cookieValue: string, expirationDays: number): void => {
    logger.log('This runs');
    const date = new Date();
    date.setTime(date.getTime() + expirationDays * 24 * 60 * 60 * 1000);
    document.cookie = `${cookieName}=${cookieValue};expires=${date.toUTCString()};path=/`;
    setIsCookieSet(true);
  };

  return [isCookieSet, setCookie, getCookieValue];
};

export default useCookie;
