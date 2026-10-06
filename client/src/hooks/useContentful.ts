import { createClient, ContentfulClientApi } from 'contentful';
import config from '../clientConfig';
import { logger } from '../helpers/logger';

const useContentful = (): ContentfulClientApi | null => {
  if (!config.contentfulSpaceId || !config.contentfulAccessToken) {
    logger.warn('[useContentful] Missing spaceId or accessToken, skipping Contentful init');
    return null;
  }
  const client = createClient({
    space: config.contentfulSpaceId,
    accessToken: config.contentfulAccessToken,
  });
  return client;
};

export default useContentful;
