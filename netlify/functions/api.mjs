
import serverless from 'serverless-http';
import app from '../../server.js';

const expressHandler = serverless(app);
const FUNCTION_PREFIX = '/.netlify/functions/api';

export const handler = async (event, context) => {
  const originalPath = event.path || '/';

  if (originalPath.startsWith(FUNCTION_PREFIX)) {
    event.path =
      originalPath.slice(FUNCTION_PREFIX.length) || '/';
  }

  return expressHandler(event, context);
};
