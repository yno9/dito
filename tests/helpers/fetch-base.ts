// Import this FIRST: identity-host.ts reads IDENTITY_FETCH_BASE_URL once, when it loads, and the helper that imports it comes next.
export const fetchBasePort = 18_000 + Math.floor(Math.random() * 10_000);
process.env.IDENTITY_FETCH_BASE_URL = `http://127.0.0.1:${fetchBasePort}`;
