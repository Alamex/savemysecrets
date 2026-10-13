// Cloudflare Pages entry: every request goes through the same handler as the Worker build.
import { handleRequest } from '../src/worker.js';
export const onRequest = ({ request, env }) => handleRequest(request, env);
