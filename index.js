/**
 * Cloudflare Worker — Secure Proxy for YouTube APIs by Billie
 *
 * Deploy Steps:
 * 1. cloudflare.com → Workers & Pages → Create Worker
 * 2. paste this code → Deploy
 * 3. Settings → Variables → 2 add the secrets:
 *      SHRUTI_API_KEY    → your actual Youtube API key
 *      WORKER_PASSPHRASE → Any strong password
 * 4. In bot's .env:
 *      SHRUTI_API_URL=https://your-worker.your-username.workers.dev
 *      WORKER_PASSPHRASE=Same_password_as_above
 */

const UPSTREAM      = "https://api.shrutibots.site";
const MAX_SIZE      = 550 * 1024 * 1024;
const ALLOWED_PATHS = ["/download", "/search", "/info"];
const ALLOWED_TYPES = ["audio", "video"];
const SAFE_CT       = [
  "audio/",
  "video/",
  "application/octet-stream",
  "application/json",
];

export default {
  async fetch(request, env) {

    // LAYER 1 — Only your bot can access it.
    const secret = request.headers.get("X-Bot-Secret");
    if (!secret || secret !== env.WORKER_PASSPHRASE) {
      return new Response("Unauthorized", { status: 401 });
    }

    // LAYER 2 — Only GET allowed
    if (request.method !== "GET") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    const url  = new URL(request.url);
    const path = url.pathname;

    // LAYER 3 — Whitelisted paths only
    if (!ALLOWED_PATHS.includes(path)) {
      return new Response("Not Found", { status: 404 });
    }

    // LAYER 4 — type param validate
    const t = url.searchParams.get("type");
    if (t && !ALLOWED_TYPES.includes(t)) {
      return new Response("Invalid type", { status: 400 });
    }

    // LAYER 5 — Clean upstream URL build
    // Client's api_key block, Worker's inject
    const up = new URL(path, UPSTREAM);
    for (const [k, v] of url.searchParams.entries()) {
      if (k === "api_key") continue;
      up.searchParams.set(k, v);
    }
    if (env.SHRUTI_API_KEY) {
      up.searchParams.set("api_key", env.SHRUTI_API_KEY);
    }

    // LAYER 6 — Fetch with clean headers (no VPS info)
    let resp;
    try {
      resp = await fetch(up.toString(), {
        method: "GET",
        headers: {
          "User-Agent": "MusicBot/1.0",
          "Accept": "audio/*, video/*, application/json",
        },
      });
    } catch {
      return new Response("Upstream unreachable", { status: 502 });
    }

    if (!resp.ok) {
      return new Response("Upstream error", { status: resp.status });
    }

    // LAYER 7 — Content-type validation
    const ct = (resp.headers.get("Content-Type") || "").toLowerCase();
    if (!SAFE_CT.some((s) => ct.startsWith(s))) {
      return new Response("Blocked: unsafe content type", { status: 403 });
    }

    // LAYER 8 — Size cap
    const cl = parseInt(resp.headers.get("Content-Length") || "0");
    if (cl > MAX_SIZE) {
      return new Response("Blocked: file too large", { status: 413 });
    }

    // Clean response — no identifying headers
    return new Response(resp.body, {
      status: resp.status,
      headers: {
        "Content-Type": ct,
        "Cache-Control": "no-store",
      },
    });
  },
};
