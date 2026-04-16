// Cloudflare Worker: serves API routes under /api/*.
// Static assets + SPA fallback are handled by wrangler's [assets] config
// with not_found_handling = "single-page-application".

interface Env {
  ASSETS: Fetcher;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // ── API routes ────────────────────────────────────────────────
    if (url.pathname.startsWith("/api")) {
      return handleApi(url, request);
    }

    // ── Everything else: static assets / SPA ─────────────────────
    // Handled automatically by the assets binding + SPA fallback.
    return env.ASSETS.fetch(request);
  },
} satisfies ExportedHandler<Env>;

// ── API handler ─────────────────────────────────────────────────────────────

async function handleApi(url: URL, _request: Request): Promise<Response> {
  const path = url.pathname;

  if (path === "/api/health") {
    return json({ status: "ok", timestamp: new Date().toISOString() });
  }

  // Add more routes here as needed:
  // if (path === "/api/rounds") { ... }
  // if (path === "/api/leaderboard") { ... }

  return json({ error: "Not found" }, 404);
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    },
  });
}
