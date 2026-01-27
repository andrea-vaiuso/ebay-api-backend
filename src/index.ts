export interface Env {
  EBAY_ENV: string;
  EBAY_CLIENT_ID: string;
  EBAY_CLIENT_SECRET: string;
  TOKEN_CACHE?: KVNamespace; // optional KV binding for cross-isolate cache
}

const DEFAULT_CATEGORY_ID = "6000";
const BROWSE_SCOPE = "https://api.ebay.com/oauth/api_scope";

const inMemory = { token: "", exp: 0 };

const apiRoot = (env: Env) =>
  env.EBAY_ENV?.toLowerCase() === "production"
    ? "https://api.ebay.com"
    : "https://api.sandbox.ebay.com";

async function getAppToken(env: Env): Promise<string> {
  const now = Date.now() / 1000;
  if (inMemory.token && now < inMemory.exp - 30) return inMemory.token;

  // Trim to avoid trailing-space issues from secrets input
  const clientId = (env.EBAY_CLIENT_ID || "").trim();
  const clientSecret = (env.EBAY_CLIENT_SECRET || "").trim();
  if (!clientId || !clientSecret) {
    throw new Error("Missing EBAY_CLIENT_ID or EBAY_CLIENT_SECRET");
  }

  if (env.TOKEN_CACHE) {
    const cached = (await env.TOKEN_CACHE.get("oauth_token", { type: "json" })) as
      | { token: string; exp: number }
      | null;
    if (cached && now < cached.exp - 30) {
      inMemory.token = cached.token;
      inMemory.exp = cached.exp;
      return cached.token;
    }
  }

  const body = new URLSearchParams({
    grant_type: "client_credentials",
    scope: BROWSE_SCOPE,
  });
  const auth = btoa(`${clientId}:${clientSecret}`);

  const res = await fetch(`${apiRoot(env)}/identity/v1/oauth2/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${auth}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body,
  });

  if (!res.ok) throw new Error(`OAuth error ${res.status} ${await res.text()}`);

  const payload = (await res.json()) as { access_token: string; expires_in: number };
  const token = payload.access_token;
  const exp = now + Number(payload.expires_in || 0);

  inMemory.token = token;
  inMemory.exp = exp;

  if (env.TOKEN_CACHE) {
    await env.TOKEN_CACHE.put("oauth_token", JSON.stringify({ token, exp }), {
      expiration: Math.floor(exp),
    });
  }

  return token;
}

const normalizeItems = (payload: any) => ({
  href: payload.href,
  total: payload.total,
  limit: payload.limit,
  offset: payload.offset,
  items: (payload.itemSummaries || []).map((it: any) => ({
    itemId: it.itemId,
    title: it.title,
    condition: it.condition,
    price: {
      value: it.price?.value,
      currency: it.price?.currency,
    },
    imageUrl: it.image?.imageUrl,
    itemWebUrl: it.itemWebUrl,
    compatibilityMatch: it.compatibilityMatch,
    compatibilityProperties: it.compatibilityProperties,
  })),
});

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    if (url.pathname === "/health") {
      return Response.json({ ok: true, env: env.EBAY_ENV ?? "production" });
    }

    if (url.pathname === "/api/ebay/search") {
      const qParam = url.searchParams.get("q");
      if (!qParam) return Response.json({ error: "Missing q" }, { status: 400 });

      const make = url.searchParams.get("brand") || undefined;
      const model = url.searchParams.get("model") || undefined;
      const year = url.searchParams.get("year") || undefined;
      const trim = url.searchParams.get("trim") || undefined;
      const engine = url.searchParams.get("engine") || undefined;
      const marketplace = url.searchParams.get("marketplace_id") || "EBAY_US";
      const deliveryCountry = url.searchParams.get("delivery_country") || "US";
      const limit = url.searchParams.get("limit") || "20";
      const offset = url.searchParams.get("offset") || "0";
      const categoryIds = DEFAULT_CATEGORY_ID;

      let query = qParam;
      if (make) query = `${make} ${query}`;
      if (model) query = `${model} ${query}`;
      if (trim) query = `${trim} ${query}`;
      if (year) query = `${year} ${query}`;
      if (engine) query = `${engine} ${query}`;

      try {
        const token = await getAppToken(env);
        const params = new URLSearchParams({
          q: query,
          category_ids: categoryIds,
          limit,
          offset,
        });

        if (deliveryCountry) params.set("filter", `deliveryCountry:${deliveryCountry}`);

        const res = await fetch(
          `${apiRoot(env)}/buy/browse/v1/item_summary/search?${params.toString()}`,
          {
            headers: {
              Authorization: `Bearer ${token}`,
              "X-EBAY-C-MARKETPLACE-ID": marketplace,
              Accept: "application/json",
            },
          }
        );

        if (!res.ok) {
          return Response.json(
            { error: "eBay search failed", status: res.status, details: await res.text() },
            { status: 502 }
          );
        }

        return Response.json(normalizeItems(await res.json()));
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        return Response.json({ error: "Internal error", details: message }, { status: 500 });
      }
    }

    return new Response("Not found", { status: 404 });
  },
};
