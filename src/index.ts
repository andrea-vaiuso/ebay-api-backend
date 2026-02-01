export interface Env {
  EBAY_ENV: string;
  EBAY_CLIENT_ID: string;
  EBAY_CLIENT_SECRET: string;
  TOKEN_CACHE?: KVNamespace; // optional KV binding for cross-isolate cache
}

const DEFAULT_CATEGORY_ID = "6000";
const BROWSE_SCOPE = "https://api.ebay.com/oauth/api_scope";

const inMemory = { token: "", exp: 0 };

// ============== RATE LIMITING CONFIG ==============
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute window
const MAX_REQUESTS_PER_WINDOW = 60; // max requests per window
const BURST_LIMIT = 10; // max requests in burst window
const BURST_WINDOW_MS = 1000; // 1 second burst window
const BLOCK_DURATION_MS = 5 * 60 * 1000; // 5 minute block for violators

// In-memory rate limit store (per isolate)
interface RateLimitEntry {
  count: number;
  burstCount: number;
  windowStart: number;
  burstWindowStart: number;
  blockedUntil: number;
}

const rateLimitStore = new Map<string, RateLimitEntry>();

// Clean up old entries periodically (every 100 requests)
let cleanupCounter = 0;
function cleanupRateLimitStore() {
  cleanupCounter++;
  if (cleanupCounter >= 100) {
    cleanupCounter = 0;
    const now = Date.now();
    for (const [ip, entry] of rateLimitStore.entries()) {
      // Remove entries that are no longer blocked and window has expired
      if (entry.blockedUntil < now && now - entry.windowStart > RATE_LIMIT_WINDOW_MS * 2) {
        rateLimitStore.delete(ip);
      }
    }
  }
}

function getClientIP(req: Request): string {
  // Cloudflare provides the real IP in CF-Connecting-IP header
  return (
    req.headers.get("CF-Connecting-IP") ||
    req.headers.get("X-Real-IP") ||
    req.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() ||
    "unknown"
  );
}

interface RateLimitResult {
  allowed: boolean;
  retryAfter?: number;
  reason?: string;
}

function checkRateLimit(ip: string): RateLimitResult {
  cleanupRateLimitStore();
  const now = Date.now();

  let entry = rateLimitStore.get(ip);

  if (!entry) {
    entry = {
      count: 0,
      burstCount: 0,
      windowStart: now,
      burstWindowStart: now,
      blockedUntil: 0,
    };
    rateLimitStore.set(ip, entry);
  }

  // Check if IP is currently blocked
  if (entry.blockedUntil > now) {
    const retryAfter = Math.ceil((entry.blockedUntil - now) / 1000);
    return {
      allowed: false,
      retryAfter,
      reason: `IP temporarily blocked due to excessive requests. Retry after ${retryAfter} seconds.`,
    };
  }

  // Reset window if expired
  if (now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
    entry.count = 0;
    entry.windowStart = now;
  }

  // Reset burst window if expired
  if (now - entry.burstWindowStart > BURST_WINDOW_MS) {
    entry.burstCount = 0;
    entry.burstWindowStart = now;
  }

  // Increment counters
  entry.count++;
  entry.burstCount++;

  // Check burst limit
  if (entry.burstCount > BURST_LIMIT) {
    entry.blockedUntil = now + BLOCK_DURATION_MS;
    const retryAfter = Math.ceil(BLOCK_DURATION_MS / 1000);
    return {
      allowed: false,
      retryAfter,
      reason: `Burst limit exceeded. IP blocked for ${retryAfter} seconds.`,
    };
  }

  // Check rate limit
  if (entry.count > MAX_REQUESTS_PER_WINDOW) {
    entry.blockedUntil = now + BLOCK_DURATION_MS;
    const retryAfter = Math.ceil(BLOCK_DURATION_MS / 1000);
    return {
      allowed: false,
      retryAfter,
      reason: `Rate limit exceeded. IP blocked for ${retryAfter} seconds.`,
    };
  }

  return { allowed: true };
}

// ============== SECURITY CONFIG ==============
const MAX_REQUEST_SIZE = 10 * 1024; // 10KB max request body
const MAX_URL_LENGTH = 2048; // Max URL length
const MAX_QUERY_PARAM_LENGTH = 500; // Max length per query parameter

// Patterns that might indicate injection attempts
const INJECTION_PATTERNS = [
  // SQL injection patterns
  /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|DECLARE)\b)/gi,
  /(-{2}|\/\*|\*\/|;)/g, // SQL comments and statement terminators
  // NoSQL injection patterns
  /(\$where|\$gt|\$lt|\$ne|\$regex|\$or|\$and)/gi,
  // Script injection patterns
  /<script\b[^>]*>/gi,
  /javascript:/gi,
  /on\w+\s*=/gi, // event handlers like onclick=
  // Path traversal
  /\.\.\//g,
  /\.\.%2f/gi,
  // Null bytes
  /%00/g,
  /\x00/g,
  // LDAP injection
  /[)(|*\\]/g,
];

// Allowed characters pattern (alphanumeric, spaces, common punctuation for searches)
const SAFE_INPUT_PATTERN = /^[\p{L}\p{N}\s\-_.,'"!?@#$%&*+=:;\/\[\]{}()]+$/u;

interface ValidationResult {
  valid: boolean;
  error?: string;
}

function sanitizeInput(input: string): string {
  // Decode URL encoding first
  let decoded = input;
  try {
    decoded = decodeURIComponent(input);
  } catch {
    // If decoding fails, use original
  }

  // Remove null bytes
  decoded = decoded.replace(/%00/g, "").replace(/\x00/g, "");

  // Trim and limit length
  return decoded.trim().slice(0, MAX_QUERY_PARAM_LENGTH);
}

function checkForInjection(input: string): ValidationResult {
  const sanitized = sanitizeInput(input);

  // Check against injection patterns
  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.test(sanitized)) {
      // Reset regex lastIndex for global patterns
      pattern.lastIndex = 0;
      return {
        valid: false,
        error: "Potentially malicious input detected",
      };
    }
  }

  return { valid: true };
}

function validateQueryParams(url: URL): ValidationResult {
  // Check URL length
  if (url.href.length > MAX_URL_LENGTH) {
    return { valid: false, error: "URL too long" };
  }

  // Validate each query parameter
  for (const [key, value] of url.searchParams.entries()) {
    // Check key length
    if (key.length > 50) {
      return { valid: false, error: `Parameter name '${key.slice(0, 20)}...' too long` };
    }

    // Check value length
    if (value.length > MAX_QUERY_PARAM_LENGTH) {
      return { valid: false, error: `Parameter '${key}' value too long` };
    }

    // Check for injection in values
    const injectionCheck = checkForInjection(value);
    if (!injectionCheck.valid) {
      return { valid: false, error: `Invalid value for parameter '${key}': ${injectionCheck.error}` };
    }
  }

  return { valid: true };
}

async function checkRequestSize(req: Request): Promise<ValidationResult> {
  // Check Content-Length header first (if present)
  const contentLength = req.headers.get("Content-Length");
  if (contentLength && parseInt(contentLength) > MAX_REQUEST_SIZE) {
    return { valid: false, error: "Request body too large" };
  }

  // For requests with body, validate actual size
  if (req.method !== "GET" && req.method !== "HEAD") {
    try {
      const body = await req.clone().text();
      if (body.length > MAX_REQUEST_SIZE) {
        return { valid: false, error: "Request body too large" };
      }

      // Check body for injection patterns
      const injectionCheck = checkForInjection(body);
      if (!injectionCheck.valid) {
        return { valid: false, error: `Invalid request body: ${injectionCheck.error}` };
      }
    } catch {
      // If we can't read the body, allow the request to proceed
    }
  }

  return { valid: true };
}

function createSecurityErrorResponse(message: string, status: number, retryAfter?: number): Response {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  if (retryAfter) {
    headers["Retry-After"] = String(retryAfter);
  }

  return new Response(
    JSON.stringify({ error: message }),
    { status, headers }
  );
}

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
    const clientIP = getClientIP(req);

    // ============== SECURITY CHECKS ==============

    // 1. Rate limit check
    const rateLimitResult = checkRateLimit(clientIP);
    if (!rateLimitResult.allowed) {
      return createSecurityErrorResponse(
        rateLimitResult.reason || "Rate limit exceeded",
        429,
        rateLimitResult.retryAfter
      );
    }

    // 2. Request size check
    const sizeCheck = await checkRequestSize(req);
    if (!sizeCheck.valid) {
      return createSecurityErrorResponse(sizeCheck.error || "Request too large", 413);
    }

    // 3. Query parameter validation (injection & length checks)
    const paramValidation = validateQueryParams(url);
    if (!paramValidation.valid) {
      return createSecurityErrorResponse(paramValidation.error || "Invalid request", 400);
    }

    // ============== ROUTE HANDLERS ==============

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
