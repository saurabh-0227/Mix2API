// ==================== 配置和类型定义 ====================

interface Env {
  ADMIN_PASSWORD?: string;
  AUTH_KEYS?: string;
  MODELS?: string;
  DEBUG?: string;
  [key: string]: string | undefined;
}

const KV_KEYS = {
  AUTH_KEYS: "auth_keys",
  MODELS: "models",
  COOKIES: "cookies",
  STATS: "stats",
  SESSIONS: "sessions",
};

const DEFAULTS = {
  ADMIN_PASSWORD: "admin123",
  AUTH_KEYS: ["sk-default", "sk-false"],
  MODELS: ["momentum"],
  COOKIE_PREFIX: "cookie_",
};

interface Stats {
  chatRequests: number;
  modelsRequests: number;
  totalCookies: number;
  activeCookies: number;
  totalQuota: number;
  remainingQuota: number;
  lastUpdated: number;
}

interface AuthKey {
  key: string;
  isEnabled: boolean;
  isDefault: boolean;
  createdAt: number;
}

interface CookieAccount {
  id: string;
  name: string;
  cookieString: string;
  isEnabled: boolean;
  isDefault: boolean;
  planType?: string;
  dailyLimit?: number;
  currentCount?: number;
  remaining?: number;
  hasReachedLimit?: boolean;
  lastChecked?: number;
  error?: string;
}

interface ModelConfig {
  id: string;
  isEnabled: boolean;
  isDefault: boolean;
  createdAt: number;
}

interface AdminSession {
  token: string;
  createdAt: number;
  expiresAt: number;
}

// ==================== 调试日志工具 ====================

let DEBUG_MODE = false;

function debugLog(...args: any[]) {
  if (DEBUG_MODE) {
    console.log("[DEBUG]", new Date().toISOString(), ...args);
  }
}

function debugError(...args: any[]) {
  if (DEBUG_MODE) {
    console.error("[ERROR]", new Date().toISOString(), ...args);
  }
}

// ==================== 工具函数 ====================

function getCorsHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, auth",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  };
}

function parseCookie(cookieHeader: string | null, name: string): string | null {
  if (!cookieHeader) return null;
  const parts = cookieHeader.split(";");
  for (const part of parts) {
    const [key, ...valueParts] = part.trim().split("=");
    if (key === name) {
      return valueParts.join("=");
    }
  }
  return null;
}

function base64UrlDecode(str: string): string {
  let s = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4;
  if (pad) {
    s += "=".repeat(4 - pad);
  }
  return atob(s);
}

function extractHandshakeToken(setCookieHeader: string): string | null {
  if (!setCookieHeader) return null;
  const marker = "__clerk_handshake=";
  const idx = setCookieHeader.indexOf(marker);
  if (idx === -1) return null;
  const start = idx + marker.length;
  let end = setCookieHeader.indexOf(";", start);
  if (end === -1) end = setCookieHeader.length;
  return setCookieHeader.slice(start, end);
}

function parseHandshakeCookies(jwt: string): Record<string, string> {
  const parts = jwt.split(".");
  if (parts.length < 2) {
    throw new Error("Invalid Clerk handshake JWT structure");
  }
  const payloadJson = base64UrlDecode(parts[1]);
  const payload = JSON.parse(payloadJson);
  
  const cookieMap: Record<string, string> = {};
  const ops: string[] = [];

  if (Array.isArray(payload.handshake)) {
    ops.push(...payload.handshake.filter((item: any) => typeof item === "string"));
  }

  for (const key in payload) {
    if (key === "handshake") continue;
    const v = payload[key];
    if (typeof v === "string" && v.includes("=") && v.includes(";")) {
      ops.push(v);
    }
  }

  for (const op of ops) {
    const first = op.split(";", 1)[0];
    const eq = first.indexOf("=");
    if (eq === -1) continue;
    const name = first.slice(0, eq).trim();
    const value = first.slice(eq + 1).trim();
    if (!name || name === "__clerk_handshake") continue;
    cookieMap[name] = value;
  }

  return cookieMap;
}

function parseCookieString(str: string): Record<string, string> {
  const map: Record<string, string> = {};
  if (!str) return map;
  const parts = str.split(";");
  for (const part of parts) {
    const p = part.trim();
    if (!p) continue;
    const eq = p.indexOf("=");
    if (eq === -1) continue;
    const name = p.slice(0, eq).trim();
    const value = p.slice(eq + 1).trim();
    if (name) {
      map[name] = value;
    }
  }
  return map;
}

function cookieMapToHeader(cookies: Record<string, string>): string {
  return Object.entries(cookies)
    .filter(([_, v]) => v != null && v !== "")
    .map(([k, v]) => `${k}=${v}`)
    .join("; ");
}

function parseSessionId(sessionToken: string): string {
  try {
    if (!sessionToken) return "";
    const parts = sessionToken.split(".");
    if (parts.length < 2) return "";
    const payload = JSON.parse(base64UrlDecode(parts[1]));
    return payload.sid || "";
  } catch {
    return "";
  }
}

function parseMovementLine(line: string): { type: "g" | "0" | "d"; text?: string } | null {
  if (!line) return null;
  let t = line.trim();
  if (!t) return null;
  if (t.startsWith("data:")) {
    t = t.slice(5).trim();
  }
  if (!t) return null;
  if (t.endsWith(",")) {
    t = t.slice(0, -1);
  }
  if (t.startsWith("g:")) {
    const core = t.slice(2);
    try {
      const obj = JSON.parse(`{"v":${core}}`);
      return { type: "g", text: obj.v || "" };
    } catch {
      return null;
    }
  }
  if (t.startsWith("0:")) {
    const core = t.slice(2);
    try {
      const obj = JSON.parse(`{"v":${core}}`);
      return { type: "0", text: obj.v || "" };
    } catch {
      return null;
    }
  }
  if (t.startsWith("d:")) {
    return { type: "d" };
  }
  return null;
}

function parseMovementFullText(raw: string): { thinking: string; answer: string } {
  let thinking = "";
  let answer = "";
  if (!raw) return { thinking, answer };
  const lines = raw.split("\n");
  for (const line of lines) {
    const p = parseMovementLine(line);
    if (!p) continue;
    if (p.type === "g") {
      thinking += p.text || "";
    } else if (p.type === "0") {
      answer += p.text || "";
    }
  }
  return { thinking, answer };
}

function normalizeMessages(messages: any[]): Array<{ role: string; content: string }> {
  if (!Array.isArray(messages)) return [];
  return messages.map((m) => {
    let content = "";
    if (typeof m.content === "string") {
      content = m.content;
    } else if (Array.isArray(m.content)) {
      content = m.content
        .map((part: any) => {
          if (!part) return "";
          if (typeof part === "string") return part;
          if (typeof part.text === "string") return part.text;
          if (typeof part.content === "string") return part.content;
          return "";
        })
        .join("");
    }
    return {
      role: m.role || "user",
      content,
    };
  });
}

function generateId(prefix: string): string {
  return `${prefix}_${crypto.randomUUID()}`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// ==================== KV 操作 ====================

async function initializeDefaultData(kv: Deno.Kv, env: Env) {
  debugLog("Initializing default data...");
  
  // 设置 DEBUG 模式
  DEBUG_MODE = env.DEBUG === "true" || env.DEBUG === "1";
  debugLog("DEBUG mode:", DEBUG_MODE);
  
  const defaultKeys = env.AUTH_KEYS
    ? env.AUTH_KEYS.split(",").map((k) => k.trim()).filter((k) => k)
    : DEFAULTS.AUTH_KEYS;
  
  for (const key of defaultKeys) {
    const existing = await kv.get<AuthKey>([KV_KEYS.AUTH_KEYS, key]);
    if (!existing.value) {
      await kv.set([KV_KEYS.AUTH_KEYS, key], {
        key,
        isEnabled: true,
        isDefault: true,
        createdAt: Date.now(),
      });
      debugLog("Created default auth key:", key);
    }
  }

  const defaultModels = env.MODELS
    ? env.MODELS.split(",").map((m) => m.trim()).filter((m) => m)
    : DEFAULTS.MODELS;
  
  for (const modelId of defaultModels) {
    const existing = await kv.get<ModelConfig>([KV_KEYS.MODELS, modelId]);
    if (!existing.value) {
      await kv.set([KV_KEYS.MODELS, modelId], {
        id: modelId,
        isEnabled: true,
        isDefault: true,
        createdAt: Date.now(),
      });
      debugLog("Created default model:", modelId);
    }
  }

  for (const [key, value] of Object.entries(env)) {
    if (key.startsWith(DEFAULTS.COOKIE_PREFIX) && value) {
      const cookieId = `env_${key}`;
      const existing = await kv.get<CookieAccount>([KV_KEYS.COOKIES, cookieId]);
      if (!existing.value) {
        await kv.set([KV_KEYS.COOKIES, cookieId], {
          id: cookieId,
          name: key,
          cookieString: value,
          isEnabled: true,
          isDefault: true,
          lastChecked: Date.now(),
        });
        debugLog("Created default cookie:", key);
      }
    }
  }
}

async function getAllAuthKeys(kv: Deno.Kv): Promise<AuthKey[]> {
  const keys = kv.list<AuthKey>({ prefix: [KV_KEYS.AUTH_KEYS] });
  const result: AuthKey[] = [];
  for await (const entry of keys) {
    result.push(entry.value);
  }
  return result;
}

async function getAllModels(kv: Deno.Kv): Promise<ModelConfig[]> {
  const keys = kv.list<ModelConfig>({ prefix: [KV_KEYS.MODELS] });
  const result: ModelConfig[] = [];
  for await (const entry of keys) {
    result.push(entry.value);
  }
  return result;
}

async function getAllCookies(kv: Deno.Kv): Promise<CookieAccount[]> {
  const keys = kv.list<CookieAccount>({ prefix: [KV_KEYS.COOKIES] });
  const result: CookieAccount[] = [];
  for await (const entry of keys) {
    result.push(entry.value);
  }
  return result;
}

async function isValidAuthKey(kv: Deno.Kv, key: string): Promise<boolean> {
  const entry = await kv.get<AuthKey>([KV_KEYS.AUTH_KEYS, key]);
  return !!(entry.value && entry.value.isEnabled);
}

async function getEnabledModels(kv: Deno.Kv): Promise<string[]> {
  const models = await getAllModels(kv);
  return models.filter((m) => m.isEnabled).map((m) => m.id);
}

async function getEnabledCookies(kv: Deno.Kv): Promise<CookieAccount[]> {
  const cookies = await getAllCookies(kv);
  return cookies.filter((c) => {
    if (!c.isEnabled) return false;
    const remaining = c.remaining ?? 0;
    const dailyLimit = c.dailyLimit ?? 0;
    if (dailyLimit === 0 && remaining === 0) return true;
    return remaining > 0;
  });
}

async function pickRandomCookie(kv: Deno.Kv): Promise<CookieAccount | null> {
  const cookies = await getEnabledCookies(kv);
  if (!cookies.length) return null;
  const idx = Math.floor(Math.random() * cookies.length);
  return cookies[idx];
}

async function updateStats(
  kv: Deno.Kv,
  updates: Partial<Stats>
): Promise<Stats> {
  const existing = await kv.get<Stats>([KV_KEYS.STATS]);
  const stats: Stats = existing.value || {
    chatRequests: 0,
    modelsRequests: 0,
    totalCookies: 0,
    activeCookies: 0,
    totalQuota: 0,
    remainingQuota: 0,
    lastUpdated: Date.now(),
  };
  
  Object.assign(stats, updates);
  stats.lastUpdated = Date.now();
  await kv.set([KV_KEYS.STATS], stats);
  return stats;
}

async function getStats(kv: Deno.Kv): Promise<Stats> {
  const entry = await kv.get<Stats>([KV_KEYS.STATS]);
  return entry.value || {
    chatRequests: 0,
    modelsRequests: 0,
    totalCookies: 0,
    activeCookies: 0,
    totalQuota: 0,
    remainingQuota: 0,
    lastUpdated: Date.now(),
  };
}

// ==================== 管理员认证 ====================

async function generateAdminToken(password: string): Promise<string> {
  const enc = new TextEncoder();
  const data = enc.encode(password);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function createAdminSession(
  kv: Deno.Kv,
  password: string
): Promise<string> {
  const token = await generateAdminToken(password);
  const now = Date.now();
  const session: AdminSession = {
    token,
    createdAt: now,
    expiresAt: now + 7 * 24 * 60 * 60 * 1000,
  };
  await kv.set([KV_KEYS.SESSIONS, token], session);
  return token;
}

async function verifyAdminSession(
  kv: Deno.Kv,
  token: string
): Promise<boolean> {
  const entry = await kv.get<AdminSession>([KV_KEYS.SESSIONS, token]);
  if (!entry.value) return false;
  if (entry.value.expiresAt < Date.now()) {
    await kv.delete([KV_KEYS.SESSIONS, token]);
    return false;
  }
  return true;
}

async function deleteAdminSession(kv: Deno.Kv, token: string): Promise<void> {
  await kv.delete([KV_KEYS.SESSIONS, token]);
}

// ==================== API 处理 ====================

async function checkAuth(kv: Deno.Kv, request: Request): Promise<boolean> {
  const headers = request.headers;
  const auth =
    headers.get("auth") ||
    headers.get("Auth") ||
    headers.get("Authorization") ||
    headers.get("authorization");
  
  if (!auth) {
    debugLog("No auth header found");
    return false;
  }
  
  const cleanAuth = auth.replace(/^Bearer\s+/i, "");
  const isValid = await isValidAuthKey(kv, cleanAuth);
  debugLog("Auth validation result:", isValid, "for key:", cleanAuth.substring(0, 10) + "...");
  return isValid;
}

async function handleModels(kv: Deno.Kv, cors: Record<string, string>): Promise<Response> {
  debugLog("Handling /v1/models request");
  const models = await getEnabledModels(kv);
  const created = Math.floor(Date.now() / 1000);
  
  const data = models.map((id) => ({
    id,
    object: "model",
    created,
    owned_by: "movementlabs2api",
  }));

  await updateStats(kv, { modelsRequests: (await getStats(kv)).modelsRequests + 1 });

  return new Response(
    JSON.stringify({ object: "list", data }),
    { status: 200, headers: { ...cors, "Content-Type": "application/json" } }
  );
}

async function getMovementCookies(account: CookieAccount): Promise<Record<string, string>> {
  debugLog("Getting Movement cookies for account:", account.name);
  
  const baseCookies = parseCookieString(account.cookieString);
  const client = baseCookies["__client"];
  
  if (!client) {
    throw new Error(
      `${account.name} 缺少 __client Cookie。请在 ${account.name} 中至少配置 "__client=..."`
    );
  }

  debugLog("Base cookies parsed, __client found:", client.substring(0, 20) + "...");

  const handshakeUrl =
    "https://clerk.movementlabs.ai/v1/client/handshake" +
    "?redirect_url=" +
    encodeURIComponent("https://movementlabs.ai/") +
    "&__clerk_api_version=2025-04-10" +
    "&suffixed_cookies=false" +
    "&__clerk_hs_reason=session-token-but-no-client-uat" +
    "&format=nonce";

  const cookieHeader = cookieMapToHeader(baseCookies);
  debugLog("Requesting handshake with cookie header length:", cookieHeader.length);

  const res = await fetch(handshakeUrl, {
    method: "GET",
    headers: {
      accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      cookie: cookieHeader,
      "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
    },
    redirect: "manual",
  });

  debugLog("Handshake response status:", res.status);

  const setCookieHeader = res.headers.get("set-cookie") || "";
  const handshakeToken = extractHandshakeToken(setCookieHeader);
  
  if (!handshakeToken) {
    const text = await res.text().catch(() => "");
    debugError("Failed to extract handshake token. Response:", text.slice(0, 500));
    throw new Error(
      `无法从 Clerk handshake 响应中提取 __clerk_handshake Cookie (${account.name})。HTTP ${res.status}`
    );
  }

  debugLog("Handshake token extracted successfully");

  const handshakeCookies = parseHandshakeCookies(handshakeToken);
  const merged = { ...baseCookies, ...handshakeCookies };

  if (!merged["__session"]) {
    debugError("No __session cookie found after handshake");
    throw new Error(
      `Clerk handshake 响应中没有解析出 __session Cookie (${account.name})，请确认该账户已在浏览器中成功登录 movementlabs.ai。`
    );
  }

  debugLog("Cookies merged successfully, __session found");
  return merged;
}

async function updateAccountLimits(
  kv: Deno.Kv,
  account: CookieAccount
): Promise<CookieAccount> {
  debugLog("Updating account limits for:", account.name);
  
  try {
    const cookies = await getMovementCookies(account);
    const apiCookie = cookieMapToHeader(cookies);
    
    const res = await fetch("https://movementlabs.ai/api/user/limits", {
      method: "GET",
      headers: {
        accept: "*/*",
        cookie: apiCookie,
        referer: "https://movementlabs.ai/",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
      },
    });

    debugLog("Limits API response status:", res.status);

    if (res.ok) {
      const data = await res.json();
      account.planType = data.planType;
      account.dailyLimit = data.dailyLimit;
      account.currentCount = data.currentCount;
      account.remaining = data.remaining;
      account.hasReachedLimit = data.hasReachedLimit;
      account.error = undefined;
      debugLog("Account limits updated:", {
        dailyLimit: account.dailyLimit,
        remaining: account.remaining,
      });
    } else {
      account.error = `HTTP ${res.status}`;
      debugError("Failed to get limits:", account.error);
    }
  } catch (e) {
    account.error = e instanceof Error ? e.message : "Unknown error";
    debugError("Error updating account limits:", account.error);
  }
  
  account.lastChecked = Date.now();
  await kv.set([KV_KEYS.COOKIES, account.id], account);
  return account;
}

async function getMovementCookiesWithRetry(
  kv: Deno.Kv,
  maxRetries: number = 3
): Promise<{ cookies: Record<string, string>; account: CookieAccount }> {
  debugLog("Getting cookies with retry, max retries:", maxRetries);
  let lastError: Error | null = null;
  
  for (let i = 0; i < maxRetries; i++) {
    const account = await pickRandomCookie(kv);
    if (!account) {
      throw new Error("No enabled cookie accounts available");
    }

    debugLog(`Attempt ${i + 1}/${maxRetries}, using account:`, account.name);

    try {
      const updatedAccount = await updateAccountLimits(kv, account);
      
      const remaining = updatedAccount.remaining ?? 0;
      const dailyLimit = updatedAccount.dailyLimit ?? 0;
      const hasQuota = dailyLimit === 0 || remaining > 0;
      
      if (!hasQuota) {
        debugLog(`Account ${account.name} has no quota, trying next account...`);
        continue;
      }

      const cookies = await getMovementCookies(updatedAccount);
      debugLog("Successfully got cookies for account:", account.name);
      return { cookies, account: updatedAccount };
    } catch (e) {
      lastError = e instanceof Error ? e : new Error(String(e));
      debugError(`Failed to get cookies for account ${account.name}:`, lastError.message);
      
      account.error = lastError.message;
      await kv.set([KV_KEYS.COOKIES, account.id], account);
      
      if (i < maxRetries - 1) {
        await new Promise(resolve => setTimeout(resolve, 1000 * (i + 1)));
      }
    }
  }
  
  throw lastError || new Error("Failed to get cookies after max retries");
}

async function handleChatCompletions(
  kv: Deno.Kv,
  request: Request,
  cors: Record<string, string>
): Promise<Response> {
  debugLog("Handling /v1/chat/completions request");
  
  const body = await request.json();
  const stream = !!body.stream;
  const model = body.model || "momentum";
  const created = Math.floor(Date.now() / 1000);

  debugLog("Request params - stream:", stream, "model:", model);

  let lastError: Error | null = null;
  const maxRetries = 3;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      debugLog(`Chat request attempt ${attempt}/${maxRetries}`);
      
      const { cookies, account } = await getMovementCookiesWithRetry(kv, 1);
      const apiCookie = cookieMapToHeader(cookies);
      
      const messages = normalizeMessages(body.messages || []);
      const movementReqBody = JSON.stringify({ messages });

      debugLog("Sending request to movementlabs.ai/api/chat");

      const movementRes = await fetch("https://movementlabs.ai/api/chat", {
        method: "POST",
        headers: {
          accept: "*/*",
          "content-type": "application/json",
          cookie: apiCookie,
          origin: "https://movementlabs.ai",
          referer: "https://movementlabs.ai/",
          "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
        },
        body: movementReqBody,
      });

      debugLog("Movement API response status:", movementRes.status);

      if (!movementRes.ok) {
        const text = await movementRes.text().catch(() => "");
        throw new Error(`HTTP ${movementRes.status}: ${text.slice(0, 200)}`);
      }

      await updateStats(kv, { chatRequests: (await getStats(kv)).chatRequests + 1 });

      if (!stream) {
        const raw = await movementRes.text();
        const { answer } = parseMovementFullText(raw);
        debugLog("Non-stream response completed, answer length:", answer.length);
        
        return new Response(
          JSON.stringify({
            id: generateId("chatcmpl"),
            object: "chat.completion",
            created,
            model,
            choices: [
              {
                index: 0,
                message: { role: "assistant", content: answer },
                logprobs: null,
                finish_reason: "stop",
              },
            ],
            usage: {
              prompt_tokens: 0,
              completion_tokens: 0,
              total_tokens: 0,
            },
            system_fingerprint: null,
          }),
          { status: 200, headers: { ...cors, "Content-Type": "application/json" } }
        );
      }

      debugLog("Starting stream response");
      const encoder = new TextEncoder();
      const decoder = new TextDecoder();
      const id = generateId("chatcmpl");
      let first = true;

      const streamBody = new ReadableStream({
        async start(controller) {
          const reader = movementRes.body!.getReader();
          let buffer = "";

          try {
            while (true) {
              const { value, done } = await reader.read();
              if (done) break;

              buffer += decoder.decode(value, { stream: true });
              let idx;
              while ((idx = buffer.indexOf("\n")) !== -1) {
                const line = buffer.slice(0, idx);
                buffer = buffer.slice(idx + 1);

                const p = parseMovementLine(line);
                if (!p) continue;

                if (p.type === "0") {
                  const deltaText = p.text || "";
                  if (!deltaText) continue;

                  const chunk = {
                    id,
                    object: "chat.completion.chunk",
                    created,
                    model,
                    choices: [
                      {
                        index: 0,
                        delta: first
                          ? { role: "assistant", content: deltaText }
                          : { content: deltaText },
                        finish_reason: null,
                      },
                    ],
                  };
                  first = false;
                  controller.enqueue(
                    encoder.encode(`data: ${JSON.stringify(chunk)}\n\n`)
                  );
                } else if (p.type === "d") {
                  const doneChunk = {
                    id,
                    object: "chat.completion.chunk",
                    created,
                    model,
                    choices: [
                      {
                        index: 0,
                        delta: {},
                        finish_reason: "stop",
                      },
                    ],
                  };
                  controller.enqueue(
                    encoder.encode(`data: ${JSON.stringify(doneChunk)}\n\n`)
                  );
                  controller.enqueue(encoder.encode("data: [DONE]\n\n"));
                }
              }
            }

            if (buffer.trim()) {
              const p = parseMovementLine(buffer);
              if (p && p.type === "d") {
                controller.enqueue(
                  encoder.encode(
                    `data: ${JSON.stringify({
                      id,
                      object: "chat.completion.chunk",
                      created,
                      model,
                      choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
                    })}\n\n`
                  )
                );
                controller.enqueue(encoder.encode("data: [DONE]\n\n"));
              }
            }
          } catch (e) {
            debugError("Stream error:", e);
            const err = {
              error: {
                message: e instanceof Error ? e.message : "Upstream error",
                type: "server_error",
                param: null,
                code: null,
              },
            };
            controller.enqueue(encoder.encode(`data: ${JSON.stringify(err)}\n\n`));
          } finally {
            controller.close();
          }
        },
      });

      return new Response(streamBody, {
        status: 200,
        headers: {
          ...cors,
          "Content-Type": "text/event-stream; charset=utf-8",
          "Cache-Control": "no-cache",
        },
      });

    } catch (e) {
      lastError = e instanceof Error ? e : new Error(String(e));
      debugError(`Chat request attempt ${attempt} failed:`, lastError.message);
      
      if (attempt < maxRetries) {
        const delay = 1000 * attempt;
        debugLog(`Retrying in ${delay}ms...`);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }

  debugError("All retry attempts failed");
  return new Response(
    JSON.stringify({
      error: {
        message: `Failed after ${maxRetries} attempts: ${lastError?.message || "Unknown error"}`,
        type: "upstream_error",
        param: null,
        code: null,
      },
    }),
    { status: 500, headers: { ...cors, "Content-Type": "application/json" } }
  );
}

// ==================== 管理面板 UI ====================

function renderLoginPage(error?: string): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MovementLabs API - 管理登录</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50 flex items-center justify-center min-h-screen">
  <div class="bg-white rounded-xl shadow-lg p-8 w-full max-w-md">
    <div class="flex items-center mb-6">
      <div class="w-10 h-10 bg-gradient-to-br from-indigo-500 to-green-500 rounded-lg flex items-center justify-center text-white font-bold mr-3">M</div>
      <h1 class="text-2xl font-bold text-gray-800">MovementLabs API</h1>
    </div>
    <h2 class="text-lg font-semibold text-gray-700 mb-2">管理面板登录</h2>
    <p class="text-sm text-gray-500 mb-6">请输入管理员密码以访问控制面板</p>
    <form method="post" action="/admin/login" class="space-y-4">
      <div>
        <label class="block text-sm font-medium text-gray-700 mb-1">管理员密码</label>
        <input type="password" name="password" required
          class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent">
      </div>
      <button type="submit"
        class="w-full bg-gradient-to-r from-indigo-500 to-purple-600 text-white py-2 px-4 rounded-lg hover:from-indigo-600 hover:to-purple-700 transition-all duration-200 font-medium">
        登录
      </button>
    </form>
    ${error ? `<div class="mt-4 p-3 bg-red-50 border border-red-200 text-red-600 rounded-lg text-sm">${escapeHtml(error)}</div>` : ""}
  </div>
</body>
</html>`;
}

function renderAdminPanel(stats: Stats, authKeys: AuthKey[], models: ModelConfig[], cookies: CookieAccount[]): string {
  const totalCookies = cookies.length;
  const activeCookies = cookies.filter((c) => c.isEnabled).length;
  const totalQuota = cookies.reduce((sum, c) => sum + (c.dailyLimit || 0), 0);
  const remainingQuota = cookies.reduce((sum, c) => sum + (c.remaining || 0), 0);

  stats.totalCookies = totalCookies;
  stats.activeCookies = activeCookies;
  stats.totalQuota = totalQuota;
  stats.remainingQuota = remainingQuota;

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MovementLabs API - 管理面板</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    .sidebar-active { background-color: #f3f4f6; border-left: 3px solid #6366f1; }
    .content-section { display: none; }
    .content-section.active { display: block; }
    
    @media (max-width: 768px) {
      .sidebar {
        position: fixed;
        left: -100%;
        top: 0;
        bottom: 0;
        width: 280px;
        transition: left 0.3s ease;
        z-index: 50;
        box-shadow: 2px 0 10px rgba(0,0,0,0.1);
      }
      .sidebar.open {
        left: 0;
      }
      .sidebar-overlay {
        display: none;
        position: fixed;
        inset: 0;
        background: rgba(0,0,0,0.5);
        z-index: 40;
      }
      .sidebar-overlay.open {
        display: block;
      }
      .mobile-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 1rem;
        background: white;
        border-bottom: 1px solid #e5e7eb;
      }
    }
    
    @media (min-width: 769px) {
      .sidebar {
        position: relative;
        width: 16rem;
      }
      .mobile-menu-btn, .mobile-header, .sidebar-overlay {
        display: none;
      }
    }
    
    @media (max-width: 640px) {
      .table-container {
        overflow-x: auto;
      }
      table {
        min-width: 640px;
      }
    }
  </style>
</head>
<body class="bg-gray-50">
  <div class="mobile-header lg:hidden">
    <div class="flex items-center">
      <div class="w-8 h-8 bg-gradient-to-br from-indigo-500 to-green-500 rounded-lg flex items-center justify-center text-white font-bold mr-2">M</div>
      <div>
        <h1 class="text-lg font-bold text-gray-800">MovementLabs</h1>
        <p class="text-xs text-gray-500">API 管理面板</p>
      </div>
    </div>
    <button onclick="toggleSidebar()" class="p-2 rounded-lg text-gray-600 hover:bg-gray-100">
      <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"></path>
      </svg>
    </button>
  </div>

  <div id="sidebarOverlay" class="sidebar-overlay" onclick="toggleSidebar()"></div>

  <div class="flex h-screen">
    <div id="sidebar" class="sidebar bg-white">
      <div class="p-6 border-b border-gray-200 hidden lg:block">
        <div class="flex items-center">
          <div class="w-10 h-10 bg-gradient-to-br from-indigo-500 to-green-500 rounded-lg flex items-center justify-center text-white font-bold mr-3">M</div>
          <div>
            <h1 class="text-lg font-bold text-gray-800">MovementLabs</h1>
            <p class="text-xs text-gray-500">API 管理面板</p>
          </div>
        </div>
      </div>
      
      <nav class="p-4 flex-1">
        <ul class="space-y-2">
          <li>
            <a href="#" onclick="showSection('dashboard'); closeSidebar(); return false;" id="nav-dashboard" class="block px-4 py-3 rounded-lg text-gray-700 hover:bg-gray-100 transition-colors sidebar-active">
              <svg class="w-5 h-5 inline-block mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2H5a2 2 0 00-2-2z"></path>
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5a2 2 0 012-2h4a2 2 0 012 2v6H8V5z"></path>
              </svg>
              系统概览
            </a>
          </li>
          <li>
            <a href="#" onclick="showSection('cookies'); closeSidebar(); return false;" id="nav-cookies" class="block px-4 py-3 rounded-lg text-gray-700 hover:bg-gray-100 transition-colors">
              <svg class="w-5 h-5 inline-block mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z"></path>
              </svg>
              Cookie 账户
            </a>
          </li>
          <li>
            <a href="#" onclick="showSection('auth'); closeSidebar(); return false;" id="nav-auth" class="block px-4 py-3 rounded-lg text-gray-700 hover:bg-gray-100 transition-colors">
              <svg class="w-5 h-5 inline-block mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
              </svg>
              API 密钥
            </a>
          </li>
          <li>
            <a href="#" onclick="showSection('models'); closeSidebar(); return false;" id="nav-models" class="block px-4 py-3 rounded-lg text-gray-700 hover:bg-gray-100 transition-colors">
              <svg class="w-5 h-5 inline-block mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path>
              </svg>
              模型列表
            </a>
          </li>
        </ul>
      </nav>
      
      <div class="p-4 border-t border-gray-200 mt-auto">
        <button onclick="logout()" class="w-full bg-red-50 text-red-600 px-4 py-3 rounded-lg hover:bg-red-100 transition-colors text-sm font-medium">
          <svg class="w-5 h-5 inline-block mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"></path>
          </svg>
          退出登录
        </button>
      </div>
    </div>

    <div class="flex-1 overflow-y-auto lg:ml-0">
      <div class="p-4 lg:p-8">
        <div id="dashboard-section" class="content-section active">
          <div class="mb-6 lg:mb-8">
            <h2 class="text-xl lg:text-2xl font-bold text-gray-800 mb-2">系统概览</h2>
            <p class="text-gray-500 text-sm lg:text-base">实时监控系统运行状态</p>
          </div>
          
          <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 lg:gap-6 mb-6 lg:mb-8">
            <div class="bg-white rounded-xl shadow-sm p-4 lg:p-6">
              <div class="flex items-center justify-between">
                <div>
                  <p class="text-xs lg:text-sm text-gray-500">聊天请求</p>
                  <p class="text-xl lg:text-2xl font-bold text-gray-800 mt-1">${stats.chatRequests.toLocaleString()}</p>
                </div>
                <div class="w-8 h-8 lg:w-10 lg:h-10 bg-blue-100 rounded-lg flex items-center justify-center">
                  <svg class="w-4 h-4 lg:w-6 lg:h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"></path>
                  </svg>
                </div>
              </div>
            </div>

            <div class="bg-white rounded-xl shadow-sm p-4 lg:p-6">
              <div class="flex items-center justify-between">
                <div>
                  <p class="text-xs lg:text-sm text-gray-500">模型请求</p>
                  <p class="text-xl lg:text-2xl font-bold text-gray-800 mt-1">${stats.modelsRequests.toLocaleString()}</p>
                </div>
                <div class="w-8 h-8 lg:w-10 lg:h-10 bg-purple-100 rounded-lg flex items-center justify-center">
                  <svg class="w-4 h-4 lg:w-6 lg:h-6 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path>
                  </svg>
                </div>
              </div>
            </div>

            <div class="bg-white rounded-xl shadow-sm p-4 lg:p-6">
              <div class="flex items-center justify-between">
                <div>
                  <p class="text-xs lg:text-sm text-gray-500">活跃账户</p>
                  <p class="text-xl lg:text-2xl font-bold text-gray-800 mt-1">${activeCookies} / ${totalCookies}</p>
                </div>
                <div class="w-8 h-8 lg:w-10 lg:h-10 bg-green-100 rounded-lg flex items-center justify-center">
                  <svg class="w-4 h-4 lg:w-6 lg:h-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z"></path>
                  </svg>
                </div>
              </div>
            </div>

            <div class="bg-white rounded-xl shadow-sm p-4 lg:p-6">
              <div class="flex items-center justify-between">
                <div>
                  <p class="text-xs lg:text-sm text-gray-500">剩余配额</p>
                  <p class="text-xl lg:text-2xl font-bold text-gray-800 mt-1">${remainingQuota.toLocaleString()} / ${totalQuota.toLocaleString()}</p>
                </div>
                <div class="w-8 h-8 lg:w-10 lg:h-10 bg-yellow-100 rounded-lg flex items-center justify-center">
                  <svg class="w-4 h-4 lg:w-6 lg:h-6 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                  </svg>
                </div>
              </div>
            </div>
          </div>

          <div class="bg-blue-50 border border-blue-200 rounded-lg p-3 lg:p-4">
            <div class="flex items-center">
              <svg class="w-4 h-4 lg:w-5 lg:h-5 text-blue-600 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
              </svg>
              <p class="text-xs lg:text-sm text-blue-800">系统会自动选择有剩余配额的账户,并在请求失败时自动重试</p>
            </div>
          </div>
        </div>

        <div id="cookies-section" class="content-section">
          <div class="mb-4 lg:mb-6">
            <h2 class="text-xl lg:text-2xl font-bold text-gray-800 mb-2">Cookie 账户管理</h2>
            <p class="text-gray-500 text-sm lg:text-base">管理系统使用的 Cookie 账户</p>
          </div>
          
          <div class="flex justify-between items-center mb-4">
            <button onclick="addCookie()" class="bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700 transition-colors text-sm lg:text-base">
              添加 Cookie
            </button>
          </div>
          
          <div class="bg-white rounded-xl shadow-sm overflow-hidden table-container">
            <table class="min-w-full divide-y divide-gray-200">
              <thead class="bg-gray-50">
                <tr>
                  <th class="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">名称</th>
                  <th class="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">套餐类型</th>
                  <th class="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">每日限额</th>
                  <th class="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">已使用</th>
                  <th class="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">剩余</th>
                  <th class="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">状态</th>
                  <th class="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">操作</th>
                </tr>
              </thead>
              <tbody class="bg-white divide-y divide-gray-200">
                ${cookies.map((cookie) => `
                  <tr>
                    <td class="px-4 lg:px-6 py-4 text-sm text-gray-900">${escapeHtml(cookie.name)}</td>
                    <td class="px-4 lg:px-6 py-4 text-sm text-gray-500">${escapeHtml(cookie.planType || "-")}</td>
                    <td class="px-4 lg:px-6 py-4 text-sm text-gray-500">${cookie.dailyLimit ?? "-"}</td>
                    <td class="px-4 lg:px-6 py-4 text-sm text-gray-500">${cookie.currentCount ?? "-"}</td>
                    <td class="px-4 lg:px-6 py-4 text-sm text-gray-500">${cookie.remaining ?? "-"}</td>
                    <td class="px-4 lg:px-6 py-4">
                      <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
                        cookie.isEnabled ? "bg-green-100 text-green-800" : "bg-gray-100 text-gray-800"
                      }">
                        ${cookie.isEnabled ? "启用" : "禁用"}
                      </span>
                    </td>
                    <td class="px-4 lg:px-6 py-4 text-sm space-x-2">
                      <button onclick="toggleCookie('${cookie.id}')" class="text-indigo-600 hover:text-indigo-900">
                        ${cookie.isEnabled ? "禁用" : "启用"}
                      </button>
                      ${!cookie.isDefault ? `<button onclick="deleteCookie('${cookie.id}')" class="text-red-600 hover:text-red-900">删除</button>` : ""}
                    </td>
                  </tr>
                `).join("")}
              </tbody>
            </table>
          </div>
        </div>

        <div id="auth-section" class="content-section">
          <div class="mb-4 lg:mb-6">
            <h2 class="text-xl lg:text-2xl font-bold text-gray-800 mb-2">API 密钥管理</h2>
            <p class="text-gray-500 text-sm lg:text-base">管理 API 访问鉴权密钥</p>
          </div>
          
          <div class="flex justify-between items-center mb-4">
            <button onclick="addAuthKey()" class="bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700 transition-colors text-sm lg:text-base">
              添加密钥
            </button>
          </div>
          
          <div class="bg-white rounded-xl shadow-sm overflow-hidden table-container">
            <table class="min-w-full divide-y divide-gray-200">
              <thead class="bg-gray-50">
                <tr>
                  <th class="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">密钥</th>
                  <th class="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">状态</th>
                  <th class="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">类型</th>
                  <th class="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">操作</th>
                </tr>
              </thead>
              <tbody class="bg-white divide-y divide-gray-200">
                ${authKeys.map((key) => `
                  <tr>
                    <td class="px-4 lg:px-6 py-4 text-sm font-mono text-gray-900 break-all">${escapeHtml(key.key)}</td>
                    <td class="px-4 lg:px-6 py-4">
                      <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
                        key.isEnabled ? "bg-green-100 text-green-800" : "bg-gray-100 text-gray-800"
                      }">
                        ${key.isEnabled ? "启用" : "禁用"}
                      </span>
                    </td>
                    <td class="px-4 lg:px-6 py-4 text-sm text-gray-500">
                      ${key.isDefault ? "默认" : "自定义"}
                    </td>
                    <td class="px-4 lg:px-6 py-4 text-sm space-x-2">
                      <button onclick="toggleAuthKey('${key.key}')" class="text-indigo-600 hover:text-indigo-900">
                        ${key.isEnabled ? "禁用" : "启用"}
                      </button>
                      ${!key.isDefault ? `<button onclick="deleteAuthKey('${key.key}')" class="text-red-600 hover:text-red-900">删除</button>` : ""}
                    </td>
                  </tr>
                `).join("")}
              </tbody>
            </table>
          </div>
        </div>

        <div id="models-section" class="content-section">
          <div class="mb-4 lg:mb-6">
            <h2 class="text-xl lg:text-2xl font-bold text-gray-800 mb-2">模型列表管理</h2>
            <p class="text-gray-500 text-sm lg:text-base">管理可用的 AI 模型</p>
          </div>
          
          <div class="flex justify-between items-center mb-4">
            <button onclick="addModel()" class="bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700 transition-colors text-sm lg:text-base">
              添加模型
            </button>
          </div>
          
          <div class="bg-white rounded-xl shadow-sm overflow-hidden table-container">
            <table class="min-w-full divide-y divide-gray-200">
              <thead class="bg-gray-50">
                <tr>
                  <th class="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">模型 ID</th>
                  <th class="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">状态</th>
                  <th class="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">类型</th>
                  <th class="px-4 lg:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">操作</th>
                </tr>
              </thead>
              <tbody class="bg-white divide-y divide-gray-200">
                ${models.map((model) => `
                  <tr>
                    <td class="px-4 lg:px-6 py-4 text-sm font-mono text-gray-900">${escapeHtml(model.id)}</td>
                    <td class="px-4 lg:px-6 py-4">
                      <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
                        model.isEnabled ? "bg-green-100 text-green-800" : "bg-gray-100 text-gray-800"
                      }">
                        ${model.isEnabled ? "启用" : "禁用"}
                      </span>
                    </td>
                    <td class="px-4 lg:px-6 py-4 text-sm text-gray-500">
                      ${model.isDefault ? "默认" : "自定义"}
                    </td>
                    <td class="px-4 lg:px-6 py-4 text-sm space-x-2">
                      <button onclick="toggleModel('${model.id}')" class="text-indigo-600 hover:text-indigo-900">
                        ${model.isEnabled ? "禁用" : "启用"}
                      </button>
                      ${!model.isDefault ? `<button onclick="deleteModel('${model.id}')" class="text-red-600 hover:text-red-900">删除</button>` : ""}
                    </td>
                  </tr>
                `).join("")}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  </div>

  <script>
    function toggleSidebar() {
      const sidebar = document.getElementById('sidebar');
      const overlay = document.getElementById('sidebarOverlay');
      sidebar.classList.toggle('open');
      overlay.classList.toggle('open');
    }

    function closeSidebar() {
      const sidebar = document.getElementById('sidebar');
      const overlay = document.getElementById('sidebarOverlay');
      sidebar.classList.remove('open');
      overlay.classList.remove('open');
    }

    function showSection(sectionName) {
      document.querySelectorAll('.content-section').forEach(el => {
        el.classList.remove('active');
        el.classList.add('hidden');
      });
      
      document.querySelectorAll('nav a').forEach(el => el.classList.remove('sidebar-active'));
      
      const targetSection = document.getElementById(sectionName + '-section');
      if (targetSection) {
        targetSection.classList.remove('hidden');
        targetSection.classList.add('active');
      }
      
      const targetNav = document.getElementById('nav-' + sectionName);
      if (targetNav) {
        targetNav.classList.add('sidebar-active');
      }
    }

    async function logout() {
      if (!confirm('确定要退出登录吗?')) return;
      
      try {
        const response = await fetch('/admin/api/logout', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' }
        });
        
        if (response.ok) {
          document.cookie = 'ml_admin_auth=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT';
          window.location.href = '/admin';
        } else {
          alert('退出失败,请重试');
        }
      } catch (error) {
        console.error('Logout error:', error);
        alert('退出失败,请重试');
      }
    }

    function addCookie() {
      const name = prompt('请输入 Cookie 名称(如 cookie_4):');
      if (!name) return;
      
      const cookieString = prompt('请输入完整的 Cookie 字符串:');
      if (!cookieString) return;

      fetch('/admin/api/cookies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, cookieString })
      }).then(() => location.reload());
    }

    function toggleCookie(id) {
      fetch(\`/admin/api/cookies/\${id}/toggle\`, { method: 'POST' })
        .then(() => location.reload());
    }

    function deleteCookie(id) {
      if (!confirm('确定要删除这个 Cookie 吗?')) return;
      fetch(\`/admin/api/cookies/\${id}\`, { method: 'DELETE' })
        .then(() => location.reload());
    }

    function addAuthKey() {
      const key = prompt('请输入新的 API 密钥:');
      if (!key) return;

      fetch('/admin/api/auth-keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key })
      }).then(() => location.reload());
    }

    function toggleAuthKey(key) {
      fetch(\`/admin/api/auth-keys/\${encodeURIComponent(key)}/toggle\`, { method: 'POST' })
        .then(() => location.reload());
    }

    function deleteAuthKey(key) {
      if (!confirm('确定要删除这个 API 密钥吗?')) return;
      fetch(\`/admin/api/auth-keys/\${encodeURIComponent(key)}\`, { method: 'DELETE' })
        .then(() => location.reload());
    }

    function addModel() {
      const modelId = prompt('请输入模型 ID:');
      if (!modelId) return;

      fetch('/admin/api/models', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: modelId })
      }).then(() => location.reload());
    }

    function toggleModel(id) {
      fetch(\`/admin/api/models/\${encodeURIComponent(id)}/toggle\`, { method: 'POST' })
        .then(() => location.reload());
    }

    function deleteModel(id) {
      if (!confirm('确定要删除这个模型吗?')) return;
      fetch(\`/admin/api/models/\${encodeURIComponent(id)}\`, { method: 'DELETE' })
        .then(() => location.reload());
    }

    window.addEventListener('resize', function() {
      if (window.innerWidth >= 769) {
        closeSidebar();
      }
    });
  </script>
</body>
</html>`;
}

// ==================== 管理员 API 处理 ====================

async function handleAdminLogin(
  kv: Deno.Kv,
  request: Request,
  env: Env
): Promise<Response> {
  if (request.method === "GET") {
    return new Response(renderLoginPage(), {
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  if (request.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  const formData = await request.formData();
  const password = (formData.get("password") || "") as string;
  const expectedPassword = env.ADMIN_PASSWORD || DEFAULTS.ADMIN_PASSWORD;

  if (password !== expectedPassword) {
    return new Response(renderLoginPage("密码错误"), {
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  const token = await createAdminSession(kv, password);
  const headers = new Headers();
  headers.set("Content-Type", "text/html; charset=utf-8");
  headers.set(
    "Set-Cookie",
    `ml_admin_auth=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${7 * 24 * 60 * 60}`
  );
  headers.set("Location", "/admin");

  return new Response(
    `<html><body>登录成功,正在跳转...</body></html>`,
    { status: 302, headers }
  );
}

async function handleAdminLogout(
  kv: Deno.Kv,
  request: Request
): Promise<Response> {
  const token = parseCookie(request.headers.get("cookie"), "ml_admin_auth");
  
  if (token) {
    await deleteAdminSession(kv, token);
  }

  const cors = getCorsHeaders();
  return new Response(
    JSON.stringify({ success: true }),
    { status: 200, headers: { ...cors, "Content-Type": "application/json" } }
  );
}

async function handleAdminPanel(
  kv: Deno.Kv,
  request: Request
): Promise<Response> {
  const token = parseCookie(request.headers.get("cookie"), "ml_admin_auth");
  
  if (!token || !(await verifyAdminSession(kv, token))) {
    return new Response(renderLoginPage(), {
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  const cookies = await getAllCookies(kv);
  await Promise.all(
    cookies
      .filter((c) => c.isEnabled && !c.isDefault)
      .map((c) => updateAccountLimits(kv, c))
  );

  const [stats, authKeys, models, updatedCookies] = await Promise.all([
    getStats(kv),
    getAllAuthKeys(kv),
    getAllModels(kv),
    getAllCookies(kv).then((cs) => 
      Promise.all(cs.map((c) => updateAccountLimits(kv, c)))
    ),
  ]);

  return new Response(renderAdminPanel(stats, authKeys, models, updatedCookies), {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

async function handleAdminApi(
  kv: Deno.Kv,
  request: Request,
  pathname: string
): Promise<Response> {
  if (pathname === "/admin/api/logout" && request.method === "POST") {
    return await handleAdminLogout(kv, request);
  }

  const token = parseCookie(request.headers.get("cookie"), "ml_admin_auth");
  
  if (!token || !(await verifyAdminSession(kv, token))) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  const cors = getCorsHeaders();

  if (pathname.startsWith("/admin/api/cookies")) {
    if (pathname === "/admin/api/cookies" && request.method === "POST") {
      const body = await request.json();
      const id = generateId("cookie");
      const cookie: CookieAccount = {
        id,
        name: body.name,
        cookieString: body.cookieString,
        isEnabled: true,
        isDefault: false,
        lastChecked: Date.now(),
      };
      await kv.set([KV_KEYS.COOKIES, id], cookie);
      return new Response(JSON.stringify({ success: true, id }), {
        headers: { ...cors, "Content-Type": "application/json" },
      });
    }

    const toggleMatch = pathname.match(/\/admin\/api\/cookies\/(.+)\/toggle$/);
    if (toggleMatch && request.method === "POST") {
      const id = toggleMatch[1];
      const entry = await kv.get<CookieAccount>([KV_KEYS.COOKIES, id]);
      if (entry.value && !entry.value.isDefault) {
        entry.value.isEnabled = !entry.value.isEnabled;
        await kv.set([KV_KEYS.COOKIES, id], entry.value);
      }
      return new Response(JSON.stringify({ success: true }), {
        headers: { ...cors, "Content-Type": "application/json" },
      });
    }

    const deleteMatch = pathname.match(/\/admin\/api\/cookies\/(.+)$/);
    if (deleteMatch && request.method === "DELETE") {
      const id = deleteMatch[1];
      const entry = await kv.get<CookieAccount>([KV_KEYS.COOKIES, id]);
      if (entry.value && !entry.value.isDefault) {
        await kv.delete([KV_KEYS.COOKIES, id]);
      }
      return new Response(JSON.stringify({ success: true }), {
        headers: { ...cors, "Content-Type": "application/json" },
      });
    }
  }

  if (pathname.startsWith("/admin/api/auth-keys")) {
    if (pathname === "/admin/api/auth-keys" && request.method === "POST") {
      const body = await request.json();
      const key: AuthKey = {
        key: body.key,
        isEnabled: true,
        isDefault: false,
        createdAt: Date.now(),
      };
      await kv.set([KV_KEYS.AUTH_KEYS, body.key], key);
      return new Response(JSON.stringify({ success: true }), {
        headers: { ...cors, "Content-Type": "application/json" },
      });
    }

    const toggleMatch = pathname.match(/\/admin\/api\/auth-keys\/(.+)\/toggle$/);
    if (toggleMatch && request.method === "POST") {
      const key = decodeURIComponent(toggleMatch[1]);
      const entry = await kv.get<AuthKey>([KV_KEYS.AUTH_KEYS, key]);
      if (entry.value) {
        entry.value.isEnabled = !entry.value.isEnabled;
        await kv.set([KV_KEYS.AUTH_KEYS, key], entry.value);
      }
      return new Response(JSON.stringify({ success: true }), {
        headers: { ...cors, "Content-Type": "application/json" },
      });
    }

    const deleteMatch = pathname.match(/\/admin\/api\/auth-keys\/(.+)$/);
    if (deleteMatch && request.method === "DELETE") {
      const key = decodeURIComponent(deleteMatch[1]);
      const entry = await kv.get<AuthKey>([KV_KEYS.AUTH_KEYS, key]);
      if (entry.value && !entry.value.isDefault) {
        await kv.delete([KV_KEYS.AUTH_KEYS, key]);
      }
      return new Response(JSON.stringify({ success: true }), {
        headers: { ...cors, "Content-Type": "application/json" },
      });
    }
  }

  if (pathname.startsWith("/admin/api/models")) {
    if (pathname === "/admin/api/models" && request.method === "POST") {
      const body = await request.json();
      const model: ModelConfig = {
        id: body.id,
        isEnabled: true,
        isDefault: false,
        createdAt: Date.now(),
      };
      await kv.set([KV_KEYS.MODELS, body.id], model);
      return new Response(JSON.stringify({ success: true }), {
        headers: { ...cors, "Content-Type": "application/json" },
      });
    }

    const toggleMatch = pathname.match(/\/admin\/api\/models\/(.+)\/toggle$/);
    if (toggleMatch && request.method === "POST") {
      const id = decodeURIComponent(toggleMatch[1]);
      const entry = await kv.get<ModelConfig>([KV_KEYS.MODELS, id]);
      if (entry.value) {
        entry.value.isEnabled = !entry.value.isEnabled;
        await kv.set([KV_KEYS.MODELS, id], entry.value);
      }
      return new Response(JSON.stringify({ success: true }), {
        headers: { ...cors, "Content-Type": "application/json" },
      });
    }

    const deleteMatch = pathname.match(/\/admin\/api\/models\/(.+)$/);
    if (deleteMatch && request.method === "DELETE") {
      const id = decodeURIComponent(deleteMatch[1]);
      const entry = await kv.get<ModelConfig>([KV_KEYS.MODELS, id]);
      if (entry.value && !entry.value.isDefault) {
        await kv.delete([KV_KEYS.MODELS, id]);
      }
      return new Response(JSON.stringify({ success: true }), {
        headers: { ...cors, "Content-Type": "application/json" },
      });
    }
  }

  return new Response(JSON.stringify({ error: "Not found" }), {
    status: 404,
    headers: { ...cors, "Content-Type": "application/json" },
  });
}

// ==================== 主处理函数 ====================

async function handler(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const pathname = url.pathname;
  const cors = getCorsHeaders();

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors });
  }

  const kv = await Deno.openKv();
  await initializeDefaultData(kv, Deno.env.toObject());

  try {
    if (pathname.startsWith("/v1/")) {
      if (!(await checkAuth(kv, request))) {
        return new Response(
          JSON.stringify({
            error: {
              message: "Unauthorized",
              type: "invalid_auth",
              param: null,
              code: null,
            },
          }),
          { status: 401, headers: { ...cors, "Content-Type": "application/json" } }
        );
      }

      if (pathname === "/v1/models" && request.method === "GET") {
        return await handleModels(kv, cors);
      }
      if (pathname === "/v1/chat/completions" && request.method === "POST") {
        return await handleChatCompletions(kv, request, cors);
      }
    }

    if (pathname === "/admin" || pathname === "/admin/") {
      return await handleAdminPanel(kv, request);
    }

    if (pathname === "/admin/login") {
      return await handleAdminLogin(kv, request, Deno.env.toObject());
    }

    if (pathname.startsWith("/admin/api/")) {
      return await handleAdminApi(kv, request, pathname);
    }

    if (pathname === "/") {
      return new Response(
        JSON.stringify({
          message: "MovementLabs API Gateway",
          version: "2.0.0",
          endpoints: ["/v1/models", "/v1/chat/completions", "/admin"],
          features: ["自动配额检查", "失败重试机制", "侧边栏管理界面", "调试日志"]
        }),
        { status: 200, headers: { ...cors, "Content-Type": "application/json" } }
      );
    }

    return new Response("Not found", { status: 404 });
  } catch (e) {
    debugError("Handler error:", e);
    return new Response(
      JSON.stringify({
        error: {
          message: e instanceof Error ? e.message : "Internal server error",
          type: "server_error",
          param: null,
          code: null,
        },
      }),
      { status: 500, headers: { ...cors, "Content-Type": "application/json" } }
    );
  }
}

Deno.serve(handler);
