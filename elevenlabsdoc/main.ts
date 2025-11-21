// 环境变量配置
const API_BASE_URL = "https://elevenlabs.io";
const DEFAULT_AUTH_KEYS = ["sk-default", "sk-false"];
const AUTH_KEYS = Deno.env.get("AUTH_KEYS")?.split(",") || DEFAULT_AUTH_KEYS;

// 预设模型列表
const MODELS = ["gpt-4o", "gpt-4o-mini", "claude-3.5-sonnet", "claude-4.5-sonnet"];

// 浏览器 User-Agent 列表
const USER_AGENTS = {
  chrome_windows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  chrome_mac: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  chrome_linux: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  firefox_windows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
  firefox_mac: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
  safari_mac: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
  edge_windows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
  chrome_android: "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36",
};

// 工具函数：生成随机字符串
function generateRandomString(length: number, chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"): string {
  let result = "";
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// 工具函数：生成 UUID
function generateUUID(): string {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = Math.random() * 16 | 0;
    const v = c === "x" ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

// 工具函数：获取随机 User-Agent
function getRandomUserAgent(): string {
  const agents = Object.values(USER_AGENTS);
  return agents[Math.floor(Math.random() * agents.length)];
}

// 工具函数：验证 API Key
function validateAuth(request: Request): boolean {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader) return false;
  
  const token = authHeader.replace(/^Bearer\s+/i, "");
  return AUTH_KEYS.includes(token);
}

// 工具函数：格式化消息
function formatMessages(messages: Array<{ role: string; content: string }>): string {
  return messages.map(msg => `${msg.role}:${msg.content}`).join(";");
}

// 工具函数：设置 CORS 头
function setCorsHeaders(headers: Headers): void {
  headers.set("Access-Control-Allow-Origin", "*");
  headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

// 处理 OPTIONS 预检请求
function handleOptions(): Response {
  const headers = new Headers();
  setCorsHeaders(headers);
  return new Response(null, { status: 204, headers });
}

// 处理健康检查
function handleHealthCheck(): Response {
  const headers = new Headers({ "Content-Type": "application/json" });
  setCorsHeaders(headers);
  return new Response(
    JSON.stringify({ status: "ok", message: "Service is running" }),
    { status: 200, headers }
  );
}

// 处理模型列表请求
function handleModels(): Response {
  const timestamp = Math.floor(Date.now() / 1000);
  const data = MODELS.map(id => ({
    id,
    object: "model",
    created: timestamp,
    owned_by: "elevenlabs",
  }));

  const headers = new Headers({ "Content-Type": "application/json" });
  setCorsHeaders(headers);
  return new Response(
    JSON.stringify({ object: "list", data }),
    { status: 200, headers }
  );
}

// 解析 SSE 流并转换为 OpenAI 格式
async function* parseSSEStream(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  model: string,
  conversationId: string
): AsyncGenerator<string> {
  const decoder = new TextDecoder();
  let buffer = "";
  let textContent = "";
  const timestamp = Math.floor(Date.now() / 1000);

  // 发送首个开始块
  yield `data: ${JSON.stringify({
    id: conversationId,
    object: "chat.completion.chunk",
    created: timestamp,
    model,
    choices: [{
      index: 0,
      delta: { role: "assistant", content: "" },
      logprobs: null,
      finish_reason: null,
    }],
  })}\n\n`;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() || "";

    for (const line of lines) {
      if (!line.trim() || !line.startsWith("data: ")) continue;
      
      const dataStr = line.slice(6).trim();
      if (dataStr === "[DONE]") {
        // 发送结束块
        yield `data: ${JSON.stringify({
          id: conversationId,
          object: "chat.completion.chunk",
          created: timestamp,
          model,
          choices: [{
            index: 0,
            delta: {},
            logprobs: null,
            finish_reason: "stop",
          }],
        })}\n\n`;
        yield "data: [DONE]\n\n";
        return;
      }

      try {
        const data = JSON.parse(dataStr);
        
        // 提取文本内容
        if (data.type === "text-delta" && data.delta) {
          textContent += data.delta;
          yield `data: ${JSON.stringify({
            id: conversationId,
            object: "chat.completion.chunk",
            created: timestamp,
            model,
            choices: [{
              index: 0,
              delta: { content: data.delta },
              logprobs: null,
              finish_reason: null,
            }],
          })}\n\n`;
        }
      } catch {
        // 忽略解析错误
      }
    }
  }
}

// 处理聊天完成请求
async function handleChatCompletion(request: Request): Promise<Response> {
  try {
    const body = await request.json();
    const { messages, stream = false, model = "gpt-4o" } = body;

    if (!messages || !Array.isArray(messages)) {
      throw new Error("Invalid messages format");
    }

    // 格式化消息
    const formattedMessages = formatMessages(messages);
    const lastMessage = messages[messages.length - 1];

    // 构造请求体
    const conversationId = generateRandomString(32);
    const queryId = generateUUID();
    const messageId = generateRandomString(16);

    const requestBody = {
      conversationId,
      queryId,
      filters: [],
      source: "CHAT",
      documentUrls: [],
      id: generateRandomString(16),
      messages: [{
        role: "user",
        parts: [{
          type: "text",
          text: formattedMessages,
        }],
        id: messageId,
      }],
      trigger: "submit-user-message",
    };

    // 发送请求到 ElevenLabs
    const response = await fetch(`${API_BASE_URL}/docs/api/fern-docs/search/v2/chat`, {
      method: "POST",
      headers: {
        "User-Agent": "ai-sdk/5.0.86 runtime/browser",
        "Content-Type": "application/json",
        "x-fern-host": "elevenlabs.io",
        "Referer": "https://elevenlabs.io/docs/quickstart",
      },
      body: JSON.stringify(requestBody),
    });

    if (!response.ok) {
      throw new Error(`ElevenLabs API error: ${response.status}`);
    }

    const headers = new Headers();
    setCorsHeaders(headers);

    // 流式响应
    if (stream) {
      headers.set("Content-Type", "text/event-stream");
      headers.set("Cache-Control", "no-cache");
      headers.set("Connection", "keep-alive");

      const reader = response.body!.getReader();
      const streamGenerator = parseSSEStream(reader, model, conversationId);

      const readableStream = new ReadableStream({
        async start(controller) {
          try {
            for await (const chunk of streamGenerator) {
              controller.enqueue(new TextEncoder().encode(chunk));
            }
          } catch (error) {
            console.error("Stream error:", error);
          } finally {
            controller.close();
          }
        },
      });

      return new Response(readableStream, { headers });
    }

    // 非流式响应
    const reader = response.body!.getReader();
    let fullContent = "";
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() || "";

      for (const line of lines) {
        if (!line.trim() || !line.startsWith("data: ")) continue;
        
        const dataStr = line.slice(6).trim();
        if (dataStr === "[DONE]") break;

        try {
          const data = JSON.parse(dataStr);
          if (data.type === "text-delta" && data.delta) {
            fullContent += data.delta;
          }
        } catch {
          // 忽略解析错误
        }
      }
    }

    headers.set("Content-Type", "application/json");
    return new Response(
      JSON.stringify({
        id: conversationId,
        object: "chat.completion",
        created: Math.floor(Date.now() / 1000),
        model,
        choices: [{
          index: 0,
          message: {
            role: "assistant",
            content: fullContent,
          },
          finish_reason: "stop",
        }],
        usage: {
          prompt_tokens: messages.reduce((sum: number, msg: any) => sum + msg.content.length, 0),
          completion_tokens: fullContent.length,
          total_tokens: messages.reduce((sum: number, msg: any) => sum + msg.content.length, 0) + fullContent.length,
        },
      }),
      { status: 200, headers }
    );
  } catch (error) {
    const headers = new Headers({ "Content-Type": "application/json" });
    setCorsHeaders(headers);
    return new Response(
      JSON.stringify({ error: error instanceof Error ? error.message : "Unknown error" }),
      { status: 500, headers }
    );
  }
}

// 主处理函数
Deno.serve(async (request: Request) => {
  const url = new URL(request.url);
  const path = url.pathname;

  // 处理 OPTIONS 预检
  if (request.method === "OPTIONS") {
    return handleOptions();
  }

  // 健康检查
  if (request.method === "GET" && path === "/") {
    return handleHealthCheck();
  }

  // 验证鉴权
  if (!validateAuth(request)) {
    const headers = new Headers({ "Content-Type": "application/json" });
    setCorsHeaders(headers);
    return new Response(
      JSON.stringify({ error: "Unauthorized" }),
      { status: 401, headers }
    );
  }

  // 路由处理
  if (request.method === "GET" && path === "/v1/models") {
    return handleModels();
  }

  if (request.method === "POST" && path === "/v1/chat/completions") {
    return await handleChatCompletion(request);
  }

  // 404
  const headers = new Headers({ "Content-Type": "application/json" });
  setCorsHeaders(headers);
  return new Response(
    JSON.stringify({ error: "Not Found" }),
    { status: 404, headers }
  );
});
