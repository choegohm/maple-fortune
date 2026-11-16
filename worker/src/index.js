// 넥슨 Open ID 로그인을 처리하고, 로그인한 사용자 대신 넥슨 API를 호출한다.
// client_secret과 토큰은 이 Worker 안에만 있고 페이지로는 나가지 않는다.

const AUTHORIZE_URL = "https://openid.nexon.com/oauth2/authorize";
const TOKEN_URL = "https://openid.nexon.com/oauth2/token";
const API = "https://open.api.nexon.com/maplestory/v1";
const SCOPE = "maplestory.characterlist";
const STATE_COOKIE = "nx_state";
const SESSION_TTL = 60 * 60 * 24 * 14; // 갱신 토큰 수명(14일)

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") return cors(env, new Response(null, { status: 204 }));

    try {
      if (url.pathname === "/login") return login(url, env);
      if (url.pathname === "/callback") return await callback(request, url, env);
      if (url.pathname === "/characters") return cors(env, await characters(request, env));
      if (url.pathname === "/basic") return cors(env, await basic(request, url, env));
      if (url.pathname === "/logout" && request.method === "POST") return cors(env, await logout(request, env));
      return new Response("Not found", { status: 404 });
    } catch (e) {
      return cors(env, json({ error: e.message || "서버 오류가 발생했어요." }, 500));
    }
  }
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" }
  });
}

function cors(env, response) {
  const res = new Response(response.body, response);
  res.headers.set("access-control-allow-origin", env.ALLOWED_ORIGIN);
  res.headers.set("access-control-allow-headers", "authorization");
  res.headers.set("access-control-allow-methods", "GET, POST, OPTIONS");
  res.headers.set("vary", "origin");
  return res;
}

function randomToken(bytes = 32) {
  const buf = crypto.getRandomValues(new Uint8Array(bytes));
  return [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function redirectUri(url) {
  return `${url.origin}/callback`;
}

function readCookie(request, name) {
  const header = request.headers.get("cookie") || "";
  const found = header.split(/;\s*/).find((c) => c.startsWith(name + "="));
  return found ? found.slice(name.length + 1) : null;
}

function login(url, env) {
  const state = randomToken(16);
  const authorize = new URL(AUTHORIZE_URL);
  authorize.searchParams.set("response_type", "code");
  authorize.searchParams.set("client_id", env.NEXON_CLIENT_ID);
  authorize.searchParams.set("redirect_uri", redirectUri(url));
  authorize.searchParams.set("scope", SCOPE);
  authorize.searchParams.set("state", state);
  return new Response(null, {
    status: 302,
    headers: {
      location: authorize.toString(),
      "set-cookie": `${STATE_COOKIE}=${state}; Path=/callback; Max-Age=600; HttpOnly; Secure; SameSite=Lax`
    }
  });
}

function backToPage(env, hash) {
  return new Response(null, {
    status: 302,
    headers: {
      location: `${env.PAGE_URL}#${hash}`,
      "set-cookie": `${STATE_COOKIE}=; Path=/callback; Max-Age=0; HttpOnly; Secure; SameSite=Lax`
    }
  });
}

async function requestToken(env, params) {
  const res = await fetch(TOKEN_URL, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: env.NEXON_CLIENT_ID,
      client_secret: env.NEXON_CLIENT_SECRET,
      ...params
    })
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data.access_token) return null;
  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token || null,
    expiresAt: Date.now() + (Number(data.expires_in) || 1800) * 1000
  };
}

async function callback(request, url, env) {
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const savedState = readCookie(request, STATE_COOKIE);

  if (url.searchParams.get("error")) return backToPage(env, "login_error=cancelled");
  if (!code || !state || !savedState || state !== savedState) return backToPage(env, "login_error=state");

  const tokens = await requestToken(env, {
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri(url)
  });
  if (!tokens) return backToPage(env, "login_error=token");

  const sessionId = randomToken(32);
  await env.SESSIONS.put(sessionId, JSON.stringify(tokens), { expirationTtl: SESSION_TTL });
  return backToPage(env, `session=${sessionId}`);
}

function sessionIdFrom(request) {
  const header = request.headers.get("authorization") || "";
  return header.startsWith("Bearer ") ? header.slice(7) : null;
}

// 세션의 액세스 토큰을 꺼내고, 만료가 가까우면 갱신한다
async function accessTokenFor(request, env) {
  const sessionId = sessionIdFrom(request);
  if (!sessionId) return null;
  const raw = await env.SESSIONS.get(sessionId);
  if (!raw) return null;

  let tokens = JSON.parse(raw);
  if (Date.now() > tokens.expiresAt - 60 * 1000) {
    if (!tokens.refreshToken) return null;
    const refreshed = await requestToken(env, {
      grant_type: "refresh_token",
      refresh_token: tokens.refreshToken
    });
    if (!refreshed) {
      await env.SESSIONS.delete(sessionId);
      return null;
    }
    tokens = { ...refreshed, refreshToken: refreshed.refreshToken || tokens.refreshToken };
    await env.SESSIONS.put(sessionId, JSON.stringify(tokens), { expirationTtl: SESSION_TTL });
  }
  return tokens.accessToken;
}

const LOGIN_EXPIRED = () => json({ error: "로그인이 만료됐어요. 다시 로그인해 주세요.", code: "login_expired" }, 401);

async function passThrough(res) {
  return new Response(await res.text(), {
    status: res.status,
    headers: { "content-type": "application/json; charset=utf-8" }
  });
}

// ocid는 API 키 조각을 품을 수 있어 페이지로 내보내지 않는다.
// 대신 ocid의 SHA-256 앞 32자(ref)를 주고, ref → ocid 대응은 세션에 둔다.
async function characterRef(ocid) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(ocid));
  return [...new Uint8Array(digest)].slice(0, 16).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function characters(request, env) {
  const accessToken = await accessTokenFor(request, env);
  if (!accessToken) return LOGIN_EXPIRED();
  const res = await fetch(`${API}/character/list`, {
    headers: { authorization: `Bearer ${accessToken}` }
  });
  if (!res.ok) return passThrough(res);

  const data = await res.json();
  const refToOcid = {};
  for (const account of data.account_list || []) {
    for (const character of account.character_list || []) {
      const ref = await characterRef(character.ocid);
      refToOcid[ref] = character.ocid;
      character.ref = ref;
      delete character.ocid;
    }
  }
  await env.SESSIONS.put(`${sessionIdFrom(request)}:characters`, JSON.stringify(refToOcid), { expirationTtl: SESSION_TTL });
  return json(data);
}

// character/basic은 로그인 토큰으로 열리지 않아 서비스 API 키로 부른다.
// 로그인한 사용자만, 자기 캐릭터 목록에 있는 캐릭터만 조회할 수 있다.
async function basic(request, url, env) {
  const accessToken = await accessTokenFor(request, env);
  if (!accessToken) return LOGIN_EXPIRED();
  const ref = url.searchParams.get("ref") || "";
  const refToOcid = JSON.parse((await env.SESSIONS.get(`${sessionIdFrom(request)}:characters`)) || "{}");
  const ocid = refToOcid[ref];
  if (!ocid) return json({ error: "캐릭터 목록을 다시 불러와 주세요." }, 400);
  const res = await fetch(`${API}/character/basic?ocid=${encodeURIComponent(ocid)}`, {
    headers: { "x-nxopen-api-key": env.NEXON_API_KEY }
  });
  return passThrough(res);
}

async function logout(request, env) {
  const sessionId = sessionIdFrom(request);
  if (sessionId) {
    await env.SESSIONS.delete(sessionId);
    await env.SESSIONS.delete(`${sessionId}:characters`);
  }
  return json({ ok: true });
}
