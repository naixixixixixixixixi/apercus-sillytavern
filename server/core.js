'use strict';

// Apercus Gateway 的 ST 服务端插件核心：与 Express/SillyTavern 无关的纯处理层。
// 路由只在 index.js 中接线到 ST；本文件只依赖 Node 原生能力（fetch/AbortController/
// Buffer），所有外部依赖（绑定读取器、fetch、超时、体积上限）由 createCore 注入，
// 测试可直接以假实现驱动，不接触真实 ST 或网关。
//
// 固定目标（已按网关仓库 docs 核实）：
//   - docs/deploy-runbook.md:341-352：门户 Origin = https://gw.apercus.ai，
//     数据面 Origin = https://api.apercus.ai（数据面白名单 data_plane_hosts）。
//   - 查询面（v1.35）：/api/plugin/me、/me/keys、/me/key、/me/models、/me/balance
//     全部在门户目标 https://gw.apercus.ai，Bearer 插件登录凭据，不用于 /v1 数据面。
//   - GET /catalog/models 与 GET /api/user/balance 旧直连已删除（B3 改走查询面）。
//   - POST /plan（B2 防截断分节）转发到数据面 /v1/chat/completions（v1.32 冻结面）。
//   - docs/api/api.md connect §0（v1.35 草稿）：/api/connect/* 与 /api/plugin/* 在
//     门户目标 https://gw.apercus.ai。
// 因此规划走数据面常量、连接/查询面走门户常量；全部为编译期常量，
// 不接受请求方传入的 URL/Origin，也不读取请求头里的任何目标覆盖。

const { createGatewayClient } = require('./gateway-client');
const { BINDING_NAMESPACE, normalizeCustomKeys, isValidBindingKey } = require('./binding-store');

const PORTAL_ORIGIN = 'https://gw.apercus.ai';
const DATA_ORIGIN = 'https://api.apercus.ai';
// v3 连接记录命名空间（信封 {"version":1,"login_credential","key","username"}）。
const BINDING_SECRET_KEY = BINDING_NAMESPACE;

const PLAN_CHAT_COMPLETIONS_PATH = '/v1/chat/completions';
const PLAN_TEMPERATURE = 0.2;
// B2 规划调用的输出预算。推理型模型（如 deepseek-v4.1-flash）会先把预算耗在
// reasoning 上：实网探针 max_tokens=600 时 sections 调用返回 choices=[]（全部
// 预算记为 reasoning_tokens），2048 才能拿到 JSON。留足余量取 4096；4096 只是
// 输出上限，实际计费以网关口径为准。
const PLAN_MAX_TOKENS = 4096;
const PLAN_MODEL_MAX = 512;
const PLAN_PROMPT_MAX = 32768;
// /plan 请求体专用上限（64KiB）。规格的 16KiB 体限与“调用一摘要 ≤16000
// 字符”自相矛盾：CJK 摘要按 UTF-8 约 3 字节/字符，仅摘要就接近 48KiB，
// 再加两段固定提示词与 JSON 外壳超过 16KiB。取 64KiB 容纳合法最大摘要；
// 上游响应体仍走 maxBytes（默认 512KiB）。
const PLAN_MAX_BYTES = 64 * 1024;
const APPLY_MODEL_BODY_MAX = 16 * 1024;

const DEFAULT_PLAN_TIMEOUT_MS = 12000;
const DEFAULT_CONNECT_TIMEOUT_MS = 8000;
const DEFAULT_MAX_BYTES = 512 * 1024;
const DEFAULT_PLAN_RATE_LIMIT_PER_MINUTE = 6;
const DEFAULT_APPLY_MODEL_RATE_LIMIT_PER_MINUTE = 10;
const DEFAULT_QUERY_RATE_LIMIT_PER_MINUTE = 60;
const DEFAULT_RELEASE_RATE_LIMIT_PER_MINUTE = 30;
const RATE_WINDOW_MS = 60 * 1000;
// 机会式登录探活：/status 在授权态且距上次成功探活超过 1 小时时，
// 异步 fetchMeKey（不阻塞响应）；key 与信封不同则刷新信封（F9），
// 401 → 按查询面失效清理，其他失败忽略。
const DEFAULT_LOGIN_PROBE_INTERVAL_MS = 60 * 60 * 1000;
// F5：approved 写库失败的重试上限（含首次失败）。第 4 次失败清会话并标记连接
// 失效；前 3 次仍回 pending 并附重试态。
const APPROVED_WRITE_MAX_ATTEMPTS = 4;
// F1：默认只允许 loopback 字面量 Host（去端口/小写/去 IPv6 括号后精确匹配）。
// 反代/自定义域名部署必须经 createCore deps 的 allowedHosts 扩充（server/index.js
// 从 APERCUS_ALLOWED_HOSTS 逗号分隔注入）；插件这一层是默认 deny-by-host 的兜底，
// ST 的 hostWhitelist 仍建议同时开启。
const DEFAULT_ALLOWED_HOSTS = Object.freeze(['localhost', '127.0.0.1', '::1']);
// 契约固定轮询节奏 ≥5 秒（非协商，不进响应体）；实际取 5.5 秒——恰踩网关 5 秒
// 硬闸下限会在网络抖动下偶发 429（连接期显示「暂不可用」后自恢复）。连接请求 TTL 15 分钟。
const CONNECT_POLL_INTERVAL_MS = 5500;
const CONNECT_TTL_MS = 15 * 60 * 1000;

const MESSAGE_STATUS = '网关 Pass 账户绑定尚未开放：网关授权与交付契约未完成，登录暂不可用。';
const MESSAGE_PENDING = '等待网关网页授权完成。';
const MESSAGE_AUTHORIZED = '已授权（已授权不等于已连接）。';
const MESSAGE_FORBIDDEN = '未登录或会话无效。';
const MESSAGE_ORIGIN = '跨源写请求被拒绝。';
const MESSAGE_NOT_CONNECTED = '尚未完成 Apercus 网关账户绑定。';
const MESSAGE_LOGIN_INVALID = '登录已失效或已撤销，请重新连接 Apercus 网关。';
const MESSAGE_INVALID_REQUEST = '请求体仅接受 model 与 prompt 两个非空字符串字段。';
const MESSAGE_APPLY_MODEL_INVALID = '请求体仅接受 model 非空字符串与 switchSource 布尔值。';
const MESSAGE_UPSTREAM = '网关暂时不可用，请稍后重试。';
const MESSAGE_BINDING_INVALIDATED = '绑定凭据失效（key 已重置或登录已撤销），请重新连接网关。';
const MESSAGE_RATE_LIMITED = '请求过于频繁，请稍后重试。';
const MESSAGE_TIMEOUT = '网关响应超时，请稍后重试。';
const MESSAGE_INVALID = '网关返回了无法识别的响应。';
const MESSAGE_INTERNAL = '网关插件内部错误。';
const MESSAGE_CUSTOM_WRITE_FAILED = '网关 key 未能写入酒馆 Custom 源，模型接入未应用。';
const MESSAGE_CUSTOM_WRITE_PARTIAL = '网关 key 的 Custom 源写入未完成，结果不确定；请重试，或退出登录清理后再试。';
const MESSAGE_LOGOUT_LOCAL_CLEAR_FAILED = '退出登录时本地凭据清理失败；请重试，或到门户“退出所有酒馆插件”兜底。';
const MESSAGE_HOST_NOT_ALLOWED = '请求 Host 不在允许列表。';
const MESSAGE_BINDING_CONFLICT = '登录状态已变更，本次操作已取消，请重试。';

const CONNECT_INVALID_REASON = 'connect_request_invalid';
const LOGIN_INVALID_REASON = 'login_invalidated';
const AUTHORIZATION_WRITE_FAILED_REASON = 'authorization_write_failed';

// GET /status v3：state 四态（not_connected / pending / authorized / invalid）。
// connected 恒 false（现有约定：插件从不代替酒馆报告连接）；st_connection 独立
// 表示酒馆侧连接，服务端固定 unknown——酒馆连接态由 UI 读取 ST 自身状态
// （ctx.onlineStatus 可用时显示 connected/disconnected，否则 unknown），插件
// 不另设判定，也不接收 UI 上报改变它。F4：只有登录失效（login_invalidated：
// logout 本地清理失败 / 查询面 401 清理失败）才让 /status 报 invalid；连接请求
// 失效（poll 404/取消/过期/授权写库重试耗尽）只影响 /connect/status 与连接
// 面板，已有有效信封时 /status 仍按 authorized 回答（失效标记不得压过信封）。
// I9：legacy code/message 按 state 输出（UI 可继续忽略），authorized 时不再
// 与 state 自相矛盾地报 pass_binding_unavailable。
const STATUS_CODE_PASS_UNAVAILABLE = 'pass_binding_unavailable';
const STATUS_CODE_CONNECT_PENDING = 'connect_pending';
const STATUS_CODE_AUTHORIZED = 'authorized';
const STATUS_CODE_LOGIN_INVALID = 'login_invalidated';

function statusCodeFor(state) {
    switch (state) {
        case 'pending': return { code: STATUS_CODE_CONNECT_PENDING, message: MESSAGE_PENDING };
        case 'authorized': return { code: STATUS_CODE_AUTHORIZED, message: MESSAGE_AUTHORIZED };
        case 'invalid': return { code: STATUS_CODE_LOGIN_INVALID, message: MESSAGE_LOGIN_INVALID };
        default: return { code: STATUS_CODE_PASS_UNAVAILABLE, message: MESSAGE_STATUS };
    }
}

function buildStatusBody(record, hasSession, invalid, invalidReason, loginLocalCleared, loginCustomCleared) {
    let state;
    let reason = null;
    let username = null;
    if (invalid) {
        state = 'invalid';
        reason = typeof invalidReason === 'string' && invalidReason.length > 0
            ? invalidReason
            : LOGIN_INVALID_REASON;
    } else if (record) {
        state = 'authorized';
        username = typeof record.username === 'string' && record.username.length > 0
            ? record.username
            : null;
    } else if (hasSession) {
        state = 'pending';
    } else {
        state = 'not_connected';
    }
    const { code, message } = statusCodeFor(state);
    const body = {
        authAvailable: false,
        connected: false,
        code,
        message,
        protocols: {
            chat: false,
            anthropic: false,
            responses: false,
        },
        state,
        // W1：独立于 state 表示“仍有存活连接请求”。已授权时重新发起连接
        // （换账号/续期）state 仍是 authorized，UI 刷新后靠本字段恢复轮询，
        // 否则 approved 交付永远没人领取。
        connect_pending: hasSession === true,
        st_connection: { state: 'unknown' },
    };
    if (reason !== null) body.reason = reason;
    if (state === 'invalid' && reason === LOGIN_INVALID_REASON) {
        // W10：分别说明信封与 Custom 清理是否完整成功。UI 只在 Custom
        // 清理确认成功（或 URL 仍为网关）时清空/恢复 Custom 设置。
        body.local_cleared = loginLocalCleared === true;
        body.custom_cleared = loginCustomCleared === true;
    }
    if (username !== null) body.username = username;
    return body;
}

class GatewayError extends Error {
    constructor(status, code, message) {
        super(message);
        this.status = status;
        this.code = code;
    }
}

function forbidden() { return new GatewayError(403, 'forbidden', MESSAGE_FORBIDDEN); }
function unauthorized() { return new GatewayError(401, 'unauthorized', MESSAGE_FORBIDDEN); }
function originForbidden() { return new GatewayError(403, 'origin_forbidden', MESSAGE_ORIGIN); }
function hostNotAllowed() { return new GatewayError(403, 'host_not_allowed', MESSAGE_HOST_NOT_ALLOWED); }
function bindingConflict() { return new GatewayError(409, 'not_connected', MESSAGE_BINDING_CONFLICT); }
function invalidRequest() { return new GatewayError(422, 'invalid_request', MESSAGE_INVALID_REQUEST); }
function invalidApplyModelRequest() { return new GatewayError(422, 'invalid_request', MESSAGE_APPLY_MODEL_INVALID); }
function notConnected() { return new GatewayError(409, 'not_connected', MESSAGE_NOT_CONNECTED); }
function loginInvalid() { return new GatewayError(409, 'not_connected', MESSAGE_LOGIN_INVALID); }
function upstreamUnavailable() { return new GatewayError(502, 'upstream_unavailable', MESSAGE_UPSTREAM); }
function bindingInvalidated() { return new GatewayError(502, 'binding_invalidated', MESSAGE_BINDING_INVALIDATED); }
function upstreamTimeout() { return new GatewayError(504, 'upstream_timeout', MESSAGE_TIMEOUT); }
function invalidResponse() { return new GatewayError(502, 'upstream_invalid_response', MESSAGE_INVALID); }
function customSourceWriteFailed() { return new GatewayError(502, 'custom_source_write_failed', MESSAGE_CUSTOM_WRITE_FAILED); }
function customSourceWritePartial() { return new GatewayError(502, 'custom_source_write_partial', MESSAGE_CUSTOM_WRITE_PARTIAL); }
function logoutLocalClearFailed() { return new GatewayError(502, 'logout_local_clear_failed', MESSAGE_LOGOUT_LOCAL_CLEAR_FAILED); }

// cancel() 返回 Promise：流已 errored 时会以 stored error 拒绝，未处理的 rejection
// 会击穿 ST 的 uncaughtException 处理器（exitProcess，整个 ST 退出）。统一走这里。
function cancelBodyQuietly(response) {
    try {
        const body = response && response.body;
        if (body && typeof body.cancel === 'function') {
            Promise.resolve(body.cancel()).catch(() => {});
        }
    } catch {
        // 同步异常同样吞掉：cancel 失败不影响错误语义。
    }
}

function sendJson(res, status, payload) {
    res.statusCode = status;
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.end(JSON.stringify(payload));
}

function sendError(res, error) {
    if (error instanceof GatewayError) {
        sendJson(res, error.status, { error: { code: error.code, message: error.message } });
        return;
    }
    sendJson(res, 500, { error: { code: 'internal_error', message: MESSAGE_INTERNAL } });
}

// ===== F1 Host allowlist =====
// Host 头解析：去端口、小写、去 IPv6 方括号；缺失/畸形/多冒号未加方括号一律
// null（随后 403 host_not_allowed）。只做 hostname 精确比较，不信任
// X-Forwarded-Host（反代必须把实际 Host 透传并加入 allowedHosts）。
function normalizeHostHeader(raw) {
    if (typeof raw !== 'string') return null;
    const value = raw.trim();
    if (value.length === 0 || value.length > 1024) return null;
    if (/[\s/\\]/.test(value)) return null;
    if (value.startsWith('[')) {
        const close = value.indexOf(']');
        if (close < 0) return null;
        const host = value.slice(1, close);
        const rest = value.slice(close + 1);
        if (host.length === 0 || /[\s/\\]/.test(host)) return null;
        if (rest !== '' && !/^:\d+$/.test(rest)) return null;
        return host.toLowerCase();
    }
    const colon = value.indexOf(':');
    if (colon >= 0) {
        if (value.indexOf(':', colon + 1) >= 0) return null; // 未加括号的 IPv6 Host 非法
        if (!/^\d+$/.test(value.slice(colon + 1))) return null;
        return value.slice(0, colon).toLowerCase();
    }
    return value.toLowerCase();
}

// allowedHosts 配置项归一化：每项非空字符串 → 去空白、小写、去 IPv6 方括号；
// 允许写 host:port（按 host 比较）。空数组/缺省 = 只允许 loopback 默认集。
function normalizeAllowedHosts(value) {
    const entries = [];
    for (const item of value) {
        if (typeof item !== 'string') return null;
        const raw = item.trim().toLowerCase();
        if (raw.length === 0) return null;
        // 配置项允许裸 IPv6（Host 头的裸 IPv6 仍然非法）。
        const normalized = raw.indexOf(':') >= 0 && !raw.startsWith('[')
            && raw.split(':').length > 2
            ? raw
            : normalizeHostHeader(raw);
        if (!normalized) return null;
        if (!entries.includes(normalized)) entries.push(normalized);
    }
    return entries;
}

// 身份/同源校验之前的统一 Host 闸（所有路由，含 GET）。不匹配 → 403
// host_not_allowed，不泄露配置内容。
function assertAllowedHost(req, allowedHosts) {
    const headers = (req && req.headers) || {};
    const hostname = normalizeHostHeader(headers.host);
    if (!hostname || !allowedHosts.has(hostname)) throw hostNotAllowed();
}

// 身份只取 ST 注入的 req.user.directories；不读请求体/query/头的 user id，
// 也不回落到默认用户目录。
function requireDirectories(req) {
    const user = req && req.user;
    const directories = user && user.directories;
    if (!directories || typeof directories !== 'object'
        || typeof directories.root !== 'string' || directories.root.length === 0) {
        throw forbidden();
    }
    return directories;
}

function normalizeBinding(raw) {
    if (typeof raw !== 'string' || raw.length === 0 || raw.length > 4096) {
        return null;
    }
    if (/[\r\n\x00-\x1f\x7f]/.test(raw)) {
        return null;
    }
    return raw;
}

// 连接记录统一形态：readBinding 兼容两种返回——原始 key 字符串（旧测试/旧
// 适配器，无登录凭据）与 {loginCredential, key, username, customKeys}（v3
// secrets-binding 适配器）。key 一律过 normalizeBinding（长度上限、剔除控制
// 字符）；custom_keys（插件写入过的 Custom key 历史）缺失 → []，非法 → null
// （fail-closed：坏归属列表不当作清理依据）。任何不合格形态返回 null。
function normalizeBindingRecord(raw) {
    if (raw === null || raw === undefined) return null;
    if (typeof raw === 'string') {
        const key = normalizeBinding(raw);
        return key ? { key, loginCredential: null, username: null, customKeys: [] } : null;
    }
    if (isPlainObject(raw)) {
        const key = normalizeBinding(raw.key);
        if (!key) return null;
        const loginCredential = typeof raw.loginCredential === 'string'
            ? normalizeBinding(raw.loginCredential)
            : null;
        const username = typeof raw.username === 'string' && raw.username.length > 0
            && !/[\r\n\x00-\x1f\x7f]/.test(raw.username) && raw.username.length <= 512
            ? raw.username
            : null;
        const customKeys = normalizeCustomKeys(raw.customKeys);
        if (customKeys === null) return null;
        return { key, loginCredential, username, customKeys };
    }
    return null;
}

function isPlainObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function requireString(value, maxLength) {
    if (typeof value !== 'string' || value.length === 0 || value.length > maxLength) throw invalidResponse();
    return value;
}

// catalog 原契约五键投影：未知协议面/模态整包拒绝（fail-closed），未知字段丢弃，
// 文本仅做长度上限校验、不改写内容。classification_name 未归类时保持省略。
// 该函数服务于 B3 之后的 /models 线形状（gateway-client 已把 /me/models 的
// data[].id 映射为 items[].name 并做过严格校验，这里保持同一投影纪律）。
function projectCatalog(payload) {
    if (!isPlainObject(payload) || !Array.isArray(payload.items)) {
        throw invalidResponse();
    }
    const items = payload.items.map((item) => {
        if (!isPlainObject(item)) {
            throw invalidResponse();
        }
        const projected = {
            name: requireString(item.name, 512),
            protocol_faces: requireFaces(item.protocol_faces),
        };
        if (item.modality !== undefined) {
            if (typeof item.modality !== 'string'
                || !['text', 'image', 'embedding', 'tts', 'video'].includes(item.modality)) {
                throw invalidResponse();
            }
            projected.modality = item.modality;
        }
        if (item.capabilities !== undefined) {
            if (typeof item.capabilities !== 'string' || item.capabilities.length > 8192) {
                throw invalidResponse();
            }
            projected.capabilities = item.capabilities;
        }
        if (item.classification_name !== undefined) {
            projected.classification_name = requireString(item.classification_name, 512);
        }
        return projected;
    });
    return { items };
}

function requireFaces(value) {
    if (!Array.isArray(value)) throw invalidResponse();
    const faces = [];
    for (const face of value) {
        if (typeof face !== 'string'
            || !['chat', 'responses', 'anthropic', 'image', 'tts', 'embedding', 'video'].includes(face)) {
            throw invalidResponse();
        }
        if (!faces.includes(face)) faces.push(face);
    }
    return faces;
}

async function readBoundedBody(response, maxBytes) {
    const body = response && response.body;
    if (body && typeof body.getReader === 'function') {
        const reader = body.getReader();
        const chunks = [];
        let total = 0;
        try {
            while (true) {
                const { done, value } = await reader.read();
                if (done) {
                    break;
                }
                if (!value) {
                    continue;
                }
                total += value.byteLength;
                if (total > maxBytes) {
                    try {
                        await reader.cancel();
                    } catch {
                        // 取消失败不影响拒绝结论。
                    }
                    throw invalidResponse();
                }
                chunks.push(Buffer.from(value));
            }
        } catch (error) {
            if (error instanceof GatewayError) {
                throw error;
            }
            throw upstreamUnavailable();
        }
        return Buffer.concat(chunks).toString('utf8');
    }
    throw invalidResponse();
}

// ===== POST /plan（B2 防截断分节）=====

// /plan 是写面（消耗额度）：无 req.user 直接 401；user 存在但目录非法仍按 403。
function planRequireDirectories(req) {
    if (!req || typeof req !== 'object' || !req.user || typeof req.user !== 'object') {
        throw unauthorized();
    }
    return requireDirectories(req);
}

// 写操作同源校验（fail-closed）：浏览器自带的 Sec-Fetch-Site: same-origin 直接放行；
// 否则要求 Origin 与请求自身 Host+协议同源（反代场景读 X-Forwarded-Proto，直连按 http）。
// 缺 Origin 且非同源 fetch 元数据、跨源、解析失败一律 403。
function assertOriginMatchesHost(req) {
    const headers = (req && req.headers) || {};
    const origin = typeof headers.origin === 'string' ? headers.origin : '';
    const host = typeof headers.host === 'string' ? headers.host : '';
    if (origin.length === 0 || host.length === 0) throw originForbidden();
    let parsed;
    try {
        parsed = new URL(origin);
    } catch {
        throw originForbidden();
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw originForbidden();
    const forwarded = typeof headers['x-forwarded-proto'] === 'string'
        ? headers['x-forwarded-proto'].split(',')[0].trim().toLowerCase()
        : '';
    const requestProto = forwarded === 'https' ? 'https' : 'http';
    if (parsed.protocol !== `${requestProto}:`) throw originForbidden();
    if (parsed.host.toLowerCase() !== host.toLowerCase()) throw originForbidden();
}

function assertSameOrigin(req) {
    const headers = (req && req.headers) || {};
    if (headers['sec-fetch-site'] === 'same-origin') return;
    assertOriginMatchesHost(req);
}

// GET 读面的同源软闸（/connect/status 会触发上游轮询，不能只靠默认 CORS）：
// 跨源 fetch（CORS 模式）必带 Origin——Origin 在场且与 Host+协议不同源 → 403；
// Sec-Fetch-Site: cross-site → 403。同源 GET 通常不带 Origin → 放行。
function assertSameOriginForGet(req) {
    const headers = (req && req.headers) || {};
    const fetchSite = typeof headers['sec-fetch-site'] === 'string' ? headers['sec-fetch-site'] : '';
    if (fetchSite === 'same-origin' || fetchSite === 'none') return;
    if (fetchSite === 'cross-site') throw originForbidden();
    const origin = typeof headers.origin === 'string' ? headers.origin : '';
    if (origin.length === 0) return;
    assertSameOrigin(req);
}

// I5：GET /connect/status 会触发上游轮询并可能写密钥库，同源闸比普通读面
// 更严，但不得因为需求头缺失而阻断局域网/旧浏览器部署：
// - Sec-Fetch-Site 存在 → 必须恰为 same-origin（same-site / cross-site /
//   none 等一律 403）；
// - Origin 存在 → 必须与请求自身 Host+协议精确同源（反代读 X-Forwarded-Proto）；
// - 两者都缺失（非安全上下文/旧浏览器不发这些头，同源 GET 也无 Origin）→
//   放行，只依赖 Host allowlist 与轮询会话密钥的安全边界。
// Host 闸仍由调用方前置执行。
function assertConnectStatusOrigin(req) {
    const headers = (req && req.headers) || {};
    const fetchSite = typeof headers['sec-fetch-site'] === 'string'
        ? headers['sec-fetch-site'].trim().toLowerCase()
        : '';
    if (fetchSite.length > 0 && fetchSite !== 'same-origin') throw originForbidden();
    const origin = typeof headers.origin === 'string' ? headers.origin : '';
    if (origin.length === 0) return;
    assertOriginMatchesHost(req);
}

// /plan 每用户固定窗口限频（评审 E）：键为 req.user.directories.root；
// 默认 6 次/分；窗口从该用户第一次请求起算。返回 take(root)，超限抛 429。
function createPlanRateLimiter(limitPerMinute, now, windowMs) {
    const buckets = new Map();
    return function take(root) {
        const current = now();
        let bucket = buckets.get(root);
        if (!bucket || current < bucket.start || current - bucket.start >= windowMs) {
            bucket = { start: current, count: 0 };
            buckets.set(root, bucket);
        }
        if (bucket.count >= limitPerMinute) {
            throw new GatewayError(429, 'rate_limited', MESSAGE_RATE_LIMITED);
        }
        bucket.count += 1;
    };
}

// B3 查询面统一限频：按登录凭据 60 次/分 + 按 directories.root 60 次/分
// （独立实例；各自固定窗口，窗口从该键第一次请求起算）。两个桶先判定后同时
// 计数，避免一个桶已超限时另一个桶仍被消耗。凭据只作内存 Map 键，不落日志。
function createQueryRateLimiter(limitPerMinute, now, windowMs) {
    const byRoot = new Map();
    const byCredential = new Map();
    // W2：登录凭据会随重新授权轮换（cap=1 下每次连接一条新凭据），旧桶
    // 过期后必须清掉，否则 Map 随进程寿命无限累积原始凭据。超过阈值时
    // 顺带清扫两个 Map 的过期桶；正常规模下不做额外遍历。
    const PRUNE_THRESHOLD = 256;

    function pruneExpired(map, current) {
        for (const [key, bucket] of map) {
            if (current < bucket.start || current - bucket.start >= windowMs) {
                map.delete(key);
            }
        }
    }

    function bucketFor(map, key) {
        const current = now();
        let bucket = map.get(key);
        if (!bucket || current < bucket.start || current - bucket.start >= windowMs) {
            if (map.size >= PRUNE_THRESHOLD) pruneExpired(map, current);
            bucket = { start: current, count: 0 };
            map.set(key, bucket);
        }
        return bucket;
    }

    return function take(root, credential) {
        if (typeof root !== 'string' || root.length === 0
            || typeof credential !== 'string' || credential.length === 0) {
            throw new GatewayError(429, 'rate_limited', MESSAGE_RATE_LIMITED);
        }
        const rootBucket = bucketFor(byRoot, root);
        const credentialBucket = bucketFor(byCredential, credential);
        if (rootBucket.count >= limitPerMinute || credentialBucket.count >= limitPerMinute) {
            throw new GatewayError(429, 'rate_limited', MESSAGE_RATE_LIMITED);
        }
        rootBucket.count += 1;
        credentialBucket.count += 1;
    };
}

// 请求体：ST 全局 bodyparser 通常已解析 req.body；未解析时回退读流（带上限）。
// 体积闸（评审 F）：Content-Length 头、已解析对象的序列化长度、字符串 body
// 长度都在解析/上游调用之前检查；任何解析失败都按 422 拒绝，不猜字段。
// invalidFactory 允许不同路由使用各自的固定 422 文案（/apply-model 与 /plan
// 的请求体形状不同）。
function readPlanBody(req, maxBytes, invalidFactory) {
    const makeInvalid = typeof invalidFactory === 'function' ? invalidFactory : invalidRequest;
    const headers = (req && req.headers) || {};
    const declaredLength = headers['content-length'];
    if (declaredLength !== undefined && declaredLength !== null) {
        const declared = Number(declaredLength);
        if (!Number.isFinite(declared) || declared < 0 || declared > maxBytes) {
            throw makeInvalid();
        }
    }
    if (req && isPlainObject(req.body)) {
        let serialized;
        try {
            serialized = JSON.stringify(req.body);
        } catch {
            throw makeInvalid();
        }
        if (typeof serialized !== 'string' || Buffer.byteLength(serialized, 'utf8') > maxBytes) {
            throw makeInvalid();
        }
        return req.body;
    }
    if (req && typeof req.body === 'string') {
        if (Buffer.byteLength(req.body, 'utf8') > maxBytes) {
            throw makeInvalid();
        }
        try {
            return JSON.parse(req.body);
        } catch {
            throw makeInvalid();
        }
    }
    if (!req || typeof req.on !== 'function' || req.readableEnded) throw makeInvalid();
    return new Promise((resolve, reject) => {
        const chunks = [];
        let total = 0;
        let settled = false;
        const fail = () => {
            if (settled) return;
            settled = true;
            reject(makeInvalid());
        };
        req.on('data', (chunk) => {
            if (settled) return;
            total += chunk ? chunk.length : 0;
            if (total > maxBytes) {
                settled = true;
                reject(makeInvalid());
                return;
            }
            chunks.push(Buffer.from(chunk));
        });
        req.on('end', () => {
            if (settled) return;
            settled = true;
            try {
                resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
            } catch {
                reject(makeInvalid());
            }
        });
        req.on('error', fail);
        req.on('aborted', fail);
    });
}

// 严格白名单：恰好 {"model": 非空 string, "prompt": 非空 string}，未知字段/类型错 → 422。
function validatePlanBody(payload) {
    if (!isPlainObject(payload)) throw invalidRequest();
    const keys = Object.keys(payload);
    if (keys.length !== 2 || !keys.includes('model') || !keys.includes('prompt')) {
        throw invalidRequest();
    }
    const model = payload.model;
    const prompt = payload.prompt;
    if (typeof model !== 'string' || model.length === 0 || model.length > PLAN_MODEL_MAX) {
        throw invalidRequest();
    }
    if (typeof prompt !== 'string' || prompt.length === 0 || prompt.length > PLAN_PROMPT_MAX) {
        throw invalidRequest();
    }
    return { model, prompt };
}

// /apply-model 严格白名单：恰好 {"model": 非空 string, "switchSource": boolean}。
// switchSource 只表达「用户在确认弹窗里同意了切换 source」；服务端不写 ST 设置，
// 切换仍由 UI 在确认后执行。
function validateApplyModelBody(payload) {
    if (!isPlainObject(payload)) throw invalidApplyModelRequest();
    const keys = Object.keys(payload);
    if (keys.length !== 2 || !keys.includes('model') || !keys.includes('switchSource')) {
        throw invalidApplyModelRequest();
    }
    const model = payload.model;
    if (typeof model !== 'string' || model.length === 0 || model.length > PLAN_MODEL_MAX) {
        throw invalidApplyModelRequest();
    }
    if (typeof payload.switchSource !== 'boolean') throw invalidApplyModelRequest();
    return { model, switchSource: payload.switchSource };
}

// 单次上游调用：200 → {payload}；其他状态码 → {status}（不读也不回显正文）；
// 网络/超时/正文超限/坏 JSON → 抛 GatewayError。TLS 一律 Node fetch 默认校验。
async function postPlanOnce(url, binding, payload, options) {
    const controller = new AbortController();
    let timer;
    let timedOut = false;
    const timeoutPromise = new Promise((_, reject) => {
        timer = setTimeout(() => {
            timedOut = true;
            controller.abort();
            reject(upstreamTimeout());
        }, options.timeoutMs);
    });
    try {
        const response = await Promise.race([
            Promise.resolve().then(() => options.fetchImpl(url, {
                method: 'POST',
                redirect: 'error',
                headers: {
                    accept: 'application/json',
                    'content-type': 'application/json',
                    authorization: `Bearer ${binding}`,
                },
                body: JSON.stringify(payload),
                signal: controller.signal,
            })),
            timeoutPromise,
        ]);
        if (!response) {
            throw upstreamUnavailable();
        }
        if (response.status !== 200) {
            // 不读也不回显正文；主动 cancel 释放连接（拒绝会被吞掉，见 cancelBodyQuietly 注释）。
            cancelBodyQuietly(response);
            return { status: response.status };
        }
        const text = await Promise.race([
            readBoundedBody(response, options.maxBytes),
            timeoutPromise,
        ]);
        let parsed;
        try {
            parsed = JSON.parse(text);
        } catch {
            throw invalidResponse();
        }
        return { payload: parsed };
    } catch (error) {
        if (error instanceof GatewayError) {
            throw error;
        }
        if (timedOut) {
            throw upstreamTimeout();
        }
        throw upstreamUnavailable();
    } finally {
        clearTimeout(timer);
    }
}

// 网络错误/超时/上游 5xx 恰好重试一次；4xx 与其他形态不重试，全部按现有固定错误风格映射。
async function postPlanWithRetry(url, binding, payload, options) {
    let attempt = 0;
    while (attempt < 2) {
        attempt += 1;
        let error = null;
        let outcome = null;
        try {
            outcome = await postPlanOnce(url, binding, payload, options);
        } catch (caught) {
            error = caught;
        }
        const retryable = error
            ? error instanceof GatewayError
                && (error.code === 'upstream_unavailable' || error.code === 'upstream_timeout')
            : typeof outcome.status === 'number' && outcome.status >= 500 && outcome.status <= 599;
        if (retryable && attempt === 1) continue;
        if (error) throw error;
        if (typeof outcome.status === 'number') {
            if (outcome.status === 401) {
                // chat 面的 403 还有 quota_insufficient / 注销反悔期等正常计费态，
                // 一概标失效会造成“额度耗尽 → 要求重新配对”的死循环；/plan 只有
                // 401（invalid_key / key 重置）进失效联动。
                throw bindingInvalidated();
            }
            throw upstreamUnavailable();
        }
        return outcome.payload;
    }
    throw upstreamUnavailable();
}

// 只取 choices[0].message.content；其余字段一概不出口。
function extractPlanText(payload) {
    if (!isPlainObject(payload) || !Array.isArray(payload.choices) || payload.choices.length === 0) {
        throw invalidResponse();
    }
    const message = payload.choices[0] && payload.choices[0].message;
    if (!isPlainObject(message) || typeof message.content !== 'string') {
        throw invalidResponse();
    }
    return message.content;
}

function createCore(deps) {
    const readBinding = deps && deps.readBinding;
    const fetchImpl = (deps && deps.fetchImpl) || globalThis.fetch;
    const planTimeoutMs = (deps && deps.planTimeoutMs) || DEFAULT_PLAN_TIMEOUT_MS;
    const connectTimeoutMs = (deps && deps.connectTimeoutMs) || DEFAULT_CONNECT_TIMEOUT_MS;
    const maxBytes = (deps && deps.maxBytes) || DEFAULT_MAX_BYTES;
    const planRateLimitPerMinute = deps && deps.planRateLimitPerMinute !== undefined
        ? deps.planRateLimitPerMinute
        : DEFAULT_PLAN_RATE_LIMIT_PER_MINUTE;
    const applyModelRateLimitPerMinute = deps && deps.applyModelRateLimitPerMinute !== undefined
        ? deps.applyModelRateLimitPerMinute
        : DEFAULT_APPLY_MODEL_RATE_LIMIT_PER_MINUTE;
    const queryRateLimitPerMinute = deps && deps.queryRateLimitPerMinute !== undefined
        ? deps.queryRateLimitPerMinute
        : DEFAULT_QUERY_RATE_LIMIT_PER_MINUTE;
    const releaseRateLimitPerMinute = deps && deps.releaseRateLimitPerMinute !== undefined
        ? deps.releaseRateLimitPerMinute
        : DEFAULT_RELEASE_RATE_LIMIT_PER_MINUTE;
    // F1：allowedHosts 是额外允许的精确 host（生产由 APERCUS_ALLOWED_HOSTS
    // 注入）；缺省只允许 loopback 默认集。非法配置直接抛 TypeError（fail-closed：
    // 配置坏了不静默放宽）。
    const configuredHosts = deps && deps.allowedHosts !== undefined ? deps.allowedHosts : [];
    if (!Array.isArray(configuredHosts)) {
        throw new TypeError('allowedHosts must be an array of host strings');
    }
    const extraHosts = normalizeAllowedHosts(configuredHosts);
    if (extraHosts === null) {
        throw new TypeError('allowedHosts entries must be non-empty host strings');
    }
    const allowedHosts = new Set(DEFAULT_ALLOWED_HOSTS.concat(extraHosts));
    const loginProbeIntervalMs = deps && deps.loginProbeIntervalMs !== undefined
        ? deps.loginProbeIntervalMs
        : DEFAULT_LOGIN_PROBE_INTERVAL_MS;
    const now = (deps && deps.now) || Date.now;
    // 写路径只认注入（index.js 注入 secrets-binding 适配器）；缺省/非法一律按
    // null 处理——approved 因无处落盘而 fail-closed，绝不假装已授权。
    const writeBinding = deps && typeof deps.writeBinding === 'function' ? deps.writeBinding : null;
    const clearBinding = deps && typeof deps.clearBinding === 'function' ? deps.clearBinding : null;
    const refreshKey = deps && typeof deps.refreshKey === 'function' ? deps.refreshKey : null;
    // B3 Custom 源 key 写入只经 /apply-model（用户确认后）；缺省时该路由
    // fail-closed 返回 502 custom_source_write_failed。
    const writeCustomSourceKey = deps && typeof deps.writeCustomSourceKey === 'function'
        ? deps.writeCustomSourceKey
        : null;
    // F11 运行时清理：UI 在预设切换/生成设置就绪时发现 custom_url 指向非网关域，
    // 调 /release-custom-key 清掉插件自有 Custom 条目（按信封归属）。
    const clearCustomSourceKey = deps && typeof deps.clearCustomSourceKey === 'function'
        ? deps.clearCustomSourceKey
        : null;
    // H3：Custom 同步自愈（refreshKey 刷新信封但 Custom 旧 key 同步失败 →
    // /status 每次探活重试）。缺省时无操作（仅内存标记，不影响其他路径）。
    const retryCustomSync = deps && typeof deps.retryCustomSync === 'function'
        ? deps.retryCustomSync
        : null;
    // G8：可选的详细读取状态（区分没有信封与读/解析失败）；缺省时 release 只
    // 能按 readBinding 的 null 当“无绑定”（向后兼容旧适配器/测试）。
    const readBindingState = deps && typeof deps.readBindingState === 'function'
        ? deps.readBindingState
        : null;
    // W10：无信封时探测 Custom 命名空间是否仍有条目；缺省时 release 不能
    // 断言“已无归属”，按 read_failed 保守处理。
    const hasCustomSourceEntries = deps && typeof deps.hasCustomSourceEntries === 'function'
        ? deps.hasCustomSourceEntries
        : null;

    if (typeof readBinding !== 'function') {
        throw new TypeError('createCore requires readBinding(directories)');
    }
    if (typeof fetchImpl !== 'function') {
        throw new TypeError('createCore requires a fetch implementation');
    }
    if (!Number.isInteger(planTimeoutMs) || planTimeoutMs <= 0) {
        throw new TypeError('planTimeoutMs must be a positive integer');
    }
    if (!Number.isInteger(connectTimeoutMs) || connectTimeoutMs <= 0) {
        throw new TypeError('connectTimeoutMs must be a positive integer');
    }
    if (!Number.isInteger(maxBytes) || maxBytes <= 0) {
        throw new TypeError('maxBytes must be a positive integer');
    }
    if (!Number.isInteger(planRateLimitPerMinute) || planRateLimitPerMinute <= 0) {
        throw new TypeError('planRateLimitPerMinute must be a positive integer');
    }
    if (!Number.isInteger(queryRateLimitPerMinute) || queryRateLimitPerMinute <= 0) {
        throw new TypeError('queryRateLimitPerMinute must be a positive integer');
    }
    if (!Number.isInteger(releaseRateLimitPerMinute) || releaseRateLimitPerMinute <= 0) {
        throw new TypeError('releaseRateLimitPerMinute must be a positive integer');
    }
    if (!Number.isInteger(applyModelRateLimitPerMinute) || applyModelRateLimitPerMinute <= 0) {
        throw new TypeError('applyModelRateLimitPerMinute must be a positive integer');
    }
    if (!Number.isInteger(loginProbeIntervalMs) || loginProbeIntervalMs < 0) {
        throw new TypeError('loginProbeIntervalMs must be a non-negative integer');
    }
    if (typeof now !== 'function') {
        throw new TypeError('now must be a function returning epoch milliseconds');
    }
    const takePlanToken = createPlanRateLimiter(planRateLimitPerMinute, now, RATE_WINDOW_MS);
    const takeApplyToken = createPlanRateLimiter(applyModelRateLimitPerMinute, now, RATE_WINDOW_MS);
    const takeQueryToken = createQueryRateLimiter(queryRateLimitPerMinute, now, RATE_WINDOW_MS);
    const takeReleaseToken = createPlanRateLimiter(releaseRateLimitPerMinute, now, RATE_WINDOW_MS);

    let gatewayClient = deps && deps.gatewayClient;
    if (gatewayClient) {
        if (typeof gatewayClient.startConnect !== 'function'
            || typeof gatewayClient.pollConnect !== 'function'
            || typeof gatewayClient.logout !== 'function'
            || typeof gatewayClient.fetchKeys !== 'function'
            || typeof gatewayClient.fetchMeKey !== 'function'
            || typeof gatewayClient.fetchModels !== 'function'
            || typeof gatewayClient.fetchBalance !== 'function') {
            throw new TypeError('gatewayClient must provide startConnect, pollConnect, logout, fetchKeys, fetchMeKey, fetchModels and fetchBalance');
        }
    } else {
        gatewayClient = createGatewayClient({ fetchImpl, timeoutMs: connectTimeoutMs });
    }

    // 连接会话内存表（键＝directories.root）：polling_secret 是取件凭据，只存
    // 内存、绝不出服务端（不进任何响应/日志）；单槽复用存活请求；15 分钟 TTL
    // 惰性清理。approved 后若密钥库写失败，approved 取件暂存在会话里供后续
    // status 重试写入（不重新 poll、不重新授权）。
    const connectSessions = new Map();
    const connectStarting = new Map();
    // 连接请求失效（poll 404 / 取消 / 过期 / logout / 登录失效）：清会话后
    // 保留短时标记，供后续 /status 与 /connect/status 如实显示 invalid。
    const connectInvalid = new Map();
    // 在途竞态世代（S3）：logout 与查询面 401 清理时 +1。异步 startConnect
    // 返回后、approved 写库前、refreshKey 写前都比对，世代变了就丢弃结果，
    // 防止慢请求把已退出/已失效的登录重新写回。
    const epochs = new Map();
    // 机会式登录探活（S10）：root → 上次成功探活时间；in-flight 防重复。
    const loginProbeAt = new Map();
    const loginProbeInFlight = new Set();
    // G9：每 root 的写串行锁。所有适配器变更（approved 写库、refreshKey、
    // apply-model、clearBinding）都排队执行，避免并发交错产生半写状态。
    const rootLocks = new Map();

    function epochFor(root) {
        return epochs.get(root) || 0;
    }

    function bumpEpoch(root) {
        epochs.set(root, epochFor(root) + 1);
    }

    // 串行执行 task；前一个任务的失败/异常不阻塞后续任务。锁表只在最后一个
    // 排队任务完成后清理该 root 的条目。
    function withRootLock(root, task) {
        const tail = rootLocks.get(root) || Promise.resolve();
        const run = tail.then(() => task());
        const guard = run.then(() => undefined, () => undefined);
        rootLocks.set(root, guard);
        guard.then(() => {
            if (rootLocks.get(root) === guard) rootLocks.delete(root);
        });
        return run;
    }

    function connectSessionFor(root) {
        const session = connectSessions.get(root);
        if (!session) return null;
        if (now() >= session.expiresAtMs) {
            connectSessions.delete(root);
            return null;
        }
        return session;
    }

    // F4：失效标记带 reason。login_invalidated（登录失效，长期）会让 /status
    // 报 invalid；connect_request_* / authorization_write_failed（连接请求层面的
    // 失效，短时）只影响 /connect/status 与连接面板，不压过有效信封。
    function connectInvalidFor(root) {
        const marker = connectInvalid.get(root);
        if (!marker) return null;
        if (now() >= marker.untilMs) {
            connectInvalid.delete(root);
            return null;
        }
        return marker;
    }

    function markConnectInvalid(root, untilMs, reason, localCleared, customCleared) {
        const existing = connectInvalid.get(root);
        // H10：login_invalidated 是最高优先级标记，只能由 approved 写库成功
        // 或 logout 完整清理成功清除；连接请求层面的失效（poll 404 / 取消 /
        // 过期 / 授权写库重试耗尽）不得把它降级覆盖。
        if (existing && existing.reason === LOGIN_INVALID_REASON) {
            // W10：后续清理确认成功可把 true 粘上去；显式的不确定/失败
            // （false）必须能把旧的 true 降级，避免 /status 继续宣称已清。
            if (localCleared === true) existing.localCleared = true;
            if (customCleared === true) existing.customCleared = true;
            else if (customCleared === false) existing.customCleared = false;
            return;
        }
        const until = typeof untilMs === 'number' ? untilMs : now() + CONNECT_TTL_MS;
        const markerReason = typeof reason === 'string' && reason.length > 0
            ? reason
            : CONNECT_INVALID_REASON;
        connectInvalid.set(root, {
            untilMs: until,
            reason: markerReason,
            // W10：分别记录信封与 Custom 清理结果。UI 只有在 Custom 清理
            // 确认成功或 URL 仍指向网关时才恢复/清空 Custom 设置；清理失败
            // 时强制清空 URL，绝不把残留 key 与新地址配对。
            localCleared: localCleared === true,
            customCleared: customCleared === true,
        });
    }

    // 绑定读取只接收本请求的 req.user.directories；读取失败/无值/形态不符
    // 一律按未连接拒绝（resolveBindingFor）或按未绑定展示（readBindingRecordFor）。
    async function readBindingRecordFor(directories) {
        let raw = null;
        try {
            raw = await readBinding(directories);
        } catch {
            return null;
        }
        return normalizeBindingRecord(raw);
    }

    // G4：login_invalidated 是强制拒绝标记。标记存在时 /plan、/apply-model 与
    // 查询面一律 409 not_connected，绝不使用残留信封 key（logout 本地清理失败
    // 或查询面 401 清理失败都可能留下残封信封）。/logout、/release-custom-key
    // 与 /status 不走本函数，仍可用（前者用于重试清理，后者如实展示 invalid）。
    async function resolveBindingRecordFor(directories) {
        const marker = connectInvalidFor(directories.root);
        if (marker !== null && marker.reason === LOGIN_INVALID_REASON) {
            throw loginInvalid();
        }
        const record = await readBindingRecordFor(directories);
        if (!record) {
            throw notConnected();
        }
        return record;
    }

    // ===== B3 查询面（v1.35 plugin/me，Bearer 登录凭据）=====

    // 查询面 401（登录凭据失效）：仅在 401 对应的 credential 仍等于当前信封
    // login_credential 时才清本地（慢请求的旧凭据结果不得清掉新登录）；清理时
    // 世代 +1 并保留失效标记，让 /status 如实显示 invalid。清除失败也按登录
    // 失效返回，不把内部细节带给浏览器。返回是否真正执行了清理。
    // H7：整个“重读信封 → 复核 credential/epoch → 清理”都在 root 锁内执行；
    // 新 approved 写入（同样走锁）要么先完成（credential 已变 → 不清）要么
    // 排在清理之后，不会再出现“读到旧信封、清理时删掉新信封”的窗口。
    async function invalidateLogin(directories, credential) {
        const root = directories.root;
        const startEpoch = epochFor(root);
        return withRootLock(root, async () => {
            if (epochFor(root) !== startEpoch) return false;
            const current = await readBindingRecordFor(directories);
            if (!current || typeof current.loginCredential !== 'string'
                || current.loginCredential !== credential) {
                return false;
            }
            // 读取期间 logout 可能已 bump 世代（logout 在取锁前同步 +1）。
            if (epochFor(root) !== startEpoch) return false;
            bumpEpoch(root);
            let localCleared = false;
            let customCleared = false;
            if (clearBinding) {
                try {
                    // 已在锁内，直接调用（不可再次 withRootLock，否则自锁）。
                    const cleared = normalizeClearResult(await clearBinding(directories));
                    localCleared = cleared.envelope && cleared.custom;
                    customCleared = cleared.custom && !cleared.customUncertain;
                } catch {
                    // best effort：清失败不改变对外语义；失效标记仍由下面设置，
                    // 残留信封在 /status 中显示 invalid（fail-closed）。
                }
            }
            connectSessions.delete(root);
            connectStarting.delete(root);
            // 失效标记不随 15 分钟连接 TTL 消失：否则清理失败留下的残留信封会在
            // TTL 后重新显示 authorized。新 approved 写入（F3/F4）才清除它。
            markConnectInvalid(
                root,
                Number.POSITIVE_INFINITY,
                LOGIN_INVALID_REASON,
                localCleared,
                customCleared,
            );
            loginProbeAt.delete(root);
            return true;
        });
    }

    // G9：刷新信封 + Custom 联动是适配器变更，必须串行；锁内重读当前信封，
    // 写后复核 login_credential 与 key。返回归一化结果；任何不一致按 conflict。
    async function refreshBindingLocked(directories, key, username, options, expectedEpoch) {
        const expected = options && typeof options.expectedLoginCredential === 'string'
            ? options.expectedLoginCredential
            : null;
        const root = directories.root;
        return withRootLock(root, async () => {
            if (typeof expectedEpoch === 'number' && !Number.isNaN(expectedEpoch)
                && epochFor(root) !== expectedEpoch) {
                return { envelope: false, custom: false, conflict: true };
            }
            const current = await readBindingRecordFor(directories);
            if (!current || typeof current.loginCredential !== 'string'
                || (expected !== null && current.loginCredential !== expected)) {
                return { envelope: false, custom: false, conflict: true };
            }
            if (!refreshKey) {
                return { envelope: false, custom: false, conflict: false };
            }
            let outcome;
            try {
                outcome = normalizeRefreshResult(await refreshKey(directories, key, username, options));
            } catch {
                return { envelope: false, custom: false, conflict: false };
            }
            if (outcome.conflict || !outcome.envelope) return outcome;
            // 写后复核 epoch/credential：期间新 approved 或 logout 不得被旧刷新
            // 覆盖成“成功”。
            if (typeof expectedEpoch === 'number' && !Number.isNaN(expectedEpoch)
                && epochFor(root) !== expectedEpoch) {
                return { envelope: false, custom: outcome.custom, conflict: true };
            }
            const after = await readBindingRecordFor(directories);
            if (!after || after.loginCredential !== current.loginCredential
                || after.key !== key) {
                return { envelope: false, custom: outcome.custom, conflict: true };
            }
            return outcome;
        });
    }

    // H3：/status 每次授权态探活都检查适配器的 Custom 同步待修复标记，重试
    // 把 Custom 活动值同步成当前信封 key（成功即清除）。fire-and-forget：
    // 不阻塞 /status 响应，异常吞掉；同一 root 同时只跑一次。经 root 锁与
    // approved 写库/refresh/apply/release 串行，避免旧信封 key 落在新账号后。
    const customSyncInFlight = new Set();
    function maybeRetryCustomSync(directories) {
        if (!retryCustomSync) return;
        const root = directories.root;
        if (customSyncInFlight.has(root)) return;
        customSyncInFlight.add(root);
        Promise.resolve()
            .then(() => withRootLock(root, () => retryCustomSync(directories)))
            .catch(() => undefined)
            .finally(() => {
                customSyncInFlight.delete(root);
            });
    }

    // S10/F9：授权态 /status 机会式探活。只在距上次成功探活超过阈值时异步
    // fetchMeKey：拿到当前 key 后与信封比对，不同 → refreshKey（保留
    // login_credential，刷新 custom_keys 并同步插件自有 Custom 活动值）；401
    // 按 S5 清理；网络/其他失败忽略（不阻塞响应、不影响 /status 当前结果）。
    // 同一 root 只跑一个探活。
    function maybeProbeLogin(directories, record) {
        if (!record || typeof record.loginCredential !== 'string'
            || record.loginCredential.length === 0) {
            return;
        }
        const root = directories.root;
        if (loginProbeInFlight.has(root)) return;
        const last = loginProbeAt.get(root);
        // 从未探活（启动）或距上次成功探活超过阈值 → 异步探活；阈值内不重复。
        if (last !== undefined && now() - last <= loginProbeIntervalMs) return;
        loginProbeInFlight.add(root);
        const probeEpoch = epochFor(root);
        Promise.resolve()
            .then(() => gatewayClient.fetchMeKey(record.loginCredential))
            .then(async (fresh) => {
                loginProbeAt.set(root, now());
                if (!fresh || typeof fresh.key !== 'string' || fresh.key === record.key) return;
                if (!refreshKey || epochFor(root) !== probeEpoch) return;
                let outcome;
                try {
                    outcome = await refreshBindingLocked(
                        directories,
                        fresh.key,
                        fresh.username,
                        { expectedLoginCredential: record.loginCredential },
                        probeEpoch,
                    );
                } catch {
                    return;
                }
                // 冲突/写失败都按 best-effort 忽略；下一次 /status 仍可用旧信封。
                if (!outcome.envelope || outcome.conflict) return;
                loginProbeAt.set(root, now());
            })
            .catch((error) => {
                if (error && error.unauthorized === true) {
                    return invalidateLogin(directories, record.loginCredential);
                }
                return undefined;
            })
            .catch(() => {})
            .finally(() => {
                loginProbeInFlight.delete(root);
            });
    }

    // 查询面统一入口：req.user 缺失 401（planRequireDirectories）、GET 同源
    // 软闸、本地信封取 login_credential；无登录凭据 → 409 not_connected。
    async function queryAuth(req) {
        const directories = planRequireDirectories(req);
        assertSameOriginForGet(req);
        const record = await resolveBindingRecordFor(directories);
        if (typeof record.loginCredential !== 'string' || record.loginCredential.length === 0) {
            throw notConnected();
        }
        return { directories, record, credential: record.loginCredential };
    }

    // 查询面客户端错误 → 固定 HTTP 错误：形态不符 → 502 invalid_response，
    // 其他（网络/超时/上游 5xx）→ 502 upstream_unavailable；401 已在入口处理。
    function queryFailure(error) {
        if (error instanceof GatewayError) return error;
        if (error && error.invalidShape === true) return invalidResponse();
        return upstreamUnavailable();
    }

    function makeQueryHandler(load, project) {
        return async function queryHandler(req, res) {
            let directories = null;
            let credential = null;
            try {
                // F1：Host 闸先于身份与同源校验（所有路由一致）。
                assertAllowedHost(req, allowedHosts);
                const auth = await queryAuth(req);
                directories = auth.directories;
                credential = auth.credential;
                takeQueryToken(directories.root, auth.credential);
                const result = await load(auth.credential);
                sendJson(res, 200, project(result));
            } catch (error) {
                if (error && error.unauthorized === true && directories) {
                    // 只清与本次 401 凭据相同的当前信封；慢请求旧凭据不清新登录。
                    await invalidateLogin(directories, credential);
                    sendError(res, loginInvalid());
                    return;
                }
                sendError(res, queryFailure(error));
            }
        };
    }

    // GET /keys：透传 {keys:[{id,name,masked,status}]}，不含明文 key。
    const keysHandler = makeQueryHandler(
        (credential) => gatewayClient.fetchKeys(credential),
        (result) => result,
    );

    // GET /models：查询面目录投影为既有 {items:[{name, protocol_faces, …}]}
    // 线形状（name＝上游 data[].id）；projectCatalog 再做一次白名单投影。
    const modelsHandler = makeQueryHandler(
        (credential) => gatewayClient.fetchModels(credential),
        (result) => projectCatalog(result),
    );

    // GET /balance：查询面快照（含 BILL-08 两必填字段）；H/K 缺失/非法由
    // gateway-client 的严格解析拒绝 → 502 invalid_response，绝不显示为零。
    const balanceHandler = makeQueryHandler(
        (credential) => gatewayClient.fetchBalance(credential),
        (result) => result,
    );

    async function statusHandler(req, res) {
        try {
            // F1：Host 闸先于身份。
            assertAllowedHost(req, allowedHosts);
            // spec B1：全部路由缺 req.user → 401（不再沿用旧 403）。
            const directories = planRequireDirectories(req);
            assertSameOriginForGet(req);
            const record = await readBindingRecordFor(directories);
            const session = connectSessionFor(directories.root);
            const marker = connectInvalidFor(directories.root);
            // F4：只有登录失效标记才压过信封；连接请求失效只走 /connect/status。
            const loginInvalid = marker !== null && marker.reason === LOGIN_INVALID_REASON;
            // 只有实际报告 authorized 时才做机会式探活。
            if (record && !loginInvalid) {
                maybeProbeLogin(directories, record);
                maybeRetryCustomSync(directories);
            }
            sendJson(res, 200, buildStatusBody(
                record,
                session !== null,
                loginInvalid,
                loginInvalid ? LOGIN_INVALID_REASON : null,
                marker !== null && marker.localCleared === true,
                marker !== null && marker.customCleared === true,
            ));
        } catch (error) {
            sendError(res, error);
        }
    }

    async function loginHandler(req, res) {
        try {
            assertAllowedHost(req, allowedHosts);
            // spec B1：缺 req.user → 401；目录形态非法仍 403。
            planRequireDirectories(req);
            // 登录/凭据交付未交付：即便存在专用 secret 也不得报告登录完成。
            sendJson(res, 501, {
                error: {
                    code: 'pass_binding_unavailable',
                    message: MESSAGE_STATUS,
                },
            });
        } catch (error) {
            sendError(res, error);
        }
    }

    // ===== POST /connect（B1 v3 网页授权发起）=====
    // 写面：无 req.user 401；同源校验；单槽内存会话按 directories.root 复用
    // 存活请求（同槽幂等）。响应仅 {status, authorize_url}——polling_secret /
    // request_ref 不出服务端。
    async function connectHandler(req, res) {
        try {
            assertAllowedHost(req, allowedHosts);
            const directories = planRequireDirectories(req);
            assertSameOrigin(req);
            const root = directories.root;
            const existing = connectSessionFor(root);
            if (existing) {
                sendJson(res, 200, { status: 'pending', authorize_url: existing.authorizeUrl });
                return;
            }

            let started;
            // S3：记录发起时的世代；logout / 登录失效可能发生在 await 期间，
            // 返回后世代已变则丢弃本次 start 结果（不写会话、不报 pending）。
            const startEpoch = epochFor(root);
            const inFlight = connectStarting.get(root);
            if (inFlight) {
                started = await inFlight;
            } else {
                const pending = Promise.resolve().then(() => gatewayClient.startConnect());
                connectStarting.set(root, pending);
                try {
                    started = await pending;
                } finally {
                    // 只删除自己放进去的 promise：logout + 新连接可能已换成新的一笔。
                    if (connectStarting.get(root) === pending) {
                        connectStarting.delete(root);
                    }
                }
            }
            if (epochFor(root) !== startEpoch) {
                throw notConnected();
            }
            // 并发双击时另一请求可能已写入会话：复用同一 authorize_url。
            const raced = connectSessionFor(root);
            if (raced) {
                sendJson(res, 200, { status: 'pending', authorize_url: raced.authorizeUrl });
                return;
            }
            const session = {
                pollingSecret: started.pollingSecret,
                requestRef: started.requestRef,
                authorizeUrl: started.authorizeUrl,
                expiresAtMs: now() + CONNECT_TTL_MS,
                lastPollAtMs: now(),
                pollAttempted: false,
                pollInFlight: false,
                approved: null,
                writeInFlight: false,
                writeFailures: 0,
                // H11：会话创建时的世代；approved 写库在锁内要求它与当前
                // epoch 一致，logout bump 后旧会话（即使仍在内存）不得落库。
                startEpoch,
            };
            connectSessions.set(root, session);
            // F4：发起新连接不再清除失效标记（旧标记留到新 approved 写库成功
            // 或用户显式成功重连时才清；发起/丢弃不代表登录恢复）。
            sendJson(res, 200, { status: 'pending', authorize_url: started.authorizeUrl });
        } catch (error) {
            // 固定 upstream 错误形态与文案，不携带门户错误细节。
            sendError(res, error instanceof GatewayError ? error : upstreamUnavailable());
        }
    }

    // 写 approved 取件：双命名空间都成功才算成功（写失败不标记已授权）。
    // 重试只重写、不重新 poll（consume-once 已消费在途凭据）。
    // S3：expectedEpoch 是 approve 时的世代；写前变了 → 'epoch_changed'（不
    // 落库）。写期间被 logout / 登录失效插队（写完后世代再变）也按
    // 'epoch_changed' 丢弃，绝不回报 authorized（记录可能已被清理或残留，
    // 由 /status 的失效标记兜底）。
    // F3：每次 approved 写库成功 → bumpEpoch，使任何更早发起、仍在途的
    // refreshKey/applyModel 在写前复核时被丢弃（读取者不能把旧 key 落到新登录）。
    // F5：每 root 的写失败累计到 APPROVED_WRITE_MAX_ATTEMPTS 次即清会话并标记
    // 连接失效；前 3 次保持 approved 取件，后续 /connect/status 重试写库。
    async function writeApprovedFor(directories, session, expectedEpoch) {
        if (session.writeInFlight || !session.approved) return 'pending';
        const root = directories.root;
        // H11：会话必须仍是该 root 的当前会话，且会话创建世代未变；logout
        // 在 bumpEpoch 后同步摘除会话，任何迟到 approved 结果一律丢弃。
        const mapCurrent = connectSessions.get(root) === session;
        if (!mapCurrent
            || epochFor(root) !== session.startEpoch
            || epochFor(root) !== expectedEpoch) {
            session.approved = null;
            if (mapCurrent) {
                connectSessions.delete(root);
                if (epochFor(root) !== session.startEpoch) {
                    markConnectInvalid(root, Number.POSITIVE_INFINITY, LOGIN_INVALID_REASON);
                }
            }
            return 'epoch_changed';
        }
        session.writeInFlight = true;
        let lockedOutcome = 'failed';
        try {
            // G9：approved 写库与其他适配器变更串行；锁内复核 epoch，写后再读回
            // 信封核对 credential/key/username（落库内容必须就是本次取件）。
            lockedOutcome = await withRootLock(root, async () => {
                if (connectSessions.get(root) !== session
                    || epochFor(root) !== session.startEpoch
                    || epochFor(root) !== expectedEpoch) {
                    return 'epoch_changed';
                }
                let rawResult = false;
                try {
                    rawResult = writeBinding
                        ? await writeBinding(directories, session.approved)
                        : false;
                } catch {
                    rawResult = null;
                }
                // 适配器可能返回 {ok:true, warn}（如 custom_keys 淘汰告警）；只有
                // 明确失败/异常才算未写入。
                const written = rawResult === true
                    || (isPlainObject(rawResult) && rawResult.ok === true);
                if (!written) return 'failed';
                const after = await readBindingRecordFor(directories);
                if (!after
                    || after.loginCredential !== session.approved.loginCredential
                    || after.key !== session.approved.key
                    || after.username !== session.approved.username) {
                    // 写后回读不一致：落库内容不是本次取件（视为冲突，不报授权）。
                    return 'conflict';
                }
                return 'written';
            });
        } catch {
            lockedOutcome = 'failed';
        } finally {
            session.writeInFlight = false;
        }
        const stillCurrent = connectSessions.get(root) === session
            && epochFor(root) === session.startEpoch;
        if (lockedOutcome === 'epoch_changed' || lockedOutcome === 'conflict'
            || epochFor(root) !== expectedEpoch) {
            session.approved = null;
            if (stillCurrent) {
                connectSessions.delete(root);
                // 写前/写后世代变化或落库内容不一致：残留记录不得在 /status
                // 回 authorized。H10：该标记若已是 login_invalidated 不会被降级。
                markConnectInvalid(root, Number.POSITIVE_INFINITY, LOGIN_INVALID_REASON);
            }
            return 'epoch_changed';
        }
        if (lockedOutcome === 'written') {
            session.approved = null;
            session.writeFailures = 0;
            // F3/F4：approved 写库成功是唯一清除连接失效标记的路径之一；
            // 同时 bump epoch，作废所有更早的在途刷新/接入结果。
            bumpEpoch(directories.root);
            connectInvalid.delete(directories.root);
            return 'written';
        }
        session.writeFailures += 1;
        if (session.writeFailures >= APPROVED_WRITE_MAX_ATTEMPTS) {
            session.approved = null;
            if (connectSessions.get(directories.root) === session) {
                connectSessions.delete(directories.root);
            }
            markConnectInvalid(directories.root, undefined, AUTHORIZATION_WRITE_FAILED_REASON);
            return 'failed_exhausted';
        }
        return 'failed';
    }

    // ===== GET /connect/status（B1 v3 连接状态轮询）=====
    // 同源软闸；服务端节流 ≥5 秒轮询网关；响应仅 {status, username?}，永不返回
    // polling_secret / request_ref / login_credential / key。approved 先落密钥库
    // 再报 authorized；写失败保留 approved 取件在内存，下次查询重试写入（pending）。
    async function connectStatusHandler(req, res) {
        try {
            assertAllowedHost(req, allowedHosts);
            const directories = planRequireDirectories(req);
            // H9：该路由触发上游轮询 + 可能写库，要求严格同源（见函数注释）。
            assertConnectStatusOrigin(req);
            const root = directories.root;
            const handlerEpoch = epochFor(root);
            const session = connectSessionFor(root);

            if (!session) {
                const record = await readBindingRecordFor(directories);
                // F4：连接请求层面的失效标记（poll 404/取消/过期/授权写库重试
                // 耗尽）只在本端点报 invalid；/status 只看 login_invalidated。
                const connectInvalid = connectInvalidFor(root);
                if (record && connectInvalid === null) {
                    const body = { status: 'authorized' };
                    if (record.username) body.username = record.username;
                    sendJson(res, 200, body);
                } else {
                    // 无会话、无记录（或存在失效标记）：未完成的连接（枚举只有
                    // connecting/pending/authorized/invalid，按 invalid 如实回答）。
                    sendJson(res, 200, { status: 'invalid' });
                }
                return;
            }

            // approved 已取到但密钥库写失败：每次 status 重试写入，不重新 poll。
            if (session.approved) {
                const approvedUsername = session.approved.username;
                const written = await writeApprovedFor(directories, session, handlerEpoch);
                if (written === 'written') {
                    if (connectSessions.get(root) !== session) {
                        // 写入期间 logout / 新连接已接管：不删除新会话、不误报。
                        // F3 已 bump epoch，不能再用 handlerEpoch 复核。
                        const record = await readBindingRecordFor(directories);
                        sendJson(res, 200, record
                            ? { status: 'authorized', ...(record.username ? { username: record.username } : {}) }
                            : { status: 'invalid' });
                        return;
                    }
                    connectSessions.delete(root);
                    const body = { status: 'authorized' };
                    if (typeof approvedUsername === 'string' && approvedUsername.length > 0) {
                        body.username = approvedUsername;
                    }
                    sendJson(res, 200, body);
                    return;
                }
                if (written === 'epoch_changed') {
                    // approve↔logout：世代变了，丢弃取件，不落库、不报 authorized。
                    sendJson(res, 200, { status: 'invalid' });
                    return;
                }
                if (written === 'failed_exhausted') {
                    // F5：授权写库连续失败达上限；会话已清、失效标记已置，UI
                    // 按 invalid 提示用户重新连接。
                    sendJson(res, 200, { status: 'invalid' });
                    return;
                }
                if (connectSessions.get(root) !== session) {
                    // 会话被 logout / 新连接覆盖：按当前存储态回答；失效标记
                    // 优先，残留信封不得回 authorized。
                    const record = await readBindingRecordFor(directories);
                    sendJson(res, 200, record && connectInvalidFor(root) === null
                        ? { status: 'authorized', ...(record.username ? { username: record.username } : {}) }
                        : { status: 'invalid' });
                    return;
                }
                sendJson(res, 200, {
                    status: 'pending',
                    write_retry: { attempt: session.writeFailures, max: APPROVED_WRITE_MAX_ATTEMPTS },
                });
                return;
            }

            const current = now();
            if (!session.pollAttempted && current - session.lastPollAtMs < CONNECT_POLL_INTERVAL_MS) {
                sendJson(res, 200, { status: 'connecting' });
                return;
            }
            if (session.pollInFlight || current - session.lastPollAtMs < CONNECT_POLL_INTERVAL_MS) {
                // 节流窗口内/上一次 poll 在途：不并发打门户，直接回答缓存态。
                sendJson(res, 200, { status: 'pending' });
                return;
            }
            session.lastPollAtMs = current;
            session.pollAttempted = true;
            session.pollInFlight = true;
            let polled;
            try {
                polled = await gatewayClient.pollConnect(session.pollingSecret);
            } catch {
                // 轮询失败保留会话：下次查询（≥5 秒后）自动重试。
                throw upstreamUnavailable();
            } finally {
                session.pollInFlight = false;
            }
            // 会话可能已被二次 /connect 覆盖或 logout/TTL 清理：迟到结果不落盘。
            if (connectSessions.get(root) !== session) {
                sendJson(res, 200, { status: 'invalid' });
                return;
            }
            // S3：poll 期间 logout / 登录失效可能发生；世代变了则丢弃 approved。
            if (epochFor(root) !== handlerEpoch) {
                sendJson(res, 200, { status: 'invalid' });
                return;
            }
            if (polled.status === 'pending') {
                sendJson(res, 200, { status: 'pending' });
                return;
            }
            if (polled.status !== 'approved') {
                // 404（不存在/已消费/已过期/失效联动/已取消）不可区分：清会话并
                // 保留失效标记，供后续 /status 如实显示 invalid。
                connectSessions.delete(root);
                markConnectInvalid(root);
                sendJson(res, 200, { status: 'invalid' });
                return;
            }

            session.approved = polled.connect;
            const written = await writeApprovedFor(directories, session, handlerEpoch);
            if (written === 'written') {
                if (connectSessions.get(root) !== session) {
                    // 写入期间 logout / 新连接已接管：不删除新会话、不误报。
                    // F3 的 epoch bump 已发生，这里不再用 handlerEpoch 复核（否则
                    // 会把已成功写入的记录误判成 invalid）。
                    const record = await readBindingRecordFor(directories);
                    sendJson(res, 200, record
                        ? { status: 'authorized', ...(record.username ? { username: record.username } : {}) }
                        : { status: 'invalid' });
                    return;
                }
                connectSessions.delete(root);
                sendJson(res, 200, {
                    status: 'authorized',
                    username: polled.connect.username,
                });
            } else if (written === 'epoch_changed') {
                // approve↔logout：不落库、不报 authorized。
                sendJson(res, 200, { status: 'invalid' });
            } else if (written === 'failed_exhausted') {
                // F5：授权写库连续失败达上限 → invalid，用户需重新连接。
                sendJson(res, 200, { status: 'invalid' });
            } else {
                // 双写失败：保留取件态，后续 status 重试写入（不重新 poll）；
                // 附重试态供 UI/诊断（≤3 次仍 pending）。
                sendJson(res, 200, {
                    status: 'pending',
                    write_retry: { attempt: session.writeFailures, max: APPROVED_WRITE_MAX_ATTEMPTS },
                });
            }
        } catch (error) {
            sendError(res, error instanceof GatewayError ? error : upstreamUnavailable());
        }
    }

    // ===== POST /release-custom-key（F11）=====
    // UI 在预设切换 / 生成设置就绪时若发现 custom_url 已指向非网关域，调用本
    // 路由清掉插件自有的 api_key_custom 条目（按信封 custom_keys ∪ 当前 key）。
    // 幂等：无绑定/未授权/无可识别 key 也返回 200 {cleared:true}；用户自有值
    // 不动。限频独立于 /apply-model（默认 30 次/分；阻塞型清理不做客户端
    // 节流，快速连续切换预设/生成会重复请求本路由，服务端幂等但需避免 429）。
    // G8：读取状态区分“没有信封”和“读/解析失败”。只有真正没有信封才是幂等
    // 成功；读失败时无法识别插件归属，不能报 cleared:true。
    async function readBindingForRelease(directories) {
        if (readBindingState) {
            let state = null;
            try {
                state = await readBindingState(directories);
            } catch {
                state = null;
            }
            if (state && state.status === 'ok' && isPlainObject(state.record)) {
                return { readFailed: false, record: state.record };
            }
            if (state && state.status === 'empty') {
                return { readFailed: false, record: null };
            }
            return { readFailed: true, record: null };
        }
        try {
            const raw = await readBinding(directories);
            if (raw === null || raw === undefined) {
                return { readFailed: false, record: null };
            }
            const record = normalizeBindingRecord(raw);
            if (!record) return { readFailed: true, record: null };
            return { readFailed: false, record };
        } catch {
            return { readFailed: true, record: null };
        }
    }

    function normalizeCustomClearResult(value) {
        if (value === true) return { ok: true, cleared: true };
        if (isPlainObject(value)) {
            return {
                ok: value.ok === true,
                cleared: value.cleared === true,
            };
        }
        return { ok: false, cleared: false };
    }

    async function releaseCustomKeyHandler(req, res) {
        try {
            assertAllowedHost(req, allowedHosts);
            const directories = planRequireDirectories(req);
            assertSameOrigin(req);
            takeReleaseToken(directories.root);
            // H8：读取归属 + 清理整体在 root 锁内，与 approved 写库、refreshKey、
            // apply-model 串行；apply 先完成则本次按更新后的信封归属清理，apply
            // 后完成则不会在清理窗口里插队写入插件 key。
            const outcome = await withRootLock(directories.root, async () => {
                const read = await readBindingForRelease(directories);
                if (read.readFailed) {
                    return { status: 'read_failed' };
                }
                const record = read.record;
                const keys = [];
                if (record) {
                    if (isValidBindingKey(record.key)) keys.push(record.key);
                    const customKeys = Array.isArray(record.customKeys) ? record.customKeys : [];
                    for (const key of customKeys) {
                        if (isValidBindingKey(key) && !keys.includes(key)) keys.push(key);
                    }
                }
                if (keys.length === 0) {
                    // W10：无信封时不能仅凭“没有 keys”断言已清；先探测
                    // Custom 命名空间。仍有条目/无法读取 → read_failed，
                    // UI 不得宣称“已清理插件写入的 key”。
                    if (read.record === null) {
                        if (!hasCustomSourceEntries) return { status: 'read_failed' };
                        try {
                            const probe = await hasCustomSourceEntries(directories);
                            if (!probe || probe.known !== true || probe.present === true) {
                                return { status: 'read_failed' };
                            }
                        } catch {
                            return { status: 'read_failed' };
                        }
                    }
                    return { cleared: true };
                }
                if (!clearCustomSourceKey) return { cleared: false };
                try {
                    const normalized = normalizeCustomClearResult(
                        await clearCustomSourceKey(directories, keys),
                    );
                    return { cleared: normalized.cleared };
                } catch {
                    return { cleared: false };
                }
            });
            if (outcome.status === 'read_failed') {
                sendJson(res, 200, { cleared: false, reason: 'read_failed' });
                return;
            }
            sendJson(res, 200, { cleared: outcome.cleared });
        } catch (error) {
            sendError(res, error);
        }
    }

    // ===== POST /logout（B1 退出登录）=====
    // 同源写闸；先世代 +1（在途 start/approve/refresh 结果一律丢弃），再调网关
    // logout（Bearer 登录凭据）；无论远端成败都清本地两命名空间 + 内存会话。
    // 响应：{status:'logged_out', remote_revoked, local_cleared}。本地清理失败
    //（信封或 Custom key 任一未清）→ 502 logout_local_clear_failed 并保留失效
    // 标记：残留信封不得在 /status 重新显示 authorized。
    function normalizeClearResult(value) {
        if (isPlainObject(value)) {
            return {
                envelope: value.envelope === true,
                custom: value.custom === true,
                customUncertain: value.customUncertain === true,
            };
        }
        if (typeof value === 'boolean') {
            return { envelope: value, custom: value, customUncertain: false };
        }
        return { envelope: false, custom: false, customUncertain: false };
    }

    async function logoutHandler(req, res) {
        try {
            assertAllowedHost(req, allowedHosts);
            const directories = planRequireDirectories(req);
            assertSameOrigin(req);
            const root = directories.root;
            bumpEpoch(root);
            // H11：同步摘除该 root 的连接会话与在途 start；任何正在 poll 的
            // approved 结果都会因会话身份/世代不符被丢弃（不落库、不报授权）。
            connectSessions.delete(root);
            connectStarting.delete(root);
            const record = await readBindingRecordFor(directories);
            let remoteRevoked = false;
            if (record && record.loginCredential) {
                try {
                    await gatewayClient.logout(record.loginCredential);
                    remoteRevoked = true;
                } catch {
                    // 远端失败不阻止本地清理（门户 revoke-all 可兜底）。
                }
            }
            let cleared = { envelope: false, custom: false };
            if (clearBinding) {
                try {
                    // G9：logout 清理与在手的 approved/refresh/apply 串行，避免
                    // 清理期间又写入新记录。
                    cleared = normalizeClearResult(
                        await withRootLock(root, () => clearBinding(directories)),
                    );
                } catch {
                    cleared = { envelope: false, custom: false };
                }
            }
            connectSessions.delete(root);
            connectStarting.delete(root);
            if (!cleared.envelope || !cleared.custom) {
                // 持久失效标记：残封信封不得在 /status 回 authorized（直到新登录）。
                markConnectInvalid(
                    root,
                    Number.POSITIVE_INFINITY,
                    LOGIN_INVALID_REASON,
                    false,
                    cleared.custom && !cleared.customUncertain,
                );
                throw logoutLocalClearFailed();
            }
            if (cleared.customUncertain) {
                // W10：Custom 归属无法确认。保留持久失效标记，让 /status 在
                // 页面刷新/其他标签中也继续要求清理；响应仍报告本地已退出，
                // 但 custom_cleared=false，UI 强制清空 Custom URL。
                markConnectInvalid(
                    root,
                    Number.POSITIVE_INFINITY,
                    LOGIN_INVALID_REASON,
                    true,
                    false,
                );
            } else {
                connectInvalid.delete(root);
                loginProbeAt.delete(root);
            }
            sendJson(res, 200, {
                status: 'logged_out',
                remote_revoked: remoteRevoked,
                local_cleared: true,
                custom_cleared: !cleared.customUncertain,
            });
        } catch (error) {
            sendError(res, error);
        }
    }

    // ===== POST /apply-model（B3 模型接入确认）=====
    // 用户在 UI 确认弹窗里同意选择该模型后调用：服务端只写 ST Custom 源读取的
    // api_key_custom（当前信封里的网关 key），从不写 chat source / custom_url /
    // custom_model（这三项由 UI 在确认后自行写入，失败时回滚）。写失败 → 502
    // 固定错误，不报告接入成功（fail-closed）。S6：每 root 限频 10 次/分（可配），
    // 写前必须已有信封（未授权 → 409），严格 body 白名单在限频之后执行。
    async function applyModelHandler(req, res) {
        try {
            assertAllowedHost(req, allowedHosts);
            const directories = planRequireDirectories(req);
            assertSameOrigin(req);
            const root = directories.root;
            const record = await resolveBindingRecordFor(directories);
            takeApplyToken(root);
            const epochAtStart = epochFor(root);
            const rawBody = await readPlanBody(req, APPLY_MODEL_BODY_MAX, invalidApplyModelRequest);
            const { model } = validateApplyModelBody(rawBody);
            // 读 body 期间 logout / 登录失效 / 新 approved：不再写 Custom key
            // （避免把已退出或上一账号的 key 重新激活到 ST Custom 源）。
            if (epochFor(root) !== epochAtStart) throw bindingConflict();
            // G9：锁内重读信封、写前复核 credential/epoch、写 Custom、写后复核。
            // G1：写入值一律取锁内重新读到的信封 key，不用请求开始时捕获的 key。
            const outcome = await withRootLock(root, async () => {
                if (epochFor(root) !== epochAtStart) {
                    return { ok: false, conflict: true, known: true, customWritten: false, envelopeWritten: false };
                }
                const current = await readBindingRecordFor(directories);
                if (!current || current.loginCredential !== record.loginCredential) {
                    return { ok: false, conflict: true, known: true, customWritten: false, envelopeWritten: false };
                }
                if (!writeCustomSourceKey) {
                    return { ok: false, conflict: false, known: true, customWritten: false, envelopeWritten: false };
                }
                let normalized;
                try {
                    normalized = normalizeCustomWriteResult(await writeCustomSourceKey(
                        directories,
                        current.key,
                        { expectedLoginCredential: current.loginCredential },
                    ));
                } catch {
                    // 适配器异常：无法得知写入进度（可能 partial）。
                    return { ok: false, conflict: false, known: false, customWritten: null, envelopeWritten: null };
                }
                if (normalized.conflict) return normalized;
                if (epochFor(root) !== epochAtStart) {
                    return {
                        ok: false,
                        conflict: true,
                        known: normalized.known,
                        customWritten: normalized.customWritten,
                        envelopeWritten: normalized.envelopeWritten,
                    };
                }
                const after = await readBindingRecordFor(directories);
                if (!after || after.loginCredential !== current.loginCredential
                    || after.key !== current.key) {
                    return {
                        ok: false,
                        conflict: true,
                        known: normalized.known,
                        customWritten: normalized.customWritten,
                        envelopeWritten: normalized.envelopeWritten,
                    };
                }
                return normalized;
            });
            // H5：冲突只有“可证明完全未写”（known 且 custom/envelope 都 false）
            // 才能按 409 让 UI 安全回滚 URL；只要已知任一写入或结果未知（例如
            // 适配器先写归属后 epoch 变化），一律按 partial 502——写后不得把
            // 已发生的副作用谎报成“未接入、可回滚”。
            if (outcome.conflict) {
                const fullyUnwritten = outcome.known === true
                    && outcome.customWritten === false
                    && outcome.envelopeWritten === false;
                if (fullyUnwritten) throw bindingConflict();
                throw customSourceWritePartial();
            }
            if (!outcome.ok) {
                // G1：信封归属已写/写入状态未知 → 结果不确定，返回 partial；
                // 只有明确“完全未写”才允许 UI 安全回滚 custom_url/custom_model。
                if (outcome.known === true
                    && outcome.customWritten === false
                    && outcome.envelopeWritten === false) {
                    throw customSourceWriteFailed();
                }
                throw customSourceWritePartial();
            }
            sendJson(res, 200, { status: 'applied', model });
        } catch (error) {
            sendError(res, error);
        }
    }

    // B2 防截断分节规划：固定转发数据面 /v1/chat/completions；请求体、上游响应体、
    // 绑定 key 一律不落日志。未连接时 readBinding 恒空 → 恒 409 not_connected（预期 fail-closed）。
    //
    // key 重置自动刷新：数据面 401（invalid_key / key 重置）且记录带 login_credential
    // 时，经查询面 GET /api/plugin/me/key 取当前 key，信封刷新成功后再重试
    // 一次上游。查询面 401（P3 起）属登录失效，与数据面 key 401 区分：前者刷新
    // 也不会成功，最终按固定 502 返回，不把两类混成一个用户提示。
    async function planHandler(req, res) {
        try {
            assertAllowedHost(req, allowedHosts);
            const directories = planRequireDirectories(req);
            assertSameOrigin(req);
            // 限频先于读 body / 上游调用（评审 E）：每用户固定窗口。
            takePlanToken(directories.root);
            // 身份先于请求体：未连接时 /plan 恒 409，不解析/不回显请求体。
            const binding = await resolveBindingRecordFor(directories);
            const planEpoch = epochFor(directories.root);
            // S7：/plan 请求体专用上限 64KiB（容纳 16000 字符 CJK 摘要）。
            const rawBody = await readPlanBody(req, PLAN_MAX_BYTES);
            const { model, prompt } = validatePlanBody(rawBody);
            const payload = {
                model,
                messages: [{ role: 'user', content: prompt }],
                temperature: PLAN_TEMPERATURE,
                max_tokens: PLAN_MAX_TOKENS,
            };
            const planOptions = {
                fetchImpl,
                timeoutMs: planTimeoutMs,
                maxBytes,
            };
            let upstream;
            try {
                upstream = await postPlanWithRetry(
                    `${DATA_ORIGIN}${PLAN_CHAT_COMPLETIONS_PATH}`,
                    binding.key,
                    payload,
                    planOptions,
                );
            } catch (error) {
                const keyInvalidated = error instanceof GatewayError && error.code === 'binding_invalidated';
                if (!keyInvalidated
                    || !refreshKey
                    || typeof binding.loginCredential !== 'string'
                    || binding.loginCredential.length === 0) {
                    throw error;
                }
                let refreshed;
                try {
                    refreshed = await gatewayClient.fetchMeKey(binding.loginCredential);
                } catch (refreshError) {
                    // 查询面 401 = 登录凭据失效，刷新 key 不会成功：清本地登录并
                    // 返回 409 引导重新连接（与数据面 key 401 的刷新路径区分）。
                    if (refreshError && refreshError.unauthorized === true) {
                        await invalidateLogin(directories, binding.loginCredential);
                        throw loginInvalid();
                    }
                    throw error;
                }
                // S3/F3：查询面取新 key 期间 logout / 登录失效 / 新 approved 可能
                // 发生；世代变了就不写信封（绝不让慢请求把已退出的登录或上一
                // 账号的 key 重新激活）。
                if (epochFor(directories.root) !== planEpoch) throw bindingConflict();
                let refreshOutcome = { envelope: false, custom: false, conflict: false };
                try {
                    refreshOutcome = await refreshBindingLocked(
                        directories,
                        refreshed.key,
                        refreshed.username,
                        { expectedLoginCredential: binding.loginCredential },
                        planEpoch,
                    );
                } catch {
                    refreshOutcome = { envelope: false, custom: false, conflict: false };
                }
                if (refreshOutcome.conflict) throw bindingConflict();
                if (!refreshOutcome.envelope) throw error;
                // Custom 同步失败只是 best-effort：信封已刷新，重试仍用新 key。
                // 新 key 双写成功：只重试一次；仍失败 → 固定 502（不循环刷新）。
                upstream = await postPlanWithRetry(
                    `${DATA_ORIGIN}${PLAN_CHAT_COMPLETIONS_PATH}`,
                    refreshed.key,
                    payload,
                    planOptions,
                );
            }
            sendJson(res, 200, { text: extractPlanText(upstream) });
        } catch (error) {
            sendError(res, error);
        }
    }

    // 写/刷新适配器返回值归一化：生产适配器返回结构化对象，测试/旧适配器可能
    // 仍返回 boolean。未知形态一律按失败（fail-closed）。
    function normalizeCustomWriteResult(value) {
        if (value === true) {
            return {
                ok: true,
                conflict: false,
                known: true,
                customWritten: true,
                envelopeWritten: true,
            };
        }
        if (isPlainObject(value)) {
            const customKnown = typeof value.customWritten === 'boolean';
            const envelopeKnown = typeof value.envelopeWritten === 'boolean';
            return {
                ok: value.ok === true || value.written === true,
                conflict: value.conflict === true,
                known: customKnown && envelopeKnown,
                customWritten: customKnown ? value.customWritten : null,
                envelopeWritten: envelopeKnown ? value.envelopeWritten : null,
            };
        }
        // boolean false / null / 未知形态：旧适配器无法报告写入进度，按“未知”
        // 处理（core 映射 partial，不谎称完全未写）。
        return {
            ok: false,
            conflict: false,
            known: false,
            customWritten: null,
            envelopeWritten: null,
        };
    }

    function normalizeRefreshResult(value) {
        if (value === true) return { envelope: true, custom: true, conflict: false };
        if (isPlainObject(value)) {
            return {
                envelope: value.envelope === true || value.ok === true,
                custom: value.custom === true,
                conflict: value.conflict === true,
            };
        }
        return { envelope: false, custom: false, conflict: false };
    }

    const handlers = {
        status: statusHandler,
        keys: keysHandler,
        models: modelsHandler,
        balance: balanceHandler,
        login: loginHandler,
        plan: planHandler,
        applyModel: applyModelHandler,
        connect: connectHandler,
        connectStatus: connectStatusHandler,
        logout: logoutHandler,
        releaseCustomKey: releaseCustomKeyHandler,
    };

    function registerRoutes(router) {
        if (!router || typeof router.get !== 'function' || typeof router.post !== 'function') {
            throw new TypeError('registerRoutes requires an Express-style router');
        }
        router.get('/status', handlers.status);
        router.get('/keys', handlers.keys);
        router.get('/models', handlers.models);
        router.get('/balance', handlers.balance);
        router.post('/login', handlers.login);
        router.post('/plan', handlers.plan);
        router.post('/apply-model', handlers.applyModel);
        router.post('/connect', handlers.connect);
        router.get('/connect/status', handlers.connectStatus);
        router.post('/logout', handlers.logout);
        router.post('/release-custom-key', handlers.releaseCustomKey);
    }

    return { handlers, registerRoutes };
}

module.exports = {
    createCore,
    PORTAL_ORIGIN,
    DATA_ORIGIN,
    BINDING_SECRET_KEY,
    MESSAGE_STATUS,
};
