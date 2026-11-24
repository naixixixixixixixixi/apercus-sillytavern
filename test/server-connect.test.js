'use strict';

// POST /connect、GET /connect/status、POST /logout（B1 v3 网页授权存根）与
// /status v3 状态机、/plan key 刷新路径的集成锁定。stub 网关 + 内存密钥库，
// 不接触真实 ST / 网关。helper 与 server-plan.test.js 同款（假 req/res）。

const test = require('node:test');
const assert = require('node:assert/strict');

const { createCore } = require('../server/core.js');
const { createSecretBindingAdapter } = require('../server/secrets-binding.js');

const PLAN_URL = 'https://api.apercus.ai/v1/chat/completions';
const CONNECT_SECRET = 'polling_secret_should_never_leave';
const CONNECT_REF = 'request_ref_should_never_leave';
const LOGIN_CREDENTIAL = 'login_credential_should_never_leave';
const BINDING_KEY = 'agw_key_secret_value';
const NEW_KEY = 'agw_key_after_reset';
const AUTHORIZE_URL = 'https://gw.apercus.ai/portal/connect?request_ref=ref-1';

const MESSAGES = {
    forbidden: '未登录或会话无效。',
    origin: '跨源写请求被拒绝。',
    notConnected: '尚未完成 Apercus 网关账户绑定。',
    upstream: '网关暂时不可用，请稍后重试。',
    invalidated: '绑定凭据失效（key 已重置或登录已撤销），请重新连接网关。',
};

function makeRes() {
    const headers = {};
    return {
        statusCode: 200,
        headers,
        body: '',
        setHeader(name, value) { headers[name.toLowerCase()] = value; },
        end(value) { this.body = value || ''; },
    };
}

async function call(handler, req) {
    const res = makeRes();
    await handler(req, res);
    return {
        statusCode: res.statusCode,
        headers: res.headers,
        body: res.body,
        json: () => JSON.parse(res.body),
    };
}

function streamOf(text, chunkSize) {
    const bytes = Buffer.from(text, 'utf8');
    const size = chunkSize || bytes.length || 1;
    return new ReadableStream({
        start(controller) {
            for (let offset = 0; offset < bytes.length; offset += size) {
                controller.enqueue(new Uint8Array(bytes.subarray(offset, offset + size)));
            }
            controller.close();
        },
    });
}

function completionBody(text) {
    return JSON.stringify({ choices: [{ message: { role: 'assistant', content: text } }] });
}

function makeGateway(options) {
    const config = options || {};
    const calls = { start: [], poll: [], logout: [], meKey: [] };
    let startCount = 0;
    const client = {
        async startConnect() {
            calls.start.push(true);
            if (config.startError) throw new Error('gateway down');
            startCount += 1;
            return {
                requestRef: `${CONNECT_REF}-${startCount}`,
                pollingSecret: `${CONNECT_SECRET}-${startCount}`,
                authorizeUrl: `${AUTHORIZE_URL}-${startCount}`,
                expiresAt: '2026-11-23T00:15:00Z',
            };
        },
        async pollConnect(secret) {
            calls.poll.push(secret);
            if (!config.poll) return { status: 'pending' };
            return config.poll(secret, calls.poll.length);
        },
        async logout(credential) {
            calls.logout.push(credential);
            if (config.logoutError) throw new Error('logout failed');
            return { status: 'logged_out' };
        },
        async fetchMeKey(credential) {
            calls.meKey.push(credential);
            if (config.meKeyError) throw new Error('me/key failed');
            return { key: config.meKeyValue || NEW_KEY, username: config.meKeyUsername || 'alice' };
        },
        async fetchMe() { return { username: 'alice' }; },
        async fetchKeys() { return { keys: [{ id: 'default', name: '默认 key', masked: '****7x2a', status: 'enabled' }] }; },
        async fetchModels() { return { items: [{ name: 'model-a', protocol_faces: ['chat'] }] }; },
        async fetchBalance() {
            return {
                permanent_balance: '1.000000',
                debt: '0.000000',
                daily_quota: '5.000000',
                daily_quota_used: '0.000000',
                daily_quota_remaining: '5.000000',
                quota_date: '2026-11-23',
                needs_refresh: false,
                observed_at: '2026-11-23T00:00:00Z',
                penalty_input_threshold: '1000',
                penalty_multiplier: '1000',
            };
        },
    };
    return { client, calls };
}

function connectReq(overrides) {
    const extra = overrides || {};
    return {
        method: 'POST',
        url: '/api/plugins/apercus-gateway/connect',
        headers: { host: 'localhost:8000', origin: 'http://localhost:8000', ...(extra.headers || {}) },
        user: 'user' in extra ? extra.user : { directories: { root: '/u/alice' } },
        body: 'body' in extra ? extra.body : '{}',
    };
}

function statusReq(overrides) {
    const extra = overrides || {};
    return {
        method: 'GET',
        url: '/api/plugins/apercus-gateway/connect/status',
        // H9：该路由要求 Sec-Fetch-Site: same-origin 或精确同源 Origin；
        // 默认按浏览器同源 fetch 的形态带上该头。
        headers: { host: 'localhost:8000', 'sec-fetch-site': 'same-origin', ...(extra.headers || {}) },
        user: 'user' in extra ? extra.user : { directories: { root: '/u/alice' } },
    };
}

function logoutReq(overrides) {
    const extra = overrides || {};
    return {
        method: 'POST',
        url: '/api/plugins/apercus-gateway/logout',
        headers: { host: 'localhost:8000', origin: 'http://localhost:8000', ...(extra.headers || {}) },
        user: 'user' in extra ? extra.user : { directories: { root: '/u/alice' } },
        body: '{}',
    };
}

// GET /status 的普通请求（软同源闸：无 Origin 的同源 GET 放行）。
function plainStatusReq() {
    return {
        method: 'GET',
        url: '/api/plugins/apercus-gateway/status',
        headers: { host: 'localhost:8000' },
        user: { directories: { root: '/u/alice' } },
    };
}

function makeSecretStore() {
    const records = new Map();
    return {
        records,
        readBinding: async (directories) => (records.has(directories.root) ? { ...records.get(directories.root) } : null),
        writeBinding: null,
        clearBinding: null,
        refreshKey: null,
    };
}

function buildCore(overrides) {
    const options = overrides || {};
    const store = options.store || makeSecretStore();
    let clock = options.clock ? options.clock.now : 1000;
    const now = () => clock;
    const writeCalls = [];
    const clearCalls = [];
    const refreshCalls = [];
    let failWrites = options.failWrites || 0;
    let failRefresh = options.failRefresh === true;
    const gateway = options.gateway || makeGateway();
    const fetchImpl = options.fetchImpl || (async () => ({ status: 200, body: streamOf(completionBody('PLAN')) }));
    const clearResult = Object.hasOwn(options, 'clearResult') ? options.clearResult : true;

    const core = createCore({
        readBinding: options.readBinding || store.readBinding,
        writeBinding: options.noWriteBinding
            ? null
            : async (directories, record) => {
                writeCalls.push({ directories, record });
                if (options.writeThrows) throw new Error('kv write failed');
                if (failWrites > 0) {
                    failWrites -= 1;
                    return false;
                }
                store.records.set(directories.root, {
                    loginCredential: record.loginCredential,
                    key: record.key,
                    username: record.username,
                });
                return true;
            },
        clearBinding: options.noClearBinding
            ? null
            : async (directories) => {
                clearCalls.push(directories);
                if (options.clearThrows) throw new Error('clear failed');
                if (options.clearKeepsRecord !== true) store.records.delete(directories.root);
                return clearResult;
            },
        refreshKey: options.noRefreshKey
            ? null
            : async (directories, key, username, refreshOptions) => {
                refreshCalls.push({ directories, key, username, options: refreshOptions });
                if (failRefresh) return false;
                const current = store.records.get(directories.root);
                if (!current) return false;
                store.records.set(directories.root, {
                    loginCredential: current.loginCredential,
                    key,
                    username,
                });
                return true;
            },
        gatewayClient: gateway.client,
        fetchImpl,
        now,
        planTimeoutMs: options.planTimeoutMs || 1000,
        maxBytes: options.maxBytes || 1024 * 1024,
        planRateLimitPerMinute: options.planRateLimitPerMinute || 1000,
    });

    return {
        core,
        store,
        gateway,
        writeCalls,
        clearCalls,
        refreshCalls,
        tick: (ms) => { clock += ms; },
        setClock: (value) => { clock = value; },
        setFailRefresh: (value) => { failRefresh = value; },
    };
}

function assertNoStore(result) {
    assert.equal(result.headers['cache-control'], 'no-store');
}

function assertNoSecrets(body) {
    for (const secret of [CONNECT_SECRET, CONNECT_REF, LOGIN_CREDENTIAL, BINDING_KEY]) {
        assert.equal(body.includes(secret), false, secret);
    }
}

function flush(times) {
    const runs = times || 4;
    let chain = Promise.resolve();
    for (let index = 0; index < runs; index += 1) {
        chain = chain.then(() => new Promise((done) => setImmediate(done)));
    }
    return chain;
}

// ===== POST /connect =====

test('connect requires a user (401), same-origin write, and returns only status + authorize_url', async () => {
    const h = buildCore();
    const missing = await call(h.core.handlers.connect, connectReq({ user: undefined }));
    assert.equal(missing.statusCode, 401);
    assert.equal(missing.json().error.code, 'unauthorized');

    const malformed = await call(h.core.handlers.connect, connectReq({ user: {} }));
    assert.equal(malformed.statusCode, 403);
    assert.equal(malformed.json().error.code, 'forbidden');

    const noOrigin = await call(h.core.handlers.connect, connectReq({ headers: { origin: undefined } }));
    assert.equal(noOrigin.statusCode, 403);
    assert.equal(noOrigin.json().error.code, 'origin_forbidden');

    const crossSite = await call(h.core.handlers.connect, connectReq({ headers: { origin: 'https://evil.example' } }));
    assert.equal(crossSite.statusCode, 403);

    const ok = await call(h.core.handlers.connect, connectReq());
    assert.equal(ok.statusCode, 200);
    assert.deepEqual(Object.keys(ok.json()).sort(), ['authorize_url', 'status']);
    assert.equal(ok.json().status, 'pending');
    assert.equal(ok.json().authorize_url, `${AUTHORIZE_URL}-1`);
    assertNoSecrets(ok.body);
    assertNoStore(ok);
    assert.equal(h.gateway.calls.start.length, 1);
});

test('connect reuses a live single-slot request and starts a new one after TTL', async () => {
    const h = buildCore();
    const first = await call(h.core.handlers.connect, connectReq());
    assert.equal(first.statusCode, 200);
    const second = await call(h.core.handlers.connect, connectReq());
    assert.equal(second.statusCode, 200);
    assert.equal(second.json().authorize_url, first.json().authorize_url);
    assert.equal(h.gateway.calls.start.length, 1);

    h.tick(15 * 60 * 1000);
    const third = await call(h.core.handlers.connect, connectReq());
    assert.equal(third.statusCode, 200);
    assert.notEqual(third.json().authorize_url, first.json().authorize_url);
    assert.equal(h.gateway.calls.start.length, 2);
});

test('connect failures are the fixed upstream error without gateway detail', async () => {
    const gateway = makeGateway({ startError: true });
    const h = buildCore({ gateway });
    const result = await call(h.core.handlers.connect, connectReq());
    assert.equal(result.statusCode, 502);
    assert.equal(result.json().error.code, 'upstream_unavailable');
    assert.equal(result.json().error.message, MESSAGES.upstream);
    assertNoStore(result);
});

test('in-flight duplicate connect calls share one gateway start', async () => {
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const client = {
        calls: [],
        async startConnect() {
            client.calls.push(true);
            await gate;
            return {
                requestRef: CONNECT_REF,
                pollingSecret: CONNECT_SECRET,
                authorizeUrl: AUTHORIZE_URL,
                expiresAt: '2026-11-23T00:15:00Z',
            };
        },
        async pollConnect() { return { status: 'pending' }; },
        async logout() { return { status: 'logged_out' }; },
        async fetchMeKey() { return { key: NEW_KEY, username: 'alice' }; },
        async fetchMe() { return { username: 'alice' }; },
        async fetchKeys() { return { keys: [] }; },
        async fetchModels() { return { items: [] }; },
        async fetchBalance() { return { penalty_input_threshold: '0', penalty_multiplier: '1000' }; },
    };
    const h = buildCore({ gateway: { client, calls: client.calls } });
    const first = call(h.core.handlers.connect, connectReq());
    const second = call(h.core.handlers.connect, connectReq());
    await Promise.resolve();
    release();
    const [a, b] = await Promise.all([first, second]);
    assert.equal(a.statusCode, 200);
    assert.equal(b.statusCode, 200);
    assert.equal(client.calls.length, 1);
    assert.equal(a.json().authorize_url, b.json().authorize_url);
});

// ===== GET /connect/status =====

test('connect status: 401 without user, strict same-origin gate, and no secrets', async () => {
    const h = buildCore();
    const missing = await call(h.core.handlers.connectStatus, statusReq({ user: undefined }));
    assert.equal(missing.statusCode, 401);

    const crossSite = await call(h.core.handlers.connectStatus, statusReq({
        headers: { 'sec-fetch-site': 'same-site', origin: 'https://evil.example' },
    }));
    assert.equal(crossSite.statusCode, 403);

    const noSession = await call(h.core.handlers.connectStatus, statusReq());
    assert.equal(noSession.statusCode, 200);
    assert.deepEqual(noSession.json(), { status: 'invalid' });
    assertNoStore(noSession);
});

test('connect status throttles gateway polling to >=5s and reports connecting/pending', async () => {
    const h = buildCore();
    await call(h.core.handlers.connect, connectReq());
    const first = await call(h.core.handlers.connectStatus, statusReq());
    assert.equal(first.json().status, 'connecting');
    assert.equal(h.gateway.calls.poll.length, 0);

    h.tick(5500);
    const second = await call(h.core.handlers.connectStatus, statusReq());
    assert.equal(second.json().status, 'pending');
    assert.equal(h.gateway.calls.poll.length, 1);

    const throttled = await call(h.core.handlers.connectStatus, statusReq());
    assert.equal(throttled.json().status, 'pending');
    assert.equal(h.gateway.calls.poll.length, 1);
    assertNoSecrets(second.body);
});

test('approved connect writes the envelope and reports authorized with username only', async () => {
    let polls = 0;
    const gateway = makeGateway({
        poll: () => {
            polls += 1;
            return polls === 1
                ? { status: 'pending' }
                : {
                    status: 'approved',
                    connect: { loginCredential: LOGIN_CREDENTIAL, key: BINDING_KEY, username: 'alice' },
                };
        },
    });
    const h = buildCore({ gateway });
    await call(h.core.handlers.connect, connectReq());
    h.tick(5500);
    assert.equal((await call(h.core.handlers.connectStatus, statusReq())).json().status, 'pending');
    h.tick(5500);
    const authorized = await call(h.core.handlers.connectStatus, statusReq());
    assert.equal(authorized.statusCode, 200);
    assert.deepEqual(authorized.json(), { status: 'authorized', username: 'alice' });
    assertNoSecrets(authorized.body);
    assert.equal(h.writeCalls.length, 1);
    assert.deepEqual(h.store.records.get('/u/alice'), {
        loginCredential: LOGIN_CREDENTIAL,
        key: BINDING_KEY,
        username: 'alice',
    });

    // 会话已清：后续 status 从密钥库记录回答，不再打网关。
    h.tick(5500);
    const after = await call(h.core.handlers.connectStatus, statusReq());
    assert.deepEqual(after.json(), { status: 'authorized', username: 'alice' });
    assert.equal(h.gateway.calls.poll.length, 2);
});

test('approved with storage failure stays pending, retries the write without re-polling', async () => {
    let polls = 0;
    const gateway = makeGateway({
        poll: () => {
            polls += 1;
            return {
                status: 'approved',
                connect: { loginCredential: LOGIN_CREDENTIAL, key: BINDING_KEY, username: 'alice' },
            };
        },
    });
    const h = buildCore({ gateway, failWrites: 1 });
    await call(h.core.handlers.connect, connectReq());
    h.tick(5500);
    const pending = await call(h.core.handlers.connectStatus, statusReq());
    assert.equal(pending.json().status, 'pending');
    assert.equal(h.writeCalls.length, 1);
    assert.equal(h.gateway.calls.poll.length, 1);

    // 不等待 5 秒：approved 取件在内存，每次 status 直接重试写入。
    const authorized = await call(h.core.handlers.connectStatus, statusReq());
    assert.deepEqual(authorized.json(), { status: 'authorized', username: 'alice' });
    assert.equal(h.writeCalls.length, 2);
    assert.equal(h.gateway.calls.poll.length, 1);
    assert.equal(h.store.records.get('/u/alice').key, BINDING_KEY);
});

test('approved write exceptions are fail-closed and retryable', async () => {
    const gateway = makeGateway({
        poll: () => ({
            status: 'approved',
            connect: { loginCredential: LOGIN_CREDENTIAL, key: BINDING_KEY, username: 'alice' },
        }),
    });
    const h = buildCore({ gateway, writeThrows: true });
    await call(h.core.handlers.connect, connectReq());
    h.tick(5500);
    const pending = await call(h.core.handlers.connectStatus, statusReq());
    assert.equal(pending.json().status, 'pending');
    assert.equal(h.store.records.has('/u/alice'), false);
});

test('invalid connect (404) clears the session and surfaces invalid on status', async () => {
    const gateway = makeGateway({ poll: () => ({ status: 'invalid' }) });
    const h = buildCore({ gateway });
    await call(h.core.handlers.connect, connectReq());
    h.tick(5500);
    const invalid = await call(h.core.handlers.connectStatus, statusReq());
    assert.deepEqual(invalid.json(), { status: 'invalid' });

    const status = await call(h.core.handlers.status, {
        method: 'GET',
        url: '/api/plugins/apercus-gateway/status',
        headers: { host: 'localhost:8000' },
        user: { directories: { root: '/u/alice' } },
    });
    // F4：连接请求层面的失效（poll 404）不再让 /status 报 invalid；无记录 →
    // not_connected（连接面板由 /connect/status 报 invalid）。
    assert.equal(status.json().state, 'not_connected');
    assert.equal(Object.hasOwn(status.json(), 'reason'), false);
    assert.equal(status.json().connected, false);
    assert.deepEqual(status.json().st_connection, { state: 'unknown' });

    // 重新发起清除失效标记，进入 pending。
    await call(h.core.handlers.connect, connectReq());
    const pending = await call(h.core.handlers.status, {
        method: 'GET',
        url: '/api/plugins/apercus-gateway/status',
        headers: { host: 'localhost:8000' },
        user: { directories: { root: '/u/alice' } },
    });
    assert.equal(pending.json().state, 'pending');
});

test('poll network failure is 502 but keeps the session for the next 5s retry', async () => {
    let fail = true;
    const gateway = makeGateway({
        poll: () => {
            if (fail) throw new Error('network down');
            return { status: 'pending' };
        },
    });
    const h = buildCore({ gateway });
    await call(h.core.handlers.connect, connectReq());
    h.tick(5500);
    const failed = await call(h.core.handlers.connectStatus, statusReq());
    assert.equal(failed.statusCode, 502);
    assert.equal(failed.json().error.code, 'upstream_unavailable');
    assertNoStore(failed);

    fail = false;
    h.tick(5500);
    const retried = await call(h.core.handlers.connectStatus, statusReq());
    assert.deepEqual(retried.json(), { status: 'pending' });
    assert.equal(h.gateway.calls.poll.length, 2);
});

test('users have isolated connect sessions and bindings', async () => {
    const gateway = makeGateway({
        poll: (secret) => (secret.endsWith('-1')
            ? { status: 'approved', connect: { loginCredential: 'cred-a', key: 'key-a', username: 'alice' } }
            : { status: 'approved', connect: { loginCredential: 'cred-b', key: 'key-b', username: 'bob' } }),
    });
    const h = buildCore({ gateway });
    const aliceConnect = await call(h.core.handlers.connect, connectReq());
    const bobConnect = await call(h.core.handlers.connect, connectReq({
        user: { directories: { root: '/u/bob' } },
    }));
    assert.notEqual(aliceConnect.json().authorize_url, bobConnect.json().authorize_url);

    h.tick(5500);
    const aliceStatus = await call(h.core.handlers.connectStatus, statusReq());
    const bobStatus = await call(h.core.handlers.connectStatus, statusReq({
        user: { directories: { root: '/u/bob' } },
    }));
    assert.deepEqual(aliceStatus.json(), { status: 'authorized', username: 'alice' });
    assert.deepEqual(bobStatus.json(), { status: 'authorized', username: 'bob' });
    assert.equal(h.gateway.calls.poll.length, 2);
    assert.equal(h.store.records.get('/u/alice').key, 'key-a');
    assert.equal(h.store.records.get('/u/bob').key, 'key-b');
    assert.deepEqual(h.writeCalls.map((item) => item.directories.root).sort(), ['/u/alice', '/u/bob']);
});

// ===== POST /logout =====

test('logout revokes remotely and always clears both local namespaces + session', async () => {
    const h = buildCore();
    h.store.records.set('/u/alice', {
        loginCredential: LOGIN_CREDENTIAL,
        key: BINDING_KEY,
        username: 'alice',
    });
    await call(h.core.handlers.connect, connectReq());
    h.tick(5500);

    const result = await call(h.core.handlers.logout, logoutReq());
    assert.equal(result.statusCode, 200);
    assert.deepEqual(result.json(), {
        status: 'logged_out',
        remote_revoked: true,
        local_cleared: true,
        custom_cleared: true,
    });
    assert.equal(h.gateway.calls.logout.length, 1);
    assert.equal(h.gateway.calls.logout[0], LOGIN_CREDENTIAL);
    assert.equal(h.clearCalls.length, 1);
    assert.equal(h.store.records.has('/u/alice'), false);
    assertNoSecrets(result.body);
    assertNoStore(result);

    // 会话已清：/connect/status 回到 invalid（无记录、无会话）。
    const status = await call(h.core.handlers.connectStatus, statusReq());
    assert.deepEqual(status.json(), { status: 'invalid' });

    // 清理后 /status 必须回到 not_connected（不得因残留信封回 authorized）。
    const v3 = await call(h.core.handlers.status, {
        method: 'GET',
        url: '/api/plugins/apercus-gateway/status',
        headers: { host: 'localhost:8000' },
        user: { directories: { root: '/u/alice' } },
    });
    assert.equal(v3.json().state, 'not_connected');
});

test('logout still clears locally when the remote call fails or no binding exists', async () => {
    const gateway = makeGateway({ logoutError: true });
    const h = buildCore({ gateway });
    h.store.records.set('/u/alice', {
        loginCredential: LOGIN_CREDENTIAL,
        key: BINDING_KEY,
        username: 'alice',
    });
    const result = await call(h.core.handlers.logout, logoutReq());
    assert.equal(result.statusCode, 200);
    assert.deepEqual(result.json(), {
        status: 'logged_out',
        remote_revoked: false,
        local_cleared: true,
        custom_cleared: true,
    });
    assert.equal(h.gateway.calls.logout.length, 1);
    assert.equal(h.clearCalls.length, 1);
    assert.equal(h.store.records.has('/u/alice'), false);

    const noBinding = await call(h.core.handlers.logout, logoutReq());
    assert.equal(noBinding.statusCode, 200);
    assert.deepEqual(noBinding.json(), {
        status: 'logged_out',
        remote_revoked: false,
        local_cleared: true,
        custom_cleared: true,
    });
    assert.equal(h.gateway.calls.logout.length, 1);
    assert.equal(h.clearCalls.length, 2);
});

test('logout reports custom_cleared=false when the envelope is gone but Custom entries remain', async () => {
    const h = buildCore({
        clearResult: { envelope: true, custom: true, customUncertain: true },
    });
    h.store.records.set('/u/alice', {
        loginCredential: LOGIN_CREDENTIAL,
        key: BINDING_KEY,
        username: 'alice',
    });
    const result = await call(h.core.handlers.logout, logoutReq());
    assert.equal(result.statusCode, 200);
    assert.equal(result.json().local_cleared, true);
    assert.equal(result.json().custom_cleared, false);

    // 不确定性必须持久到 /status：页面刷新/其他标签也要继续要求清理。
    const status = await call(h.core.handlers.status, {
        method: 'GET',
        url: '/api/plugins/apercus-gateway/status',
        headers: { host: 'localhost:8000' },
        user: { directories: { root: '/u/alice' } },
    });
    assert.equal(status.json().state, 'invalid');
    assert.equal(status.json().reason, 'login_invalidated');
    assert.equal(status.json().local_cleared, true);
    assert.equal(status.json().custom_cleared, false);
});

test('logout requires the user and same-origin write gate', async () => {
    const h = buildCore();
    const missing = await call(h.core.handlers.logout, logoutReq({ user: undefined }));
    assert.equal(missing.statusCode, 401);
    assert.equal(missing.json().error.code, 'unauthorized');

    const crossSite = await call(h.core.handlers.logout, logoutReq({ headers: { origin: 'https://evil.example' } }));
    assert.equal(crossSite.statusCode, 403);
    assert.equal(crossSite.json().error.code, 'origin_forbidden');
    assert.equal(h.gateway.calls.logout.length, 0);
});

test('logout: local clear failure returns 502 logout_local_clear_failed and status stays invalid (S2)', async () => {
    const h = buildCore({
        clearResult: { envelope: false, custom: false },
        clearKeepsRecord: true,
    });
    h.store.records.set('/u/alice', {
        loginCredential: LOGIN_CREDENTIAL,
        key: BINDING_KEY,
        username: 'alice',
    });
    const result = await call(h.core.handlers.logout, logoutReq());
    assert.equal(result.statusCode, 502);
    assert.equal(result.json().error.code, 'logout_local_clear_failed');
    assert.equal(result.json().error.message,
        '退出登录时本地凭据清理失败；请重试，或到门户“退出所有酒馆插件”兜底。');
    assert.equal(h.clearCalls.length, 1);
    assert.equal(h.store.records.has('/u/alice'), true);

    // 残留信封不得因失效标记缺失而回 authorized。
    const status = await call(h.core.handlers.status, {
        method: 'GET',
        url: '/api/plugins/apercus-gateway/status',
        headers: { host: 'localhost:8000' },
        user: { directories: { root: '/u/alice' } },
    });
    assert.equal(status.json().state, 'invalid');
    assert.equal(status.json().reason, 'login_invalidated');
    assert.equal(status.json().local_cleared, false);
    assert.equal(status.json().custom_cleared, false);
    assert.equal(Object.hasOwn(status.json(), 'username'), false);

    const connectStatus = await call(h.core.handlers.connectStatus, statusReq());
    assert.deepEqual(connectStatus.json(), { status: 'invalid' });

    // 失效标记不随 15 分钟连接 TTL 过期：时间推进后残留信封仍不得 authorized。
    h.tick(60 * 60 * 1000);
    const afterTtl = await call(h.core.handlers.status, {
        method: 'GET',
        url: '/api/plugins/apercus-gateway/status',
        headers: { host: 'localhost:8000' },
        user: { directories: { root: '/u/alice' } },
    });
    assert.equal(afterTtl.json().state, 'invalid');
});

test('logout: partial clear (envelope gone, custom not) is still a 502 failure', async () => {
    const h = buildCore({
        clearResult: { envelope: true, custom: false },
        clearKeepsRecord: true,
    });
    h.store.records.set('/u/alice', {
        loginCredential: LOGIN_CREDENTIAL,
        key: BINDING_KEY,
        username: 'alice',
    });
    const result = await call(h.core.handlers.logout, logoutReq());
    assert.equal(result.statusCode, 502);
    assert.equal(result.json().error.code, 'logout_local_clear_failed');
});

test('logout: a throwing clear is fail-closed without a fake success', async () => {
    const h = buildCore({ clearThrows: true });
    h.store.records.set('/u/alice', {
        loginCredential: LOGIN_CREDENTIAL,
        key: BINDING_KEY,
        username: 'alice',
    });
    const result = await call(h.core.handlers.logout, logoutReq());
    assert.equal(result.statusCode, 502);
    assert.equal(result.json().error.code, 'logout_local_clear_failed');
});

test('startConnect result is discarded when logout bumped the epoch while in flight (S3)', async () => {
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const client = {
        starts: 0,
        async startConnect() {
            client.starts += 1;
            await gate;
            return {
                requestRef: CONNECT_REF,
                pollingSecret: CONNECT_SECRET,
                authorizeUrl: AUTHORIZE_URL,
                expiresAt: '2026-11-23T00:15:00Z',
            };
        },
        async pollConnect() { return { status: 'pending' }; },
        async logout() { return { status: 'logged_out' }; },
        async fetchMeKey() { return { key: NEW_KEY, username: 'alice' }; },
        async fetchMe() { return { username: 'alice' }; },
        async fetchKeys() { return { keys: [] }; },
        async fetchModels() { return { items: [] }; },
        async fetchBalance() { return { penalty_input_threshold: '0', penalty_multiplier: '1000' }; },
    };
    const h = buildCore({ gateway: { client, calls: { start: [], poll: [], logout: [], meKey: [] } } });
    const pendingConnect = call(h.core.handlers.connect, connectReq());
    await Promise.resolve();
    assert.equal(client.starts, 1);

    const logout = await call(h.core.handlers.logout, logoutReq());
    assert.equal(logout.statusCode, 200);
    release();
    const result = await pendingConnect;
    assert.equal(result.statusCode, 409);
    assert.equal(result.json().error.code, 'not_connected');
    assert.equal(result.body.includes(AUTHORIZE_URL), false);

    // 没有会话被建：connect/status 不会去轮询。
    const status = await call(h.core.handlers.connectStatus, statusReq());
    assert.deepEqual(status.json(), { status: 'invalid' });
});

test('approved connect result is dropped when logout happens while polling (S3)', async () => {
    let releasePoll;
    const gate = new Promise((resolve) => { releasePoll = resolve; });
    const client = {
        async startConnect() {
            return {
                requestRef: CONNECT_REF,
                pollingSecret: CONNECT_SECRET,
                authorizeUrl: AUTHORIZE_URL,
                expiresAt: '2026-11-23T00:15:00Z',
            };
        },
        async pollConnect() {
            await gate;
            return {
                status: 'approved',
                connect: { loginCredential: LOGIN_CREDENTIAL, key: BINDING_KEY, username: 'alice' },
            };
        },
        async logout() { return { status: 'logged_out' }; },
        async fetchMeKey() { return { key: NEW_KEY, username: 'alice' }; },
        async fetchMe() { return { username: 'alice' }; },
        async fetchKeys() { return { keys: [] }; },
        async fetchModels() { return { items: [] }; },
        async fetchBalance() { return { penalty_input_threshold: '0', penalty_multiplier: '1000' }; },
    };
    const h = buildCore({ gateway: { client, calls: { start: [], poll: [], logout: [], meKey: [] } } });
    await call(h.core.handlers.connect, connectReq());
    h.tick(5500);
    const pendingStatus = call(h.core.handlers.connectStatus, statusReq());
    await Promise.resolve();
    await Promise.resolve();

    const logout = await call(h.core.handlers.logout, logoutReq());
    assert.equal(logout.statusCode, 200);
    releasePoll();
    const result = await pendingStatus;
    assert.deepEqual(result.json(), { status: 'invalid' });
    assert.equal(h.writeCalls.length, 0);
    assert.equal(h.store.records.has('/u/alice'), false);
});

test('a slow query 401 does not clear a newer login (credential mismatch, S3/S5)', async () => {
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const gateway = makeGateway();
    gateway.client.fetchModels = async () => {
        await gate;
        const error = new Error('unauthorized');
        error.unauthorized = true;
        throw error;
    };
    const h = buildCore({ gateway });
    h.store.records.set('/u/alice', {
        loginCredential: 'old-credential',
        key: 'old-key',
        username: 'alice',
    });
    const pending = call(h.core.handlers.models, {
        method: 'GET',
        url: '/api/plugins/apercus-gateway/models',
        headers: { host: 'localhost:8000' },
        user: { directories: { root: '/u/alice' } },
    });
    await Promise.resolve();

    // 慢 401 返回前用户已重新连接：当前信封已是新凭据。
    h.store.records.set('/u/alice', {
        loginCredential: 'new-credential',
        key: 'new-key',
        username: 'alice',
    });
    release();
    const result = await pending;
    assert.equal(result.statusCode, 409);
    assert.equal(result.json().error.code, 'not_connected');
    assert.equal(result.json().error.message, '登录已失效或已撤销，请重新连接 Apercus 网关。');
    assert.equal(h.clearCalls.length, 0);
    assert.deepEqual(h.store.records.get('/u/alice'), {
        loginCredential: 'new-credential',
        key: 'new-key',
        username: 'alice',
    });

    const status = await call(h.core.handlers.status, {
        method: 'GET',
        url: '/api/plugins/apercus-gateway/status',
        headers: { host: 'localhost:8000' },
        user: { directories: { root: '/u/alice' } },
    });
    assert.equal(status.json().state, 'authorized');
    assert.equal(status.json().username, 'alice');
});

test('status opportunistically probes the login after the interval; 401 clears (S10/F9)', async () => {
    const gateway = makeGateway();
    let meKeyCalls = 0;
    let unauthorized = false;
    gateway.client.fetchMeKey = async () => {
        meKeyCalls += 1;
        if (unauthorized) {
            const error = new Error('unauthorized');
            error.unauthorized = true;
            throw error;
        }
        // 与信封 key 相同：探活成功但不刷新。
        return { key: BINDING_KEY, username: 'alice' };
    };
    const h = buildCore({ gateway });
    h.store.records.set('/u/alice', {
        loginCredential: LOGIN_CREDENTIAL,
        key: BINDING_KEY,
        username: 'alice',
    });
    const statusReqV3 = () => ({
        method: 'GET',
        url: '/api/plugins/apercus-gateway/status',
        headers: { host: 'localhost:8000' },
        user: { directories: { root: '/u/alice' } },
    });

    // 首次授权态 status 就做启动探活（异步、不阻塞响应）。
    const first = await call(h.core.handlers.status, statusReqV3());
    assert.equal(first.json().state, 'authorized');
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(meKeyCalls, 1);

    h.tick(60 * 60 * 1000 + 1);
    const second = await call(h.core.handlers.status, statusReqV3());
    assert.equal(second.json().state, 'authorized');
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(meKeyCalls, 2);

    // 阈值内不再探活（成功探活已刷新基线）。
    h.tick(60);
    await call(h.core.handlers.status, statusReqV3());
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(meKeyCalls, 2);

    // 下一次超过阈值 → 401 → 按 S5 清理，/status 转 invalid。
    unauthorized = true;
    h.tick(60 * 60 * 1000 + 1);
    await call(h.core.handlers.status, statusReqV3());
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(meKeyCalls, 3);
    assert.equal(h.clearCalls.length, 1);
    assert.equal(h.store.records.has('/u/alice'), false);
    const after = await call(h.core.handlers.status, statusReqV3());
    assert.equal(after.json().state, 'invalid');
});

// ===== /plan key reset refresh =====

test('plan 401 refreshes the key via me/key, rewrites the envelope, and retries once', async () => {
    let upstreamCalls = 0;
    const fetchImpl = async (url, options) => {
        assert.equal(url, PLAN_URL);
        upstreamCalls += 1;
        if (upstreamCalls === 1) {
            assert.equal(options.headers.authorization, `Bearer ${BINDING_KEY}`);
            return { status: 401, body: streamOf('{"error":"secret-leak"}') };
        }
        assert.equal(options.headers.authorization, `Bearer ${NEW_KEY}`);
        return { status: 200, body: streamOf(completionBody('PLAN_OK')) };
    };
    const h = buildCore({ fetchImpl });
    h.store.records.set('/u/alice', {
        loginCredential: LOGIN_CREDENTIAL,
        key: BINDING_KEY,
        username: 'alice',
    });

    const result = await call(h.core.handlers.plan, {
        method: 'POST',
        url: '/api/plugins/apercus-gateway/plan',
        headers: { host: 'localhost:8000', origin: 'http://localhost:8000' },
        user: { directories: { root: '/u/alice' } },
        body: { model: 'model-a', prompt: 'prompt' },
    });
    assert.equal(result.statusCode, 200);
    assert.deepEqual(result.json(), { text: 'PLAN_OK' });
    assert.equal(upstreamCalls, 2);
    assert.deepEqual(h.gateway.calls.meKey, [LOGIN_CREDENTIAL]);
    assert.deepEqual(h.refreshCalls, [{
        directories: { root: '/u/alice' },
        key: NEW_KEY,
        username: 'alice',
        options: { expectedLoginCredential: LOGIN_CREDENTIAL },
    }]);
    assert.equal(h.store.records.get('/u/alice').key, NEW_KEY);
    assert.equal(h.store.records.get('/u/alice').loginCredential, LOGIN_CREDENTIAL);
    assert.equal(result.body.includes('secret-leak'), false);
    assertNoStore(result);
});

test('plan 401 refreshes the envelope and the plugin-owned Custom key through the real adapter (S4)', async () => {
    async function run(customKey) {
        const store = {
            apercus_gateway: JSON.stringify({
                version: 1,
                login_credential: LOGIN_CREDENTIAL,
                key: BINDING_KEY,
                username: 'alice',
            }),
            api_key_custom: customKey,
        };
        class Manager {
            async readSecret(name) {
                return Object.hasOwn(store, name) ? store[name] : null;
            }
            async writeSecret(name, value) {
                store[name] = value;
                return 1;
            }
            async deleteSecret(name) { delete store[name]; }
        }
        const adapter = createSecretBindingAdapter({
            stRoot: 'x',
            secretManagerLoader: async () => Manager,
        });
        const gateway = makeGateway();
        let calls = 0;
        const fetchImpl = async (url, options) => {
            calls += 1;
            if (calls === 1) {
                assert.equal(url, PLAN_URL);
                assert.equal(options.headers.authorization, `Bearer ${BINDING_KEY}`);
                return { status: 401, body: streamOf('{"error":"leak"}') };
            }
            assert.equal(options.headers.authorization, `Bearer ${NEW_KEY}`);
            return { status: 200, body: streamOf(completionBody('PLAN_OK')) };
        };
        const core = createCore({
            readBinding: adapter.readBinding,
            writeBinding: adapter.writeBinding,
            clearBinding: adapter.clearBinding,
            refreshKey: adapter.refreshKey,
            writeCustomSourceKey: adapter.writeCustomSourceKey,
            gatewayClient: gateway.client,
            fetchImpl,
            now: () => 1000,
            planRateLimitPerMinute: 1000,
        });
        const result = await call(core.handlers.plan, {
            method: 'POST',
            url: '/api/plugins/apercus-gateway/plan',
            headers: { host: 'localhost:8000', origin: 'http://localhost:8000' },
            user: { directories: { root: '/u/alice' } },
            body: { model: 'model-a', prompt: 'prompt' },
        });
        assert.equal(result.statusCode, 200);
        assert.deepEqual(result.json(), { text: 'PLAN_OK' });
        assert.equal(calls, 2);
        assert.equal(JSON.parse(store.apercus_gateway).key, NEW_KEY);
        return store;
    }

    const pluginOwned = await run(BINDING_KEY);
    assert.equal(pluginOwned.api_key_custom, NEW_KEY);

    const userOwned = await run('user-own-key');
    assert.equal(userOwned.api_key_custom, 'user-own-key');
});

test('H3: /status self-heals a new envelope with an old plugin Custom value (real adapter)', async () => {
    const store = {
        apercus_gateway: JSON.stringify({
            version: 1,
            login_credential: LOGIN_CREDENTIAL,
            key: BINDING_KEY,
            username: 'alice',
        }),
        api_key_custom: BINDING_KEY,
    };
    let failCustomSync = true;
    class Manager {
        async readSecret(name) {
            return Object.hasOwn(store, name) ? store[name] : null;
        }
        async writeSecret(name, value) {
            if (name === 'api_key_custom' && failCustomSync) throw new Error('custom write failed');
            store[name] = value;
            return 1;
        }
        async deleteSecret(name) { delete store[name]; }
        getAllSecrets() {
            const snapshot = {};
            for (const [name, value] of Object.entries(store)) {
                snapshot[name] = [{ id: name, value, label: 'x', active: true }];
            }
            return snapshot;
        }
    }
    const adapter = createSecretBindingAdapter({
        stRoot: 'x',
        secretManagerLoader: async () => Manager,
    });
    // data plane 401 → me/key 返回 NEW_KEY → 刷新信封；Custom 同步第一次失败。
    let dataCalls = 0;
    const fetchImpl = async (url, options) => {
        dataCalls += 1;
        if (dataCalls === 1) {
            assert.equal(options.headers.authorization, `Bearer ${BINDING_KEY}`);
            return { status: 401, body: streamOf('{"error":"leak"}') };
        }
        assert.equal(options.headers.authorization, `Bearer ${NEW_KEY}`);
        return { status: 200, body: streamOf(completionBody('PLAN_OK')) };
    };
    const core = createCore({
        readBinding: adapter.readBinding,
        readBindingState: adapter.readBindingState,
        writeBinding: adapter.writeBinding,
        clearBinding: adapter.clearBinding,
        refreshKey: adapter.refreshKey,
        writeCustomSourceKey: adapter.writeCustomSourceKey,
        clearCustomSourceKey: adapter.clearCustomSourceKey,
        retryCustomSync: adapter.retryCustomSync,
        gatewayClient: makeGateway().client,
        fetchImpl,
        now: () => 1000,
        planRateLimitPerMinute: 1000,
    });
    const plan = await call(core.handlers.plan, {
        method: 'POST',
        url: '/api/plugins/apercus-gateway/plan',
        headers: { host: 'localhost:8000', origin: 'http://localhost:8000' },
        user: { directories: { root: '/u/alice' } },
        body: { model: 'model-a', prompt: 'prompt' },
    });
    assert.equal(plan.statusCode, 200);
    assert.equal(JSON.parse(store.apercus_gateway).key, NEW_KEY);
    assert.equal(store.api_key_custom, BINDING_KEY, 'Custom sync failed and stays old');

    // 下一次 /status 探活触发 Custom 同步重试并自愈。
    failCustomSync = false;
    const status = await call(core.handlers.status, plainStatusReq());
    assert.equal(status.json().state, 'authorized');
    await flush();
    assert.equal(store.api_key_custom, NEW_KEY);
});

test('plan 401 with a failing me/key or refresh stays 502 binding_invalidated without a retry loop', async () => {
    const fetch401 = async () => ({ status: 401, body: streamOf('{"error":"leak"}') });

    const meKeyFails = buildCore({ fetchImpl: fetch401, gateway: makeGateway({ meKeyError: true }) });
    meKeyFails.store.records.set('/u/alice', {
        loginCredential: LOGIN_CREDENTIAL, key: BINDING_KEY, username: 'alice',
    });
    const a = await call(meKeyFails.core.handlers.plan, {
        method: 'POST',
        url: '/api/plugins/apercus-gateway/plan',
        headers: { host: 'localhost:8000', origin: 'http://localhost:8000' },
        user: { directories: { root: '/u/alice' } },
        body: { model: 'model-a', prompt: 'prompt' },
    });
    assert.equal(a.statusCode, 502);
    assert.equal(a.json().error.code, 'binding_invalidated');
    assert.equal(a.json().error.message, MESSAGES.invalidated);

    const refreshFails = buildCore({ fetchImpl: fetch401, failRefresh: true });
    refreshFails.store.records.set('/u/alice', {
        loginCredential: LOGIN_CREDENTIAL, key: BINDING_KEY, username: 'alice',
    });
    const b = await call(refreshFails.core.handlers.plan, {
        method: 'POST',
        url: '/api/plugins/apercus-gateway/plan',
        headers: { host: 'localhost:8000', origin: 'http://localhost:8000' },
        user: { directories: { root: '/u/alice' } },
        body: { model: 'model-a', prompt: 'prompt' },
    });
    assert.equal(b.statusCode, 502);
    assert.equal(b.json().error.code, 'binding_invalidated');
    assert.equal(refreshFails.refreshCalls.length, 1);

    // 刷新成功但重试仍 401：只重试一次、不再刷新。
    let calls = 0;
    const still401 = buildCore({
        fetchImpl: async () => {
            calls += 1;
            return { status: 401, body: streamOf('') };
        },
    });
    still401.store.records.set('/u/alice', {
        loginCredential: LOGIN_CREDENTIAL, key: BINDING_KEY, username: 'alice',
    });
    const c = await call(still401.core.handlers.plan, {
        method: 'POST',
        url: '/api/plugins/apercus-gateway/plan',
        headers: { host: 'localhost:8000', origin: 'http://localhost:8000' },
        user: { directories: { root: '/u/alice' } },
        body: { model: 'model-a', prompt: 'prompt' },
    });
    assert.equal(c.statusCode, 502);
    assert.equal(c.json().error.code, 'binding_invalidated');
    assert.equal(calls, 2);
    assert.equal(still401.gateway.calls.meKey.length, 1);
});

test('plan refresh does not rewrite the envelope when logout raced the me/key fetch (S3)', async () => {
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const gateway = makeGateway();
    gateway.client.fetchMeKey = async () => {
        await gate;
        return { key: NEW_KEY, username: 'alice' };
    };
    const h = buildCore({
        gateway,
        fetchImpl: async () => ({ status: 401, body: streamOf('{"error":"leak"}') }),
    });
    h.store.records.set('/u/alice', {
        loginCredential: LOGIN_CREDENTIAL,
        key: BINDING_KEY,
        username: 'alice',
    });
    const pending = call(h.core.handlers.plan, {
        method: 'POST',
        url: '/api/plugins/apercus-gateway/plan',
        headers: { host: 'localhost:8000', origin: 'http://localhost:8000' },
        user: { directories: { root: '/u/alice' } },
        body: { model: 'model-a', prompt: 'prompt' },
    });
    // 让首轮上游 401 与 me/key 进入在途状态。
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();

    const logout = await call(h.core.handlers.logout, logoutReq());
    assert.equal(logout.statusCode, 200);
    release();
    const result = await pending;
    assert.equal(result.statusCode, 409);
    assert.equal(result.json().error.code, 'not_connected');
    assert.equal(result.json().error.message, '登录状态已变更，本次操作已取消，请重试。');
    assert.equal(h.refreshCalls.length, 0);
    assert.equal(h.store.records.has('/u/alice'), false);
});

test('plan 401 without a login credential never calls the query plane', async () => {
    const h = buildCore({
        fetchImpl: async () => ({ status: 401, body: streamOf('{"error":"leak"}') }),
    });
    // 旧形态记录（无 login credential）：兼容读取但不可刷新。
    h.store.records.set('/u/alice', { key: BINDING_KEY });
    const result = await call(h.core.handlers.plan, {
        method: 'POST',
        url: '/api/plugins/apercus-gateway/plan',
        headers: { host: 'localhost:8000', origin: 'http://localhost:8000' },
        user: { directories: { root: '/u/alice' } },
        body: { model: 'model-a', prompt: 'prompt' },
    });
    assert.equal(result.statusCode, 502);
    assert.equal(result.json().error.code, 'binding_invalidated');
    assert.equal(h.gateway.calls.meKey.length, 0);
    assert.equal(h.refreshCalls.length, 0);
});

// ===== /status v3 =====

test('status v3 reports pending while a connect session is live', async () => {
    const h = buildCore();
    await call(h.core.handlers.connect, connectReq());
    const pending = await call(h.core.handlers.status, {
        method: 'GET',
        url: '/api/plugins/apercus-gateway/status',
        headers: { host: 'localhost:8000' },
        user: { directories: { root: '/u/alice' } },
    });
    assert.equal(pending.json().state, 'pending');
    assert.equal(pending.json().connected, false);
    assert.equal(pending.json().authAvailable, false);
    assert.equal(pending.json().connect_pending, true);
    // I9：pending 的 legacy code/message 与状态一致。
    assert.equal(pending.json().code, 'connect_pending');
    assert.equal(pending.json().message, '等待网关网页授权完成。');
    assert.deepEqual(pending.json().st_connection, { state: 'unknown' });
    assert.equal(Object.hasOwn(pending.json(), 'username'), false);

    const stored = await call(h.core.handlers.status, {
        method: 'GET',
        url: '/api/plugins/apercus-gateway/status',
        headers: { host: 'localhost:8000' },
        user: { directories: { root: '/u/bob' } },
    });
    assert.equal(stored.json().state, 'not_connected');
});

test('connect and status responses never serialize secrets', async () => {
    const h = buildCore();
    const connect = await call(h.core.handlers.connect, connectReq());
    assertNoSecrets(connect.body);
    h.tick(5500);
    const pending = await call(h.core.handlers.connectStatus, statusReq());
    assertNoSecrets(pending.body);
    const status = await call(h.core.handlers.status, {
        method: 'GET',
        url: '/api/plugins/apercus-gateway/status',
        headers: { host: 'localhost:8000' },
        user: { directories: { root: '/u/alice' } },
    });
    assertNoSecrets(status.body);
});

test('connect flow writes nothing to the console', async () => {
    const recorded = [];
    const methods = ['log', 'info', 'warn', 'error', 'debug'];
    const originals = {};
    for (const method of methods) {
        originals[method] = console[method];
        console[method] = (...args) => recorded.push({ method, args });
    }
    try {
        const h = buildCore();
        await call(h.core.handlers.connect, connectReq());
        h.tick(5500);
        await call(h.core.handlers.connectStatus, statusReq());
        await call(h.core.handlers.status, {
            method: 'GET',
            url: '/api/plugins/apercus-gateway/status',
            headers: { host: 'localhost:8000' },
            user: { directories: { root: '/u/alice' } },
        });
        await call(h.core.handlers.logout, logoutReq());
        assert.equal(recorded.length, 0);
    } finally {
        for (const method of methods) {
            console[method] = originals[method];
        }
    }
});

// ===== F4：连接请求失效不压过有效信封 =====

test('connect request invalidation only affects /connect/status, not an existing authorized /status (F4)', async () => {
    const gateway = makeGateway({ poll: () => ({ status: 'invalid' }) });
    const h = buildCore({ gateway });
    h.store.records.set('/u/alice', {
        loginCredential: LOGIN_CREDENTIAL,
        key: BINDING_KEY,
        username: 'alice',
    });
    await call(h.core.handlers.connect, connectReq());
    h.tick(5500);
    const connectStatus = await call(h.core.handlers.connectStatus, statusReq());
    assert.deepEqual(connectStatus.json(), { status: 'invalid' });

    // 旧信封仍有效：poll 404 / 取消 / 过期不得把 /status 压成 invalid。
    const status = await call(h.core.handlers.status, statusReqV3Req());
    assert.equal(status.json().state, 'authorized');
    assert.equal(status.json().username, 'alice');
    assert.equal(Object.hasOwn(status.json(), 'reason'), false);

    // 重新发起连接不会清除标记（失效标记只在新 approved 写库成功时清）；
    // 已有有效信封时 /status 仍按 authorized 回答，连接面板自己显示 connecting。
    await call(h.core.handlers.connect, connectReq());
    const stillAuthorized = await call(h.core.handlers.status, statusReqV3Req());
    assert.equal(stillAuthorized.json().state, 'authorized');
    const connectAfter = await call(h.core.handlers.connectStatus, statusReq());
    // 新会话还在 5 秒节流窗口内：connecting（不再是上次的 invalid 标记）。
    assert.equal(connectAfter.json().status, 'connecting');
});

function statusReqV3Req() {
    return {
        method: 'GET',
        url: '/api/plugins/apercus-gateway/status',
        headers: { host: 'localhost:8000' },
        user: { directories: { root: '/u/alice' } },
    };
}

// ===== F5：approved 写库失败重试上限 =====

test('approved write failures stay pending with retry state 3 times, then invalidate (F5)', async () => {
    const gateway = makeGateway({
        poll: () => ({
            status: 'approved',
            connect: { loginCredential: LOGIN_CREDENTIAL, key: BINDING_KEY, username: 'alice' },
        }),
    });
    const h = buildCore({ gateway, failWrites: 100 });
    await call(h.core.handlers.connect, connectReq());
    h.tick(5500);

    for (let attempt = 1; attempt <= 3; attempt += 1) {
        const pending = await call(h.core.handlers.connectStatus, statusReq());
        assert.equal(pending.json().status, 'pending', String(attempt));
        assert.deepEqual(pending.json().write_retry, { attempt, max: 4 }, String(attempt));
        assert.equal(h.gateway.calls.poll.length, 1);
    }

    // 第 4 次失败：清会话 + 连接失效标记，/connect/status 报 invalid。
    const exhausted = await call(h.core.handlers.connectStatus, statusReq());
    assert.deepEqual(exhausted.json(), { status: 'invalid' });
    assert.equal(h.writeCalls.length, 4);
    assert.equal(h.gateway.calls.poll.length, 1);
    assert.equal(h.store.records.has('/u/alice'), false);

    // 无记录、只有连接层失效标记：/status 是 not_connected（不是 invalid）。
    const status = await call(h.core.handlers.status, statusReqV3Req());
    assert.equal(status.json().state, 'not_connected');


    // 重新连接（写库恢复）→ 新 approved 写库成功，标记被清除并 bump epoch。
    const gateway2 = makeGateway({
        poll: () => ({
            status: 'approved',
            connect: { loginCredential: LOGIN_CREDENTIAL, key: BINDING_KEY, username: 'alice' },
        }),
    });
    const h2 = buildCore({ gateway: gateway2 });
    h2.store.records.set('/u/alice', {
        loginCredential: 'old-cred',
        key: 'old-key',
        username: 'alice',
    });
    await call(h2.core.handlers.connect, connectReq());
    h2.tick(5500);
    const authorized = await call(h2.core.handlers.connectStatus, statusReq());
    assert.deepEqual(authorized.json(), { status: 'authorized', username: 'alice' });
    assert.equal(h2.store.records.get('/u/alice').key, BINDING_KEY);
    const after = await call(h2.core.handlers.status, statusReqV3Req());
    assert.equal(after.json().state, 'authorized');
});

// ===== F3：approved 写库成功 bump epoch，作废在途刷新 =====

test('a plan refresh in flight cannot land after a newer approved write (F3)', async () => {
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const gateway = makeGateway({
        poll: () => ({
            status: 'approved',
            connect: { loginCredential: LOGIN_CREDENTIAL, key: BINDING_KEY, username: 'alice' },
        }),
    });
    gateway.client.fetchMeKey = async () => {
        await gate;
        return { key: NEW_KEY, username: 'alice' };
    };
    const h = buildCore({
        gateway,
        fetchImpl: async () => ({ status: 401, body: streamOf('{"error":"leak"}') }),
    });
    h.store.records.set('/u/alice', {
        loginCredential: 'old-cred',
        key: 'old-key',
        username: 'alice',
    });

    const pendingPlan = call(h.core.handlers.plan, {
        method: 'POST',
        url: '/api/plugins/apercus-gateway/plan',
        headers: { host: 'localhost:8000', origin: 'http://localhost:8000' },
        user: { directories: { root: '/u/alice' } },
        body: { model: 'model-a', prompt: 'prompt' },
    });
    // 首轮数据面 401 + me/key 在途。
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();

    // 新 approved 写库：信封换成 B，epoch +1。
    await call(h.core.handlers.connect, connectReq());
    h.tick(5500);
    const approved = await call(h.core.handlers.connectStatus, statusReq());
    assert.deepEqual(approved.json(), { status: 'authorized', username: 'alice' });
    assert.equal(h.store.records.get('/u/alice').loginCredential, LOGIN_CREDENTIAL);

    release();
    const result = await pendingPlan;
    assert.equal(result.statusCode, 409);
    assert.equal(result.json().error.code, 'not_connected');
    assert.equal(result.body.includes(NEW_KEY), false);
    assert.equal(result.body.includes('old-key'), false);
    // A 的刷新没有落库：仍是 B 的凭据与 key。
    assert.deepEqual(h.store.records.get('/u/alice'), {
        loginCredential: LOGIN_CREDENTIAL,
        key: BINDING_KEY,
        username: 'alice',
    });
    assert.equal(h.refreshCalls.length, 0);
});

// ===== F9：探活发现 key 变化后刷新信封与插件自有 Custom key =====

test('login probe compares me/key with the envelope and refreshes it plus the plugin Custom key (F9)', async () => {
    const store = {
        apercus_gateway: JSON.stringify({
            version: 1,
            login_credential: LOGIN_CREDENTIAL,
            key: BINDING_KEY,
            username: 'alice',
            custom_keys: [BINDING_KEY],
        }),
        api_key_custom: [
            { id: 1, value: BINDING_KEY, label: 'custom', active: true },
            { id: 2, value: 'user-own-key', label: 'custom', active: false },
        ],
    };
    class Manager {
        async readSecret(name) {
            const value = store[name];
            if (Array.isArray(value)) {
                const active = value.find((entry) => entry.active);
                return active ? active.value : '';
            }
            return Object.hasOwn(store, name) ? store[name] : null;
        }
        async writeSecret(name, value, label) {
            if (Array.isArray(store[name])) {
                for (const entry of store[name]) entry.active = false;
                store[name].push({ id: 100 + store[name].length, value, label, active: true });
            } else {
                store[name] = value;
            }
            return 1;
        }
        async deleteSecret(name, id) {
            if (Array.isArray(store[name]) && id !== undefined) {
                store[name] = store[name].filter((entry) => entry.id !== id);
            } else {
                delete store[name];
            }
        }
        getAllSecrets() { return store; }
    }
    const adapter = createSecretBindingAdapter({
        stRoot: 'x',
        secretManagerLoader: async () => Manager,
    });
    const gateway = makeGateway();
    // makeGateway 的 fetchMeKey 默认返回 NEW_KEY（与信封 BINDING_KEY 不同）。
    const core = createCore({
        readBinding: adapter.readBinding,
        writeBinding: adapter.writeBinding,
        clearBinding: adapter.clearBinding,
        refreshKey: adapter.refreshKey,
        writeCustomSourceKey: adapter.writeCustomSourceKey,
        clearCustomSourceKey: adapter.clearCustomSourceKey,
        gatewayClient: gateway.client,
        fetchImpl: async () => ({ status: 200, body: streamOf(completionBody('X')) }),
        now: () => 1000,
        planRateLimitPerMinute: 1000,
    });
    const result = await call(core.handlers.status, {
        method: 'GET',
        url: '/api/plugins/apercus-gateway/status',
        headers: { host: 'localhost:8000' },
        user: { directories: { root: '/u/alice' } },
    });
    assert.equal(result.json().state, 'authorized');
    // 等探活链路（fetchMeKey → refreshKey 信封 + Custom）跑完。
    for (let index = 0; index < 8; index += 1) {
        await new Promise((resolve) => setImmediate(resolve));
    }
    assert.deepEqual(gateway.calls.meKey, [LOGIN_CREDENTIAL]);
    const envelope = JSON.parse(store.apercus_gateway);
    assert.equal(envelope.key, NEW_KEY);
    assert.equal(envelope.login_credential, LOGIN_CREDENTIAL);
    assert.deepEqual(envelope.custom_keys, [BINDING_KEY, NEW_KEY]);
    assert.equal(store.api_key_custom.find((entry) => entry.active).value, NEW_KEY);
    assert.equal(store.api_key_custom.find((entry) => entry.value === 'user-own-key').active, false);
});

test('G4: only a successful new approval clears login_invalidated (queries resume afterwards)', async () => {
    let polls = 0;
    const gateway = makeGateway({
        poll: () => {
            polls += 1;
            return polls === 1
                ? { status: 'pending' }
                : {
                    status: 'approved',
                    connect: { loginCredential: LOGIN_CREDENTIAL, key: BINDING_KEY, username: 'alice' },
                };
        },
    });
    const h = buildCore({
        gateway,
        clearKeepsRecord: true,
        clearResult: false,
        noRefreshKey: true,
    });
    h.store.records.set('/u/alice', {
        loginCredential: 'old-cred',
        key: 'old-key',
        username: 'alice',
    });

    // 本地清理失败：502 + login_invalidated（残信封仍在）。
    const logout = await call(h.core.handlers.logout, logoutReq());
    assert.equal(logout.statusCode, 502);
    assert.equal(logout.json().error.code, 'logout_local_clear_failed');
    assert.equal(h.store.records.has('/u/alice'), true);
    const plainStatusReq = () => ({
        method: 'GET',
        url: '/api/plugins/apercus-gateway/status',
        headers: { host: 'localhost:8000' },
        user: { directories: { root: '/u/alice' } },
    });
    assert.equal((await call(h.core.handlers.status, plainStatusReq())).json().state, 'invalid');

    // 新批准写入成功是唯一清标记路径。
    await call(h.core.handlers.connect, connectReq());
    h.tick(5500);
    assert.equal((await call(h.core.handlers.connectStatus, statusReq())).json().status, 'pending');
    h.tick(5500);
    const approved = await call(h.core.handlers.connectStatus, statusReq());
    assert.deepEqual(approved.json(), { status: 'authorized', username: 'alice' });

    const status = await call(h.core.handlers.status, plainStatusReq());
    assert.equal(status.json().state, 'authorized');
    const keys = await call(h.core.handlers.keys, {
        method: 'GET',
        url: '/api/plugins/apercus-gateway/keys',
        headers: { host: 'localhost:8000' },
        user: { directories: { root: '/u/alice' } },
    });
    assert.equal(keys.statusCode, 200);
});

// ===== I5：/connect/status 同源闸 =====
// SFS 存在时必须是 same-origin；Origin 存在时必须精确同源；两者都缺失（非安全
// 上下文/旧浏览器）放行，只依赖 Host allowlist 与轮询会话密钥。

test('I5: connect/status rejects non-same-origin SFS and inexact Origin, allows header-less LAN clients', async () => {
    const h = buildCore();
    // SFS 存在但不是 same-origin → 403，即便 Origin 精确同源。
    for (const fetchSite of ['same-site', 'none', 'cross-site']) {
        const withoutOrigin = await call(h.core.handlers.connectStatus, statusReq({
            headers: { 'sec-fetch-site': fetchSite },
        }));
        assert.equal(withoutOrigin.statusCode, 403, fetchSite);
        assert.equal(withoutOrigin.json().error.code, 'origin_forbidden', fetchSite);
        const withOrigin = await call(h.core.handlers.connectStatus, statusReq({
            headers: { 'sec-fetch-site': fetchSite, origin: 'http://localhost:8000' },
        }));
        assert.equal(withOrigin.statusCode, 403, `${fetchSite} + exact Origin`);
        assert.equal(withOrigin.json().error.code, 'origin_forbidden', `${fetchSite} + exact Origin`);
    }

    // SFS same-origin：放行（无 Origin 或精确同源 Origin 均可）。
    const sameOrigin = await call(h.core.handlers.connectStatus, statusReq({
        headers: { 'sec-fetch-site': 'same-origin' },
    }));
    assert.equal(sameOrigin.statusCode, 200);
    const sameOriginWithOrigin = await call(h.core.handlers.connectStatus, statusReq({
        headers: { 'sec-fetch-site': 'same-origin', origin: 'http://localhost:8000' },
    }));
    assert.equal(sameOriginWithOrigin.statusCode, 200);
    // Origin 存在时必须精确同源——SFS 声称同源也不能掩盖矛盾 Origin。
    const contradictory = await call(h.core.handlers.connectStatus, statusReq({
        headers: { 'sec-fetch-site': 'same-origin', origin: 'https://localhost:8000' },
    }));
    assert.equal(contradictory.statusCode, 403);
    assert.equal(contradictory.json().error.code, 'origin_forbidden');

    // 无 SFS、仅有精确同源 Origin（含反代 X-Forwarded-Proto）→ 放行。
    const originOnly = await call(h.core.handlers.connectStatus, statusReq({
        headers: { 'sec-fetch-site': undefined, origin: 'http://localhost:8000' },
    }));
    assert.equal(originOnly.statusCode, 200);
    const forwardedOk = await call(h.core.handlers.connectStatus, statusReq({
        headers: {
            'sec-fetch-site': undefined,
            origin: 'https://localhost:8000',
            'x-forwarded-proto': 'https',
        },
    }));
    assert.equal(forwardedOk.statusCode, 200);
    // Origin 看似同 host 但协议不符 / 非法 Origin → 403。
    for (const origin of ['https://localhost:8000', 'not a url', 'null']) {
        const bad = await call(h.core.handlers.connectStatus, statusReq({
            headers: { 'sec-fetch-site': undefined, origin },
        }));
        assert.equal(bad.statusCode, 403, origin);
        assert.equal(bad.json().error.code, 'origin_forbidden', origin);
    }

    // 两者都缺失：局域网 / 旧浏览器 / 非安全上下文 → 放行（Host 闸仍在）。
    const bare = await call(h.core.handlers.connectStatus, {
        method: 'GET',
        url: '/api/plugins/apercus-gateway/connect/status',
        headers: { host: 'localhost:8000' },
        user: { directories: { root: '/u/alice' } },
    });
    assert.equal(bare.statusCode, 200);
    assert.deepEqual(bare.json(), { status: 'invalid' });
    // Host allowlist 仍是硬闸：无头请求也不能绕过 Host 校验。
    const badHost = await call(h.core.handlers.connectStatus, {
        method: 'GET',
        url: '/api/plugins/apercus-gateway/connect/status',
        headers: { host: 'evil.example' },
        user: { directories: { root: '/u/alice' } },
    });
    assert.equal(badHost.statusCode, 403);
    assert.equal(badHost.json().error.code, 'host_not_allowed');
});

// ===== H7：invalidateLogin 锁内复核 =====

test('H7: an epoch bump during the locked read aborts invalidation (no double clear)', async () => {
    const oldRecord = {
        loginCredential: 'cred_old',
        key: BINDING_KEY,
        username: 'alice',
    };
    const store = makeSecretStore();
    store.records.set('/u/alice', oldRecord);
    let reads = 0;
    let resolveInvalidationRead = null;
    const baseGateway = makeGateway();
    const unauthorized = () => {
        const error = new Error('unauthorized');
        error.unauthorized = true;
        return error;
    };
    const gateway = {
        calls: baseGateway.calls,
        client: {
            ...baseGateway.client,
            async fetchKeys() { throw unauthorized(); },
        },
    };
    const h = buildCore({
        store,
        gateway,
        readBinding: async () => {
            reads += 1;
            if (reads === 1) return { ...oldRecord };
            if (reads === 2) {
                // invalidateLogin 在锁内读取：挂起，等 logout bump 世代后返回。
                return new Promise((resolve) => {
                    resolveInvalidationRead = () => resolve({ ...oldRecord });
                });
            }
            return store.records.has('/u/alice') ? { ...store.records.get('/u/alice') } : null;
        },
    });
    const keysPromise = call(h.core.handlers.keys, {
        method: 'GET',
        url: '/api/plugins/apercus-gateway/keys',
        headers: { host: 'localhost:8000', 'sec-fetch-site': 'same-origin' },
        user: { directories: { root: '/u/alice' } },
    });
    await flush();
    assert.equal(typeof resolveInvalidationRead, 'function', 'invalidateLogin holds the lock in its read');

    // logout 在取锁前 bumpEpoch 并同步摘除会话；其清理排队在 invalidate 之后。
    const logoutPromise = call(h.core.handlers.logout, logoutReq());
    await flush();
    resolveInvalidationRead();
    const keys = await keysPromise;
    const logout = await logoutPromise;

    assert.equal(keys.statusCode, 409);
    assert.equal(h.clearCalls.length, 1, 'only logout cleared; stale invalidation aborted');
    assert.equal(logout.statusCode, 200);
    assert.equal(store.records.has('/u/alice'), false);
    const status = await call(h.core.handlers.status, plainStatusReq());
    assert.equal(status.json().state, 'not_connected');
});

test('H7: a newer approved envelope that lands before invalidation is preserved', async () => {
    const oldRecord = {
        loginCredential: 'cred_old',
        key: BINDING_KEY,
        username: 'alice',
    };
    const newRecord = {
        loginCredential: 'cred_new',
        key: NEW_KEY,
        username: 'bob',
    };
    const store = makeSecretStore();
    store.records.set('/u/alice', oldRecord);
    let reads = 0;
    const baseGateway = makeGateway();
    const unauthorized = () => {
        const error = new Error('unauthorized');
        error.unauthorized = true;
        return error;
    };
    const gateway = {
        calls: baseGateway.calls,
        client: {
            ...baseGateway.client,
            async fetchKeys() { throw unauthorized(); },
        },
    };
    const h = buildCore({
        store,
        gateway,
        // 第一次读取（queryAuth）看到旧信封；invalidize 的锁内重读前，新
        // approved 写入已落地（模拟另一标签页写成功）。
        readBinding: async (directories) => {
            reads += 1;
            if (reads === 1) return { ...oldRecord };
            store.records.set(directories.root, newRecord);
            return { ...newRecord };
        },
    });
    const result = await call(h.core.handlers.keys, {
        method: 'GET',
        url: '/api/plugins/apercus-gateway/keys',
        headers: { host: 'localhost:8000', 'sec-fetch-site': 'same-origin' },
        user: { directories: { root: '/u/alice' } },
    });
    assert.equal(result.statusCode, 409);
    assert.equal(result.json().error.code, 'not_connected');
    // 旧凭据的 401 不得清掉更晚写入的新信封。
    assert.equal(h.clearCalls.length, 0);
    assert.deepEqual(store.records.get('/u/alice'), newRecord);
    const status = await call(h.core.handlers.status, plainStatusReq());
    assert.equal(status.json().state, 'authorized');
    assert.equal(status.json().username, 'bob');
});

// ===== H10：失效标记优先级 =====

test('H10: a cancelled reconnect cannot downgrade login_invalidated (G4 stays enforced)', async () => {
    let upstreamCalls = 0;
    const gateway = makeGateway({ poll: () => ({ status: 'invalid' }) });
    const h = buildCore({
        gateway,
        clearResult: { envelope: false, custom: false },
        clearKeepsRecord: true,
        fetchImpl: async () => {
            upstreamCalls += 1;
            return { status: 200, body: streamOf(completionBody('PLAN')) };
        },
    });
    h.store.records.set('/u/alice', {
        loginCredential: LOGIN_CREDENTIAL,
        key: BINDING_KEY,
        username: 'alice',
    });
    // 本地清理失败 → login_invalidated（残信封保留）。
    assert.equal((await call(h.core.handlers.logout, logoutReq())).statusCode, 502);
    // 重连发起后在轮询阶段取消（poll invalid）：只产生短时连接失效标记，
    // 不得把 login_invalidated 降级成可被 TTL 清掉/忽略的短标记。
    await call(h.core.handlers.connect, connectReq());
    h.tick(5500);
    const connectStatus = await call(h.core.handlers.connectStatus, statusReq());
    assert.deepEqual(connectStatus.json(), { status: 'invalid' });
    const status = await call(h.core.handlers.status, plainStatusReq());
    assert.equal(status.json().state, 'invalid');
    assert.equal(status.json().reason, 'login_invalidated');
    const plan = await call(h.core.handlers.plan, {
        method: 'POST',
        url: '/api/plugins/apercus-gateway/plan',
        headers: { host: 'localhost:8000', origin: 'http://localhost:8000' },
        user: { directories: { root: '/u/alice' } },
        body: { model: 'model-a', prompt: 'prompt' },
    });
    assert.equal(plan.statusCode, 409);
    assert.equal(plan.json().error.message, '登录已失效或已撤销，请重新连接 Apercus 网关。');
    assert.equal(upstreamCalls, 0);
});

// ===== H11：logout 会话摘除与 epoch =====

test('H11: logout during another tab\'s approved poll discards the approval (no write)', async () => {
    let resolvePoll = null;
    const gateway = makeGateway({ poll: () => new Promise((resolve) => { resolvePoll = resolve; }) });
    const h = buildCore({ gateway });
    await call(h.core.handlers.connect, connectReq());
    h.tick(5500);
    const pollPromise = call(h.core.handlers.connectStatus, statusReq());
    await flush();
    assert.equal(typeof resolvePoll, 'function', 'poll is in flight');

    const logoutPromise = call(h.core.handlers.logout, logoutReq());
    await flush();
    resolvePoll({
        status: 'approved',
        connect: {
            loginCredential: LOGIN_CREDENTIAL,
            key: BINDING_KEY,
            username: 'alice',
        },
    });
    const polled = await pollPromise;
    const logout = await logoutPromise;
    assert.equal(logout.statusCode, 200);
    assert.deepEqual(polled.json(), { status: 'invalid' });
    assert.equal(h.writeCalls.length, 0, 'stale approved result is never written');
    const status = await call(h.core.handlers.status, plainStatusReq());
    assert.equal(status.json().state, 'not_connected');
    assert.equal(Object.hasOwn(status.json(), 'username'), false);
});

// ===== H12：logout 401 语义 =====

test('H12: a gateway 401 on logout counts as already revoked (no "remote still valid" warning)', async () => {
    const gateway = makeGateway();
    gateway.client.logout = async () => ({ ok: true, alreadyRevoked: true });
    const h = buildCore({ gateway });
    h.store.records.set('/u/alice', {
        loginCredential: LOGIN_CREDENTIAL,
        key: BINDING_KEY,
        username: 'alice',
    });
    const result = await call(h.core.handlers.logout, logoutReq());
    assert.equal(result.statusCode, 200);
    assert.deepEqual(result.json(), {
        status: 'logged_out',
        remote_revoked: true,
        local_cleared: true,
        custom_cleared: true,
    });
    assert.equal(h.store.records.has('/u/alice'), false);
});
