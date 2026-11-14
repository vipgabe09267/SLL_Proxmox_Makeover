/* Isolated loopback fixture using the installed native ExtJS/PVE runtime. No PVE API calls. */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const root = path.resolve(__dirname, '..');
const types = { '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.woff': 'font/woff', '.ttf': 'font/ttf', '.gif': 'image/gif' };
function pageHtml(mode, readonly, user = 'preview@pam') {
    const styles = [
        ['/pve2/ext6/theme-crisp/resources/theme-crisp-all.css', ''],
        ['/pve2/ext6/crisp/resources/charts-all.css', ''], ['/pve2/fa/css/font-awesome.css', ''],
        ['/pve2/font-logos/css/font-logos.css', ''], ['/pve2/css/ext6-pve.css', ''], ['/pwt/css/ext6-pmx.css', ''],
        ['/pwt/themes/theme-proxmox-dark.css', 'sls-base-theme'], ['/beta/southland.css', 'sls-branding-css'], ['/beta/makeover.css', 'sll-makeover-css'],
    ];
    const scripts = ['/pve2/ext6/ext-all.js', '/pve2/ext6/charts.js', '/pve2/js/u2f-api.js', '/qrcode.min.js',
        '/proxmoxlib.js', '/pve2/js/pvemanagerlib.js'];
    return '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">' +
        '<title>Offline Proxmox fixture</title><link rel="icon" href="/pve2/images/SLS_Proxmox_Favicon.png">' +
        styles.map(([url, id]) => '<link rel="stylesheet" href="' + url + '"' + (id ? ' id="' + id + '"' : '') + '>').join('') +
        '<script>function gettext(x){return x}function ngettext(a,b,n){return n===1?a:b}function pgettext(c,x){return x}function npgettext(c,a,b,n){return n===1?a:b}' +
        'window.Proxmox={Setup:{auth_cookie_name:"PVEAuthCookie"},defaultLang:"en",NodeName:"preview",NodeArch:"amd64",UserName:' +
        JSON.stringify(mode === 'login' ? '' : user) + ',CSRFPreventionToken:"offline-fixture",ConsentText:""};</script>' +
        scripts.map(url => '<script src="' + url + '"></script>').join('') +
        '<script src="/beta/config.js"></script>' +
        '<script>Ext.History.fieldid="x-history-field";Ext.onReady(function(){' +
        'Ext.create("Ext.state.LocalStorageProvider").set("GuiCap",{dc:{"Sys.Audit":1,"Sys.Modify":' + (readonly ? 0 : 1) + '},nodes:{},vms:{},storage:{},access:{},sdn:{},mapping:{}});' +
        'Ext.create("PVE.StdWorkspace");});</script>' +
        '<script src="/beta/southland.js?v=beta"></script><script src="/beta/native-security.js?v=beta"></script><script src="/beta/login-passkeys.js?v=beta"></script><script src="/beta/makeover.js?v=beta"></script>' +
        (mode === 'login' ? '' : '<script>Ext.onReady(function(){Ext.create("SLL.window.Makeover").show()});</script>') +
        '</head><body><form id="history-form" class="x-hidden"><input type="hidden" id="x-history-field"></form></body></html>';
}
async function startFixture(options = {}) {
    fs.mkdirSync(path.join(root, 'evidence'), { recursive: true });
    const fixtureUser = options.user || 'preview@pam';
    let config = JSON.parse(fs.readFileSync(path.join(root, 'config.json'), 'utf8'));
    if (options.config) config = { ...config, ...JSON.parse(JSON.stringify(options.config)) };
    const legacy = options.legacy === true;
    if (legacy) { config.schema_version = 1; delete config.update_safe; delete config.fonts; }
    let revision = 'offline-revision-1';
    const writes = [];
    const requests = [];
    const apiBodies = [], uploads = new Map(), tfaWrites = [], tfaEdits = [], tfaRemovals = [], modeRequests = [], modeWrites = [];
    const keys = JSON.parse(JSON.stringify(options.nativeKeys || [{ id: 'fixture-key-1', type: 'webauthn', description: 'Example security key', created: 1794172800, enable: true }]));
    const modeRevision = () => crypto.createHash('sha256').update(JSON.stringify({ keys, locked: Boolean(options.modeLocked) })).digest('hex');
    const modeState = async () => {
        const native = keys.filter(key => ['webauthn', 'u2f'].includes(key.type));
        const enabled = native.filter(key => key.enable !== false && key.enable !== 0 && key.enable !== '0').length;
        const primaryCount = options.getPrimaryCount ? await options.getPrimaryCount() : options.primaryCount || 0;
        return { mode: enabled ? 'two_factor' : 'alternative', revision: modeRevision(), can_change: !options.modeLocked,
            reason: options.modeLocked ? 'Your realm requires native two-factor authentication. This mode cannot be changed here.' : null,
            native_keys: native.map(key => ({ ...key, enable: key.enable !== false && key.enable !== 0 && key.enable !== '0' })),
            native_key_count: native.length, enabled_native_key_count: enabled,
            other_factors_enabled: keys.some(key => !['webauthn', 'u2f'].includes(key.type) && key.enable !== false),
            primary_key_count: primaryCount, primary_ready: primaryCount > 0,
        };
    };
    let uploadCounter = 0;
    const server = http.createServer(async (req, res) => {
        const url = new URL(req.url, 'http://127.0.0.1');
        requests.push({ method: req.method, path: url.pathname });
        const send = (data, status = 200) => {
            res.writeHead(status, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: status < 400, data }));
        };
        if (url.pathname === '/' || url.pathname === '/login' || url.pathname === '/SLL-Customs') {
            const mode = url.pathname === '/login' ? 'login' : 'authenticated';
            const readonly = url.searchParams.get('readonly') === '1';
            res.writeHead(200, { 'Content-Type': 'text/html', 'Set-Cookie': [
                'PVEAuthCookie=' + (mode === 'login' ? '' : encodeURIComponent('PVE:' + fixtureUser + ':offline-fixture')) + '; Path=/; SameSite=Lax',
                'fixture-role=' + (readonly ? 'readonly' : 'admin') + '; Path=/; SameSite=Lax',
            ] });
            res.end(pageHtml(mode, readonly, fixtureUser)); return;
        }
        if (url.pathname === '/beta/config.js') {
            res.writeHead(200, { 'Content-Type': 'text/javascript' });
            res.end('window.SLLMakeoverConfig=' + JSON.stringify(config).replace(/</g, '\\u003c') + ';'); return;
        }
        if (url.pathname.startsWith('/api2/')) {
            const endpoint = url.pathname.replace(/^\/api2\/(json|extjs)/, '');
            let body;
            if (req.method === 'POST' || req.method === 'PUT') {
                const chunks = []; for await (const chunk of req) chunks.push(chunk);
                body = Buffer.concat(chunks);
                apiBodies.push({ path: endpoint, bytes: body.length, contentType: req.headers['content-type'] || '' });
                // Match the vendor's ordinary-request body limit; do not raise it for tests.
                if (body.length > 512 * 1024) return send(null, 413);
            }
            if (endpoint.startsWith('/sll-passkeys/')) {
                if (endpoint === '/sll-passkeys/mode' && options.perUserMode) {
                    if (req.method === 'GET') return send(await modeState());
                    if (req.method === 'POST') {
                        const payload = JSON.parse(body);
                        modeRequests.push({ mode: payload.mode, key_id: payload.key_id || null, hasPassword: Boolean(payload.password),
                            expected_revision: payload.expected_revision, csrf: req.headers.csrfpreventiontoken,
                            passwordInQuery: url.searchParams.has('password'), jsonBody: (req.headers['content-type'] || '').includes('application/json') });
                        if (options.modeLocked || payload.password !== 'fixture-password' || req.headers.csrfpreventiontoken !== 'offline-fixture' ||
                            url.searchParams.has('password') || Object.keys(payload).some(key => !['mode', 'key_id', 'password', 'expected_revision'].includes(key))) return send(null, 401);
                        if (payload.expected_revision !== modeRevision()) return send(null, 409);
                        const native = keys.filter(key => ['webauthn', 'u2f'].includes(key.type));
                        if (payload.mode === 'two_factor') {
                            const chosen = native.find(key => key.id === payload.key_id); if (!chosen) return send(null, 401); chosen.enable = true;
                        } else if (payload.mode === 'alternative' && !payload.key_id) native.forEach(key => { key.enable = false; });
                        else return send(null, 401);
                        modeWrites.push({ mode: payload.mode, key_id: payload.key_id || null }); return send(await modeState());
                    }
                }
                if (endpoint === '/sll-passkeys/remove-second-factor' && req.method === 'POST') {
                    if (!options.secondaryRemoval) return send(null, 404);
                    const payload = JSON.parse(body);
                    if (url.searchParams.has('password') || req.headers.csrfpreventiontoken !== 'offline-fixture' ||
                        (fixtureUser !== 'root@pam' && payload.password !== 'fixture-password')) return send(null, 403);
                    const index = keys.findIndex(key => key.id === payload.id && ['webauthn', 'u2f'].includes(key.type));
                    if (index < 0 || Object.keys(payload).some(key => !['id', 'password'].includes(key))) return send(null, 400);
                    tfaRemovals.push({ id: payload.id, hasPassword: Boolean(payload.password), csrf: req.headers.csrfpreventiontoken,
                        jsonBody: (req.headers['content-type'] || '').includes('application/json'), passwordInQuery: url.searchParams.has('password') });
                    keys.splice(index, 1); return send({ removed: true });
                }
                if (endpoint === '/sll-passkeys/status' && (options.secondaryRemoval || options.perUserMode) && !options.passkeys) return send({
                    secondary_removal: options.secondaryRemoval === true, per_user_mode: options.perUserMode === true, primary_passkeys: false, supported: false });
                if (!options.passkeys) return send({ supported: false, reason: 'The login passkey backend is not active.' });
                try {
                    const result = await options.passkeys({ endpoint: endpoint.slice('/sll-passkeys'.length), method: req.method,
                        headers: req.headers, payload: body ? JSON.parse(body) : {} });
                    if (endpoint === '/sll-passkeys/status' && options.perUserMode && result.data) result.data.per_user_mode = true;
                    return send(result.data, result.status || 200);
                } catch (_failure) { return send(null, 400); }
            }
            if (endpoint === '/sll-customs/config') return send({ config, revision, font_selection: !legacy && options.fontSelection !== false, version: legacy ? '0.1.0' : '0.1-beta', can_modify: !String(req.headers.cookie).includes('fixture-role=readonly'), assets: {
                logo: { width: 2048, height: 768, bytes: 1240433 }, favicon: { width: 1254, height: 1254, bytes: 791576 },
            } });
            if (endpoint === '/sll-customs/upload') {
                if (legacy) return send(null, 404);
                const payload = JSON.parse(body);
                if (payload.expected_revision !== revision) return send(null, 409);
                if (!['logo', 'favicon'].includes(payload.kind)) return send(null, 400);
                const chunk = Buffer.from(payload.content_base64, 'base64');
                if (!chunk.length || chunk.length > 192 * 1024 || payload.total_size > 3 * 1024 * 1024) return send(null, 400);
                let id = payload.upload_id;
                if (!id) {
                    if (payload.index !== 0) return send(null, 400);
                    id = (++uploadCounter).toString(16).padStart(32, '0');
                    uploads.set(id, { kind: payload.kind, total_size: payload.total_size, received: 0, next_index: 0, revision });
                }
                const staged = uploads.get(id);
                if (!staged || staged.kind !== payload.kind || staged.total_size !== payload.total_size ||
                    staged.revision !== revision || staged.next_index !== payload.index || staged.received + chunk.length > staged.total_size) return send(null, 400);
                staged.received += chunk.length; staged.next_index++;
                return send({ upload_id: id, complete: staged.received === staged.total_size,
                    received: staged.received, total_size: staged.total_size, next_index: staged.next_index });
            }
            if (endpoint === '/sll-customs/apply') {
                const payload = JSON.parse(body);
                if (legacy) {
                    if (Object.keys(payload).some(key => !['config_json', 'logo_base64', 'favicon_base64'].includes(key))) return send(null, 400);
                    const candidate = JSON.parse(payload.config_json);
                    if (candidate.schema_version !== 1 || Object.hasOwn(candidate, 'update_safe') || Object.hasOwn(candidate, 'fonts')) return send(null, 400);
                } else if (payload.expected_revision !== revision) return send(null, 409);
                const assets = {};
                for (const kind of ['logo', 'favicon']) {
                    if (!payload[kind + '_upload_id']) continue;
                    const staged = uploads.get(payload[kind + '_upload_id']);
                    if (!staged || staged.kind !== kind || staged.received !== staged.total_size || staged.revision !== revision) return send(null, 400);
                    assets[kind] = staged.received;
                }
                writes.push({ payload, assets, csrf: req.headers.csrfpreventiontoken });
                for (const kind of Object.keys(assets)) uploads.delete(payload[kind + '_upload_id']);
                config = JSON.parse(payload.config_json); revision = 'offline-revision-' + (writes.length + 1);
                return send({ status: 'ok', revision });
            }
            if (endpoint === '/access/domains') return send([{ realm: 'pam', type: 'pam', comment: 'Linux PAM standard authentication', default: 1 }]);
            if (endpoint === '/access/ticket') {
                if (options.nativeTicket) return send(await options.nativeTicket({ body, headers: req.headers }));
                return send({ username: fixtureUser, ticket: 'PVE:' + fixtureUser + ':offline-fixture', CSRFPreventionToken: 'offline-fixture', cap: { dc: { 'Sys.Audit': 1, 'Sys.Modify': 1 }, nodes: {}, vms: {}, storage: {}, access: {}, sdn: {}, mapping: {} } });
            }
            if (endpoint.endsWith('/subscription')) return send({ status: 'active' });
            const ownKey = endpoint.match(/^\/access\/tfa\/([^/]+)\/([^/]+)$/);
            if (ownKey && decodeURIComponent(ownKey[1]) === fixtureUser) {
                const key = keys.find(entry => entry.id === decodeURIComponent(ownKey[2]));
                if (!key) return send(null, 404);
                if (req.method === 'GET') return send({ description: key.description, enable: key.enable ? 1 : 0 });
                if (req.method === 'PUT') {
                    const values = (req.headers['content-type'] || '').includes('application/json') ? JSON.parse(body) : Object.fromEntries(new URLSearchParams(body.toString()));
                    tfaEdits.push({ id: key.id, enable: String(values.enable), hasPassword: Boolean(values.password), csrf: req.headers.csrfpreventiontoken });
                    if (fixtureUser !== 'root@pam' && values.password !== 'fixture-password') return send(null, 403);
                    key.enable = String(values.enable) === '1'; key.description = String(values.description || key.description);
                    return send(null);
                }
            }
            const ownList = endpoint.match(/^\/access\/tfa\/([^/]+)$/);
            if (ownList && decodeURIComponent(ownList[1]) === fixtureUser) {
                if (req.method === 'GET') return send(keys);
                if (req.method === 'POST') {
                    const values = (req.headers['content-type'] || '').includes('application/json') ? JSON.parse(body) : Object.fromEntries(new URLSearchParams(body.toString()));
                    if (values.type !== 'webauthn') return send(null, 400);
                    const complete = Boolean(values.challenge && values.value);
                    tfaWrites.push({ phase: complete ? 'finish' : 'begin', csrf: req.headers.csrfpreventiontoken, hasPassword: Boolean(values.password), type: values.type });
                    if (complete) {
                        keys.push({ id: 'fixture-key-new', description: 'Test device', type: 'webauthn', created: 1794172800, enable: true });
                        return send({ id: 'fixture-key-new' });
                    }
                    return send({ challenge: JSON.stringify({ publicKey: {
                        challenge: 'Zml4dHVyZS1jaGFsbGVuZ2U', user: { id: 'Zml4dHVyZS11c2Vy', name: fixtureUser, displayName: 'Preview' },
                        rp: { name: 'Makeover test', id: 'localhost' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }], timeout: 60000,
                    } }) });
                }
            }
            if (endpoint === '/cluster/options') return send({ 'allowed-tags': [], webauthn: { id: 'localhost', origin: 'http://' + req.headers.host, rp: 'Preview' } });
            if (endpoint === '/version') return send({ version: '9.2.25', release: 'offline', repoid: 'fixture' });
            if (endpoint === '/access/permissions') return send({ '/': { 'Sys.Audit': 1, 'Sys.Modify': 1 } });
            if (endpoint.endsWith('/status')) return send({});
            if (endpoint === '/cluster/ui-options') return send({});
            return send([]);
        }
        const mappings = [
            ['/beta/', root], ['/pve2/ext6/', '/usr/share/javascript/extjs'],
            ['/pve2/fa/', '/usr/share/fonts-font-awesome'], ['/pve2/font-logos/', '/usr/share/fonts-font-logos'],
            ['/pwt/', '/usr/share/javascript/proxmox-widget-toolkit'], ['/pve2/', '/usr/share/pve-manager'],
        ];
        const exact = { '/proxmoxlib.js': '/usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js', '/qrcode.min.js': '/usr/share/javascript/qrcodejs/qrcode.min.js',
            '/pve2/css/sls-dm-sans.ttf': path.join(root, 'assets/fonts/dm-sans.ttf'),
            '/pve2/css/sls-oxanium.ttf': path.join(root, 'assets/fonts/oxanium.ttf'),
            '/pve2/images/SLS_Proxmox.png': path.join(root, 'assets/SLS_Proxmox.png'), '/pve2/images/SLS_Proxmox_Favicon.png': path.join(root, 'assets/SLS_Proxmox_Favicon.png') };
        let file = exact[url.pathname];
        if (!file) for (const [prefix, directory] of mappings) if (url.pathname.startsWith(prefix)) {
            const candidate = path.resolve(directory, decodeURIComponent(url.pathname.slice(prefix.length)));
            if (candidate.startsWith(directory + '/')) file = candidate;
            break;
        }
        if (!file || !fs.existsSync(file) || !fs.statSync(file).isFile()) { res.writeHead(404); res.end('Fixture resource missing'); return; }
        res.writeHead(200, { 'Content-Type': types[path.extname(file)] || 'application/octet-stream' });
        fs.createReadStream(file).pipe(res);
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    return { server, url: 'http://127.0.0.1:' + server.address().port, writes, requests, apiBodies, tfaWrites, tfaEdits, tfaRemovals,
        modeRequests, modeWrites, keys, close: () => new Promise(resolve => server.close(resolve)) };
}
async function launchBrowser() {
    const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
    return chromium.launch({ headless: true,
        executablePath: process.env.CHROMIUM_EXECUTABLE || undefined,
        env: { ...process.env },
        args: ['--no-sandbox', '--no-proxy-server'],
    });
}
module.exports = { startFixture, launchBrowser, root };
