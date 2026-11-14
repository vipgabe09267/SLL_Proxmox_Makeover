/* Real Chromium virtual passkeys verified by the production crypto classes in an isolated Store. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const { startFixture, launchBrowser, root } = require('./browser-fixture.cjs');
const origin = 'https://pve.example.test';
const rp = { id: 'pve.example.test', name: 'Example PVE', origin };
const user = 'preview@pam';
const csrf = 'offline-fixture';
function coreFixture() {
    const child = spawn(process.env.PYTHON_EXECUTABLE || '/usr/bin/python3', [path.join(root, 'tests/passkeys-core-fixture.py')], { cwd: root, env: process.env });
    let next = 0, output = '', diagnostic = '', stopped = false;
    const pending = new Map();
    child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
    child.stderr.on('data', text => { diagnostic = (diagnostic + text).slice(-2000); });
    child.stdout.on('data', text => {
        output += text;
        let newline;
        while ((newline = output.indexOf('\n')) >= 0) {
            const line = output.slice(0, newline); output = output.slice(newline + 1);
            const value = JSON.parse(line), waiter = pending.get(value.id); pending.delete(value.id);
            if (value.error) waiter?.reject(new Error(value.error)); else waiter?.resolve(value.data);
        }
    });
    const stop = () => {
        stopped = true;
        for (const waiter of pending.values()) waiter.reject(new Error('Crypto fixture stopped. ' + diagnostic));
        pending.clear();
    };
    child.on('error', stop); child.on('exit', stop);
    return {
        call: request => new Promise((resolve, reject) => {
            if (stopped) return reject(new Error('Crypto fixture is unavailable. ' + diagnostic));
            const id = ++next; pending.set(id, { resolve, reject });
            child.stdin.write(JSON.stringify({ id, request: { client: 'virtual-browser', ...request } }) + '\n');
        }),
        close: async () => { if (!stopped) { child.stdin.end(); await once(child, 'exit'); } },
    };
}
const nativeData = () => ({ username: user, ticket: 'PVE:preview@pam:fixture-passkey-ticket', CSRFPreventionToken: csrf,
    cap: { dc: { 'Sys.Audit': 1, 'Sys.Modify': 1 }, nodes: {}, vms: {}, storage: {}, access: {}, sdn: {}, mapping: {} } });
(async () => {
    const core = coreFixture();
    await core.call({ op: 'status' });
    const calls = [], errors = [], external = [];
    let requireTfa = false, partialTicket = null, lastLoginProof = null, lastLoginNonce = null, backendAvailable = true;
    let nativeTfaCompletions = 0, nativePasswordSignins = 0, nativeTicketCalls = 0;
    const fixture = await startFixture({ legacy: true, secondaryRemoval: true, perUserMode: true,
        nativeKeys: [{ id: 'fixture-key-1', type: 'webauthn', description: 'Retained native key', enable: false, created: 1794172800 }],
        getPrimaryCount: async () => (await core.call({ op: 'list', user })).credentials.length,
        passkeys: async ({ endpoint, method, headers, payload }) => {
            calls.push({ endpoint, method, hasPassword: Boolean(payload.password), keys: Object.keys(payload).sort() });
            if (endpoint === '/status') return { data: { version: '0.1-beta', primary_passkeys: true, secondary_removal: true, supported: backendAvailable,
                reason: backendAvailable ? undefined : 'The backend is not active.', rp } };
            const token = headers.csrfpreventiontoken;
            if (endpoint === '/login-begin') {
                assert.equal(token, 'SLL-Passkey-Login');
                const data = await core.call({ op: 'login_begin' }); lastLoginNonce = data.nonce;
                return { data };
            }
            if (endpoint === '/login-finish') {
                assert.equal(token, lastLoginNonce);
                lastLoginProof = { ...payload, nonce: token };
                const verified = await core.call({ op: 'login_finish', ceremony: payload.ceremony, nonce: token, response: JSON.parse(payload.response) });
                assert.equal(verified.user, user);
                if (!requireTfa) return { data: nativeData() };
                partialTicket = 'PVE:!tfa!' + encodeURIComponent(JSON.stringify({ totp: true })) + ':fixture';
                return { data: { username: user, ticket: partialTicket, CSRFPreventionToken: csrf, NeedTFA: 1 } };
            }
            assert.equal(token, csrf, 'Management requests use native CSRF');
            assert.match(headers.cookie || '', /PVEAuthCookie=/, 'Management requests retain the native session');
            if (endpoint === '/credentials' && method === 'GET') return { data: await core.call({ op: 'list', user }) };
            if (endpoint === '/register-begin') {
                assert.equal(payload.password, 'fixture-password');
                return { data: await core.call({ op: 'register_begin', user, description: payload.description }) };
            }
            if (endpoint === '/register-finish') return { data: await core.call({ op: 'register_finish', user, ceremony: payload.ceremony, response: JSON.parse(payload.response) }) };
            if (endpoint.startsWith('/credentials/') && method === 'DELETE') return { data: await core.call({ op: 'delete', user, id: endpoint.split('/').pop() }) };
            return { status: 404, data: null };
        },
        nativeTicket: async ({ body }) => {
            nativeTicketCalls++;
            const values = Object.fromEntries(new URLSearchParams(body?.toString() || ''));
            if (values['tfa-challenge']) {
                assert.equal(values['tfa-challenge'], partialTicket);
                assert.equal(values.password, 'totp:123456');
                nativeTfaCompletions++;
            } else if (values.password && !values.password.startsWith('PVE:')) nativePasswordSignins++;
            return nativeData();
        },
    });
    const browser = await launchBrowser();
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, hasTouch: true });
    await context.route('**/*', async route => {
        const request = route.request(), url = new URL(request.url());
        if (url.origin !== origin) { external.push(request.url()); return route.abort(); }
        const response = await route.fetch({ url: fixture.url + url.pathname + url.search,
            headers: { ...request.headers(), host: 'pve.example.test' } });
        return route.fulfill({ response });
    });
    const page = await context.newPage();
    page.on('pageerror', error => errors.push(error.stack || String(error)));
    const cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
        protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true,
        isUserVerified: true, automaticPresenceSimulation: true,
    } });
    const editor = () => page.evaluate(() => Boolean(Ext.ComponentQuery.query('sllMakeoverWindow')[0]?.ready));
    async function openSecurity() {
        await page.waitForFunction(() => Ext.ComponentQuery.query('sllMakeoverWindow')[0]?.ready);
        await page.getByRole('tab', { name: 'Security', exact: true }).click();
        await page.getByRole('button', { name: 'Add login passkey', exact: true }).waitFor();
        await page.waitForFunction(() => !Ext.ComponentQuery.query('#login-passkeys-grid')[0].down('button[ariaLabel="Add login passkey"]').disabled);
    }
    try {
        await page.goto(origin, { waitUntil: 'networkidle' });
        await page.waitForFunction(() => Ext.ComponentQuery.query('sllMakeoverWindow')[0]?.ready);
        assert.equal(await editor(), true);
        await page.getByRole('tab', { name: 'Login', exact: true }).click();
        await page.getByRole('button', { name: 'Set up passkey sign-in', exact: true }).click();
        await page.waitForFunction(() => Ext.ComponentQuery.query('window[sllLoginPasskeysWindow=true]').length === 1);
        assert.equal(await page.evaluate(()=>{const manager=Ext.ComponentQuery.query('window[sllLoginPasskeysWindow=true]')[0];return Boolean(manager.down('#login-passkeys')&&manager.down('#second-factor-keys'));}),true);
        await page.evaluate(() => Ext.ComponentQuery.query('window[sllLoginPasskeysWindow=true]')[0].close());
        await openSecurity();
        await page.getByRole('button', { name: 'Add login passkey', exact: true }).click();
        const add = page.getByRole('dialog', { name: 'Add login passkey', exact: true });
        assert.match(await add.innerText(), /Verify your password once to add this passkey/);
        assert.match(await add.innerText(), /Current Proxmox password \(setup only\)/);
        await add.locator('input[name=description]').fill('Virtual primary passkey');
        await add.locator('input[name=password]').fill('fixture-password');
        await add.getByRole('button', { name: 'Create login passkey', exact: true }).click();
        await page.waitForFunction(() => Ext.ComponentQuery.query('#login-passkeys-grid')[0]?.getStore().getCount() === 1);
        assert.equal((await core.call({ op: 'list', user })).credentials.length, 1);
        const credentials = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
        assert.equal(credentials.credentials.length, 1);
        assert.equal(credentials.credentials[0].isResidentCredential, true);
        assert.equal(fixture.tfaWrites.length, 0, 'Primary enrollment never writes native TFA entries');
        assert.equal(fixture.writes.length, 0, 'Primary enrollment never applies appearance');
        await page.screenshot({ path: path.join(root, 'evidence/login-passkeys-manager.png') });
        // Primary login uses the resident credential, with a deliberately stale native CSRF global.
        await page.goto(origin + '/login', { waitUntil: 'networkidle' });
        await page.getByRole('button', { name: 'Sign in with passkey', exact: true }).waitFor();
        await page.waitForFunction(() => !Ext.ComponentQuery.query('#sll-passkey-login')[0]?.disabled);
        assert.equal(await page.locator('input[name=username]').count(), 1);
        assert.equal(await page.locator('input[name=password]').count(), 1);
        assert.equal(await page.locator('input[name=password]').inputValue(), '');
        await page.locator('input[name=username]').fill('');
        await page.locator('input[name=password]').fill('');
        assert.equal(await page.getByRole('button', { name: 'Sign in with password', exact: true }).count(), 1);
        assert.equal(await page.locator('[id="' + await page.evaluate(() => Ext.ComponentQuery.query('#sll-login-choice-or')[0].id) + '"]').innerText(), 'or');
        await page.evaluate(() => { Proxmox.CSRFPreventionToken = 'stale-native-csrf'; });
        await page.screenshot({ path: path.join(root, 'evidence/login-passkey-button.png') });
        const nativeTicketsBeforeEmptyLogin = nativeTicketCalls;
        await page.getByRole('button', { name: 'Sign in with passkey', exact: true }).click();
        await page.waitForFunction(() => Proxmox.UserName === 'preview@pam' && !Proxmox.LoggedOut && !Ext.ComponentQuery.query('#sll-passkey-login').length);
        assert.match(await page.evaluate(() => Ext.util.Cookies.get('PVEAuthCookie')), /fixture-passkey-ticket/);
        assert.equal(await page.evaluate(() => Proxmox.CSRFPreventionToken), csrf);
        assert.equal(nativeTicketCalls, nativeTicketsBeforeEmptyLogin, 'Blank-field passkey login never submits the native password form');
        assert.equal((await core.call({ op: 'list', user })).credentials[0].last_used > 0, true);
        await assert.rejects(core.call({ op: 'login_finish', ceremony: lastLoginProof.ceremony, nonce: lastLoginProof.nonce, response: JSON.parse(lastLoginProof.response) }));
        // Password-manager autofill is irrelevant to this separate sign-in
        // action, including deliberately wrong account/password values.
        await page.goto(origin + '/login', { waitUntil: 'networkidle' });
        await page.waitForFunction(() => !Ext.ComponentQuery.query('#sll-passkey-login')[0]?.disabled);
        await page.locator('input[name=username]').fill('incorrect-autofill');
        await page.locator('input[name=password]').fill('incorrect-autofill-password');
        await page.getByRole('button', { name: 'Sign in with passkey', exact: true }).click();
        await page.waitForFunction(() => Proxmox.UserName === 'preview@pam' && !Proxmox.LoggedOut && !Ext.ComponentQuery.query('#sll-passkey-login').length);
        assert.equal(nativePasswordSignins, 0, 'Passkey choice never submits autofilled native login credentials');
        // A UV-verified primary passkey still goes through the installed native TFA controller.
        requireTfa = true;
        await page.goto(origin + '/login', { waitUntil: 'networkidle' });
        await page.waitForFunction(() => !Ext.ComponentQuery.query('#sll-passkey-login')[0]?.disabled);
        await page.getByRole('button', { name: 'Sign in with passkey', exact: true }).click();
        await page.locator('input[name=totp]').waitFor();
        assert.equal(await page.evaluate(() => Ext.ComponentQuery.query('textfield[name=totp]')[0].fieldLabel), '2FA code (TOTP)');
        assert.equal(await page.evaluate(() => Proxmox.LoggedOut), true);
        assert.equal(nativeTfaCompletions, 0);
        await page.locator('input[name=totp]').fill('123456');
        await page.getByRole('button', { name: 'Confirm Second Factor', exact: true }).click();
        await page.waitForFunction(() => Proxmox.UserName === 'preview@pam' && !Proxmox.LoggedOut && !Ext.ComponentQuery.query('#sll-passkey-login').length);
        assert.equal(nativeTfaCompletions, 1);
        // Canceling only our partial login clears that partial ticket.
        await page.goto(origin + '/login', { waitUntil: 'networkidle' });
        await page.waitForFunction(() => !Ext.ComponentQuery.query('#sll-passkey-login')[0]?.disabled);
        await page.getByRole('button', { name: 'Sign in with passkey', exact: true }).click();
        await page.locator('input[name=totp]').waitFor();
        await page.evaluate(() => {
            // Native showLogin may reset the displayed username before the owned
            // challenge settles. Its exact partial ticket must still be removed.
            Proxmox.UserName = null;
            Ext.ComponentQuery.query('window').find(view => view.$className === 'Proxmox.window.TfaLoginWindow').close();
        });
        await page.waitForFunction(() => !Proxmox.LoggedOut && !Ext.util.Cookies.get('PVEAuthCookie'));
        // A separate native login may finish while an authenticator prompt is open.
        await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: false });
        requireTfa = false;
        await page.goto(origin + '/login', { waitUntil: 'networkidle' });
        await page.waitForFunction(() => !Ext.ComponentQuery.query('#sll-passkey-login')[0]?.disabled);
        await page.getByRole('button', { name: 'Sign in with passkey', exact: true }).click();
        await page.waitForTimeout(100);
        await page.evaluate(data => { Ext.ComponentQuery.query('window').find(view => view.$className === 'PVE.window.LoginWindow').getController().success(data); }, nativeData());
        await page.waitForFunction(() => Proxmox.UserName === 'preview@pam' && !Proxmox.LoggedOut);
        assert.match(await page.evaluate(() => Ext.util.Cookies.get('PVEAuthCookie')), /fixture-passkey-ticket/);
        // Own-account management remains available without entering Makeover/config APIs.
        await page.waitForFunction(() => Boolean(Ext.getCmp('userinfo')?.getMenu().down('#sll-login-passkeys-menu')));
        const configReads = fixture.requests.filter(request => request.path.endsWith('/sll-customs/config')).length;
        await page.evaluate(() => { const caps = Ext.state.Manager.get('GuiCap'); caps.dc['Sys.Audit'] = 0; caps.dc['Sys.Modify'] = 0; Ext.state.Manager.set('GuiCap', caps); });
        await page.locator('#userinfo').click();
        await page.getByRole('menuitem', { name: 'Login passkeys', exact: true }).click();
        await page.waitForFunction(() => Ext.ComponentQuery.query('window[sllLoginPasskeysWindow=true]').length === 1);
        assert.equal(await page.locator('.sll-makeover-window').count(), 0);
        await page.waitForFunction(() => Ext.ComponentQuery.query('#login-passkeys-grid')[0]?.getStore().getCount() === 1);
        const primaryDeletes = () => calls.filter(call => call.method === 'DELETE').length;
        const toggle = page.getByRole('switch', { name: 'Use passkeys for 2FA', exact: true });
        await page.waitForFunction(()=>Ext.ComponentQuery.query('window[sllLoginPasskeysWindow=true]')[0].down('#security-mode-toggle').disabled===false);
        assert.equal(await toggle.isChecked(),false,'The native disabled key leaves login-alternative mode active');
        assert.equal(fixture.modeWrites.length,0,'Opening the unified manager changes no policy');
        // Both retained lists and their per-row removal stay reachable on a phone.
        for(const width of [390,320]) {
            await page.setViewportSize({width,height:844});
            await page.waitForFunction(()=>{const box=Ext.ComponentQuery.query('window[sllLoginPasskeysWindow=true]')[0].el.dom.getBoundingClientRect();return box.left>=0&&box.right<=innerWidth;});
            await page.getByRole('button',{name:'Remove login passkey',exact:true}).scrollIntoViewIfNeeded();
            await page.screenshot({path:path.join(root,'evidence/key-removal-primary-mobile-'+width+'.png')});
        }
        assert.equal(fixture.modeWrites.length,0);
        await page.setViewportSize({width:1440,height:1000});
        await page.getByRole('button', { name: 'Remove login passkey', exact: true }).click();
        await page.getByText('Remove login passkey?', { exact: true }).waitFor();
        assert.match(await page.locator('.x-message-box:visible').innerText(), /Virtual primary passkey/);
        await page.waitForFunction(() => document.activeElement?.textContent?.trim() === 'Cancel');
        await page.keyboard.press('Enter');
        await page.waitForFunction(() => !Ext.ComponentQuery.query('#sll-remove-login-passkey').length);
        assert.equal(primaryDeletes(), 0, 'Canceling a named primary removal sends no DELETE');
        // Revocation is session management and remains available even when
        // this password-authenticated browser cannot enroll/use WebAuthn.
        await page.evaluate(() => {
            window.__fixturePublicKeyDescriptor = Object.getOwnPropertyDescriptor(window, 'PublicKeyCredential');
            Object.defineProperty(window, 'PublicKeyCredential', { configurable: true, writable: true, value: undefined });
        });
        await page.getByRole('button', { name: 'Refresh login passkeys', exact: true }).click();
        await page.waitForFunction(() => {
            const manager = Ext.ComponentQuery.query('window[sllLoginPasskeysWindow=true]')[0];
            return manager.down('#login-passkeys-grid').getStore().getCount() === 1 && manager.down('button[ariaLabel="Add login passkey"]').disabled &&
                !manager.down('button[ariaLabel="Refresh login passkeys"]').disabled;
        });
        assert.equal(await page.getByRole('button', { name: 'Remove login passkey', exact: true }).isEnabled(), true);
        await page.getByRole('button', { name: 'Remove login passkey', exact: true }).click();
        await page.getByRole('button', { name: 'Cancel', exact: true }).click();
        assert.equal(primaryDeletes(), 0, 'Unsupported browser can inspect/cancel removal without enrollment or login');
        await page.evaluate(() => { Object.defineProperty(window, 'PublicKeyCredential', window.__fixturePublicKeyDescriptor); delete window.__fixturePublicKeyDescriptor; });
        await page.getByRole('button', { name: 'Refresh login passkeys', exact: true }).click();
        await page.waitForFunction(() => !Ext.ComponentQuery.query('window[sllLoginPasskeysWindow=true]')[0].down('button[ariaLabel="Add login passkey"]').disabled);
        for (const changed of ['cookie', 'csrf']) {
            await page.getByRole('button', { name: 'Remove login passkey', exact: true }).click();
            await page.evaluate(changed => {
                window.__fixtureRemovalSession = { cookie: Ext.util.Cookies.get(Proxmox.Setup.auth_cookie_name), token: Proxmox.CSRFPreventionToken };
                if (changed === 'cookie') Ext.util.Cookies.set(Proxmox.Setup.auth_cookie_name, 'PVE:preview@pam:replacement-removal');
                else Proxmox.CSRFPreventionToken = 'replacement-removal-csrf';
            }, changed);
            await page.getByRole('button', { name: 'Remove', exact: true }).click();
            assert.equal(primaryDeletes(), 0, 'A replaced native session cannot approve old primary removal');
            await page.evaluate(() => { const saved = window.__fixtureRemovalSession; Ext.util.Cookies.set(Proxmox.Setup.auth_cookie_name, saved.cookie); Proxmox.CSRFPreventionToken = saved.token; delete window.__fixtureRemovalSession; });
        }
        await page.getByRole('button', { name: 'Remove login passkey', exact: true }).click();
        await page.evaluate(() => { Ext.ComponentQuery.query('window[sllLoginPasskeysWindow=true]')[0].close(); });
        assert.equal(await page.evaluate(() => Ext.ComponentQuery.query('#sll-remove-login-passkey').length), 0);
        assert.equal(primaryDeletes(), 0, 'Closing the panel destroys unapproved primary removal');
        await page.evaluate(() => { SLLMakeoverLoginPasskeys.openManager(); });
        await page.waitForFunction(() => Ext.ComponentQuery.query('window[sllLoginPasskeysWindow=true]')[0].down('#login-passkeys-grid').getStore().getCount() === 1);
        await page.getByRole('button', { name: 'Remove login passkey', exact: true }).click();
        await page.getByRole('button', { name: 'Remove', exact: true }).click();
        await page.waitForFunction(() => Ext.ComponentQuery.query('#login-passkeys-grid')[0]?.getStore().getCount() === 0);
        assert.equal((await core.call({ op: 'list', user })).credentials.length, 0);
        assert.equal(primaryDeletes(), 1, 'Exactly the named primary passkey is removed');
        assert.equal(fixture.requests.filter(request => request.path.endsWith('/sll-customs/config')).length, configReads,
            'Own passkey management does not need Makeover configuration/Sys.Audit');
        // The real verifier rejects the removed resident credential even when
        // its virtual authenticator still holds the private key.
        await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: true });
        await page.goto(origin + '/login', { waitUntil: 'networkidle' });
        await page.waitForFunction(() => !Ext.ComponentQuery.query('#sll-passkey-login')[0]?.disabled);
        await page.getByRole('button', { name: 'Sign in with passkey', exact: true }).click();
        await page.getByText('Passkey sign-in is unavailable. Use password sign-in; accounts using two-factor mode require a password first.', { exact: true }).waitFor();
        assert.equal(await page.evaluate(() => Boolean(Proxmox.UserName)), false, 'Removed primary credential cannot establish a new native session');
        backendAvailable = false;
        for (const width of [390, 320]) {
            await page.setViewportSize({ width, height: 844 });
            await page.goto(origin + '/login', { waitUntil: 'networkidle' });
            const passkeyButton = page.getByRole('button', { name: 'Sign in with passkey', exact: true });
            await passkeyButton.waitFor();
            await page.getByText('Passkey sign-in is unavailable. Use your existing login method.', { exact: true }).waitFor();
            assert.equal(await passkeyButton.isDisabled(), true);
            await passkeyButton.scrollIntoViewIfNeeded();
            const bounds = await passkeyButton.boundingBox();
            assert.ok(bounds.height >= 40 && bounds.y >= 0 && bounds.y + bounds.height <= 845, JSON.stringify(bounds));
            assert.equal(await page.locator('input[name=password]').count(), 1);
            assert.equal(await page.locator('input[name=username]').count(), 1);
            assert.equal(await page.getByRole('button', { name: 'Sign in with password', exact: true }).count(), 1);
            await page.screenshot({ path: path.join(root, 'evidence/login-passkey-mobile-' + width + '.png') });
        }
        assert.equal(fixture.writes.length, 0);
        assert.equal(nativePasswordSignins, 0, 'Primary passkeys never perform a native password-ticket sign-in');
        for (const call of calls.filter(call => call.endpoint.startsWith('/login-'))) {
            assert.equal(call.hasPassword, false, 'Passwordless requests contain no password');
            assert.deepEqual(call.keys, call.endpoint === '/login-begin' ? [] : ['ceremony', 'response']);
        }
        assert.deepEqual(errors, []);
        assert.deepEqual(external, []);
        const result = { tests: 'primary-login-passkeys', realCryptoVerifier: true, residentUvCredential: true,
            passwordlessLogin: true, nativeTfaContinuation: true, ownedPartialCancel: true, replayRejected: true,
            parallelNativeLoginPreserved: true, selfServiceUserMenu: true, selfServiceWithoutAudit: true,
            primaryEntriesSeparateFromTfa: true, legacyUnavailableFallback: true, mobileTouchTargets: [390, 320],
            appearanceWrites: fixture.writes.length, nativeTfaCompletions, nativePasswordSignins,
            blankPasswordFieldsSupported: true, incorrectAutofillIgnored: true, setupOnlyPasswordExplained: true, loginSettingsShortcut: true,
            unifiedManagerNoPolicyWrites: true, responsiveUnifiedManager: true, namedPrimaryRemovalCancel: true,
            stalePrimaryRemovalBlocked: true, ownedPrimaryRemovalCleanup: true, removedPasskeyRevoked: true,
            removalWithoutBrowserWebAuthn: true, errors };
        fs.writeFileSync(path.join(root, 'evidence/browser-passkeys.json'), JSON.stringify(result, null, 2) + '\n');
        console.log(JSON.stringify(result, null, 2));
    } catch (failure) {
        await page.screenshot({ path: path.join(root, 'evidence/passkeys-test-failure.png') });
        console.error(JSON.stringify({ errors, text: (await page.locator('body').innerText()).slice(-2000) }));
        throw failure;
    } finally { await browser.close(); await fixture.close(); await core.close(); }
})().catch(error => { console.error(error.stack || error); process.exitCode = 1; });
