/* Actual per-user mode UI against an isolated revision/password-checked API fixture. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { startFixture, launchBrowser, root } = require('./browser-fixture.cjs');
const key = (id, description, enable = false, type = 'webauthn') => ({ id, description, enable, type, created: 1794172800 });
const primaryApi = async ({ endpoint, headers }) => endpoint === '/status' ? { data: {
    version: '0.1-beta', primary_passkeys: true, secondary_removal: true, supported: true,
    rp: { id: 'localhost', name: 'Fixture', origin: 'http://' + headers.host },
} } : endpoint === '/credentials' ? { data: { credentials: [] } } : { status: 404, data: null };
(async () => {
    const fixture = await startFixture({ perUserMode: true, secondaryRemoval: true, passkeys: primaryApi,
        nativeKeys: [key('native-a', 'Native key A'), key('native-b', 'Native key B', false, 'u2f'),
            key('native-inert', '<img src="https://invalid.example/passkey-label" onerror="window.__modeInjected=true">'),
            key('totp-other', 'Retained TOTP', true, 'totp')] });
    const browser = await launchBrowser(), errors = [], external = [];
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, hasTouch: true });
    await context.addInitScript(() => {
        window.__modeAuthenticatorCalls = 0;
        for (const method of ['get', 'create']) Object.defineProperty(navigator.credentials, method, { configurable: true,
            value: async () => { window.__modeAuthenticatorCalls++; throw new Error('Mode changes must not request an authenticator.'); } });
    });
    await context.route('**/*', route => {
        if (!route.request().url().startsWith(fixture.url + '/')) { external.push(route.request().url()); return route.abort(); }
        return route.continue();
    });
    const page = await context.newPage(); page.on('pageerror', error => errors.push(String(error)));
    const toggle = () => page.getByRole('switch', { name: 'Use passkeys for 2FA', exact: true });
    async function ready() {
        await page.waitForFunction(() => {
            const editor = Ext.ComponentQuery.query('sllMakeoverWindow')[0], panel = editor?.down('#security');
            return editor?.ready && panel?.down('#security-mode-toggle')?.disabled === false &&
                panel?.down('button[ariaLabel="Refresh passkey mode"]')?.disabled === false;
        });
    }
    async function refreshMode() { await page.getByRole('button', { name: 'Refresh passkey mode', exact: true }).click(); await ready(); }
    async function openChange(twoFactor) {
        assert.equal(await toggle().isChecked(), !twoFactor);
        await toggle().scrollIntoViewIfNeeded(); await toggle().click();
        const dialog = page.getByRole('dialog', { name: twoFactor ? 'Use passkeys for two-factor authentication?' : 'Use passkeys as a login alternative?', exact: true });
        await dialog.waitFor(); assert.equal(await toggle().isChecked(), !twoFactor, 'A requested change must not move the confirmed thumb'); return dialog;
    }
    async function choose(dialog, label) {
        const combo = dialog.getByRole('combobox', { name: /Two-factor key to enable/ });
        await combo.focus(); await combo.press('ArrowDown');
        assert.equal(await page.locator('.x-boundlist:visible img').count(), 0, 'Native key names remain inert text in the combo picker');
        assert.equal(await page.evaluate(() => Boolean(window.__modeInjected)), false);
        await page.getByRole('option', { name: label, exact: true }).click();
    }
    async function submit(dialog, password = 'fixture-password') {
        await dialog.locator('input[name=password]').fill(password);
        await dialog.getByRole('button', { name: 'Confirm passkey mode change', exact: true }).click();
    }
    try {
        await page.goto(fixture.url, { waitUntil: 'networkidle' });
        await page.getByRole('tab', { name: 'Security', exact: true }).click(); await ready();
        assert.equal(await toggle().isChecked(), false);
        assert.equal(await page.evaluate(() => {
            const panel = Ext.ComponentQuery.query('sllMakeoverWindow')[0].down('#security');
            return panel.down('#login-passkeys').isVisible(true) && panel.down('#second-factor-keys').isVisible(true) && panel.query('tabpanel').length === 0;
        }), true, 'Both key lists are present together without a list selector');
        assert.match(await page.locator('.sll-makeover-window').innerText(), /Add a login passkey below/);
        assert.equal(await page.getByRole('button', { name: 'Enable or disable extra verification', exact: true }).count(), 0, 'Embedded flags are managed by the account mode control');
        await page.screenshot({ path: path.join(root, 'evidence/passkey-mode-alternative.png') });
        await openChange(true);
        await page.waitForFunction(() => document.activeElement?.textContent?.trim() === 'Cancel');
        await page.keyboard.press('Enter'); await ready();
        assert.equal(fixture.modeRequests.length, 0);
        const incorrect = await openChange(true); await choose(incorrect, 'Native key B (u2f)'); await submit(incorrect, 'incorrect-fixture-password');
        await page.waitForFunction(() => !Ext.ComponentQuery.query('#sll-passkey-mode-confirm').length); await ready();
        assert.equal(await toggle().isChecked(), false); assert.equal(fixture.modeWrites.length, 0);
        assert.match(await page.locator('.sll-makeover-window').innerText(), /could not be confirmed/);
        // Hold the successful response: the switch stays off even after the
        // server accepted the write, until its result is confirmed in the UI.
        let release, accepted;
        const held = new Promise(resolve => { release = resolve; }), serverAccepted = new Promise(resolve => { accepted = resolve; });
        const hold = async route => {
            if (route.request().method() !== 'POST') return route.continue();
            const response = await route.fetch(); accepted(); await held; return route.fulfill({ response });
        };
        await context.route('**/api2/extjs/sll-passkeys/mode', hold);
        const on = await openChange(true); await choose(on, 'Native key B (u2f)'); await submit(on); await serverAccepted;
        assert.equal(await toggle().isChecked(), false);
        assert.equal(await on.locator('input[name=password]').inputValue(), '', 'Fresh proof is cleared immediately after dispatch');
        assert.equal(fixture.keys.find(key => key.id === 'native-a').enable, false);
        assert.equal(fixture.keys.find(key => key.id === 'native-b').enable, true);
        // The server already accepted this write. A later session replacement
        // closes the old confirmation and reloads truth; it cannot undo it.
        await page.evaluate(() => { Proxmox.CSRFPreventionToken = 'replacement-after-mode-commit'; });
        release(); await page.waitForFunction(() => !Ext.ComponentQuery.query('#sll-passkey-mode-confirm').length); await ready();
        await page.evaluate(() => { Proxmox.CSRFPreventionToken = 'offline-fixture'; });
        await context.unroute('**/api2/extjs/sll-passkeys/mode', hold);
        assert.equal(await toggle().isChecked(), true);
        assert.match(await page.locator('.sll-makeover-window').innerText(), /cannot sign you in by themselves/i);
        await page.screenshot({ path: path.join(root, 'evidence/passkey-mode-two-factor.png') });
        const offCancel = await openChange(false); await offCancel.getByRole('button', { name: 'Cancel', exact: true }).click(); await ready();
        assert.equal(await toggle().isChecked(), true); assert.equal(fixture.modeWrites.length, 1);
        fixture.keys.find(key => key.id === 'native-a').enable = true; await refreshMode();
        const off = await openChange(false); await submit(off);
        await page.waitForFunction(() => !Ext.ComponentQuery.query('#sll-passkey-mode-confirm').length); await ready();
        assert.equal(await toggle().isChecked(), false);
        assert.equal(fixture.keys.filter(key => ['webauthn', 'u2f'].includes(key.type)).every(key => key.enable === false), true);
        assert.equal(fixture.keys.find(key => key.id === 'totp-other').enable, true, 'Other native factors remain untouched');
        assert.equal(fixture.keys.length, 4, 'Changing roles retains all registrations');
        // An external native flag change invalidates the pending revision.
        const staleRevision = await openChange(true); await choose(staleRevision, 'Native key A (webauthn)');
        fixture.keys.find(key => key.id === 'native-b').enable = true; await submit(staleRevision);
        await page.waitForFunction(() => !Ext.ComponentQuery.query('#sll-passkey-mode-confirm').length); await ready();
        assert.equal(fixture.modeWrites.length, 2); assert.equal(await toggle().isChecked(), true);
        assert.match(await page.locator('.sll-makeover-window').innerText(), /keys changed/);
        for (const changed of ['cookie', 'csrf']) {
            const dialog = await openChange(false); await dialog.locator('input[name=password]').fill('fixture-password');
            const requestCount = fixture.modeRequests.length;
            await page.evaluate(changed => {
                window.__modeOldSession = { cookie: Ext.util.Cookies.get(Proxmox.Setup.auth_cookie_name), token: Proxmox.CSRFPreventionToken };
                if (changed === 'cookie') Ext.util.Cookies.set(Proxmox.Setup.auth_cookie_name, 'PVE:preview@pam:replacement-mode');
                else Proxmox.CSRFPreventionToken = 'replacement-mode-csrf';
            }, changed);
            await dialog.getByRole('button', { name: 'Confirm passkey mode change', exact: true }).click();
            await page.waitForFunction(() => !Ext.ComponentQuery.query('#sll-passkey-mode-confirm').length);
            assert.equal(fixture.modeRequests.length, requestCount, 'A replaced session cannot dispatch an old mode confirmation');
            await page.evaluate(() => { const old = window.__modeOldSession; Ext.util.Cookies.set(Proxmox.Setup.auth_cookie_name, old.cookie); Proxmox.CSRFPreventionToken = old.token; delete window.__modeOldSession; }); await ready();
        }
        await openChange(false);
        const requestsBeforeHide = fixture.modeRequests.length;
        await page.evaluate(() => { Ext.ComponentQuery.query('sllMakeoverWindow')[0].tabs.setActiveTab(0); });
        assert.equal(await page.evaluate(() => Ext.ComponentQuery.query('#sll-passkey-mode-confirm').length), 0);
        assert.equal(fixture.modeRequests.length, requestsBeforeHide);
        await page.getByRole('tab', { name: 'Security', exact: true }).click(); await ready();
        // A missing native registration guides enrollment; it cannot fake ON.
        fixture.keys.splice(0, 3); await refreshMode(); await toggle().click();
        const guide = page.getByRole('dialog', { name: 'Add a two-factor key first', exact: true }); await guide.waitFor();
        assert.equal(await toggle().isChecked(), false); assert.match(await guide.innerText(), /No mode change has been made/);
        await guide.getByRole('button', { name: 'Cancel', exact: true }).click(); await ready();
        assert.equal(fixture.modeWrites.length, 2);
        fixture.keys.unshift(key('native-a', 'Native key A')); await refreshMode();
        for (const width of [390, 320]) {
            await page.setViewportSize({ width, height: 844 });
            await page.waitForFunction(() => { const box = Ext.ComponentQuery.query('sllMakeoverWindow')[0].el.dom.getBoundingClientRect(); return box.left >= 0 && box.right <= innerWidth; });
            await toggle().scrollIntoViewIfNeeded();
            const target = await toggle().boundingBox(); assert.ok(target.height >= 40 && target.width >= 40);
            await page.locator('.pm-security-view-switch label:visible').tap();
            const dialog = page.getByRole('dialog', { name: 'Use passkeys for two-factor authentication?', exact: true }); await dialog.waitFor();
            assert.equal(await toggle().isChecked(), false);
            const bounds = await dialog.boundingBox(); assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= width);
            await page.keyboard.press('Enter'); await ready();
            await toggle().focus(); await page.keyboard.press('Space');
            await page.getByRole('dialog', { name: 'Use passkeys for two-factor authentication?', exact: true }).waitFor();
            await page.getByRole('button', { name: 'Cancel', exact: true }).click(); await ready();
            assert.equal(fixture.modeWrites.length, 2);
            await page.getByRole('button', { name: 'Remove two-factor key', exact: true }).first().scrollIntoViewIfNeeded();
            await page.screenshot({ path: path.join(root, 'evidence/passkey-mode-mobile-' + width + '.png') });
        }
        assert.equal(await page.evaluate(() => window.__modeAuthenticatorCalls), 0);
        assert.equal(fixture.modeRequests.every(request => request.jsonBody && !request.passwordInQuery && request.hasPassword && /^[0-9a-f]{64}$/.test(request.expected_revision)), true);
        assert.equal(fixture.writes.length + fixture.tfaWrites.length + fixture.tfaEdits.length + fixture.tfaRemovals.length, 0);
        await page.setViewportSize({ width: 1440, height: 1000 });
        const clearedCaps = await openChange(true); await clearedCaps.locator('input[name=password]').fill('fixture-password');
        const requestsBeforeCapsClear = fixture.modeRequests.length;
        await page.evaluate(() => {
            const dialog = Ext.ComponentQuery.query('#sll-passkey-mode-confirm')[0];
            dialog.on('beforeclose', () => { window.__modePasswordClearedOnCapsClear = dialog.down('[name=password]').getValue() === ''; });
            window.__modeOldCaps = Ext.state.Manager.get('GuiCap'); Ext.state.Manager.clear('GuiCap');
        });
        await page.waitForFunction(() => !Ext.ComponentQuery.query('#sll-passkey-mode-confirm').length);
        assert.equal(await page.evaluate(() => window.__modePasswordClearedOnCapsClear), true, 'Clearing capabilities closes proof before native username cleanup');
        assert.equal(fixture.modeRequests.length, requestsBeforeCapsClear);
        await page.evaluate(() => { Ext.state.Manager.set('GuiCap', window.__modeOldCaps); delete window.__modeOldCaps; Ext.ComponentQuery.query('sllMakeoverWindow')[0].tabs.setActiveTab(0); });
        await page.getByRole('tab', { name: 'Security', exact: true }).click(); await ready();
        const accountChange = await openChange(true); await accountChange.locator('input[name=password]').fill('fixture-password');
        const requestsBeforeAccountChange = fixture.modeRequests.length;
        await page.evaluate(() => {
            const dialog = Ext.ComponentQuery.query('#sll-passkey-mode-confirm')[0];
            dialog.on('beforeclose', () => { window.__modePasswordClearedOnAccountChange = dialog.down('[name=password]').getValue() === ''; });
            Ext.ComponentQuery.query('pveStdWorkspace')[0].updateLoginData({ username: 'other@pam', ticket: 'PVE:other@pam:fixture-mode-account',
                CSRFPreventionToken: 'fixture-other-mode-csrf', cap: { dc: { 'Sys.Audit': 1, 'Sys.Modify': 1 }, nodes: {}, vms: {}, storage: {}, access: {}, sdn: {}, mapping: {} } });
        });
        await page.waitForFunction(() => !Ext.ComponentQuery.query('#sll-passkey-mode-confirm').length);
        assert.equal(await page.evaluate(() => window.__modePasswordClearedOnAccountChange), true);
        assert.equal(fixture.modeRequests.length, requestsBeforeAccountChange);
        assert.equal(await page.evaluate(() => {
            const panel = Ext.ComponentQuery.query('sllMakeoverWindow')[0].down('#security');
            return panel.down('#login-passkeys-grid').getStore().getCount() + panel.down('#security-keys-grid').getStore().getCount();
        }), 0, 'Changing accounts clears both previous-account key lists');
        // Root must provide fresh password proof for mode changes too.
        const rootFixture = await startFixture({ user: 'root@pam', perUserMode: true, passkeys: primaryApi, nativeKeys: [key('root-key', 'Root native key')] });
        const rootPage = await context.newPage(); rootPage.on('pageerror', error => errors.push(String(error)));
        await rootPage.route('**/*', route => route.request().url().startsWith(rootFixture.url + '/') ? route.continue() : route.abort());
        try {
            await rootPage.goto(rootFixture.url, { waitUntil: 'networkidle' }); await rootPage.getByRole('tab', { name: 'Security', exact: true }).click();
            await rootPage.waitForFunction(() => Ext.ComponentQuery.query('#security-mode-toggle')[0]?.disabled === false);
            await rootPage.getByRole('switch', { name: 'Use passkeys for 2FA', exact: true }).click();
            const dialog = rootPage.getByRole('dialog', { name: 'Use passkeys for two-factor authentication?', exact: true });
            await dialog.locator('input[name=password]').waitFor();
            await dialog.getByRole('button', { name: 'Confirm passkey mode change', exact: true }).click();
            assert.equal(rootFixture.modeRequests.length, 0, 'Root has no fresh-proof exemption for the policy control');
            await dialog.locator('input[name=password]').fill('fixture-password');
            await dialog.getByRole('button', { name: 'Confirm passkey mode change', exact: true }).click();
            await rootPage.waitForFunction(() => Ext.ComponentQuery.query('#security-mode-toggle')[0].getValue() === true);
            assert.equal(rootFixture.modeWrites.length, 1); assert.equal(rootFixture.modeRequests[0].hasPassword, true);
            await rootPage.screenshot({ path: path.join(root, 'evidence/passkey-mode-two-factor.png') });
        } finally { await rootPage.close(); await rootFixture.close(); }
        const lockedFixture = await startFixture({ perUserMode: true, modeLocked: true, nativeKeys: [key('locked-key', 'Required key', true)] });
        const lockedPage = await context.newPage(); lockedPage.on('pageerror', error => errors.push(String(error)));
        await lockedPage.route('**/*', route => route.request().url().startsWith(lockedFixture.url + '/') ? route.continue() : route.abort());
        try {
            await lockedPage.goto(lockedFixture.url, { waitUntil: 'networkidle' }); await lockedPage.getByRole('tab', { name: 'Security', exact: true }).click();
            await lockedPage.getByText(/Your realm requires native two-factor authentication/).waitFor();
            assert.equal(await lockedPage.getByRole('switch', { name: 'Use passkeys for 2FA', exact: true }).isDisabled(), true);
            assert.equal(await lockedPage.getByRole('switch', { name: 'Use passkeys for 2FA', exact: true }).isChecked(), true);
            assert.equal(lockedFixture.modeWrites.length, 0);
        } finally { await lockedPage.close(); await lockedFixture.close(); }
        assert.deepEqual(errors, []); assert.deepEqual(external, []);
        const report = { tests: 'per-user-passkey-mode', unifiedLists: true, confirmedStateOnly: true, freshPasswordIncludingRoot: true,
            enablesOnlySelectedNativeKey: true, alternativeDisablesAllNativeKeyFlags: true, otherFactorsAndRegistrationsRetained: true,
            revisionConflictReloads: true, staleSessionBlocked: true, staleCommittedResponseClosesAndReloads: true,
            capabilityClearClosesProof: true, accountChangeClearsProofAndLists: true, hideCancels: true, missingKeyGuidesEnrollment: true,
            missingPrimaryGuidesSetup: true, mandatoryRealmLocked: true, escapedNativeKeyLabels: true,
            mobileKeyboardAndTouch: [390, 320], modeWrites: fixture.modeWrites.length, errors };
        fs.writeFileSync(path.join(root, 'evidence/browser-passkey-mode.json'), JSON.stringify(report, null, 2) + '\n'); console.log(JSON.stringify(report, null, 2));
    } catch (error) {
        await page.screenshot({ path: path.join(root, 'evidence/passkey-mode-failure.png') });
        console.error(JSON.stringify({ errors, requests: fixture.modeRequests, visibleText: (await page.locator('body').innerText()).slice(-2400) })); throw error;
    } finally { await context.close(); await browser.close(); await fixture.close(); }
})().catch(error => { console.error(error.stack || error); process.exitCode = 1; });
