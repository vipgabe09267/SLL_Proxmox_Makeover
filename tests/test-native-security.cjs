/* Offline integration with the installed native Proxmox/ExtJS registration dialog. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { startFixture, launchBrowser, root } = require('./browser-fixture.cjs');
(async () => {
    const fixture = await startFixture({ legacy: true, secondaryRemoval: true });
    let browser;
    try { browser = await launchBrowser(); }
    catch (error) { await fixture.close(); throw error; }
    const errors = [], external = [];
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, hasTouch: true });
    await context.route('**/*', route => {
        const url = route.request().url();
        if (!url.startsWith(fixture.url + '/') && !url.startsWith('blob:') && !url.startsWith('data:')) {
            external.push(url); return route.abort();
        }
        return route.continue();
    });
    await context.addInitScript(() => {
        // Native form/endpoints and toolkit conversions remain in use.
        // Only the hardware/browser boundary is replaced in this loopback test;
        // these fake attestation bytes never leave the fixture HTTP server.
        window.__fixtureCredentialCalls = [];
        window.__fixtureDelayCreate = false;
        window.__fixtureCredentialAborts = 0;
        Object.defineProperty(navigator.credentials, 'create', {
            configurable: true,
            value: async options => {
                window.__fixtureCredentialCalls.push({
                    challengeIsBytes: options.publicKey.challenge instanceof Uint8Array,
                    userIdIsBytes: options.publicKey.user.id instanceof Uint8Array,
                    publicKeyAlgorithms: Array.isArray(options.publicKey.pubKeyCredParams),
                    abortSignal: options.signal instanceof AbortSignal,
                });
                const credential = { id: 'offline-native-key', type: 'public-key', rawId: new Uint8Array([1, 2, 3]).buffer,
                    response: { attestationObject: new Uint8Array([4, 5, 6]).buffer,
                        clientDataJSON: new TextEncoder().encode('{"type":"offline-fixture"}').buffer } };
                if (!window.__fixtureDelayCreate) return credential;
                // Deliberately resolve even after abort: the adapter must reject
                // a late device result independently of browser cancellation.
                return new Promise(resolve => {
                    window.__fixtureResolveCreate = () => resolve(credential);
                    options.signal?.addEventListener('abort', () => { window.__fixtureCredentialAborts++; }, { once: true });
                });
            },
        });
    });
    const page = await context.newPage();
    page.on('pageerror', error => errors.push(String(error)));
    fs.mkdirSync(path.join(root, 'evidence'), { recursive: true });
    async function securityTab() {
        await page.getByRole('tab', { name: 'Security', exact: true }).click();
        await page.getByRole('button', { name: /Add two-factor key/ }).waitFor();
        await page.waitForFunction(() => Ext.ComponentQuery.query('#security-keys-grid')[0]?.getStore().getCount() > 0);
    }
    try {
        await page.goto(fixture.url, { waitUntil: 'networkidle' });
        await securityTab();
        await page.getByText('Example security key', { exact: true }).waitFor();
        assert.equal(await page.getByRole('button', { name: /Add two-factor key/ }).isEnabled(), true);
        assert.equal(fixture.tfaWrites.length, 0, 'Opening Security must not enroll or modify keys');
        assert.equal(fixture.writes.length, 0);
        assert.match(await page.locator('body').innerText(), /Keys used after your password/);
        assert.match(await page.locator('body').innerText(), /Native WebAuthn settings/);
        // Optional extra verification requires a deliberate opt-in; cancel
        // never opens native registration or contacts a write endpoint.
        await page.getByRole('button', { name: /Add two-factor key/ }).click();
        await page.getByText('Enable extra verification?', { exact: true }).waitFor();
        assert.equal(await page.evaluate(() => Ext.ComponentQuery.query('pmxAddWebauthn').length), 0);
        await page.getByRole('button', { name: 'No', exact: true }).click();
        assert.equal(fixture.tfaWrites.length, 0);
        assert.equal(fixture.tfaEdits.length, 0);
        await page.screenshot({ path: path.join(root, 'evidence/native-security-tab.png') });
        // An unsaved appearance draft survives native key registration.
        await page.evaluate(() => {
            const editor = Ext.ComponentQuery.query('sllMakeoverWindow')[0];
            editor.forms[0].getForm().findField('company_name').setValue('Unsaved appearance draft');
        });
        await page.getByRole('button', { name: /Add two-factor key/ }).click();
        await page.getByRole('button', { name: 'Yes', exact: true }).click();
        await page.waitForFunction(() => Ext.ComponentQuery.query('pmxAddWebauthn').some(dialog => dialog.isVisible()));
        const nativeId = await page.evaluate(() => Ext.ComponentQuery.query('pmxAddWebauthn').find(dialog => dialog.isVisible()).id);
        const dialog = page.locator('[id="' + nativeId + '"]');
        assert.equal(await page.evaluate(() => Ext.ComponentQuery.query('pmxAddWebauthn')[0].fixedUser), true, 'Native dialog fixes current account');
        assert.match(await dialog.innerText(), /preview@pam/);
        assert.equal(fixture.tfaWrites.length, 0, 'Showing native dialog still makes no enrollment write');
        await page.screenshot({ path: path.join(root, 'evidence/native-security-enrollment.png') });
        await dialog.locator('input[name="description"]').fill('Offline registered key');
        await dialog.locator('input[name="password"]').fill('fixture-password');
        await dialog.getByRole('button', { name: 'Register Webauthn Device', exact: true }).click();
        await page.waitForFunction(() => !Ext.ComponentQuery.query('pmxAddWebauthn').some(dialog => dialog.isVisible()));
        await page.waitForFunction(() => Ext.ComponentQuery.query('#security-keys-grid')[0]?.getStore().getCount() === 2, null, { timeout: 5000 });
        assert.equal(fixture.tfaWrites.length, 2, 'Native registration performs begin and finish against fake API');
        assert.equal(fixture.tfaWrites.every(write => write.csrf === 'offline-fixture'), true, 'Native registration preserves CSRF');
        assert.deepEqual(await page.evaluate(() => window.__fixtureCredentialCalls), [
            { challengeIsBytes: true, userIdIsBytes: true, publicKeyAlgorithms: true, abortSignal: true },
        ], 'The owned native enrollment adapter retains toolkit byte conversion and supplies cancellation');
        assert.equal(fixture.writes.length, 0, 'Security enrollment never applies appearance');
        assert.equal(await page.evaluate(() => Ext.ComponentQuery.query('sllMakeoverWindow')[0].draft.company_name), 'Unsaved appearance draft');
        assert.equal(fixture.requests.some(request => request.method === 'GET' && /\/access\/tfa$/.test(request.path)), false,
            'Makeover never requests all users TFA metadata');
        // Compact native controls fit a phone viewport; the grid scrolls inside its panel.
        await page.setViewportSize({ width: 390, height: 844 });
        await page.getByRole('button', { name: /Add two-factor key/ }).waitFor();
        await page.screenshot({ path: path.join(root, 'evidence/native-security-mobile.png') });
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
        // Appearance read-only mode does not prevent native self-service TFA.
        await page.setViewportSize({ width: 1440, height: 1000 });
        await page.goto(fixture.url + '/?readonly=1', { waitUntil: 'networkidle' });
        await securityTab();
        assert.equal(await page.getByRole('button', { name: /Add two-factor key/ }).isEnabled(), true,
            'Own-account enrollment follows native TFA authorization, independently of appearance Sys.Modify');
        // An owned native enrollment window must not outlive its account/panel.
        // These cases stop before registration: all native API writes stay above.
        async function openOwnedDialog() {
            await page.getByRole('button', { name: /Add two-factor key/ }).click();
        await page.getByRole('button', { name: 'Yes', exact: true }).click();
            await page.waitForFunction(() => Ext.ComponentQuery.query('pmxAddWebauthn').some(dialog => dialog.isVisible()));
            await page.evaluate(() => {
                const dialog = Ext.ComponentQuery.query('pmxAddWebauthn').find(value => value.isVisible());
                dialog.down('textfield[name=password]').setValue('fixture-password');
                window.__fixturePasswordClearedOnClose = false;
                dialog.on('beforeclose', () => {
                    window.__fixturePasswordClearedOnClose = dialog.down('textfield[name=password]').getValue() === '';
                });
            });
        }
        await openOwnedDialog();
        await page.evaluate(() => {
            const editor = Ext.ComponentQuery.query('sllMakeoverWindow')[0];
            editor.forceClose = true; editor.close();
        });
        await page.waitForFunction(() => Ext.ComponentQuery.query('pmxAddWebauthn').length === 0);
        assert.equal(await page.evaluate(() => window.__fixturePasswordClearedOnClose), true, 'Closing Makeover clears and closes its native password dialog');
        await page.reload({ waitUntil: 'networkidle' });
        await securityTab(); await openOwnedDialog();
        await page.evaluate(() => {
            Ext.ComponentQuery.query('pveStdWorkspace')[0].updateLoginData({ username: 'other@pam',
                ticket: 'PVE:other@pam:offline-fixture', CSRFPreventionToken: 'offline-other',
                cap: { dc: { 'Sys.Audit': 1, 'Sys.Modify': 1 }, nodes: {}, vms: {}, storage: {}, access: {}, sdn: {}, mapping: {} } });
        });
        await page.waitForFunction(() => Ext.ComponentQuery.query('pmxAddWebauthn').length === 0);
        assert.equal(await page.evaluate(() => window.__fixturePasswordClearedOnClose), true, 'Changing native account closes the previous account enrollment dialog');
        await page.reload({ waitUntil: 'networkidle' });
        await securityTab(); await openOwnedDialog();
        await page.evaluate(() => Ext.ComponentQuery.query('pveStdWorkspace')[0].showLogin());
        await page.waitForFunction(() => !Ext.ComponentQuery.query('pmxAddWebauthn').length && !Ext.ComponentQuery.query('sllMakeoverWindow').length);
        assert.equal(await page.evaluate(() => window.__fixturePasswordClearedOnClose), true, 'Native logout clears and closes owned enrollment dialogs');
        assert.equal(fixture.tfaWrites.length, 2, 'Closing stale enrollment dialogs never begins or finishes registration');
        await page.reload({ waitUntil: 'networkidle' });
        await securityTab();
        async function startOwnedRegistration() {
            await page.evaluate(() => {
                const dialog = Ext.ComponentQuery.query('pmxAddWebauthn').find(value => value.isVisible());
                dialog.down('textfield[name=description]').setValue('Canceled device');
                window.__fixtureRegistrationSettled = false;
                dialog.getController().registerWebauthn().finally(() => { window.__fixtureRegistrationSettled = true; });
            });
        }
        const finishCount = () => fixture.tfaWrites.filter(write => write.phase === 'finish').length;
        const successfulFinishes = finishCount();
        let releaseBegin, capturedBegin;
        const heldBegin = new Promise(resolve => { releaseBegin = resolve; });
        const beginCaptured = new Promise(resolve => { capturedBegin = resolve; });
        const delayedBeginRoute = async route => {
            if (route.request().method() !== 'POST') return route.continue();
            const response = await route.fetch(); capturedBegin();
            await heldBegin; return route.fulfill({ response });
        };
        await context.route('**/api2/extjs/access/tfa/**', delayedBeginRoute);
        await openOwnedDialog(); await startOwnedRegistration(); await beginCaptured;
        await page.evaluate(() => {
            const editor = Ext.ComponentQuery.query('sllMakeoverWindow')[0];
            editor.forceClose = true; editor.close();
            Proxmox.Utils.setAuthData({ username: 'other@pam', ticket: 'PVE:other@pam:delayed-begin', CSRFPreventionToken: 'other-csrf' });
        });
        releaseBegin();
        await page.waitForFunction(() => window.__fixtureRegistrationSettled);
        assert.equal(await page.evaluate(() => window.__fixtureCredentialCalls.length), 0, 'A late begin response after panel close/new login never requests an authenticator');
        assert.equal(finishCount(), successfulFinishes, 'A late begin response never finishes enrollment');
        await context.unroute('**/api2/extjs/access/tfa/**', delayedBeginRoute);
        await page.reload({ waitUntil: 'networkidle' });
        await securityTab(); await openOwnedDialog();
        await page.evaluate(() => { window.__fixtureDelayCreate = true; });
        await startOwnedRegistration();
        await page.waitForFunction(() => typeof window.__fixtureResolveCreate === 'function');
        await page.evaluate(() => {
            Ext.ComponentQuery.query('pveStdWorkspace')[0].updateLoginData({ username: 'other@pam',
                ticket: 'PVE:other@pam:pending-create', CSRFPreventionToken: 'offline-other',
                cap: { dc: { 'Sys.Audit': 1, 'Sys.Modify': 1 }, nodes: {}, vms: {}, storage: {}, access: {}, sdn: {}, mapping: {} } });
        });
        await page.waitForFunction(() => !Ext.ComponentQuery.query('pmxAddWebauthn').length && !Ext.ComponentQuery.query('#sll-native-enrollment-wait').length);
        assert.equal(await page.evaluate(() => window.__fixtureCredentialAborts), 1, 'An account change aborts an owned pending authenticator request');
        await page.evaluate(() => window.__fixtureResolveCreate());
        await page.waitForFunction(() => window.__fixtureRegistrationSettled);
        assert.equal(finishCount(), successfulFinishes, 'An authenticator resolving after cancellation/new login never finishes enrollment');
        for (const changed of ['cookie', 'csrf']) {
            await page.reload({ waitUntil: 'networkidle' });
            await securityTab(); await openOwnedDialog();
            await page.evaluate(() => { window.__fixtureDelayCreate = true; });
            await startOwnedRegistration();
            await page.waitForFunction(() => typeof window.__fixtureResolveCreate === 'function');
            await page.evaluate(changed => {
                if (changed === 'cookie') Ext.util.Cookies.set(Proxmox.Setup.auth_cookie_name, 'PVE:preview@pam:replacement-session');
                else Proxmox.CSRFPreventionToken = 'replacement-csrf';
                window.__fixtureResolveCreate();
            }, changed);
            await page.waitForFunction(() => window.__fixtureRegistrationSettled && !Ext.ComponentQuery.query('pmxAddWebauthn').length);
            assert.equal(finishCount(), successfulFinishes, 'Replacing the same username session ' + changed + ' rejects a late credential result');
        }
        await page.reload({ waitUntil: 'networkidle' });
        await securityTab();
        // Both native API representations of relying-party settings are accepted.
        await context.route('**/api2/extjs/cluster/options*', route => route.fulfill({ contentType: 'application/json', body: JSON.stringify({
            success: true, data: { 'allowed-tags': [], webauthn: 'id=localhost,origin=' + fixture.url + ',rp=String-format fixture' },
        }) }));
        await page.reload({ waitUntil: 'networkidle' });
        await securityTab();
        await page.evaluate(() => { Ext.ComponentQuery.query('#native-webAuthn-details')[0].expand(); });
        await page.getByText('Relying party: String-format fixture', { exact: false }).waitFor();
        assert.equal(await page.getByRole('button', { name: /Add two-factor key/ }).isEnabled(), true);
        await context.unroute('**/api2/extjs/cluster/options*');
        await context.route('**/api2/extjs/cluster/options*', route => route.fulfill({ contentType: 'application/json', body: JSON.stringify({
            success: true, data: { 'allowed-tags': [], webauthn: { id: 'other.example', origin: 'https://other.example', rp: 'Other origin' } },
        }) }));
        await page.reload({ waitUntil: 'networkidle' });
        await securityTab();
        await page.evaluate(() => { Ext.ComponentQuery.query('#native-webAuthn-details')[0].expand(); });
        await page.getByText('Use this configured origin to register and use your key.', { exact: true }).waitFor();
        assert.equal(await page.getByRole('button', { name: /Add two-factor key/ }).isDisabled(), true,
            'Origin mismatch gives a clear disabled enrollment action');
        assert.equal(finishCount(), successfulFinishes, 'Context checks never finish enrollment');
        // The native confirmation keeps native password/root policy, but
        // removal uses a CSRF-protected JSON body rather than a password URL.
        async function openRemoval() {
            await page.getByRole('button', { name: 'Remove two-factor key', exact: true }).first().click();
            await page.waitForFunction(() => Ext.ComponentQuery.query('#sll-remove-second-factor').some(dialog => dialog.isVisible()));
            return page.locator('[id="' + await page.evaluate(() => Ext.ComponentQuery.query('#sll-remove-second-factor')[0].id) + '"]');
        }
        const removal = await openRemoval();
        assert.match(await removal.innerText(), /Example security key/);
        assert.equal(await page.getByRole('button', { name: 'Cancel', exact: true }).evaluate(element => element === document.activeElement), true);
        await page.keyboard.press('Enter');
        await page.waitForFunction(() => !Ext.ComponentQuery.query('#sll-remove-second-factor').length);
        assert.equal(fixture.tfaRemovals.length, 0, 'Enter defaults to Cancel without removal');
        for (const changed of ['cookie', 'csrf']) {
            const dialog = await openRemoval();
            await dialog.locator('input[name=password]').fill('fixture-password');
            await page.evaluate(changed => {
                window.__fixtureRemovalSession = { cookie: Ext.util.Cookies.get(Proxmox.Setup.auth_cookie_name), token: Proxmox.CSRFPreventionToken };
                if (changed === 'cookie') Ext.util.Cookies.set(Proxmox.Setup.auth_cookie_name, 'PVE:preview@pam:replacement-removal');
                else Proxmox.CSRFPreventionToken = 'replacement-removal-csrf';
                Ext.ComponentQuery.query('#sll-remove-second-factor')[0].submit();
            }, changed);
            await page.waitForFunction(() => !Ext.ComponentQuery.query('#sll-remove-second-factor').length);
            assert.equal(fixture.tfaRemovals.length, 0, 'An old confirmation cannot remove after a session replacement');
            await page.evaluate(() => { const saved = window.__fixtureRemovalSession; Ext.util.Cookies.set(Proxmox.Setup.auth_cookie_name, saved.cookie); Proxmox.CSRFPreventionToken = saved.token; delete window.__fixtureRemovalSession; });
        }
        await openRemoval();
        await page.evaluate(() => { Ext.ComponentQuery.query('sllMakeoverWindow')[0].tabs.setActiveTab(0); });
        assert.equal(await page.evaluate(() => Ext.ComponentQuery.query('#sll-remove-second-factor').length), 0, 'Leaving Security closes an unapproved native removal');
        assert.equal(fixture.tfaRemovals.length, 0);
        await page.getByRole('tab', { name: 'Security', exact: true }).click();
        const finalRemoval = await openRemoval();
        await finalRemoval.locator('input[name=password]').fill('fixture-password');
        await page.screenshot({ path: path.join(root, 'evidence/key-removal-native-confirm.png') });
        await finalRemoval.getByRole('button', { name: 'Remove', exact: true }).click();
        await page.waitForFunction(() => !Ext.ComponentQuery.query('#sll-remove-second-factor').length);
        await page.waitForFunction(() => Ext.ComponentQuery.query('#security-keys-grid')[0].getStore().getCount() === 1);
        assert.deepEqual(fixture.tfaRemovals, [{ id: 'fixture-key-1', hasPassword: true, csrf: 'offline-fixture', jsonBody: true, passwordInQuery: false }]);
        assert.equal(fixture.requests.some(request => request.method === 'DELETE' && request.path.includes('/access/tfa/')), false);
        await page.evaluate(() => { const editor = Ext.ComponentQuery.query('sllMakeoverWindow')[0]; editor.forceClose = true; editor.close(); });
        await page.waitForFunction(() => Ext.ComponentQuery.query('sllMakeoverWindow').length === 0);
        // Root's native removal exception remains native: its password field
        // is disabled/hidden, and the protected JSON bridge omits that field.
        const rootFixture = await startFixture({ legacy: true, user: 'root@pam', secondaryRemoval: true });
        const rootContext = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
        try {
            await rootContext.route('**/*', route => {
                if (!route.request().url().startsWith(rootFixture.url + '/')) { external.push(route.request().url()); return route.abort(); }
                return route.continue();
            });
            const rootPage = await rootContext.newPage(); rootPage.on('pageerror', error => errors.push(String(error)));
            await rootPage.goto(rootFixture.url, { waitUntil: 'networkidle' });
            await rootPage.getByRole('tab', { name: 'Security', exact: true }).click();
            await rootPage.waitForFunction(() => Ext.ComponentQuery.query('#security-keys-grid')[0]?.getStore().getCount() === 1);
            await rootPage.getByRole('button', { name: 'Remove two-factor key', exact: true }).click();
            await rootPage.waitForFunction(() => Ext.ComponentQuery.query('#sll-remove-second-factor').some(dialog => dialog.isVisible()));
            assert.equal(await rootPage.evaluate(() => Ext.ComponentQuery.query('#sll-remove-second-factor')[0].lookup('password').disabled), true);
            await rootPage.getByRole('button', { name: 'Cancel', exact: true }).click();
            assert.equal(rootFixture.tfaRemovals.length, 0);
            await rootPage.getByRole('button', { name: 'Remove two-factor key', exact: true }).click();
            await rootPage.getByRole('button', { name: 'Remove', exact: true }).click();
            await rootPage.waitForFunction(() => Ext.ComponentQuery.query('#security-keys-grid')[0].getStore().getCount() === 0);
            assert.deepEqual(rootFixture.tfaRemovals, [{ id: 'fixture-key-1', hasPassword: false, csrf: 'offline-fixture', jsonBody: true, passwordInQuery: false }]);
        } finally { await rootContext.close(); await rootFixture.close(); }
        assert.deepEqual(errors, [], 'No page errors');
        assert.deepEqual(external, [], 'No external requests');
        console.log(JSON.stringify({ tests: 'native-security', nativeDialog: true, nativeBrowserCredentialFlow: true,
            nativeApiWrites: fixture.tfaWrites.length, appearanceWrites: fixture.writes.length,
            currentAccountOnly: true, legacyBackend: true, readonlyAppearance: true, mobile: true,
            settingsObjectAndString: true, originMismatchBlocked: true, ownedDialogEditorClose: true,
            ownedDialogAccountChange: true, ownedDialogLogout: true, delayedBeginCanceled: true,
            pendingAuthenticatorCanceled: true, lateAuthenticatorIgnored: true, sameUserCookieAndCsrfBound: true,
            explicitOptInCancelNoWrites: true, nativeEditControlsAbsent: true, nativeEditWrites: fixture.tfaEdits.length,
            nativeRootPasswordPolicy: true,
            nativeNamedRemoval: true, removalDefaultCancel: true, staleRemovalBlocked: true, leavingSecurityClosesRemoval: true,
            bodyOnlyNativeRemoval: true, nativeRemovalRootPasswordPolicy: true, errors }));
    } catch (error) {
        console.error(JSON.stringify({ errors, nativeWrites: fixture.tfaWrites, nativeRequests: fixture.requests.filter(request => request.path.includes('/access/tfa')),
            credentialCalls: await page.evaluate(() => window.__fixtureCredentialCalls), visibleText: (await page.locator('body').innerText()).slice(-1400) }));
        throw error;
    } finally {
        await browser.close();
        await fixture.close();
    }
})().catch(error => { console.error(error); process.exitCode = 1; });
