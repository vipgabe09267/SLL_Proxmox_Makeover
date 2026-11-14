/* Native header geometry and click behavior, isolated from the production API. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { startFixture, launchBrowser, root } = require('./browser-fixture.cjs');
(async () => {
    const browser = await launchBrowser(), errors = [], external = [], results = [];
    try {
        for (const legacy of [false, true]) {
            const fixture = await startFixture({ legacy });
            const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
            try {
                await context.route('**/*', route => {
                    if (!route.request().url().startsWith(fixture.url + '/')) { external.push(route.request().url()); return route.abort(); }
                    return route.continue();
                });
                const page = await context.newPage(); page.on('pageerror', error => errors.push(String(error)));
                for (const bypass of [false, true]) {
                    await page.goto(fixture.url + (bypass ? '/?sls-branding=off' : '/'), { waitUntil: 'networkidle' });
                    await page.waitForFunction(() => Ext.ComponentQuery.query('sllMakeoverWindow')[0]?.ready);
                    await page.evaluate(() => { const window = Ext.ComponentQuery.query('sllMakeoverWindow')[0]; window.forceClose = true; window.close(); });
                    const geometry = await page.evaluate(() => ['Documentation', 'Create VM', 'Create CT', 'Proxmox Makeover'].map(text => {
                        const button = Ext.ComponentQuery.query('button').find(button => button.text === text);
                        if (!button?.rendered) throw new Error('Missing native header button: ' + text);
                        const element = button.el.dom, box = element.getBoundingClientRect(), style = getComputedStyle(element);
                        const inner = getComputedStyle(element.querySelector('.x-btn-inner'));
                        return { text, height: box.height, top: box.top, padding: style.padding,
                            fontFamily: inner.fontFamily, fontSize: inner.fontSize, fontWeight: inner.fontWeight, lineHeight: inner.lineHeight,
                            background: style.backgroundColor, border: style.borderTopStyle, cursor: style.cursor };
                    }));
                    const launcher = geometry[3];
                    for (const native of geometry.slice(0, 3)) {
                        assert.ok(Math.abs(launcher.height - native.height) < 1, JSON.stringify({ launcher, native }));
                        assert.ok(Math.abs(launcher.top - native.top) < 1, JSON.stringify({ launcher, native }));
                        for (const property of ['padding', 'fontFamily', 'fontSize', 'fontWeight', 'lineHeight']) assert.equal(launcher[property], native[property], property);
                    }
                    assert.ok(!['transparent', 'rgba(0, 0, 0, 0)'].includes(launcher.background));
                    assert.equal(launcher.border, 'solid'); assert.equal(launcher.cursor, 'pointer');
                    await page.getByRole('button', { name: 'Proxmox Makeover', exact: true }).click();
                    await page.waitForFunction(() => Ext.ComponentQuery.query('sllMakeoverWindow')[0]?.ready);
                    await page.evaluate(() => { const window = Ext.ComponentQuery.query('sllMakeoverWindow')[0]; window.forceClose = true; window.close(); });
                    if (!legacy && !bypass) await page.screenshot({ path: path.join(root, 'evidence/native-toolbar-uniform.png'), clip: { x: 0, y: 0, width: 1440, height: 70 } });
                    results.push({ legacy, bypass, uniformNativeGeometry: true, clickableBackdrop: true, height: launcher.height, padding: launcher.padding });
                }
                await page.goto(fixture.url + '/login', { waitUntil: 'networkidle' });
                const login = page.getByRole('button', { name: 'Sign in with passkey', exact: true }); await login.waitFor();
                assert.ok((await login.boundingBox()).height >= 44, 'Login passkey touch target retains its separate 44px minimum');
                assert.equal(fixture.writes.length + fixture.tfaWrites.length + fixture.tfaEdits.length + fixture.tfaRemovals.length, 0);
            } finally { await context.close(); await fixture.close(); }
        }
        assert.deepEqual(errors, []); assert.deepEqual(external, []);
        const report = { tests: 'native-toolbar-geometry', results, loginPasskeyTouchTargetUnchanged: true, errors, external };
        fs.writeFileSync(path.join(root, 'evidence/browser-toolbar.json'), JSON.stringify(report, null, 2) + '\n');
        console.log(JSON.stringify(report, null, 2));
    } finally { await browser.close(); }
})().catch(error => { console.error(error.stack || error); process.exitCode = 1; });
