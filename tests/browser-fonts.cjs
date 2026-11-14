/* Font selection uses actual local font files and native Proxmox components. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { startFixture, launchBrowser, root } = require('./browser-fixture.cjs');
const family = { default: 'Segoe UI', system: 'Segoe UI', 'dm-sans': 'SLL DM Sans',
    oxanium: 'SLL Oxanium', serif: 'Georgia', monospace: 'monospace' };
(async () => {
    const browser = await launchBrowser(), errors = [], external = [], failed = [];
    let contexts = 0;
    const open = async (fixture, target = '/') => {
        const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
        context.on('page', page => {
            page.on('pageerror', error => errors.push(error.message));
            page.on('requestfailed', request => failed.push(request.url()));
        });
        await context.route('**/*', route => {
            const url = route.request().url();
            if (!url.startsWith(fixture.url + '/') && !url.startsWith('data:') && !url.startsWith('blob:')) {
                external.push(url); return route.abort();
            }
            return route.continue();
        });
        const page = await context.newPage();
        await page.goto(fixture.url + target);
        if (target !== '/login') await page.waitForFunction(() => Ext.ComponentQuery.query('sllMakeoverWindow')[0]?.ready);
        await page.evaluate(() => document.fonts.ready);
        contexts++;
        return { context, page };
    };
    try {
        const fixture = await startFixture();
        try {
            const { context, page } = await open(fixture);
            assert.equal(await page.evaluate(() => {
                const el = Ext.ComponentQuery.query('sllMakeoverWindow')[0].down('[name=font_login]').getTrigger('picker').el.dom;
                return getComputedStyle(el).backgroundImage !== 'none' || !['none', 'normal', '""'].includes(getComputedStyle(el, '::before').content);
            }), true, 'Native picker arrow stays visible');
            await page.evaluate(() => {
                const w = Ext.ComponentQuery.query('sllMakeoverWindow')[0];
                window.__fontPreview = w.sidePreview.getEl().dom.querySelector('.pm-sample-logo');
            });
            const select = async (slot, label) => {
                const id = await page.evaluate(slot => Ext.ComponentQuery.query('sllMakeoverWindow')[0]
                    .down('[name=font_' + slot + ']').getId(), slot);
                await page.locator('[id="' + id + '"] .x-form-arrow-trigger').click();
                await page.getByRole('option', { name: label, exact: true }).click();
            };
            await select('login', 'DM Sans');
            await page.evaluate(() => document.fonts.ready);
            assert.equal(await page.evaluate(() => Ext.ComponentQuery.query('sllMakeoverWindow')[0].draft.fonts.login), 'dm-sans');
            assert.match(await page.locator('.pm-sample-login').first().evaluate(el => getComputedStyle(el).fontFamily), /SLL DM Sans/);
            assert.equal(await page.evaluate(() => window.__fontPreview === Ext.ComponentQuery.query('sllMakeoverWindow')[0].sidePreview.getEl().dom.querySelector('.pm-sample-logo')), true);
            await select('dashboard', 'Oxanium');
            await page.getByRole('button', { name: 'Preview dashboard', exact: true }).click();
            await page.evaluate(() => document.fonts.ready);
            assert.match(await page.locator('.pm-sample-dashboard').evaluate(el => getComputedStyle(el).fontFamily), /SLL Oxanium/);
            assert.equal(fixture.writes.length, 0);
            assert.doesNotMatch(await page.locator('.sll-makeover-launch .x-btn-inner').evaluate(el => getComputedStyle(el).fontFamily), /SLL Oxanium/);
            await page.getByRole('button', { name: 'Apply', exact: true }).click();
            await page.waitForFunction(() => Ext.Msg.isVisible() && Ext.Msg.title === 'Appearance applied');
            assert.equal(fixture.writes.length, 1);
            assert.deepEqual(JSON.parse(fixture.writes[0].payload.config_json).fonts, { login: 'dm-sans', dashboard: 'oxanium' });
            await page.reload();
            await page.waitForFunction(() => Ext.ComponentQuery.query('sllMakeoverWindow')[0]?.ready);
            await page.evaluate(() => document.fonts.ready);
            assert.deepEqual(await page.evaluate(() => Ext.ComponentQuery.query('sllMakeoverWindow')[0].draft.fonts), { login: 'dm-sans', dashboard: 'oxanium' });
            assert.match(await page.locator('.sll-makeover-launch .x-btn-inner').evaluate(el => getComputedStyle(el).fontFamily), /SLL Oxanium/);
            for (const width of [390, 320]) {
                await page.setViewportSize({ width, height: 844 });
                await page.waitForFunction(width => {
                    const w = Ext.ComponentQuery.query('sllMakeoverWindow')[0];
                    return w && w.getWidth() < width && !w.makeoverResizePosition;
                }, width);
                await page.evaluate(() => {
                    const w = Ext.ComponentQuery.query('sllMakeoverWindow')[0];
                    w.tabs.setActiveTab(w.down('#appearanceTab'));
                });
                await select('login', 'Georgia');
                assert.equal(await page.evaluate(() => Ext.ComponentQuery.query('sllMakeoverWindow')[0].draft.fonts.login), 'serif');
                await page.getByRole('button', { name: 'Reset edits', exact: true }).click();
                assert.equal(await page.evaluate(() => Ext.ComponentQuery.query('sllMakeoverWindow')[0].draft.fonts.login), 'dm-sans');
            }
            assert.equal(fixture.writes.length, 1);
            await context.close();
        } finally { await fixture.close(); }

        const presets = Object.keys(family);
        for (let index = 0; index < presets.length; index++) {
            const login = presets[index], dashboard = presets[presets.length - index - 1];
            const fixture = await startFixture({ config: { fonts: { login, dashboard } } });
            try {
                const { context, page } = await open(fixture, '/login');
                assert.match(await page.locator('.sls-login-window input.x-form-text').first().evaluate(el => getComputedStyle(el).fontFamily), new RegExp(family[login]));
                assert.match(await page.locator('.sls-login-intro h1').evaluate(el => getComputedStyle(el).fontFamily), new RegExp(login === 'default' ? 'Georgia' : family[login]));
                assert.match(await page.locator('.sls-login-footer .fa').evaluate(el => getComputedStyle(el).fontFamily), /FontAwesome/);
                const local = ['dm-sans', 'oxanium'].includes(login);
                if (local) assert.equal(await page.evaluate(name => document.fonts.check('14px "' + name + '"'), family[login]), true);
                await page.goto(fixture.url + '/');
                await page.waitForFunction(() => Ext.ComponentQuery.query('sllMakeoverWindow')[0]?.ready);
                await page.evaluate(() => document.fonts.ready);
                assert.match(await page.locator('.sll-makeover-launch .x-btn-inner').evaluate(el => getComputedStyle(el).fontFamily), new RegExp(family[dashboard]));
                assert.match(await page.locator('.sll-makeover-launch .fa').evaluate(el => getComputedStyle(el).fontFamily), /FontAwesome/);
                assert.equal(fixture.writes.length, 0);
                await context.close();
            } finally { await fixture.close(); }
        }
        for (const options of [{ legacy: true }, { fontSelection: false }]) {
            const fixture = await startFixture(options);
            try {
                const { context, page } = await open(fixture);
                assert.equal(await page.evaluate(() => Ext.ComponentQuery.query('sllMakeoverWindow')[0].down('[name=font_login]').disabled), true);
                assert.equal(fixture.writes.length, 0);
                await context.close();
            } finally { await fixture.close(); }
        }
        const fixtureReadOnly = await startFixture();
        try {
            const { context, page } = await open(fixtureReadOnly, '/?readonly=1');
            assert.equal(await page.evaluate(() => Ext.ComponentQuery.query('sllMakeoverWindow')[0].down('[name=font_dashboard]').disabled), true);
            assert.equal(fixtureReadOnly.writes.length, 0);
            await context.close();
        } finally { await fixtureReadOnly.close(); }
        assert.deepEqual(errors, []); assert.deepEqual(external, []); assert.deepEqual(failed, []);
        const result = { status: 'passed', presets: presets.length, contexts,
            independentLoginAndDashboard: true, realLocalFonts: true, previewOnlyUntilApply: true,
            iconsRetained: true, reloadAndDiscard: true, mobile: [390, 320],
            legacyAndOldBackendGated: true, readonly: true, errors, external, failed };
        fs.writeFileSync(path.join(root, 'evidence/browser-fonts-result.json'), JSON.stringify(result, null, 2));
        console.log(JSON.stringify(result, null, 2));
    } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
