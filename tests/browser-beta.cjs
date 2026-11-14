const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { startFixture, launchBrowser, root } = require('./browser-fixture.cjs');
const tab = async (page, itemId) => { const id = await page.evaluate(itemId => Ext.ComponentQuery.query('sllMakeoverWindow')[0].tabs.items.items.find(x => x.itemId === itemId).tab.id, itemId); await page.locator('[id="'+id+'"]').click(); };
const field = async (page, name, value) => page.evaluate(({name, value}) => {
    const w = Ext.ComponentQuery.query('sllMakeoverWindow')[0];
    const f = w.query('field').find(x => x.name === name); if (!f) throw new Error('Missing field ' + name);
    f.setValue(value);
}, {name,value});
(async () => {
    const browser = await launchBrowser();
    const results = [], errors = [], failed = [], external = [];
    try {
        for (const legacy of [false, true]) {
            const fixture = await startFixture({ legacy });
            const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, hasTouch: true });
            await context.route('**/*', route => {
                const url=route.request().url();
                if (!url.startsWith(fixture.url+'/') && !url.startsWith('blob:') && !url.startsWith('data:')) {external.push(url);return route.abort();}
                return route.continue();
            });
            const page = await context.newPage();
            page.on('pageerror', error=>errors.push(error.stack || String(error)));
            page.on('requestfailed',req=>failed.push(req.url()));
            try {
                await page.goto(fixture.url,{waitUntil:'networkidle'});
                await page.waitForFunction(()=>Ext.ComponentQuery.query('sllMakeoverWindow')[0]?.ready);
                assert.equal(await page.locator('.pm-editor').count(),0,'Editor must use native forms');
                assert.equal(await page.evaluate(()=>Ext.ComponentQuery.query('sllMakeoverWindow')[0].legacy),legacy);
                assert.equal(await page.evaluate(()=>Ext.ComponentQuery.query('sllMakeoverWindow')[0].isDirty()),false);
                assert.equal(await page.evaluate(()=>Ext.ComponentQuery.query('sllMakeoverWindow')[0].query('button').filter(x=>String(x.itemId||'').startsWith('colorButton_')).length),8);
                assert.ok(await page.locator('.pm-sample-login:visible').count()>0,'Login preview is visible on opening');
                await page.getByRole('button',{name:'Choose accent color',exact:true}).click();
                const wheel=page.locator('.pm-color-wheel-canvas:visible');
                await wheel.waitFor(); await wheel.scrollIntoViewIfNeeded();
                const previewNode = await page.locator('.pm-preview:visible').first().elementHandle();
                assert.equal(await page.locator('.x-color-picker-item').count(),0,'Preset swatches are replaced');
                const wb=await wheel.boundingBox();
                await page.mouse.move(wb.x+wb.width*.88,wb.y+wb.height*.5); await page.mouse.down();
                await page.mouse.move(wb.x+wb.width*.45,wb.y+wb.height*.86,{steps:9});
                const during=await page.evaluate(()=>Ext.ComponentQuery.query('sllMakeoverWindow')[0].draft.colors.accent);
                await page.mouse.move(wb.x+wb.width*.13,wb.y+wb.height*.32,{steps:9}); await page.mouse.up();
                assert.equal(await previewNode.evaluate(node => node.isConnected), true,
                    'Dragging changes preview colors without rebuilding its DOM or images');
                const dragged=await page.evaluate(()=>Ext.ComponentQuery.query('sllMakeoverWindow')[0].draft.colors.accent);
                assert.match(dragged,/^#[0-9a-f]{6}$/); assert.notEqual(dragged,during,'Drag continuously selects colors');
                assert.equal(await page.locator('.pm-preview:visible').first().evaluate(el=>getComputedStyle(el).getPropertyValue('--pm-accent').trim()),dragged);
                const brightness=page.getByRole('slider',{name:'Accent brightness',exact:true});
                await brightness.scrollIntoViewIfNeeded(); const bb=await brightness.boundingBox();
                await page.mouse.click(bb.x+bb.width*.28,bb.y+bb.height/2);
                const dimmed=await page.evaluate(()=>Ext.ComponentQuery.query('sllMakeoverWindow')[0].draft.colors.accent);
                assert.notEqual(dimmed,dragged,'Brightness has continuous pointer control');
                await brightness.focus(); await brightness.press('Home');
                assert.equal(await page.evaluate(()=>Ext.ComponentQuery.query('sllMakeoverWindow')[0].draft.colors.accent),'#000000');
                assert.ok(await wheel.evaluate(c=>{const b=c.getContext('2d').getImageData(c.width-8,Math.floor(c.height/2),1,1).data;return b[0]>180;}),'Disc stays visible at zero brightness');
                await brightness.press('End'); await wheel.focus(); await wheel.press('ArrowRight');
                assert.equal(fixture.writes.length,0,'Wheel and brightness only update the local preview');
                const previewButton=page.getByRole('button',{name:'Preview dashboard',exact:true});
                assert.equal(await previewButton.evaluate(el=>Boolean(el.closest('.pm-native-preview-panel'))),true,'Switcher is above the preview, not the settings');
                const previewRect=await page.locator('.pm-native-preview-panel:visible').boundingBox();
                const switchRect=await previewButton.boundingBox();
                assert.ok(switchRect.x>=previewRect.x && switchRect.y<previewRect.y+100,'Switcher stays in preview header');
                const launcher=page.getByRole('button',{name:'Proxmox Makeover',exact:true});
                const launchStyle=await launcher.evaluate(el=>{const c=getComputedStyle(el);return{background:c.backgroundColor,border:c.borderTopStyle,cursor:c.cursor};});
                assert.ok(!['rgba(0, 0, 0, 0)','transparent'].includes(launchStyle.background),'Launcher has a visible backdrop');
                assert.equal(launchStyle.border,'solid'); assert.equal(launchStyle.cursor,'pointer');
                await field(page,'company_name','Example <Labs>');
                assert.match(await page.locator('.pm-native-preview-panel:visible').innerText(),/Example <Labs>/);
                assert.equal(await page.locator('.pm-preview labs').count(),0);
                await field(page,'color_surface','#ffffff'); await field(page,'color_text','#ffffff');
                assert.equal(await page.locator('.pm-preview:visible').evaluate(el=>getComputedStyle(el).getPropertyValue('--pm-text').trim()),'#111512');
                await page.getByRole('button',{name:'Preview dashboard',exact:true}).click();
                assert.ok(await page.locator('.pm-sample-dashboard:visible').count()>0);
                await tab(page,'loginTab');
                await field(page,'login_heading','Hello from the preview');
                assert.match(await page.locator('.pm-native-preview-panel:visible').innerText(),/Hello from the preview/);
                assert.equal(fixture.writes.length,0);
                await page.getByRole('button',{name:'Close',exact:true}).click();
                await page.getByRole('button',{name:'No',exact:true}).click();
                assert.equal(await page.locator('.sll-makeover-window:visible').count(),1);
                await page.getByRole('button',{name:'Reset edits',exact:true}).click();
                await page.waitForFunction(()=>!Ext.ComponentQuery.query('sllMakeoverWindow')[0].isDirty());
                const logoInput = await page.evaluate(()=>Ext.ComponentQuery.query('sllMakeoverWindow')[0].down('#logoFile').fileInputEl.dom.id);
                await page.locator('#'+logoInput).setInputFiles({name:'bad.svg',mimeType:'image/svg+xml',buffer:Buffer.from('<svg/>')});
                await page.waitForFunction(()=>Object.keys(Ext.ComponentQuery.query('sllMakeoverWindow')[0].fileErrors||{}).length>0);
                assert.equal(await page.getByRole('button',{name:'Apply',exact:true}).isDisabled(),true);
                await page.getByRole('button',{name:'Reset edits',exact:true}).click();
                await page.evaluate(()=>Ext.ComponentQuery.query('sllMakeoverWindow')[0].resetEdits());
                const inputId=await page.evaluate(()=>Ext.ComponentQuery.query('sllMakeoverWindow')[0].down('#logoFile').fileInputEl.dom.id);
                await page.locator('#'+inputId).setInputFiles(path.join(root,'assets/SLS_Proxmox.png'));
                await page.waitForFunction(()=>Ext.ComponentQuery.query('sllMakeoverWindow')[0]?.files.logo);
                assert.match(await page.locator('.pm-sample-logo:visible').first().getAttribute('src'),/^blob:/);
                if (legacy) {
                    assert.equal(await page.getByRole('button',{name:'Apply',exact:true}).isDisabled(),true);
                    assert.match(await page.locator('.pm-native-status').innerText(),/too large/i);
                    assert.equal(fixture.apiBodies.filter(x=>x.path==='/sll-customs/upload').length,0);
                }
                await page.evaluate(()=>Ext.ComponentQuery.query('sllMakeoverWindow')[0].resetEdits());
                await field(page,'company_name','Native test company');
                if (!legacy) await field(page,'update_safe',false);
                await page.getByRole('button',{name:'Apply',exact:true}).click();
                await page.getByText('Appearance applied',{exact:true}).waitFor();
                assert.equal(fixture.writes.length,1);
                const saved=JSON.parse(fixture.writes[0].payload.config_json);
                assert.equal(saved.schema_version,legacy?1:2);
                assert.equal(Object.hasOwn(saved,'update_safe'),!legacy);
                assert.equal(Object.hasOwn(fixture.writes[0].payload,'expected_revision'),!legacy);
                assert.equal(fixture.writes[0].csrf,'offline-fixture');
                await page.getByRole('button',{name:'OK',exact:true}).click();
                await page.waitForLoadState('networkidle');
                await page.goto(fixture.url,{waitUntil:'networkidle'});
                await page.waitForFunction(()=>Ext.ComponentQuery.query('sllMakeoverWindow')[0]?.ready);
                await page.screenshot({path:path.join(root,'evidence/native-editor-'+(legacy?'legacy':'beta')+'.png')});
                await tab(page,'security');
                await page.getByRole('button',{name:/Add two-factor key/}).waitFor();
                assert.match(await page.locator('.sll-makeover-window').innerText(),/Keys used after your password/i);
                assert.match(await page.locator('.sll-makeover-window').innerText(),/Example security key/);
                assert.equal(await page.getByRole('button',{name:'Remove two-factor key',exact:true}).isDisabled(),true,'Old capability response safely gates body-only removal');
                await page.screenshot({path:path.join(root,'evidence/native-security-'+(legacy?'legacy':'beta')+'.png')});
                await page.getByRole('button',{name:/Add two-factor key/}).click();
                await page.getByRole('button',{name:'Yes',exact:true}).click();
                await page.waitForFunction(()=>Ext.ComponentQuery.query('pmxAddWebauthn').length===1);
                assert.equal(fixture.tfaWrites.length,0,'Opening native registration is not enrollment');
                await page.evaluate(()=>Ext.ComponentQuery.query('pmxAddWebauthn')[0].close());
                for(const width of [390,320]) {
                    await page.setViewportSize({width,height:844});
                    await page.waitForFunction(()=>{
                        const windowBox=Ext.ComponentQuery.query('sllMakeoverWindow')[0].el.dom.getBoundingClientRect();
                        return windowBox.width<=window.innerWidth+1&&windowBox.left>=0&&windowBox.right<=window.innerWidth+1;
                    });
                    await tab(page,'security');
                    const policyToggle=page.getByRole('switch',{name:'Use passkeys for 2FA',exact:true});
                    assert.equal(await policyToggle.isDisabled(),true,'Old backend cannot claim per-user policy control');
                    assert.equal(await page.evaluate(()=>{
                        const panel=Ext.ComponentQuery.query('sllMakeoverWindow')[0].down('#security');
                        return panel.down('#login-passkeys').isVisible(true)&&panel.down('#second-factor-keys').isVisible(true)&&panel.query('tabpanel').length===0;
                    }),true,'Both lists stay together at mobile sizes');
                    await page.getByRole('button',{name:'Remove two-factor key',exact:true}).scrollIntoViewIfNeeded();
                    await page.screenshot({path:path.join(root,'evidence/key-removal-security-'+width+'-'+(legacy?'legacy':'beta')+'.png')});
                    await tab(page,'previewTab');
                    await page.getByRole('button',{name:'Preview login',exact:true}).click();
                    assert.ok(await page.locator('.pm-sample-login:visible').count()>0);
                    const b=await page.locator('.sll-makeover-window').boundingBox();
                    assert.ok(b.x>=0&&b.x+b.width<=width+1,JSON.stringify(b));
                    await page.screenshot({path:path.join(root,'evidence/native-mobile-'+width+'-'+(legacy?'legacy':'beta')+'.png')});
                }
                await page.setViewportSize({width:1440,height:1000});
                await page.goto(fixture.url+'/?readonly=1',{waitUntil:'networkidle'});
                await page.waitForFunction(()=>Ext.ComponentQuery.query('sllMakeoverWindow')[0]?.ready);
                assert.equal(await page.getByRole('button',{name:'Choose accent color',exact:true}).isDisabled(),true);
                await tab(page,'security');
                assert.equal(await page.getByRole('button',{name:/Add two-factor key/}).isDisabled(),false,'Own keys remain native permissions');
                await page.goto(fixture.url+'/login',{waitUntil:'networkidle'});
                assert.equal(await page.locator('.sll-makeover-window').count(),0);
                await page.evaluate(()=>{
                    const w=Ext.ComponentQuery.query('pveStdWorkspace')[0];
                    if (w.login) { w.login.destroy(); w.login = null; }
                    w.updateLoginData({username:'preview@pam',ticket:'PVE:preview@pam:offline-fixture',CSRFPreventionToken:'offline-fixture',cap:{dc:{'Sys.Audit':1,'Sys.Modify':1},nodes:{},vms:{},storage:{},access:{},sdn:{},mapping:{}}});
                });
                await page.getByRole('button',{name:'Proxmox Makeover',exact:true}).waitFor();
                await page.getByRole('button',{name:'Proxmox Makeover',exact:true}).click();
                await page.waitForFunction(()=>Ext.ComponentQuery.query('sllMakeoverWindow')[0]?.ready);
                assert.equal(await page.evaluate(()=>Ext.ComponentQuery.query('#sllMakeoverButton').length),1);
                await page.evaluate(()=>Ext.ComponentQuery.query('pveStdWorkspace')[0].showLogin());
                assert.equal(await page.locator('.sll-makeover-window').count(),0,'Logout clears editor metadata');
                await page.goto(fixture.url+'/?sls-branding=off&mobile=0',{waitUntil:'networkidle'});
                await page.waitForFunction(()=>Ext.ComponentQuery.query('sllMakeoverWindow')[0]?.ready);
                assert.equal(await page.locator('html.sls-brand').count(),0);
                assert.ok(await page.locator('.pm-sample-login:visible').count()>0);
                results.push({backend:legacy?'0.1.0':'0.1-beta',nativeForms:true,continuousColorWheel:true,previewLocalSwitcher:true,launcherBackdrop:true,previews:true,safeApply:true,nativeKeyDialog:true,mobile:[320,390],loginLifecycle:true});
            }catch(error){ await page.screenshot({path:path.join(root,'evidence/native-test-failure-'+(legacy?'legacy':'beta')+'.png')}); console.log(JSON.stringify({stageBackend:legacy?'legacy':'beta',errors,body:(await page.locator('body').innerText()).slice(-2200)})); throw error; }finally{await context.close();await fixture.close();}
        }
        assert.deepEqual(errors,[]); assert.deepEqual(failed,[]); assert.deepEqual(external,[]);
        const report={status:'passed',results,errors,failedRequests:failed,externalRequests:external};
        fs.writeFileSync(path.join(root,'evidence/browser-beta.json'),JSON.stringify(report,null,2));console.log(JSON.stringify(report,null,2));
    }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
