const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { startFixture, launchBrowser, root } = require('./browser-fixture.cjs');
(async () => {
    const fixture = await startFixture({legacy:true});
    const browser = await launchBrowser();
    const context = await browser.newContext({viewport:{width:390,height:844},isMobile:true,hasTouch:true,deviceScaleFactor:2});
    const page = await context.newPage(); const errors=[];
    page.on('pageerror',error=>errors.push(String(error)));
    try {
        await page.goto(fixture.url,{waitUntil:'networkidle'});
        await page.waitForFunction(()=>Ext.ComponentQuery.query('sllMakeoverWindow')[0]?.ready);
        await page.getByRole('button',{name:'Choose accent color',exact:true}).click();
        const canvas=page.locator('.pm-color-wheel-canvas:visible');
        await canvas.waitFor();await canvas.scrollIntoViewIfNeeded();
        const box=await canvas.boundingBox();
        const color=()=>page.evaluate(()=>Ext.ComponentQuery.query('sllMakeoverWindow')[0].draft.colors.accent);
        const before=await color();const cdp=await context.newCDPSession(page);
        const point=(x,y)=>({x:box.x+box.width*x,y:box.y+box.height*y,id:1});
        await cdp.send('Input.dispatchTouchEvent',{type:'touchStart',touchPoints:[point(.85,.5)]});
        await cdp.send('Input.dispatchTouchEvent',{type:'touchMove',touchPoints:[point(.7,.8)]});
        const middle=await color();
        await cdp.send('Input.dispatchTouchEvent',{type:'touchMove',touchPoints:[point(.2,.3)]});
        await cdp.send('Input.dispatchTouchEvent',{type:'touchEnd',touchPoints:[]});
        const after=await color();assert.notEqual(middle,before);assert.notEqual(after,middle);assert.match(after,/^#[0-9a-f]{6}$/);
        assert.equal(fixture.writes.length,0);assert.deepEqual(errors,[]);
        await page.screenshot({path:path.join(root,'evidence/color-wheel-mobile.png')});
        console.log(JSON.stringify({touchDrag:true,continuousSelection:true,noAppearanceWrites:true,errors}));
    }finally{await context.close();await browser.close();await fixture.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
