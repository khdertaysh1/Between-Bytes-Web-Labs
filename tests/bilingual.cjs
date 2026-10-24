const {chromium}=require('playwright');const assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.BB_BROWSER_PATH,args:['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']});
 const page=await browser.newPage({viewport:{width:1440,height:1050}});const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://127.0.0.1:8000');await page.evaluate(()=>localStorage.setItem('bb-language','en'));await page.reload();
 assert.equal(await page.locator('html').getAttribute('lang'),'en');assert.equal(await page.locator('html').getAttribute('dir'),'ltr');
 const ids=['enumeration','rate-limit','email-flood','idor','edge403','reflected-xss','dom-xss','csrf','cors','open-redirect','ssrf','api-keys','exposed-files'];
 const leftovers=[];
 for(const id of ids){
  await page.goto('http://127.0.0.1:8000/#'+id);
  for(const tab of ['learn','experiment','fix']){
   await page.locator(`[data-tab=${tab}]`).click();
   const text=await page.locator('body').innerText();
   const lines=text.split('\n').filter(line=>/[\u0600-\u06ff]/.test(line)&&line.trim()!=='العربية');
   leftovers.push(...lines.map(line=>id+'/'+tab+': '+line));
  }
 }
 if(leftovers.length){console.log('UNTRANSLATED',JSON.stringify([...new Set(leftovers)],null,2));throw new Error('English UI contains untranslated prose');}
 await page.goto('http://127.0.0.1:8000/#idor');await page.locator('#go-experiment').click();await page.locator('#mission-start').click();await page.waitForFunction(()=>!document.getElementById('mission-send').disabled);
 await page.locator('.http-workbench summary').click();
 let raw=await page.locator('#raw-request').inputValue();raw=raw.replace('resource=1001','resource=1002');await page.locator('#raw-request').fill(raw);await page.locator('#request-replay').click();await page.waitForFunction(()=>!document.getElementById('mission-send').disabled);
 assert.ok((await page.locator('#mission-response').textContent()).includes('"owner": "bob"'));
 assert.ok((await page.locator('#room-app-result').innerText()).includes('bob'));
 if(process.env.BB_SCREENSHOT_DIR){await page.setViewportSize({width:390,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await page.screenshot({path:process.env.BB_SCREENSHOT_DIR+'/rooms-en-workspace.png',fullPage:true});await page.setViewportSize({width:1440,height:1050});}
 await page.locator('#raw-request').fill('POST https://outside.example/ HTTP/1.1\nHost: outside.example\n\nresource=1002');await page.locator('#request-replay').click();assert.ok((await page.locator('#request-mode-note').innerText()).includes('restricted'));
 const context2=await browser.newContext();const page2=await context2.newPage();await page2.goto('http://127.0.0.1:8000');
 const state2=await page2.evaluate(async()=>{await fetch('/rooms/session');return (await (await fetch('/rooms/status')).json()).requests_observed;});assert.equal(state2,0);
 await page.locator('#language-toggle').click();await page.waitForLoadState('load');assert.equal(await page.locator('html').getAttribute('lang'),'ar');assert.equal(await page.locator('html').getAttribute('dir'),'rtl');
 await page.locator('#language-toggle').click();await page.waitForLoadState('load');assert.equal(await page.locator('html').getAttribute('lang'),'en');
 await page.reload();assert.equal(await page.locator('html').getAttribute('lang'),'en');
 await page.setViewportSize({width:390,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
 await page.goto('http://127.0.0.1:8000/#home');
 if(process.env.BB_SCREENSHOT_DIR)await page.screenshot({path:process.env.BB_SCREENSHOT_DIR+'/rooms-en-mobile.png',fullPage:true});
 await page.setViewportSize({width:1440,height:1050});if(process.env.BB_SCREENSHOT_DIR)await page.screenshot({path:process.env.BB_SCREENSHOT_DIR+'/rooms-en-desktop.png',fullPage:true});
 assert.deepEqual(errors,[]);console.log('PASS: both languages/directions, 13 English rooms, restricted HTTP replay, separate browser sessions, persistence and mobile');await browser.close();
})().catch(e=>{console.error(e);process.exit(1)});
