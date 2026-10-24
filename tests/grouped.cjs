// UI acceptance checks for the grouped labs and real business HTTP workflow.
const {chromium}=require('playwright');const assert=require('node:assert/strict');
(async()=>{
 const b=await chromium.launch({headless:true,executablePath:process.env.BB_BROWSER_PATH,args:['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']});
 const p=await b.newPage({viewport:{width:1440,height:1050}});const errors=[],requests=[];p.on('pageerror',e=>errors.push(e.message));p.on('request',r=>requests.push(r.url()));
 const base='http://127.0.0.1:8000';await p.goto(base);await p.waitForFunction(()=>document.querySelectorAll('.lab-card').length===5);
 assert.equal(await p.locator('.lab-card').count(),5);assert.equal(await p.locator('.lab-card[href="#/payment"]').count(),1);assert.equal(await p.locator('.lab-card[href="#/xss"]').count(),1);
 if(process.env.BB_SCREENSHOT_DIR)await p.screenshot({path:process.env.BB_SCREENSHOT_DIR+'/grouped-home-ar.png',fullPage:true});
 await p.locator('.lab-card[href="#/payment"]').click();await p.waitForFunction(()=>document.querySelectorAll('#case-navigation a').length===16);assert.equal(await p.locator('#case-navigation a').count(),16);
 await p.locator('#case-navigation [data-case=pay-binding]').click();await p.waitForFunction(()=>document.getElementById('room-meta').textContent.endsWith('pay-binding'));assert.ok((await p.locator('#case-story').innerText()).includes('دولار واحد'));
 await p.locator('#readback').click();await p.waitForFunction(()=>document.getElementById('saved-resource').textContent.includes('revision'));
 assert.ok((await p.locator('#result-summary').innerText()).includes('order100'));
 const statuses=[];p.on('response',r=>{if(r.url().includes('/academy/api/'))statuses.push(r.status());});
 async function send(mode,input){await p.locator('#mode').selectOption(mode);await p.locator('#input').fill(JSON.stringify(input));await p.locator('#send').click();await p.waitForFunction(()=>!document.getElementById('send').disabled);assert.equal(await p.locator('#error').innerText(),'');}
 await send('vulnerable',{payment:'settled-order1'});assert.ok((await p.locator('#http-status').innerText()).startsWith('200'));
 await send('fixed',{payment:'settled-order1'});assert.ok((await p.locator('#http-status').innerText()).startsWith('409'));
 const wire=await p.locator('#response').textContent();assert.ok(wire.includes('HTTP 409'));assert.ok(wire.includes('payment_order_mismatch'));assert.ok(!wire.includes('"impact"'));assert.ok(!wire.includes('"flag"'));
 assert.ok((await p.locator('#saved-resource').textContent()).includes('"revision": 0'));
 await send('fixed',{payment:'settled-order100'});assert.equal(await p.locator('#checks li.done').count(),3);assert.ok((await p.locator('#saved-resource').textContent()).includes('fulfilment_released'));
 assert.deepEqual(statuses,[200,409,200]);
 await p.locator('#language').click();assert.equal(await p.locator('html').getAttribute('dir'),'ltr');
 await send('vulnerable',{payment:'settled-order1'});if(process.env.BB_SCREENSHOT_DIR)await p.screenshot({path:process.env.BB_SCREENSHOT_DIR+'/grouped-checkout-en.png',fullPage:true});
 await p.locator('#next-case').click();await p.waitForFunction(()=>document.getElementById('room-meta').textContent.endsWith('pay-replay'));assert.equal(await p.locator('#case-navigation [aria-current=page]').getAttribute('data-case'),'pay-replay');
 await p.goto(base+'/academy#/code/code-nosql');await p.waitForFunction(()=>document.getElementById('input').value.includes('PASSWORD'));
 await send('fixed',{password:{$ne:null}});assert.ok((await p.locator('#http-status').innerText()).startsWith('422'));
 await p.goto(base+'/academy#/xss/xss-dom-query');await p.waitForFunction(()=>document.querySelectorAll('#case-navigation a').length===12);await p.locator('#payload-choice').selectOption('2');await p.locator('#send').click();await p.waitForFunction(()=>!document.getElementById('send').disabled);await p.waitForFunction(()=>document.getElementById('browser-evidence').textContent.includes('Rendering completed'));
 await p.setViewportSize({width:390,height:844});assert.equal(await p.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
 await p.goto(base);await p.waitForFunction(()=>document.querySelectorAll('.lab-card').length===5);assert.equal(await p.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);if(process.env.BB_SCREENSHOT_DIR)await p.screenshot({path:process.env.BB_SCREENSHOT_DIR+'/grouped-home-mobile.png',fullPage:true});
 await p.locator('.lab-card[href="#/payment"]').click();await p.waitForFunction(()=>document.querySelectorAll('#case-navigation a').length===16);assert.equal(await p.locator('.case-map').getAttribute('open'),null);assert.equal(await p.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);if(process.env.BB_SCREENSHOT_DIR)await p.screenshot({path:process.env.BB_SCREENSHOT_DIR+'/grouped-case-mobile.png',fullPage:true});
 await p.goto(base+'/#idor');await p.waitForURL('**/foundations#idor');await p.waitForFunction(()=>!document.getElementById('lesson').hidden);
 assert.deepEqual(errors,[]);assert.ok(requests.every(url=>new URL(url).hostname==='127.0.0.1'));
 console.log('PASS: default home groups 50 cases into five labs; real 200/409/422 responses; independent persisted readback; business/evidence separation; navigation, languages, mobile and legacy links');await b.close();
})().catch(e=>{console.error(e);process.exit(1)});
