/* Optional integration check: npm install --no-save playwright; npx playwright install chromium.
   Start python app.py separately, then: node tests/browser.cjs */
const {chromium}=require('playwright');
const assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({headless:true,...(process.env.BB_BROWSER_PATH?{executablePath:process.env.BB_BROWSER_PATH,args:['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']}: {})});
 const page=await browser.newPage({viewport:{width:1440,height:1050}});
 const errors=[];const requests=[];page.on('pageerror',e=>errors.push(e.message));page.on('request',r=>requests.push(r.url()));
 await page.goto('http://127.0.0.1:8000');
 assert.equal(await page.locator('.lab-card').count(),7);
 async function start(id){await page.goto('http://127.0.0.1:8000/#'+id);await page.locator('#go-experiment').click();await page.locator('#mission-start').click();await page.waitForFunction(()=>!document.getElementById('mission-send').disabled);}
 async function send(){await page.locator('#mission-send').click();await page.waitForFunction(()=>!document.getElementById('mission-send').disabled);}
 async function mode(value){await page.locator('#task-mode').selectOption(value);}
 async function solved(){assert.ok((await page.locator('#mission-status').innerText()).includes('حُلّ التحدي'));}
 await start('enumeration');
 for(const m of ['vulnerable','fixed']){await mode(m);for(const email of ['alice@example.test','nobody@example.test']){await page.locator('#task-email').fill(email);await send();}}
 await solved();console.log('enumeration challenge PASS');
 await start('rate-limit');
 for(const m of ['vulnerable','fixed']){await mode(m);await page.locator('#task-forwarded').fill('');for(let i=0;i<4;i++)await send();await page.locator('#task-forwarded').fill('192.0.2.1');await send();}
 await solved();console.log('rate limit challenge PASS');
 await start('email-flood');for(const m of ['vulnerable','fixed']){await mode(m);for(let i=0;i<4;i++)await send();}await solved();console.log('email challenge PASS');
 await start('idor');for(const m of ['vulnerable','fixed']){await mode(m);for(const id of ['1001','1002']){await page.locator('#task-resource').fill(id);await send();}}await solved();console.log('IDOR challenge PASS');
 const payload='<img src=x onerror="alert(\'BB-LAB\')">';
 for(const id of ['reflected-xss','dom-xss']){
  await start(id);await page.locator('#task-payload').fill('<b>hello</b>');await send();
  assert.ok(!(await page.locator('#mission-status').innerText()).includes('حُلّ التحدي'));
  await page.locator('#task-payload').fill(payload);await send();
  let rows=JSON.parse(await page.locator('#mission-evidence').textContent());assert.equal(rows.at(-1).executed,true);
  await mode('fixed');await send();await solved();
  rows=JSON.parse(await page.locator('#mission-evidence').textContent());assert.equal(rows.at(-1).rendered.text,payload);assert.equal(rows.at(-1).executed,false);
  const frame=page.frames().find(f=>f.url().includes('/preview/'));
  assert.equal(await frame.evaluate(()=>{try{void parent.document.body;return false;}catch(_){return true;}}),true);
  console.log(id+' browser execution + isolation PASS');
 }
 assert.ok(requests.filter(url=>url.includes('/preview/dom-xss/')).every(url=>!new URL(url).searchParams.has('q')));
 await start('edge403');for(const m of ['vulnerable','fixed']){await mode(m);for(const layer of ['edge','origin']){await page.locator('#task-layer').selectOption(layer);await send();}}await solved();
 assert.equal(await page.locator('#progress').innerText(),'7 / 7');
 await page.setViewportSize({width:390,height:844});
 await start('idor');assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
 if(process.env.BB_SCREENSHOT_DIR)await page.screenshot({path:process.env.BB_SCREENSHOT_DIR+'/labs-mobile-v3.png',fullPage:true});
 await page.goto('http://127.0.0.1:8000/#home');
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
 await page.setViewportSize({width:1440,height:1050});
 if(process.env.BB_SCREENSHOT_DIR)await page.screenshot({path:process.env.BB_SCREENSHOT_DIR+'/labs-desktop-v3.png',fullPage:true});
 assert.deepEqual(errors,[]);
 // A guided demonstration must not mark a hands-on challenge solved.
 await page.locator('#clear-progress').click();await page.goto('http://127.0.0.1:8000/#enumeration');await page.locator('#go-experiment').click();await page.locator('#compare').click();await page.waitForFunction(()=>document.getElementById('live-status').textContent.includes('اكتملت المقارنة'));
 assert.equal(await page.locator('#progress').innerText(),'0 / 7');
 console.log('All 7 hands-on challenges, progress, browser isolation and mobile overflow: PASS');
 await browser.close();
})().catch(e=>{console.error(e);process.exit(1)});
