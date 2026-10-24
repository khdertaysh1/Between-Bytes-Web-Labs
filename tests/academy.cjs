// Optional browser integration: BB_BROWSER_PATH=/path/to/chromium node tests/academy.cjs
const {chromium}=require('playwright');const assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.BB_BROWSER_PATH,args:['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']});
 const context=await browser.newContext({viewport:{width:1440,height:1050}});const page=await context.newPage();const errors=[],requests=[];page.on('pageerror',e=>errors.push(e.message));page.on('request',r=>requests.push(r.url()));
 const base='http://127.0.0.1:8000';await page.goto(base+'/academy');await page.waitForFunction(()=>document.querySelectorAll('.scenario-card').length===5);
 assert.equal(await page.locator('html').getAttribute('dir'),'rtl');
 await page.locator('#language').click();assert.equal(await page.locator('html').getAttribute('dir'),'ltr');
 const catalog=await page.evaluate(async()=> (await (await fetch('/academy/catalog')).json()).cases);
 async function run(mode,input,xss=false){
  await page.locator('#mode').selectOption(mode);await page.locator('#input').fill(JSON.stringify(input));await page.locator('#send').click();await page.waitForFunction(()=>!document.getElementById('send').disabled);
  assert.equal(await page.locator('#error').innerText(),'');
  if(xss)await page.waitForFunction(()=>{const v=document.getElementById('browser-evidence').textContent;return v.includes('Rendering completed')||v.includes('Browser observed');});
  if(xss)await page.waitForTimeout(650);
 }
 for(const c of catalog){
  await page.goto(base+'/academy#'+c.id);await page.waitForFunction(id=>document.getElementById('room-meta').textContent.endsWith(id),c.id);
  assert.equal(await page.locator('#case-title').innerText(),c.title.en);
  const isXss=c.group==='xss';
  await run('fixed',c.normal,isXss);
  if(c.group==='rate')await run('vulnerable',c.normal);
  await run('vulnerable',c.attack,isXss);
  if(isXss)assert.ok((await page.locator('#browser-evidence').innerText()).includes('Browser observed'),c.id+' missing browser evidence');
  await run('fixed',c.attack,isXss);
  assert.equal(await page.locator('#checks li.done').count(),3,c.id+' incomplete: '+await page.locator('#checks').innerText());
  if(!isXss)assert.ok((await page.locator('#flag').innerText()).startsWith('BB{'),c.id+' missing flag');
  if(isXss)assert.equal(await page.locator('#flag').innerText(),'');
  const arabic=(await page.locator('body').innerText()).split('\n').filter(s=>/[\u0600-\u06ff]/.test(s)&&s.trim()!=='العربية');assert.deepEqual(arabic,[],c.id+' untranslated');
  console.log('PASS '+c.id);
 }
 await page.locator('#language').click();assert.equal(await page.locator('html').getAttribute('lang'),'ar');
 await page.setViewportSize({width:390,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
 await page.goto(base+'/academy');await page.waitForFunction(()=>document.querySelectorAll('.scenario-card').length===5);
 assert.equal(await page.locator('#total-done').innerText(),'50');assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
 await page.locator('#search').fill('double');assert.ok(await page.locator('.scenario-card').count()>0);assert.ok(await page.locator('.scenario-card').count()<50);
 await page.locator('#search').fill('');await page.locator('#groups button').nth(1).click();assert.equal(await page.locator('.scenario-card').count(),1);
 if(process.env.BB_SCREENSHOT_DIR){await page.screenshot({path:process.env.BB_SCREENSHOT_DIR+'/academy-mobile.png',fullPage:true});await page.setViewportSize({width:1440,height:1050});await page.screenshot({path:process.env.BB_SCREENSHOT_DIR+'/academy-desktop.png',fullPage:true});await page.goto(base+'/academy#pay-binding');await page.waitForFunction(()=>document.getElementById('case-title').textContent.includes('ربط'));await run('vulnerable',{payment:'settled-order1'});await page.screenshot({path:process.env.BB_SCREENSHOT_DIR+'/academy-room.png',fullPage:true});}
 const other=await browser.newContext();const p2=await other.newPage();await p2.goto(base+'/academy');await p2.waitForFunction(()=>document.querySelectorAll('.scenario-card').length===5);assert.equal(await p2.locator('#total-done').innerText(),'0');
 assert.deepEqual(errors,[]);assert.ok(requests.every(u=>new URL(u).hostname==='127.0.0.1'),requests.filter(u=>new URL(u).hostname!=='127.0.0.1').join('\n'));
 console.log('PASS: 50 cases, 11 executing XSS contexts plus URL policy inspection, fixed controls, matching evidence, bilingual UI, mobile, session isolation and no external requests');await browser.close();
})().catch(e=>{console.error(e);process.exit(1)});
