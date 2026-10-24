// Four independent labs, legacy UI removal, state/response meaning and bilingual layout.
const {chromium}=require('playwright');const assert=require('node:assert/strict');
(async()=>{
 const b=await chromium.launch({headless:true,executablePath:process.env.BB_BROWSER_PATH,args:['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']});
 const p=await b.newPage({viewport:{width:1440,height:1000}});const errors=[],requests=[];p.on('pageerror',e=>errors.push(e.message));p.on('request',r=>requests.push(r.url()));const base='http://127.0.0.1:8000';
 await p.goto(base);await p.waitForFunction(()=>document.querySelectorAll('.lab-card').length===9);
 assert.equal(await p.locator('a[href="/foundations"]').count(),0);assert.ok((await p.locator('header').innerText()).includes('0.11.0'));
 const catalog=await p.evaluate(async()=> (await (await fetch('/academy/catalog')).json()).cases);assert.equal(catalog.length,72);
 for(const name of ['index.html','ui.js','catalog.js','progression.js','course.js','new_lessons.js','challenges.js','rooms_ui.js','i18n.js','english.js','style.css'])assert.equal((await p.request.get(base+'/'+name)).status(),404,name);
 async function send(mode,input){await p.locator('#mode').selectOption(mode);await p.locator('#input').fill(JSON.stringify(input));await p.locator('#send').click();await p.waitForFunction(()=>!document.getElementById('send').disabled);assert.equal(await p.locator('#error').innerText(),'');}
 for(const group of ['ssrf','csrf','cors','redirect']){
  await p.goto(base+'/academy#/'+group);await p.waitForFunction(()=>document.querySelectorAll('#case-navigation a').length===6);
  assert.equal(await p.locator('#case-navigation a').count(),6);assert.equal(catalog.filter(c=>c.group===group).length,6);
  assert.ok((await p.locator('#source-note').innerText()).includes('نموذج'));
  for(const c of catalog.filter(c=>c.group===group)){
   if(!(await p.locator('#room-meta').textContent()).endsWith(c.id))await p.locator('#case-navigation [data-case="'+c.id+'"]').click();await p.waitForFunction(id=>document.getElementById('room-meta').textContent.endsWith(id),c.id);
   assert.equal(await p.locator('#steps li').count(),3);assert.ok((await p.locator('.lesson').innerText()).includes('كيف تعمل الميزة؟'));
   await send('fixed',c.normal);await send('vulnerable',c.attack);await send('fixed',c.attack);assert.equal(await p.locator('#checks li.done').count(),3,c.id);
   if(group==='cors'){assert.ok((await p.locator('#http-status').innerText()).startsWith('200'));assert.ok((await p.locator('#result-summary').innerText()).includes('السماح بقراءة الاستجابة'));}
   if(group==='csrf'){assert.ok((await p.locator('#result-summary').innerText()).includes('الملاحظة قبل الطلب'));assert.ok((await p.locator('#response').textContent()).includes(c.id==='csrf-get'?'method_not_allowed':c.id==='csrf-content-type'?'unsupported_content_type':'csrf_verification_failed'));}
  }
  await p.setViewportSize({width:390,height:844});assert.equal(await p.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,group+' mobile overflow');await p.setViewportSize({width:1440,height:1000});
 }
 await p.goto(base+'/foundations#csrf');await p.waitForURL('**/academy#/csrf/csrf-missing');await p.waitForFunction(()=>document.getElementById('room-meta').textContent.endsWith('csrf-missing'));
 await p.goto(base+'/#cors');await p.waitForURL('**/#/cors/cors-reflect');
 await p.locator('#language').click();await p.waitForFunction(()=>document.documentElement.lang==='en');
 for(const group of ['ssrf','csrf','cors','redirect']){
  const c=catalog.find(c=>c.group===group);await p.goto(base+'/academy#/'+group+'/'+c.id);await p.waitForFunction(id=>document.getElementById('room-meta').textContent.endsWith(id),c.id);await send('fixed',c.normal);
  const arabic=(await p.locator('body').innerText()).split('\n').filter(s=>/[\u0600-\u06ff]/.test(s)&&s.trim()!=='العربية');assert.deepEqual(arabic,[],group+' untranslated');
 }
 if(process.env.BB_SCREENSHOT_DIR){await p.locator('#language').click();await p.goto(base+'/academy#/csrf/csrf-binding');await p.waitForFunction(()=>document.getElementById('room-meta').textContent.endsWith('csrf-binding'));await send('fixed',catalog.find(c=>c.id==='csrf-binding').attack);await p.screenshot({path:process.env.BB_SCREENSHOT_DIR+'/request-security-ar.png',fullPage:true});await p.goto(base);await p.waitForFunction(()=>document.querySelectorAll('.lab-card').length===9);await p.screenshot({path:process.env.BB_SCREENSHOT_DIR+'/nine-labs-ar.png',fullPage:true});}
 assert.deepEqual(errors,[]);assert.ok(requests.every(u=>new URL(u).hostname==='127.0.0.1'));console.log('PASS: four independent six-case labs; 24 workflows; legacy UI removed; bilingual/mobile layout; local-only requests');await b.close();
})().catch(e=>{console.error(e);process.exit(1)});
