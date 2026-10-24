/* Optional integration check: npm install --no-save playwright; npx playwright install chromium.
   Start python app.py separately, then: node tests/browser.cjs */
const {chromium}=require('playwright');
const assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({headless:true,...(process.env.BB_BROWSER_PATH?{executablePath:process.env.BB_BROWSER_PATH,args:['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']}: {})});
 const page=await browser.newPage({viewport:{width:1440,height:1050}});
 const errors=[];const requests=[];page.on('pageerror',e=>errors.push(e.message));page.on('request',r=>requests.push(r.url()));
 await page.goto('http://127.0.0.1:8000');
 assert.equal(await page.locator('.lab-card').count(),13);
 async function start(id,exam=true){await page.goto('http://127.0.0.1:8000/#'+id);await page.locator('[data-tab=learn]').click();await page.locator('#go-experiment').click();if(exam){await page.locator('#go-fix').click();await page.locator('#exam-start').click();}else{await page.locator('#mission-start').click();}await page.waitForFunction(()=>!document.getElementById('mission-send').disabled);}
 async function send(){await page.locator('#mission-send').click();await page.waitForFunction(()=>!document.getElementById('mission-send').disabled);}
 async function mode(value){await page.locator('#task-mode').selectOption(value);}
 async function solved(){assert.ok((await page.locator('#mission-status').innerText()).includes('اجتزت الاختبار'));}
 await page.goto('http://127.0.0.1:8000/#idor');
 await page.waitForFunction(()=>!document.getElementById('home').hidden);
 assert.ok((await page.locator('#course-notice').innerText()).includes('مقفل'));
 await start('enumeration',false);
 for(const m of ['vulnerable','fixed']){await mode(m);for(const email of ['alice@example.test','nobody@example.test']){await page.locator('#task-email').fill(email);await send();}}
 assert.ok((await page.locator('#mission-status').innerText()).includes('حُلّ التحدي التدريبي'));
 assert.equal(await page.locator('#score-total').innerText(),'0 / 1300 نقطة');
 await start('enumeration');
 for(const m of ['vulnerable','fixed']){await mode(m);for(const email of ['bob@example.test','visitor@example.test']){await page.locator('#task-email').fill(email);await send();}}
 await solved();console.log('enumeration challenge PASS');
 await start('rate-limit');
 for(const m of ['vulnerable','fixed']){await mode(m);await page.locator('#task-forwarded').fill('');for(let i=0;i<4;i++)await send();await page.locator('#task-forwarded').fill('192.0.2.1');await send();}
 await solved();console.log('rate limit challenge PASS');
 await start('email-flood');for(const m of ['vulnerable','fixed']){await mode(m);for(let i=0;i<4;i++)await send();}await solved();assert.equal(await page.locator('#score-total').innerText(),'300 / 1300 نقطة');console.log('email challenge PASS');
 await start('idor');for(const m of ['vulnerable','fixed']){await mode(m);for(const id of ['2001','2002']){await page.locator('#task-resource').fill(id);await send();}}await solved();console.log('IDOR challenge PASS');
 await start('edge403');for(const m of ['vulnerable','fixed']){await mode(m);for(const layer of ['edge','origin']){await page.locator('#task-layer').selectOption(layer);await send();}}await solved();
 assert.equal(await page.locator('#score-total').innerText(),'500 / 1300 نقطة');
 const payload='<img src=x onerror="alert(\'BB-EXAM\')">';
 for(const id of ['reflected-xss','dom-xss']){
  await start(id);await page.locator('#task-payload').fill('<b>hello</b>');await send();
  assert.ok(!(await page.locator('#mission-status').innerText()).includes('اجتزت الاختبار'));
  await page.locator('#task-payload').fill(payload);await send();
  let rows=JSON.parse(await page.locator('#mission-evidence').textContent());assert.equal(rows.at(-1).executed,true);
  await mode('fixed');await send();await solved();
  rows=JSON.parse(await page.locator('#mission-evidence').textContent());assert.equal(rows.at(-1).rendered.text,payload);assert.equal(rows.at(-1).executed,false);
  const frame=page.frames().find(f=>f.url().includes('/preview/'));
  assert.equal(await frame.evaluate(()=>{try{void parent.document.body;return false;}catch(_){return true;}}),true);
  console.log(id+' browser execution + isolation PASS');
 }

 assert.equal(await page.locator('#score-total').innerText(),'700 / 1300 نقطة');
 await start('csrf');
 for(const [m,source] of [['vulnerable','attacker'],['fixed','attacker'],['fixed','legitimate']]){await mode(m);await page.locator('#task-source').selectOption(source);await page.locator('#task-value').fill('exam-csrf');await send();}
 await solved();console.log('CSRF: real second-origin write, fixed rejection and legitimate success PASS');
 await start('cors');
 for(const [m,source] of [['vulnerable','attacker'],['fixed','attacker'],['fixed','legitimate']]){await mode(m);await page.locator('#task-source').selectOption(source);await send();}
 await solved();console.log('CORS: real credentialed browser read and denial PASS');
 assert.equal(await page.locator('#score-total').innerText(),'900 / 1300 نقطة');
 await start('open-redirect');for(const m of ['vulnerable','fixed']){await mode(m);for(const value of ['/account','https://outside.example/exam']){await page.locator('#task-value').fill(value);await send();}}await solved();
 await start('ssrf');for(const m of ['vulnerable','fixed']){await mode(m);for(const value of ['http://internal.lab/config','http://public.lab/redirect','http://public.lab/welcome']){await page.locator('#task-value').fill(value);await send();}}await solved();
 assert.equal(await page.locator('#score-total').innerText(),'1100 / 1300 نقطة');
 await start('api-keys');for(const m of ['vulnerable','fixed']){await mode(m);await page.locator('#task-value').fill('/assets/billing.js');await send();}await solved();
 await start('exposed-files');await page.locator('#task-value').fill('/robots.txt');await send();for(const m of ['vulnerable','fixed']){await mode(m);await page.locator('#task-value').fill('/backups/settings.env');await send();}await mode('fixed');await page.locator('#task-value').fill('/public/readme.txt');await send();await solved();
 console.log('Redirect/SSRF models and API key/environment file exercises PASS');
 assert.ok(requests.filter(url=>url.includes('/preview/dom-xss/')).every(url=>!new URL(url).searchParams.has('q')));

 assert.equal(await page.locator('#progress').innerText(),'13 / 13');
 assert.equal(await page.locator('#score-total').innerText(),'1300 / 1300 نقطة');
 await page.reload();assert.equal(await page.locator('#score-total').innerText(),'1300 / 1300 نقطة');
 await start('idor');for(const m of ['vulnerable','fixed']){await mode(m);for(const id of ['2001','2002']){await page.locator('#task-resource').fill(id);await send();}}await solved();
 assert.equal(await page.locator('#score-total').innerText(),'1300 / 1300 نقطة');
 await page.setViewportSize({width:390,height:844});
 await start('csrf');await mode('vulnerable');await page.locator('#task-value').fill('mobile-exam');await send();assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
 if(process.env.BB_SCREENSHOT_DIR)await page.screenshot({path:process.env.BB_SCREENSHOT_DIR+'/labs-mobile-v3.png',fullPage:true});
 await page.goto('http://127.0.0.1:8000/#home');
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
 await page.setViewportSize({width:1440,height:1050});
 if(process.env.BB_SCREENSHOT_DIR)await page.screenshot({path:process.env.BB_SCREENSHOT_DIR+'/labs-desktop-v3.png',fullPage:true});
 assert.deepEqual(errors,[]);assert.ok(requests.every(url=>new URL(url).hostname==='127.0.0.1')); 
 // A guided demonstration must not mark a hands-on challenge solved.
 page.once('dialog',dialog=>dialog.accept());await page.locator('#clear-progress').click();await page.goto('http://127.0.0.1:8000/#enumeration');await page.locator('#go-experiment').click();await page.locator('#compare').click();await page.waitForFunction(()=>document.getElementById('live-status').textContent.includes('اكتملت المقارنة'));
 assert.equal(await page.locator('#progress').innerText(),'0 / 13');
 console.log('All 13 practical exams, practice separation, one-time scores, level locks, reload, isolation and mobile: PASS');
 await browser.close();
})().catch(e=>{console.error(e);process.exit(1)});
