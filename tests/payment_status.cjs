// Payment POST statuses, outcomes and independent GET readback must not be confused.
const {chromium}=require('playwright');const assert=require('node:assert/strict');
(async()=>{
 const b=await chromium.launch({headless:true,executablePath:process.env.BB_BROWSER_PATH,args:['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']});const p=await b.newPage();const errors=[];p.on('pageerror',e=>errors.push(e.message));const base='http://127.0.0.1:8000';
 await p.goto(base);await p.waitForFunction(()=>document.querySelectorAll('.lab-card').length===9);await p.locator('#language').click();
 const cases=await p.evaluate(async()=>(await (await fetch('/academy/catalog')).json()).cases.filter(c=>c.group==='payment'));
 const expected={'price':422,'quantity':422,'discount':422,'coupon-reuse':409,'currency':409,'rounding':422,'total':422,'shipping':422,'tax':422,'status':409,'webhook':401,'binding':409,'replay':200,'gift':409,'refund':409,'trial':409};
 async function run(mode,input){await p.locator('#mode').selectOption(mode);await p.locator('#input').fill(JSON.stringify(input));await p.locator('#send').click();await p.waitForFunction(()=>!document.getElementById('send').disabled);assert.equal(await p.locator('#error').innerText(),'');return Number((await p.locator('#http-status').innerText()).split(' ')[0]);}
 for(const c of cases){
  await p.goto(base+'/academy#/'+c.group+'/'+c.id);await p.waitForFunction(id=>document.getElementById('room-meta').textContent.endsWith(id),c.id);
  assert.equal(await run('vulnerable',c.attack),200,c.id);assert.ok((await p.locator('#decision-note').innerText()).includes('vulnerable variant accepted'));
  assert.equal(await run('fixed',c.normal),200,c.id);
  const status=await run('fixed',c.attack);assert.equal(status,expected[c.id.slice(4)],c.id);
  assert.ok((await p.locator('#http-status').innerText()).includes('POST'));
  const saved=await p.locator('#saved-resource').textContent();assert.ok(saved.startsWith('GET /academy/resource'));assert.ok(saved.includes('HTTP 200'));
  const note=await p.locator('#decision-note').innerText();assert.ok(note.includes(c.id==='pay-replay'?'ignored the repeat':'rejected'),c.id+' '+note);
  assert.equal(await p.locator('#checks li.done').count(),3,c.id);
  console.log(c.id+': vulnerable=200, fixed valid=200, fixed probe='+status);
 }
 for(const id of ['pay-coupon-reuse','pay-gift']){
  const c=cases.find(c=>c.id===id);await p.goto(base+'/academy#/payment/'+id);await p.waitForFunction(id=>document.getElementById('room-meta').textContent.endsWith(id),id);await p.locator('#reset').click();await p.waitForFunction(()=>!document.getElementById('send').disabled&&document.getElementById('response').textContent==='{}');
  assert.equal(await run('fixed',c.attack),207);assert.ok((await p.locator('#decision-note').innerText()).includes('partial outcome'));
 }
 await p.locator('#mode').selectOption('vulnerable');assert.equal(await p.locator('#http-status').innerText(),'');
 await p.locator('#input').fill('{broken json');await p.locator('#send').click();await p.waitForFunction(()=>!document.getElementById('send').disabled);assert.equal(await p.locator('#http-status').innerText(),'');assert.ok(await p.locator('#error').innerText());
 await p.locator('#language').click();assert.equal(await p.locator('html').getAttribute('lang'),'ar');await p.locator('#reset').click();await p.waitForFunction(()=>!document.getElementById('send').disabled&&document.getElementById('response').textContent==='{}');assert.equal(await run('fixed',{spend:6000,repeat:2}),207);assert.ok((await p.locator('#decision-note').innerText()).includes('نتيجة جزئية'));
 assert.deepEqual(errors,[]);console.log('PASS: all 16 payment HTTP outcomes, partial batches, bilingual notes, GET/POST labels and stale-status clearing');await b.close();
})().catch(e=>{console.error(e);process.exit(1)});
