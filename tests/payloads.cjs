// Exercise all primary, alternate and negative payloads against both variants.
const {chromium}=require('playwright');const assert=require('node:assert/strict');
(async()=>{
 const b=await chromium.launch({headless:true,executablePath:process.env.BB_BROWSER_PATH,args:['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']});const p=await b.newPage();await p.goto('http://127.0.0.1:8000/academy');
 const results=await p.evaluate(async()=>{
  await fetch('/rooms/session');const cases=(await (await fetch('/academy/catalog')).json()).cases.filter(c=>c.group==='xss');const results=[];
  for(const c of cases){
   const probes=c.payloads.flatMap((probe,index)=>['vulnerable','fixed'].map(mode=>({probe,index,mode})));
   const group=await Promise.all(probes.map(async({probe,index,mode})=>{
    const r=await (await fetch('/academy/run',{method:'POST',body:new URLSearchParams({case:c.id,mode,input:JSON.stringify({value:probe.value})})})).json();
    return new Promise(resolve=>{
     const frame=document.createElement('iframe');frame.sandbox='allow-scripts';let executed=false,policy=null,timer;
     const listener=e=>{if(e.source!==frame.contentWindow||e.data?.token!==r.token)return;if(e.data.type==='academy-executed')executed=true;if(e.data.type==='academy-url-policy')policy=e.data.dangerous;if(e.data.type==='academy-rendered'){clearTimeout(timer);timer=setTimeout(finish,350);}};
     function finish(){removeEventListener('message',listener);frame.remove();resolve({id:c.id,index,mode,executed,expected:probe.expected_execution&&mode==='vulnerable',policy});}
     addEventListener('message',listener);let url=r.preview;if(c.id==='xss-dom-fragment')url+='#'+encodeURIComponent(probe.value);if(c.id==='xss-dom-query')url+='?search='+encodeURIComponent(probe.value);frame.src=url;document.body.append(frame);timer=setTimeout(finish,5000);
    });
   }));results.push(...group);
  }return results;
 });
 assert.equal(results.length,72);for(const r of results){assert.equal(r.executed,r.expected,JSON.stringify(r));if(r.id==='xss-url')assert.equal(r.policy,r.mode==='vulnerable'&&r.index<2,JSON.stringify(r));}
 console.log('PASS: all 36 payload/control samples in both variants (72 sandboxed browser observations), including inert encodings and DOM-inserted script elements');await b.close();
})().catch(e=>{console.error(e);process.exit(1)});
