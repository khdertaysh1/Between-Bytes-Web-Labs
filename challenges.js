'use strict';
let mission = null;
const instructions = {
 enumeration:{goal:'ميّز بين حساب موجود وغير موجود في الضعيفة، ثم أثبت أن الردّين متطابقان في المُصلحة.',checks:['الموجود في الضعيفة: 200','غير الموجود في الضعيفة: 404','طلب للحسابين في المُصلحة: نفس 202 والرسالة'],hints:['ابدأ بـ alice@example.test ثم جرّب nobody@example.test.','غيّر النسخة وكرّر البريدين؛ اقرأ حالة HTTP والجسم معاً.']},
 'rate-limit':{goal:'أوصل الطلب إلى المنع، ثم غيّر الترويسة بيدك. اجمع دليلاً على التجاوز في الضعيفة وبقاء المنع في المُصلحة.',checks:['شاهد 429 دون تغيير الترويسة في الضعيفة','غيّر الترويسة بعد المنع وشاهد 401 في الضعيفة','في المُصلحة: الوصول للمنع ثم تغيير الترويسة يبقى 429'],hints:['أرسل 4 طلبات بالنسخة الضعيفة مع ترك الترويسة فارغة.','بعد 429 اكتب 192.0.2.1 في الترويسة وأرسل طلباً واحداً.','في المُصلحة أرسل 4 طلبات، ثم غيّر الترويسة. 401 يعني رفض الدخول، وليس نجاحه.']},
 'email-flood':{goal:'أرسل أربعة طلبات في كل نسخة، واحسب الرسائل المنشأة في الصندوق الوهمي.',checks:['4 رسائل في الضعيفة','4 طلبات في المُصلحة','رسالة واحدة في المُصلحة خلال 60 ثانية'],hints:['استخدم alice@example.test أربع مرات في الضعيفة.','بدّل النسخة وكرّر أربع مرات بسرعة؛ اقرأ mail_count في دفتر الدليل.']},
 idor:{goal:'أنت Alice دائماً. اقرأ فاتورتك، غيّر رقمها للوصول إلى بيانات Bob، ثم تحقق من صلاحيات النسخة المُصلحة.',checks:['فاتورة Alice في الضعيفة','فاتورة Bob في الضعيفة','المُصلحة ترفض فاتورة Bob','المُصلحة تسمح بفاتورة Alice'],hints:['فاتورتك 1001؛ ابدأ بها ولاحظ حقل owner.','عدّل resource من 1001 إلى 1002، مع بقاء actor هو alice.','اختر المُصلحة: جرّب 1002 ثم 1001.']},
 'reflected-xss':{goal:'اكتب مدخلاً يطلق alert("BB-LAB") في الضعيفة، ثم اختبر المدخل نفسه في المُصلحة وأثبت عرضه كنص.',checks:['رُصد تنفيذ BB-LAB في الإطار الضعيف','نفس المدخل ظهر كنص في المُصلحة دون إشارة تنفيذ خلال المعاينة'],hints:['ابدأ بـ <b>hello</b>؛ هذا تفسير HTML وليس تنفيذ JavaScript.','وسم صورة غير صالحة يستطيع إطلاق حدث onerror.','مثال لهذا المختبر فقط: <img src=x onerror="alert(\'BB-LAB\')">']},
 'dom-xss':{goal:'تتبّع إدخال النص عبر postMessage إلى innerHTML، ثم جرّب نفس المدخل مع textContent.',checks:['رُصد تنفيذ BB-LAB في نقطة إدراج DOM الضعيفة','نفس المدخل صار نصاً في المُصلحة دون إشارة تنفيذ خلال المعاينة'],hints:['المدخل يصل إلى المتصفح كرسالة ولا يذهب للخادم.','innerHTML لا يشغّل وسم script المضاف بهذه الطريقة عادة؛ جرّب حدث عنصر.','مثال داخل الإطار: <img src=x onerror="alert(\'BB-LAB\')">']},
 edge403:{goal:'قارن مساري edge وorigin الوهميين للزائر المجهول، ثم أثبت أن المُصلحة تمنع الاثنين.',checks:['edge الضعيف يعيد 403','origin الضعيف يعيد بيانات إدارية 200','edge المُصلح يعيد 403','origin المُصلح يعيد 403'],hints:['المدخل layer يختار مساراً وهمياً داخل التطبيق نفسه.','جرّب edge ثم origin في الضعيفة.','كرّر الاختبارين في المُصلحة. هذا خطأ صلاحيات الأصل، وليس تجاوز Cloudflare فعلياً.']}
};
for(const [id,l] of Object.entries(advancedLessons))instructions[id]={goal:l.goal,checks:l.checks,hints:l.hints};
I18n.applyInstructions(instructions);
function setupChallenge(id, exam=false) {
  if(mission?.pending) mission.pending.cancel();
  mission={id,exam,active:false,rows:[],hints:0,pending:null};
  const spec=JSON.parse(JSON.stringify(instructions[id]));
  mission.existing=exam?'bob@example.test':'alice@example.test';mission.missing=exam?'visitor@example.test':'nobody@example.test';
  mission.own=exam?'2001':'1001';mission.other=exam?'2002':'1002';mission.marker=exam?'BB-EXAM':'BB-LAB';
  if(exam){spec.goal=courseContent[id].exam;spec.checks=spec.checks.map(t=>t.replaceAll('BB-LAB','BB-EXAM'));}
  mission.spec=spec;
  $('mission-start').textContent=exam?tr('إعادة بدء الاختبار'):tr('ابدأ / صفّر التدريب');
  $('mission-kind').textContent=exam?tr('تمرين اختباري مستقل'):tr('تدريب مع تلميحات');
  $('mission-title').textContent=exam?tr('طبّق ما فهمته دون تلميحات'):tr('اكتشف الفرق بنفسك');
  document.querySelector('.hints').hidden=exam;
  $('guided-demo').hidden=exam||!!extraLessons[id];
  $('mission-goal').textContent=spec.goal;
  $('mission-checks').replaceChildren(...spec.checks.map(text=>{const li=document.createElement('li');li.textContent='○ '+text;return li;}));
  $('mission-status').textContent=tr('اضغط «ابدأ» ثم عدّل المدخلات بنفسك.');
  $('mission-response').textContent=tr('لم تُرسل طلبات بعد.');
  $('mission-send').disabled=true;$('hint-text').textContent='';$('mission-evidence').textContent='[]';
  $('browser-frame-area').hidden=true;$('browser-frame').removeAttribute('src');
  $('preview-area').hidden=true;$('xss-preview').removeAttribute('src');
  const mode=tr('<label>النسخة<select id="task-mode"><option value="vulnerable">ضعيفة</option><option value="fixed">مُصلحة</option></select></label>');
  let fields=mode;
  if(advancedLessons[id])fields+=advancedInputs(id);
  else if(id==='idor') fields+=tr('<label>رقم الفاتورة · resource<input id="task-resource" value="1001" maxlength="12" inputmode="numeric"></label>');
  else if(id==='edge403') fields+=tr('<label>المسار الوهمي · layer<select id="task-layer"><option value="edge">edge · البوابة</option><option value="origin">origin · الخادم الأصلي</option></select></label>');
  else if(id.endsWith('xss')) fields+=tr('<label class="wide">مدخل البحث · اكتب بنفسك<textarea id="task-payload" maxlength="1000" dir="ltr">hello</textarea></label>');
  else fields+=tr('<label>البريد<input id="task-email" type="email" value="alice@example.test" required></label>')+(id==='rate-limit'?tr('<label>ترويسة X-Forwarded-For<input id="task-forwarded" placeholder="فارغ أولاً، ثم غيّر القيمة" maxlength="100"></label>'):'');
  $('mission-inputs').innerHTML=fields;
  if(exam&&$('task-email'))$('task-email').value=mission.existing;
  if(exam&&id==='csrf')$('task-value').value='exam-csrf';
  if(exam&&$('task-resource'))$('task-resource').value=mission.own;
  if(typeof RoomUI!=='undefined')RoomUI.render();
}
function gradeMission() {
  const rows=mission.rows;
  const has=(mode,predicate)=>rows.some(r=>r.mode===mode&&predicate(r));
  const id=mission.id;
  let checks=[];
  if(advancedLessons[id])checks=gradeAdvanced(id,rows);
  else if(id==='idor') checks=[has('vulnerable',r=>r.input===mission.own&&r.status===200&&r.body.invoice?.owner==='alice'),has('vulnerable',r=>r.input===mission.other&&r.status===200&&r.body.invoice?.owner==='bob'),has('fixed',r=>r.input===mission.other&&r.status===403),has('fixed',r=>r.input===mission.own&&r.status===200)];
  else if(id==='edge403') checks=['vulnerable','fixed'].flatMap(mode=>['edge','origin'].map(layer=>has(mode,r=>r.input===layer&&r.status===(mode==='vulnerable'&&layer==='origin'?200:403))));
  else if(id==='enumeration') checks=[has('vulnerable',r=>r.input===mission.existing&&r.status===200),has('vulnerable',r=>r.input===mission.missing&&r.status===404),[mission.existing,mission.missing].every(email=>has('fixed',r=>r.input===email&&r.status===202))&&new Set(rows.filter(r=>r.mode==='fixed').map(r=>JSON.stringify(r.body))).size===1];
  else if(id==='rate-limit') {
    const first=rows.findIndex(r=>r.mode==='vulnerable'&&r.status===429&&!r.forwarded);
    const fixedFirst=rows.findIndex(r=>r.mode==='fixed'&&r.status===429&&!r.forwarded);
    checks=[first>=0,first>=0&&rows.some((r,i)=>i>first&&r.mode==='vulnerable'&&r.forwarded&&r.status===401),fixedFirst>=0&&rows.some((r,i)=>i>fixedFirst&&r.mode==='fixed'&&r.forwarded&&r.status===429)];
  } else if(id==='email-flood') checks=[has('vulnerable',r=>r.mail_count>=4),rows.filter(r=>r.mode==='fixed'&&r.status===202).length>=4,rows.filter(r=>r.mode==='fixed').at(-1)?.mail_count===1];
  else {
    const executed=rows.find(r=>r.mode==='vulnerable'&&r.executed);
    checks=[!!executed,!!executed&&has('fixed',r=>r.input===executed.input&&!r.executed&&r.rendered?.text===r.input&&r.rendered?.images===0)];
  }
  [...$('mission-checks').children].forEach((li,i)=>{li.classList.toggle('done',!!checks[i]);li.textContent=(checks[i]?'✓ ':'○ ')+mission.spec.checks[i];});
  if(checks.every(Boolean)) {
    if(mission.exam){
      const fresh=courseProgress.complete(id);saveProgress();
      $('mission-status').textContent=fresh?tr('اجتزت الاختبار العملي! يمكنك الانتقال لأي درس تختاره.'):tr('اجتزت الاختبار مجدداً. يمكنك إعادة التدريب أو اختيار أي درس آخر.');
    }else{
      completed.add(id);saveProgress();$('mission-status').textContent=tr('حُلّ التحدي التدريبي. راجع شرح الإصلاح ثم جرّب الاختبار العملي لتطبيق فهمك.');
    }
  }
}
function addEvidence(row) {
  $('mission-response').textContent=JSON.stringify(row,null,2);
  mission.rows.push({...row,at:new Date().toISOString()});
  if(typeof RoomUI!=='undefined')RoomUI.showApplicationResult(row);
  $('mission-evidence').textContent=JSON.stringify(mission.rows,null,2);
  gradeMission();
}
async function startMission(exam=false){
  if(busy)return;
  lock(true);$('mission-send').disabled=true;
  try{if(typeof RoomUI!=='undefined')await RoomUI.start();await reset();setupChallenge(current,exam);mission.active=true;$('mission-status').textContent=exam?tr('بدأ الاختبار: اقرأ المهمة واجمع الأدلة دون تلميحات.'):tr('التدريب جاهز. عدّل المدخلات واقرأ النتائج.');tab('experiment');}
  catch(error){$('mission-status').textContent=tr('تعذر بدء الجولة: ')+error.message;}
  finally{lock(false);$('mission-send').disabled=!mission.active;}
}
$('mission-start').onclick=()=>startMission(mission?.exam||false);
$('practice-return').onclick=()=>startMission(false);
$('exam-start').onclick=()=>startMission(true);
async function accessRequest(kind, mode, field, value) {
  const path=`/lab/${kind}/${mode}`;
  const response=await fetch(path,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({[field]:value}),signal:AbortSignal.timeout(8000)});
  return {path,status:response.status,body:await response.json()};
}
function previewXss(kind,mode,input) {
  return new Promise((resolve,reject)=>{
    const frame=$('xss-preview');
    const bytes=crypto.getRandomValues(new Uint8Array(16));
    const token=[...bytes].map(n=>n.toString(16).padStart(2,'0')).join('');
    const query=new URLSearchParams({token});
    if(kind==='reflected-xss')query.set('q',input);
    const path=`/preview/${kind}/${mode}?${query}`;
    let rendered=null,executed=false,finished=false,settle;
    function finish(error) {
      if(finished)return;finished=true;
      clearTimeout(timeout);clearTimeout(settle);window.removeEventListener('message',onMessage);mission.pending=null;
      if(error)reject(error);else resolve({mode,input,path,transport:kind==='dom-xss'?'postMessage (payload stays in browser)':'GET query reflected by local server',executed,rendered,observation_ms:650});
    }
    function onMessage(event) {
      if(event.source!==frame.contentWindow||event.data?.token!==token)return;
      const data=event.data;
      if(data.type==='bb-ready'&&kind==='dom-xss')frame.contentWindow.postMessage({token,value:input},'*');
      if(data.type==='bb-executed'&&data.value===mission.marker)executed=true;
      if(data.type==='bb-rendered'&&typeof data.text==='string'&&typeof data.images==='number'){
        rendered={text:data.text.slice(0,2000),images:data.images};
        clearTimeout(settle);settle=setTimeout(()=>finish(),650);
      }
    }
    window.addEventListener('message',onMessage);
    const timeout=setTimeout(()=>finish(new Error(tr('لم تصل نتيجة من إطار التدريب. تحقق من تحميله وسياسة المتصفح.'))),5000);
    mission.pending={cancel:()=>finish(new Error(tr('توقفت معاينة التحدي')))};
    $('preview-area').hidden=false;
    frame.src=path;
  });
}
$('mission-form').onsubmit=async event=>{
  event.preventDefault();if(busy||!mission.active)return;
  if(mission.rows.length>=60){$('mission-status').textContent=tr('وصلت لحد 60 تجربة في هذه الجولة؛ ابدأ جولة جديدة.');return;}
  lock(true);$('mission-send').disabled=true;$('mission-start').disabled=true;
  const id=current,mode=$('task-mode').value;
  try{
    let row;
    if(advancedLessons[id]){row=await runAdvanced(id,mode);$('mission-status').textContent=tr('وصل دليل التجربة. اقرأ آخر استجابة وحدّد الخطوة التالية من قائمة المهمة.');}
    else if(id==='idor'||id==='edge403'){
      const input=id==='idor'?$('task-resource').value:$('task-layer').value;
      row={mode,input,...await accessRequest(id,mode,id==='idor'?'resource':'layer',input)};
      $('mission-status').textContent=tr(`HTTP ${row.status} · اقرأ الجسم في دفتر الدليل. actor هوية يحددها الخادم، وليست حقلاً ترسله.`);
    }else if(id.endsWith('xss')){
      row=await previewXss(id,mode,$('task-payload').value);
      $('mission-status').textContent=row.executed?tr('رُصدت إشارة التنفيذ المطلوبة داخل الإطار.'):tr('لم تُرصد إشارة التنفيذ المطلوبة خلال المعاينة. هذه النتيجة وحدها لا تثبت سلامة أي مدخل آخر.');
    }else{
      const input=$('task-email').value.trim().toLowerCase();const forwarded=id==='rate-limit'?$('task-forwarded').value:'';
      row={mode,input,forwarded,...await post(`/lab/${id}/${mode}`,input,forwarded)};
      if(id==='email-flood')row.mail_count=(await inbox()).filter(m=>m.mode===mode).length;
      $('mission-status').textContent=tr(`HTTP ${row.status}${row.mail_count!==undefined?' · الرسائل في هذه النسخة: '+row.mail_count:''}. اقرأ الدليل وعدّل المدخل للخطوة التالية.`);
    }
    addEvidence(row);
    if(typeof RoomUI!=='undefined')await RoomUI.refreshVerification();
  }catch(error){$('mission-status').textContent=tr('تعذر إكمال الطلب: ')+error.message;}
  finally{lock(false);$('mission-start').disabled=false;$('mission-send').disabled=!mission.active;}
};
$('mission-hint').onclick=()=>{if(mission.exam)return;const hints=instructions[current].hints;mission.hints=Math.min(mission.hints+1,hints.length);$('hint-text').textContent=hints.slice(0,mission.hints).map((text,i)=>`${i+1}. ${text}`).join('\n');};
$('export-evidence').onclick=()=>{
  const blob=new Blob([JSON.stringify({lesson:current,kind:mission.exam?"assessment":"practice",local_training:true,evidence:mission.rows},null,2)],{type:'application/json'});
  const url=URL.createObjectURL(blob);const link=document.createElement('a');link.href=url;link.download=`between-bytes-${current}.json`;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
};
setupChallenge(current);
