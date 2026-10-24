'use strict';
const RoomUI={
 profiles:{
  enumeration:['Northstar Support','Account recovery','استعادة الحساب','Request recovery','طلب الاستعادة'],
  'rate-limit':['Northstar Access','Sign-in gateway','بوابة الدخول','Try sign-in','محاولة الدخول'],
  'email-flood':['Northstar Recovery','Message delivery desk','مكتب رسائل الاستعادة','Request a reset message','طلب رسالة استعادة'],
  idor:['Northstar Shop','Invoices and ownership','الفواتير وملكيتها','Open invoice','فتح الفاتورة'],
  edge403:['Northstar Admin','Gateway and origin routes','مسارات الوكيل والأصل','Visit selected route','زيارة المسار المحدد'],
  'reflected-xss':['Northstar Search','Server-rendered search','بحث يعرضه الخادم','Search','بحث'],
  'dom-xss':['Northstar Preview','Client-side message preview','معاينة رسائل داخل المتصفح','Render preview','عرض المعاينة'],
  csrf:['Northstar Profile','Account preferences','تفضيلات الحساب','Save the note','حفظ الملاحظة'],
  cors:['Northstar Account API','Private account overview','ملخص الحساب الخاص','Read account data','قراءة بيانات الحساب'],
  'open-redirect':['Northstar Checkout','Return destination policy','سياسة وجهة العودة','Preview redirect decision','معاينة قرار التحويل'],
  ssrf:['Northstar Link Preview','Server-side fetch policy model','نموذج سياسة جلب الخادم','Fetch synthetic resource','جلب المورد الوهمي'],
  'api-keys':['Northstar Billing Assets','Published client bundle','حزمة الواجهة المنشورة','Open fixture asset','فتح عينة المورد'],
  'exposed-files':['Northstar Deploy','Public build explorer','متصفح ملفات النشر العامة','Open fixture path','فتح مسار العينة']
 },
 render(){
  const profile=this.profiles[current];
  $('room-brand').textContent=profile[0];$('room-scene-title').textContent=bi(profile[2],profile[1]);
  $('room-account').textContent=current==='edge403'?bi('زائر مجهول وهمي','Synthetic anonymous visitor'):bi('مساحة تدريب خاصة بهذا المتصفح','Training workspace for this browser');
  $('mission-send').textContent=bi(profile[4],profile[3]);
  $('room-live-address').textContent=location.origin+' · '+current;
  $('room-scope').textContent=['ssrf','open-redirect','edge403','api-keys','exposed-files'].includes(current)?bi('نموذج أو عينات محلية محدودة؛ راجع حدود الدرس.','Bounded local model or fixtures; read this lesson’s scope.'):bi('تطبيق تجريبي محلي ببيانات وهمية.','Local training application with synthetic data.');
  $('room-form-slot').append($('mission-form'));
  $('room-app-result').hidden=true;
  document.querySelector('.room-app').append($('preview-area'),$('browser-frame-area'));
  const browserOnly=['reflected-xss','dom-xss','csrf','cors'].includes(current);
  $('request-replay').hidden=browserOnly;
  $('request-mode-note').textContent=browserOnly?bi('هذه تجربة متصفح: عدّل مدخل التطبيق. السجل يعرض الأدلة الفعلية، ولا يدّعي تزوير Origin أو محاكاة تنفيذ JavaScript بطلب نصي.','Browser workflow: edit the application input. Evidence reflects the real browser interaction; raw HTTP replay cannot forge Origin or substitute for JavaScript execution.'):bi('عدّل جسم الطلب أو الترويسة المدعومة ثم أعد إرساله إلى هذا المختبر المحلي فقط.','Edit the body or supported header, then replay only to this local room.');
  $('room-verification').textContent=bi('ابدأ جولة لجمع دليل من الخادم.','Start a round to collect server-observed evidence.');
  this.syncRequest();
 },
 showApplicationResult(row){
  const root=$('room-app-result');root.replaceChildren();root.hidden=false;
  const heading=document.createElement('h3');heading.textContent=bi('ما ظهر في التطبيق','Application result');root.append(heading);
  const body=row.body||{};
  const line=(label,value)=>{const p=document.createElement('p');const strong=document.createElement('strong');strong.textContent=label+': ';p.append(strong,document.createTextNode(String(value)));root.append(p);};
  if(current==='idor'&&body.invoice){
   line(bi('فاتورة','Invoice'),body.invoice.id);line(bi('المالك','Owner'),body.invoice.owner);line(bi('المبلغ الوهمي','Synthetic amount'),body.invoice.amount);line(bi('المستخدم الحالي','Current actor'),body.actor);
  }else if(current==='csrf'){
   line(bi('الملاحظة السابقة','Previous note'),row.before.note);line(bi('الملاحظة الحالية','Current note'),row.after.note);line(bi('رقم المراجعة','Revision'),row.after.revision);line(bi('تغيرت الحالة','State changed'),row.changed);
  }else if(current==='cors'){
   line(bi('استطاع المتصفح قراءة الرد','Browser could read the response'),row.readable);if(row.readable)line(bi('بيانات الحساب الوهمية','Synthetic account data'),body.private||body.error);
  }else if(current==='email-flood'){
   line(bi('الرسائل المنشأة داخل الذاكرة','Messages created in memory'),row.mail_count);line('HTTP',row.status);
  }else if(current==='open-redirect'){
   line(bi('قرار السياسة — لا انتقال فعلي','Policy decision — no actual navigation'),body.decision||body.error);if(body.location)line('Location',body.location);
  }else if(current==='ssrf'){
   line(bi('نقل وهمي — دون شبكة','Synthetic transport — no network'),body.body||body.error);if(body.private!==undefined)line(bi('مورد داخلي وهمي','Synthetic private resource'),body.private);
  }else if(current==='api-keys'||current==='exposed-files'){
   line(bi('المسار','Path'),row.input);const pre=document.createElement('pre');pre.dir='ltr';pre.textContent=body.content||body.error||'Not found';root.append(pre);
  }else if(current.endsWith('xss')){
   line(bi('إشارة التنفيذ المرصودة','Execution signal observed'),row.executed);line(bi('نص المعاينة','Preview text'),row.rendered?.text||'');
  }else{
   line('HTTP',row.status);line(bi('رد التطبيق','Application response'),body.message||body.error||body.resource||'');
  }
 },
 syncRequest(){
  const mode=$('task-mode')?.value||'vulnerable';
  if(['reflected-xss','dom-xss','csrf','cors'].includes(current)){
   $('raw-request').value=bi('تفاعل من المتصفح. تفاصيل الطلب الفعلي تظهر في دفتر الدليل بعد التنفيذ.','Browser-driven interaction. The evidence notebook shows actual request details after execution.');return;
  }
  const fields={};
  if($('task-email'))fields.email=$('task-email').value;
  if($('task-resource'))fields.resource=$('task-resource').value;
  if($('task-layer'))fields.layer=$('task-layer').value;
  if($('task-value'))fields.value=$('task-value').value;
  const forwarded=$('task-forwarded')?.value;
  $('raw-request').value=`POST /lab/${current}/${mode} HTTP/1.1\nHost: ${location.host}\nContent-Type: application/x-www-form-urlencoded\n${forwarded?'X-Forwarded-For: '+forwarded+'\n':''}\n${new URLSearchParams(fields)}`;
 },
 replay(){
  if(busy||!mission.active){$('request-mode-note').textContent=bi('ابدأ الجولة أولاً.','Start the round first.');return;}
  try{
   const raw=$('raw-request').value.replaceAll('\r\n','\n'),[head,...rest]=raw.split('\n\n');
   const [first,...lines]=head.split('\n');const match=first.match(/^POST (\/lab\/([a-z-]+)\/(vulnerable|fixed)) HTTP\/1\.[01]$/);
   if(!match||match[2]!==current)throw new Error(bi('المحرر مقيد بمسار الغرفة الحالية.','The editor is restricted to this room endpoint.'));
   const headers={};for(const line of lines){const index=line.indexOf(':');if(index<1)throw new Error('Invalid header');headers[line.slice(0,index).toLowerCase()]=line.slice(index+1).trim();}
   if(headers.host!==location.host||headers['content-type']!=='application/x-www-form-urlencoded'||Object.keys(headers).some(k=>!['host','content-type','x-forwarded-for'].includes(k)))throw new Error(bi('لا يمكن تعديل الوجهة أو الجلسة أو Origin من هذا المحرر.','Host, session and Origin cannot be overridden here.'));
   const body=new URLSearchParams(rest.join('\n\n'));
   const targets={email:'task-email',resource:'task-resource',layer:'task-layer',value:'task-value'};
   for(const [key,value] of body){if(!targets[key]||!$(targets[key])||body.getAll(key).length!==1)throw new Error('Unsupported or duplicate form field');$(targets[key]).value=value;}
   $('task-mode').value=match[3];if($('task-forwarded'))$('task-forwarded').value=headers['x-forwarded-for']||'';
   $('mission-form').requestSubmit();
  }catch(error){$('request-mode-note').textContent=error.message;}
 },
 async start(){
  const session=await fetch('/rooms/session');if(!session.ok)throw new Error('Could not create a local workspace');
  const response=await fetch('/rooms/start',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({lesson:current})});if(!response.ok)throw new Error('Could not start the room');
 },
 async refreshVerification(){
  const response=await fetch('/rooms/status');if(!response.ok)throw new Error('Could not read server observations');
  const report=await response.json();
  if(report.room!==current)return;
  const label=report.verification==='browser-assisted'?bi('الخادم رصد الطلبات؛ التنفيذ أو القراءة يحتاج دليل المتصفح أيضاً.','The server observed the requests; execution/readability also requires browser evidence.'):bi('دليل من طلبات رصدها الخادم ضمن هذا النموذج المحلي.','Evidence from requests observed by the server within this local model.');
  $('room-verification').textContent=`${label}\n${report.server_checks.filter(Boolean).length} / ${report.server_checks.length} · ${report.requests_observed} ${bi('طلبات مرصودة','requests observed')}${report.flag?'\n'+report.flag:''}`;
  $('server-evidence').textContent=JSON.stringify(report,null,2);
  if(['reflected-xss','dom-xss','csrf','cors'].includes(current))$('raw-request').value=JSON.stringify(mission.rows.at(-1),null,2);
 }
};
$('request-replay').onclick=()=>RoomUI.replay();
$('request-from-form').onclick=()=>RoomUI.syncRequest();
$('mission-form').addEventListener('input',()=>RoomUI.syncRequest());
$('language-toggle').title=bi('تبديل اللغة يعيد تحميل العرض؛ علامات الإنجاز محفوظة.','Switching language reloads the view; completion marks are retained.');
$('language-toggle').textContent=I18n.lang==='en'?'العربية':'English';
$('language-toggle').onclick=()=>{if(busy)return;try{localStorage.setItem('bb-language',I18n.lang==='en'?'ar':'en');}catch(_){}location.reload();};
RoomUI.render();
