'use strict';
const $ = id => document.getElementById(id);
const lessons = {
  enumeration: {
    number:'01', title:'كشف وجود الحساب', english:'USER ENUMERATION', time:'5 دقائق',
    short:'هل تكشف رسالة استعادة كلمة المرور إن كان البريد مسجّلاً؟',
    subtitle:'اختلاف صغير في الاستجابة قد يكشف معلومة عن حسابات المستخدمين.',
    scenario:'نسيت كلمة المرور… لكن ماذا يكشف الرد؟',
    body:'تخيّل صفحة استعادة كلمة مرور في متجر. المستخدم يدخل بريده؛ الخادم يرد برسالة. سنجرّب حساباً موجوداً وآخر غير موجود، ونرى هل يمكن التمييز بينهما من خارج التطبيق.',
    steps:['أرسل طلب استعادة للحساب الوهمي الموجود، ثم لبريد غير مسجّل.','قارن حالة HTTP ونص الاستجابة في النسخة الضعيفة.','كرّر الطلبين بعد الإصلاح. المفروض أن تكون الاستجابة العامة متطابقة.'],
    copy:'نرسل طلبين لكل نسخة: حساب موجود وحساب غير موجود. هذا الدرس يحاكي الرد فقط ولا ينشئ بريداً.',
    root:'التسريب موجود في رد الخادم',
    cause:'النسخة الضعيفة تكشف وجود الحساب بحالة 200 ورسالة مختلفة، وتعيد 404 عند غيابه. تغيير النص في واجهة الموقع وحده لا يخفي اختلاف الاستجابة الشبكية.',
    bad:'if account_exists:\n    return 200, "Reset queued"\nreturn 404, "Account not found"',
    good:'# Same status and body for both accounts\nreturn 202, GENERIC.copy()',
    limits:'الإصلاح يوحّد الحالة والرسالة فقط. لم نختبر فروقات التوقيت. النظام الحقيقي يحتاج مراجعة الزمن والترويسات والتحويلات، ومعالجة خلفية لا تكشف وجود الحساب.',
    question:'إذا الرسالة في الشاشة واحدة لكن HTTP مختلف، هل انتهى التسريب؟',
    answer:'لا. يمكن قراءة حالة HTTP مباشرة من الشبكة. توحيد واجهة العرض لا يكفي إذا بقي فرق يمكن رصده في استجابة الخادم.',
    takeaway:'النسخة الضعيفة ميّزت بين الحسابين. المُصلحة أعادت نفس الحالة ونفس الرسالة. هذه مقارنة مثبتة داخل المختبر؛ لا تستنتج منها أن أي موقع آخر مصاب.'
  },
  'rate-limit': {
    number:'02', title:'تجاوز حد المحاولات', english:'RATE LIMIT BYPASS', time:'7 دقائق',
    short:'ما الذي يحصل إذا وثق الخادم بعنوان يختاره العميل؟',
    subtitle:'افهم كيف يجعل مفتاح خاطئ للعدّاد حماية المحاولات قابلة للتجاوز.',
    scenario:'ثلاث محاولات فقط… أم ثلاث لكل ترويسة؟',
    body:'لدينا تسجيل دخول تجريبي يرفض كل محاولة. الحد ثلاث محاولات في الدقيقة. سنصل للمنع، ثم نغيّر ترويسة X-Forwarded-For، ونشاهد هل يعتبرنا التطبيق مصدراً جديداً.',
    steps:['أرسل 4 محاولات بنفس الحساب والمصدر. الرابعة يجب أن تعيد 429.','غيّر X-Forwarded-For لعنوان تجريبي، ثم أرسل محاولة خامسة.','قارن النسخة المُصلحة: تغيير الترويسة يجب ألا يفتح محاولات جديدة.'],
    copy:'نرسل 5 محاولات لكل نسخة. الطلب الخامس فقط يحمل ترويسة مختلفة. لا توجد كلمة مرور صحيحة أو عملية دخول فعلية.',
    root:'مصدر غير موثوق أصبح مفتاح الحماية',
    cause:'X-Forwarded-For قد يرسلها العميل بنفسه. اعتمادها مباشرة كمفتاح للعدّاد يجعل كل قيمة جديدة تحصل على حد جديد. المُصلحة تربط الحد بالحساب الموحّد وبعنوان الاتصال الفعلي.',
    bad:'identity = forwarded_header or peer\nallowed = allow(identity, 3, 60)',
    good:'account_ok = allow(account_key, 3, 60)\nsource_ok = allow(socket_peer, 6, 60)\nallowed = account_ok and source_ok',
    limits:'عنوان الاتصال مناسب هنا لأن المختبر بلا proxy. في الإنتاج يلزم تعريف proxies موثوقة، عدّادات ذرية مشتركة بين العمال، وانتهاء صلاحية للمفاتيح. حد الحساب وحده قد يسمح بإزعاج صاحبه بالمنع المؤقت.',
    question:'هل HTTP 401 في المحاولة الخامسة يعني أن تسجيل الدخول نجح؟',
    answer:'لا. يعني أن الطلب وصل إلى رفض بيانات الدخول بدلاً من منعه بسبب الحد 429. هذا يثبت تجاوز الحد في النسخة الضعيفة، ولا يثبت اختراق حساب.',
    takeaway:'بعد الوصول للحد، تغيير الترويسة أعاد المحاولة إلى 401 في النسخة الضعيفة. المُصلحة أبقتها 429؛ تغيير الترويسة لم يتجاوز حد الحساب.'
  },
  'email-flood': {
    number:'03', title:'إساءة استخدام بريد الاستعادة', english:'RESET EMAIL ABUSE', time:'6 دقائق',
    short:'أربع طلبات متتالية: كم رسالة يجب أن تُنشأ فعلياً؟',
    subtitle:'لا تكتفِ بحالة 202؛ راقب ما يحدث بعد قبول الطلب.',
    scenario:'زر استعادة واحد، ورسائل متكررة',
    body:'صفحة الاستعادة تقبل الطلب برسالة عامة. لكن الخادم قد ينشئ رسالة جديدة كل مرة. سنرسل أربعة طلبات محدودة، ونقيس الأثر في صندوق بريد وهمي داخل التطبيق.',
    steps:['أرسل 4 طلبات استعادة للحساب نفسه في النسخة الضعيفة.','عدّ الرسائل المنشأة داخل صندوق البريد الوهمي.','كرّر بعد الإصلاح: مهلة الحساب يجب أن تمنع تكرار الرسالة خلال 60 ثانية.'],
    copy:'نرسل 4 طلبات لكل نسخة. كل البريد يبقى في الذاكرة؛ لا يوجد SMTP أو إرسال لعناوين حقيقية.',
    root:'قبول الطلب ليس أمراً بإرسال رسالة جديدة',
    cause:'إنشاء رسالة لكل طلب يتيح إزعاج المستلم. المُصلحة تبقي الاستجابة عامة، وتطبق مهلة 60 ثانية للحساب وحداً قدره 6 طلبات للمصدر في الدقيقة قبل إنشاء الرسالة.',
    bad:'if account_exists:\n    queue_demo_message(email)\nreturn 202, generic_response',
    good:'if source_ok and cooldown_ok:\n    remember_cooldown(email)\n    if account_exists:\n        queue_demo_message(email)\nreturn 202, generic_response',
    limits:'صندوق البريد واجهة مراقبة للمتدرّب فقط ويعرض آخر 100 رسالة. في الإنتاج نحتاج إزالة تكرار ذرية، طابوراً محدوداً، حداً عالمياً ومراقبة المصادر الموزعة. لا يتضمن المختبر دورة حياة توكنات الاستعادة.',
    question:'هل أربع استجابات 202 تثبت أن أربع رسائل وصلت؟',
    answer:'لا. 202 تعني قبول الطلب للمعالجة، ولا تثبت إنشاء الرسالة أو تسليمها. هنا نثبت الإنشاء من صندوق الاختبار، ولا يوجد إرسال فعلي خارج الجهاز.',
    takeaway:'نفس طلبات الاستعادة أنشأت 4 رسائل وهمية في النسخة الضعيفة ورسالة واحدة في المُصلحة. حالة HTTP بقيت 202 في الحالتين؛ الأثر يظهر في عدد الرسائل.'
  }
};
Object.assign(lessons, extraLessons);
let current = 'enumeration';
let busy = false;
const orderedLessons=Course.groups.flat().map(id=>[id,lessons[id]]);
for(const id of Object.keys(lessons))delete lessons[id];
orderedLessons.forEach(([id,l],index)=>{l.number=String(index+1).padStart(2,'0');lessons[id]=l;});
let completed, courseProgress;
try{completed=new Set(JSON.parse(localStorage.getItem('bb-practice-v4')||localStorage.getItem('bb-challenges-v3')||'[]').filter(id=>lessons[id]));}catch(_){completed=new Set();}
try{courseProgress=new Course.CourseProgress(JSON.parse(localStorage.getItem('bb-exams-v4')||'{}'));}catch(_){courseProgress=new Course.CourseProgress();}
function saveProgress(){
 try{localStorage.setItem('bb-practice-v4',JSON.stringify([...completed]));localStorage.setItem('bb-exams-v4',JSON.stringify(courseProgress.awards));}catch(_){}
 const passed=Object.keys(courseProgress.awards).length;
 $('progress').textContent=`${passed} / 7`;$('progress-bar').style.width=`${passed/7*100}%`;
 $('score-total').textContent=`${courseProgress.points} / 700 نقطة`;
 for(const element of document.querySelectorAll('[data-completion]')){
  const id=element.dataset.completion;
  element.textContent=courseProgress.awards[id]?'اجتزت الاختبار · 100 نقطة ✓':!courseProgress.canAccess(id)?'مقفل · أكمل المستوى السابق':completed.has(id)?'التدريب مكتمل · الاختبار متاح':'ابدأ الدرس ←';
 }
 for(const element of document.querySelectorAll('[data-nav], .lab-card')){
  const id=element.dataset.nav||element.hash.slice(1),locked=!courseProgress.canAccess(id);
  element.classList.toggle('locked',locked);element.setAttribute('aria-disabled',String(locked));
 }
 const names=['أساسيات الحسابات والحدود','صلاحيات الموارد والطبقات','حقن JavaScript وسياقات العرض'];
 $('roadmap').replaceChildren(...Course.groups.map((ids,i)=>{
  const div=document.createElement('div');div.className='roadmap-level';
  const title=document.createElement('h3');title.textContent=`المستوى ${i+1} · ${names[i]}`;
  const p=document.createElement('p');const done=ids.every(id=>courseProgress.awards[id]);
  p.textContent=done?'مكتمل ✓':courseProgress.canAccess(ids[0])?'متاح الآن':`يفتح بعد اجتياز جميع اختبارات المستوى السابق (${i===1?'300':'500'} نقطة إجمالاً)`;
  div.classList.toggle('available',courseProgress.canAccess(ids[0]));div.append(title,p);return div;
 }));
}
// All inserted markup below is authored lesson content; HTTP/user data uses textContent.
$('navigation').innerHTML = Object.entries(lessons).map(([id,l]) => `<a href="#${id}" class="nav-item" data-nav="${id}"><b class="nav-number">${l.number}</b>${l.title}<span>←</span></a>`).join('');
$('cards').innerHTML = Object.entries(lessons).map(([id,l]) => `<a class="lab-card" href="#${id}"><div class="card-top"><span class="number">${l.number}</span><span class="level">مستوى ${courseProgress.level(id)} · ${l.time}</span></div><h3>${l.title}</h3><span class="english" dir="ltr">${l.english}</span><p>${l.short}</p><div class="card-bottom"><span data-completion="${id}">افتح المختبر ←</span><span>ضعيف / مُصلح</span></div></a>`).join('');
function tab(name) {
  for (const id of ['learn','experiment','fix']) $(id).hidden = id !== name;
  for (const button of document.querySelectorAll('[data-tab]')) {
    const selected = button.dataset.tab === name;
    button.setAttribute('aria-selected', String(selected));
    button.tabIndex = selected ? 0 : -1;
  }
}
function route() {
  let id = location.hash.slice(1);
  if(lessons[id]&&!courseProgress.canAccess(id)){
    $('course-notice').textContent='هذا المستوى مقفل. اجتز الاختبارات العملية في المستوى السابق أولاً؛ قراءة الدرس أو مشاهدة المقارنة لا تمنح نقاطاً.';
    history.replaceState(null,'','#home');id='home';
  }else{$('course-notice').textContent='';}
  if (busy) { history.replaceState(null, '', '#' + current); return; }
  const home = !lessons[id];
  $('home').hidden = !home;
  $('lesson').hidden = home;
  $('home-link').classList.toggle('active', home);
  for (const element of document.querySelectorAll('[data-nav]')) element.classList.toggle('active', !home && element.dataset.nav === id);
  if (home) { document.title = 'Between Bytes — مختبرات أمن الويب'; return; }
  current = id;
  renderCourse(id);
  const l = lessons[id];
  document.title = `${l.title} — Between Bytes`;
  for (const [key,value] of Object.entries({'lesson-meta':`مختبر ${l.number} / ${l.english} / ${l.time}`,'lesson-title':l.title,'lesson-subtitle':l.subtitle,'scenario-title':l.scenario,'scenario-body':l.body,'experiment-copy':l.copy,'root-title':l.root,'root-body':l.cause,'bad-code':l.bad,'good-code':l.good,limits:l.limits,question:l.question,answer:l.answer})) $(key).textContent = value;
  $('steps').replaceChildren(...l.steps.map(text => { const li = document.createElement('li'); li.textContent = text; return li; }));
  $('forwarded-label').hidden = id !== 'rate-limit';
  $('takeaway').hidden = true;
  $('live-status').textContent = '';
  $('manual-response').textContent = 'الاستجابة ستظهر هنا.';
  $('outbox').textContent = '[]';
  for (const mode of ['vulnerable','fixed']) $(mode+'-result').innerHTML = '<p class="empty">شغّل المقارنة لتشاهد النتيجة هنا.</p>';
  const ids = Object.keys(lessons); const next = ids[ids.indexOf(id)+1];
  $('next-lesson').href = next ? '#'+next : '#home';
  $('next-lesson').textContent = next ? 'المختبر التالي ←' : 'ارجع لمسارك التعليمي ←';
  $('guided-demo').hidden = !!extraLessons[id];
  if (typeof setupChallenge === 'function') setupChallenge(id);
  tab('learn');
  window.scrollTo(0,0);
}
async function post(path, email='alice@example.test', forwarded='') {
  const response = await fetch(path, {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded','X-Forwarded-For':forwarded},body:new URLSearchParams({email}),signal:AbortSignal.timeout(8000)});
  const body = await response.json();
  return {status:response.status, body};
}
async function reset() {
  const r = await post('/reset');
  if (r.status !== 200) throw new Error('تعذر تصفير المختبرات');
}
async function inbox() {
  const r = await fetch('/outbox', {signal:AbortSignal.timeout(8000)});
  if (!r.ok) throw new Error('تعذر قراءة صندوق البريد');
  return (await r.json()).messages;
}
function lock(value) {
  busy = value;
  for (const button of document.querySelectorAll('#compare, #manual button, #reset, #refresh')) button.disabled = value;
  $('compare').textContent = value ? 'جارٍ تنفيذ الطلبات…' : 'شغّل المقارنة';
}
function showResult(mode, rows, count) {
  const root = $(mode+'-result'); root.replaceChildren();
  const metric = document.createElement('div'); metric.className='result-metric';
  metric.textContent = current==='email-flood' ? `${count} / 4` : current==='rate-limit' ? `HTTP ${rows.at(-1).status}` : rows.map(r=>r.status).join(' ≠ ');
  if (current==='enumeration' && mode==='fixed') metric.textContent=rows.map(r=>r.status).join(' = ');
  const caption=document.createElement('p');caption.className='result-caption';
  caption.textContent = current==='email-flood' ? 'رسائل أُنشئت من أصل 4 طلبات' : current==='rate-limit' ? 'نتيجة المحاولة الخامسة بعد تغيير الترويسة' : 'حالة الرد للحساب الموجود ثم غير الموجود';
  root.append(metric,caption);
  rows.forEach(r=>{ const row=document.createElement('div'); row.className='request-row';const label=document.createElement('span');label.textContent=r.label;const code=document.createElement('code');code.textContent=`HTTP ${r.status}`;row.append(label,code);root.append(row); });
  const detail=document.createElement('details');const summary=document.createElement('summary');summary.textContent='شاهد الطلبات والاستجابات';const pre=document.createElement('pre');pre.dir='ltr';pre.textContent=JSON.stringify(rows,null,2);detail.append(summary,pre);root.append(detail);
}
$('compare').onclick = async () => {
  if (busy) return;
  lock(true); $('takeaway').hidden=true;
  const results={};
  try {
    for (const mode of ['vulnerable','fixed']) {
      $('live-status').textContent = `نختبر النسخة ${mode==='fixed'?'المُصلحة':'الضعيفة'}…`;
      await reset();
      const rows=[]; const n=current==='enumeration'?2:current==='rate-limit'?5:4;
      for (let i=0;i<n;i++) {
        const email = current==='enumeration'&&i===1?'nobody@example.test':'alice@example.test';
        const forwarded = current==='rate-limit'&&i===4?'192.0.2.1':'';
        const path=`/lab/${current}/${mode}`;
        const r=await post(path,email,forwarded);
        rows.push({label:current==='enumeration'?(i===0?'حساب موجود':'حساب غير موجود'):`طلب ${i+1}${forwarded?' · ترويسة جديدة':''}`,method:'POST',path,email,forwarded,...r});
      }
      const messages=await inbox();
      results[mode]={rows,count:messages.filter(m=>m.mode===mode).length};
      showResult(mode,rows,results[mode].count);
    }
    const a=results.vulnerable,b=results.fixed;
    const expected=current==='enumeration' ? a.rows[0].status===200&&a.rows[1].status===404&&b.rows.every(r=>r.status===202)&&JSON.stringify(b.rows[0].body)===JSON.stringify(b.rows[1].body) : current==='rate-limit' ? a.rows[3].status===429&&a.rows[4].status===401&&b.rows[3].status===429&&b.rows[4].status===429 : a.count===4&&b.count===1&&[...a.rows,...b.rows].every(r=>r.status===202);
    $('takeaway').replaceChildren();
    const title=document.createElement('h3');title.textContent=expected?'شو أثبتت التجربة؟':'النتيجة اختلفت عن السيناريو المتوقع';
    const body=document.createElement('p');body.textContent=expected?lessons[current].takeaway:'راجع تفاصيل الاستجابات. قد يكون هناك تداخل مع طلبات أخرى أو نسخة مختلفة من الخادم. لم تُسجّل التجربة كمكتملة.';
    $('takeaway').append(title,body);$('takeaway').hidden=false;
    $('live-status').textContent=expected?'اكتملت المقارنة من استجابات الخادم الفعلية.':'المقارنة تحتاج مراجعة.';
    // Guided viewing does not complete a hands-on challenge.
    $('outbox').textContent=JSON.stringify(await inbox(),null,2);
  } catch(error) {
    $('live-status').textContent=`تعذّر إكمال التجربة. تأكد أن python app.py يعمل، ثم أعد المحاولة. (${error.message})`;
  } finally {lock(false);}
};
$('manual').onsubmit = async event => {
  event.preventDefault();if(busy)return;lock(true);
  try {const r=await post(`/lab/${current}/${$('mode').value}`,$('email').value,$('forwarded').value);$('manual-response').textContent=`HTTP ${r.status}\n${JSON.stringify(r.body,null,2)}`;$('outbox').textContent=JSON.stringify(await inbox(),null,2);}
  catch(error){$('manual-response').textContent=error.message;}finally{lock(false);}
};
$('reset').onclick=async()=>{if(busy)return;lock(true);try{await reset();$('outbox').textContent='[]';$('manual-response').textContent='تم تصفير العدّادات والبريد.';}catch(error){$('manual-response').textContent=error.message;}finally{lock(false);}};
$('refresh').onclick=async()=>{try{$('outbox').textContent=JSON.stringify(await inbox(),null,2);}catch(error){$('outbox').textContent=error.message;}};
$('clear-progress').onclick=()=>{if(!confirm('مسح نقاط الاختبارات والتدريب وإعادة قفل المستويات؟'))return;completed.clear();courseProgress.reset();saveProgress();route();};
for(const button of document.querySelectorAll('[data-tab]')){
  button.onclick=()=>tab(button.dataset.tab);
  button.onkeydown=event=>{if(!['ArrowRight','ArrowLeft'].includes(event.key))return;event.preventDefault();const buttons=[...document.querySelectorAll('[data-tab]')];const next=buttons[(buttons.indexOf(button)+(event.key==='ArrowLeft'?1:2))%3];tab(next.dataset.tab);next.focus();};
}
$('go-experiment').onclick=()=>tab('experiment');$('go-fix').onclick=()=>tab('fix');
window.addEventListener('hashchange',route);saveProgress();route();
