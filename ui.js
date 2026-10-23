const byId = id => document.getElementById(id);
async function inbox() {
  const result = await fetch('/outbox');
  byId('outbox').textContent = JSON.stringify(await result.json(), null, 2);
}
byId('experiment').addEventListener('submit', async event => {
  event.preventDefault();
  try {
    const result = await fetch(`/lab/${byId('lesson').value}/${byId('mode').value}`, {
      method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded', 'X-Forwarded-For': byId('forwarded').value},
      body: new URLSearchParams({email: byId('email').value})
    });
    byId('response').textContent = `HTTP ${result.status}\n${JSON.stringify(await result.json(), null, 2)}`;
    await inbox();
  } catch (error) { byId('response').textContent = String(error); }
});
byId('refresh').onclick = () => inbox().catch(error => { byId('outbox').textContent = String(error); });
byId('reset').onclick = async () => {
  try {
    await fetch('/reset', {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: 'reset=1'});
    byId('response').textContent = 'تم تصفير المختبرات';
    await inbox();
  } catch (error) { byId('response').textContent = String(error); }
};
byId('lesson').onchange = () => {
  byId('hint').textContent = {
    enumeration: 'بدّل البريد بين الموجود وغير الموجود وقارن الحالة والرسالة.',
    'rate-limit': 'أرسل 4 طلبات بنفس الهوية، ثم بدّل X-Forwarded-For. قارن النسخة المُصلحة بعد التصفير.',
    'email-flood': 'أرسل 4 طلبات للحساب الوهمي وقارن عدد الرسائل بين النسختين بعد التصفير. مهلة النسخة المُصلحة 60 ثانية.'
  }[byId('lesson').value];
};
