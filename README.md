# Between Bytes Web Labs

مختبرات عربية لفهم ثغرات تطبيقات الويب: تجربة واضحة، سبب برمجي، وإصلاح يمكن التحقق منه.

**الإصدار 0.6:** ثلاثة عشر مختبراً مستقلاً، كل واحد بنسخة ضعيفة `vulnerable` ونسخة مُصلحة `fixed`. يعمل المشروع محلياً على Python 3.10+ دون مكتبات خارجية، مع منصة دروس عربية تناسب الهاتف.

| المختبر | الخطأ المتعمّد | ما يوضحه الإصلاح |
|---|---|---|
| User Enumeration | اختلاف حالة HTTP والرسالة حسب وجود الحساب | توحيد الاستجابة العامة |
| Rate Limit | الوثوق بـ X-Forwarded-For المرسل من العميل | حدود للحساب الموحّد ولمصدر الاتصال |
| Reset Email Abuse | إنشاء رسالة لكل طلب استعادة | مهلة للحساب وحد للمصدر مع استجابة عامة |
| IDOR | قراءة فاتورة بمعرّفها دون فحص ملكيتها | تحقق صلاحيات المورد على الخادم |
| Reflected XSS | انعكاس مدخل البحث كـHTML | ترميز سياق نص HTML |
| DOM XSS | رسالة غير موثوقة إلى innerHTML | العرض باستخدام textContent |
| Edge / Origin 403 | منع عند الوكيل دون تحقق الأصل | رفض الزائر المجهول عند الطبقتين — محاكاة محلية |
| CSRF | كتابة عبر أصل آخر اعتماداً على الجلسة | تحقق Origin وتوكن CSRF في جلسة وهمية |
| CORS | إتاحة بيانات الجلسة لأصل غير موثوق | اختبار قراءة فعلية بين منفذين محليين |
| Open Redirect | قبول وجهة غير موثوقة | قائمة مسارات مسموحة — معاينة قرار فقط |
| SSRF | قبول وجهة داخلية وتحويل إليها | نقل وهمي بلا شبكة مع سياسة وجهات |
| API Keys | سر خادم داخل عينة الواجهة | إزالة السر الوهمي مع بقاء المفتاح العام |
| Exposed Files | نشر إعداد ونسخة احتياطية | حجب ملفات وهمية مع بقاء الموارد العامة |

## التشغيل على Termux

```bash
pkg update
pkg install python git
git clone https://github.com/khdertaysh1/Between-Bytes-Web-Labs.git
cd Between-Bytes-Web-Labs
python app.py
```

على Linux/macOS استخدم Python 3.10+ وGit، ثم أوامر الاستنساخ والتشغيل نفسها (قد يكون الأمر `python3`). افتح في المتصفح:

**http://127.0.0.1:8000**

إذا كان المنفذ مشغولاً: `python app.py --port 8001` ثم افتح `http://127.0.0.1:8001`.

## أول تجربة خلال دقيقة

1. اختر **أي درس** واقرأ الشرح الموسّع داخل الصفحة.
2. انتقل إلى **جرّب وقارن** وابدأ التدريب اليدوي؛ عدّل المدخلات واجمع الأدلة واستعن بالتلميحات.
3. افتح **افهم الإصلاح** لمراجعة السبب وحدود الحل.
4. اضغط **ابدأ الاختبار العملي**: جولة جديدة دون تلميحات، وببيانات اختبار مذكورة في المهمة.
5. أكمل قائمة الأدلة وراجع تفسير النتيجة. يمكنك الانتقال لأي درس في أي وقت.

**جميع الدروس والتمارين مفتوحة من البداية.** المستويات الستة تقسيم للموضوعات فقط؛ اختر الترتيب الذي يناسبك. لا يوجد رصيد أو شرط اجتياز لفتح درس.

[تفاصيل الدروس الستة الجديدة وحدودها](docs/advanced.ar.md) · [دليل المستويات والاختبارات](docs/course.ar.md) · [English course guide](docs/course.en.md) · [دليل التمارين](docs/challenges.ar.md)

التقدّم محفوظ محلياً على نفس المتصفح، وليس نظام امتحانات محصناً ضد تعديل المستخدم أو نظام شهادات. علامات الإنجاز اختيارية ولا تتحكم بالوصول. بدء جولة يمسح عدّادات الخادم والبريد الوهمي؛ الجولة تسمح حتى 60 تجربة.

الحسابات الوهمية الموجودة في دروس البريد: `alice@example.test` و`bob@example.test`. لا توجد حسابات فعلية أو كلمات سر أو رسائل تُرسل للخارج. زر **تصفير عدّادات المختبرات والبريد** يمسح العدّادات والبريد في النسختين، وإعادة التشغيل تمسح بيانات الخادم المؤقتة؛ علامات الإنجاز تبقى محفوظة في المتصفح.

## الاختبارات

```bash
python -m unittest discover -s tests -v
```

تختبر سلوك النسختين وملكية الفواتير ومسارات 403 وعزل المعاينات وترميز الانعكاس، بالإضافة إلى انقضاء المهلة بساعة وهمية، حدود الحساب والمصدر، وصندوق البريد ومسارات HTTP محلياً. لا تحتاج اتصالاً بالإنترنت.

## حدود التجارب الجديدة

CSRF وCORS تجارب متصفح فعلية بأصلين محليين مختلفي المنفذ ضمن نفس الموقع، مع جلسة وحالة وهميتين. SSRF نقل وهمي لا يتصل بالشبكة. Open Redirect معاينة قرار لا انتقال خارجي. ملفات ENV والمفاتيح عينات غير صالحة في الذاكرة، ولا يقرأ التطبيق ملفات جهازك. المنفذ المحلي الثاني يعمل ويغلق تلقائياً.

## مختبرات XSS و403

XSS يعمل داخل إطار sandbox منفصل عن أصل المنصة، مع رصد إشارة تنفيذ تعليمية. **DOM input لا يُرسل للخادم**، بينما مدخل Reflected يُعكس عبر استجابة الخادم المحلي. راجع الدليل لحدود CSP ونافذة رصد التنفيذ؛ هذه ليست عزلة نظام تشغيل.

درس 403 يحاكي خطأ صلاحيات بين edge وorigin داخل التطبيق نفسه. لا يتصل بـCloudflare ولا ينفذ تجاوزاً حقيقياً لحمايته.

## حدود المختبر

يرتبط الخادم بـ `127.0.0.1` فقط. لا تنشره على استضافة عامة أو تمرره عبر نفق. الدروس تحتوي أخطاء مقصودة. صندوق البريد أداة مراقبة محلية متاحة للمتدرّب، وليس واجهة لمستخدم خارجي. يقبل صندوق البريد الحسابين الوهميين فقط ويحتفظ بآخر 100 رسالة في الذاكرة؛ لا يحتوي التطبيق أي عميل SMTP.

النسخ المُصلحة أمثلة تعليمية مركّزة وليست نظام مصادقة جاهزاً للإنتاج: لا قاعدة بيانات، لا مصادقة فعلية، لا طوابير بريد أو تخزين موزّع. درس enumeration يعالج تسريب الحالة والرسالة ولا يثبت مقاومة فروقات التوقيت. اقرأ حدود كل إصلاح في الدليل.

## English

Version 0.6 makes all 13 lessons and exercises available immediately, in any order. Six levels organize topics only; there are no points or prerequisites. Optional local completion marks remain. See the [course guide](docs/course.en.md).

Thirteen local, intentionally vulnerable web lessons with paired fixes: CSRF, CORS, modeled SSRF/redirect, synthetic API-key/file disclosures, IDOR, reflected XSS, DOM XSS, an edge/origin 403 simulation, account enumeration, trusting spoofed proxy identity for rate limiting, and repeated reset-email generation. Python 3.10+, standard library only. Run `python app.py`, open `http://127.0.0.1:8000`, then solve the manual challenges using editable inputs, evidence and progressive hints. See [hands-on guide](docs/challenges.en.md). All mail is captured in memory for two synthetic accounts; no external delivery or target scanner exists. See [English guide](docs/lessons.en.md).

Created for the Between Bytes community by [khdertaysh1](https://github.com/khdertaysh1).

See [new lesson scope and browser-origin details](docs/advanced.en.md).
