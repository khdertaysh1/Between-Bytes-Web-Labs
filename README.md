# Between Bytes Web Labs

مختبرات بالعربية والإنكليزية لفهم ثغرات تطبيقات الويب: تجربة واضحة، سبب برمجي، وإصلاح يمكن التحقق منه.

**الإصدار 0.9.2:** خمسة مختبرات تجمع 50 حالة داخلها: الدفع، XSS، الصلاحيات، حدود المحاولات، والخدمات البرمجية. الصفحة الرئيسية تعرض المختبرات الخمسة؛ افتح أي مختبر للتنقّل بين حالاته. [الشرح العربي الكامل](docs/academy.ar.md) · [English guide](docs/academy.en.md).

محرك الدفع يحفظ الطلب والمعاملات والمبالغ المحصلة والمستردة والاستحقاقات؛ الاستجابة تحمل حالة HTTP الفعلية، ويمكن قراءة المورد بطلب GET مستقل. لكل حالة سيناريو مفصل، مسار بيانات، دليل متوقع ومقتطف قبل الإصلاح وبعده.

**الغرف الأساسية:** ثلاثة عشر مختبراً مستقلاً، كل واحد بنسخة ضعيفة `vulnerable` ونسخة مُصلحة `fixed`. يعمل المشروع محلياً على Python 3.10+ دون مكتبات خارجية، مع غرف تفاعلية بالعربية والإنكليزية تناسب الهاتف.

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

## أول تجربة

اختر اللغة من الزر أعلى الصفحة؛ كل الدروس مفتوحة. افتح أي غرفة، اقرأ الشرح، ثم ابدأ التدريب وشغّل نموذج التطبيق الوهمي بنفسك. افحص الطلب والاستجابة، جرّب الإصلاح، ثم انتقل للتمرين المستقل إذا أردت. لا توجد نقاط أو شروط انتقال.

- سياق تطبيق مختلف لكل غرفة، وليس IDOR فقط.
- محرر طلبات HTTP محلي لتعديل وإعادة طلبات الغرف المناسبة؛ غرف المتصفح تعرض أدلة التنفيذ/القراءة الفعلية.
- حالة تعليمية منفصلة لكل متصفح، وسجل للطلبات التي رصدها الخادم، وعلامات محلية للغرف التي تسمح معاييرها بذلك.
- دعم RTL/LTR وحفظ اللغة وعلامات الإنجاز، دون أي خدمة ترجمة خارجية.

[شرح الغرف بالعربي](docs/rooms.ar.md) · [Room guide in English](docs/rooms.en.md) · [حدود الدروس الإضافية](docs/advanced.ar.md)

النماذج والحسابات والمفاتيح والبريد وهمية. بعض الغرف نقل أو سياسة محاكاة، وليست كل الغرف آلات هدف كاملة؛ الدليل يميّز ذلك. تبديل اللغة يعيد تحميل العرض ويحتفظ بالإنجاز، لكن يلزم بدء جولة جديدة لاستئناف دفتر دليل غير محفوظ.

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

All 13 rooms now have themed application workspaces and a full Arabic/English learning edition. Switch language in the header; its preference persists. Nine HTTP-handler rooms support restricted local request replay; four browser-dependent rooms use real browser workflows instead. Per-browser synthetic state and a server-observation journal complement the existing evidence checklist. This is a local classroom application, not cloud VMs or a secure hosted examination service. See [room architecture and limits](docs/rooms.en.md).


Version 0.7 makes all 13 lessons and exercises available immediately, in any order. Six levels organize topics only; there are no points or prerequisites. Optional local completion marks remain. See the [course guide](docs/course.en.md).

Thirteen local, intentionally vulnerable web lessons with paired fixes: CSRF, CORS, modeled SSRF/redirect, synthetic API-key/file disclosures, IDOR, reflected XSS, DOM XSS, an edge/origin 403 simulation, account enumeration, trusting spoofed proxy identity for rate limiting, and repeated reset-email generation. Python 3.10+, standard library only. Run `python app.py`, open `http://127.0.0.1:8000`, then solve the manual challenges using editable inputs, evidence and progressive hints. See [hands-on guide](docs/challenges.en.md). All mail is captured in memory for two synthetic accounts; no external delivery or target scanner exists. See [English guide](docs/lessons.en.md).

Created for the Between Bytes community by [khdertaysh1](https://github.com/khdertaysh1).

See [new lesson scope and browser-origin details](docs/advanced.en.md).

## خمسة مختبرات · 50 حالة داخلية

افتح **http://127.0.0.1:8000/** أو **http://127.0.0.1:8000/academy**. الغرف الأساسية القديمة محفوظة في `/foundations`. عند استخدام `--port 8002` يصبح الرابط **http://127.0.0.1:8002/academy**.

| المسار | الحالات | أمثلة |
|---|---:|---|
| منطق الدفع | 16 | السعر والكمية والخصم والعملة والإجمالي، تسوية الطلب، إشعارات المزود، إعادة الأحداث والاسترداد والتجارب |
| الصلاحيات وIDOR | 10 | قراءة وتعديل وحذف، موارد فرعية، مؤسسة، مجموعات، تصدير وتنزيل وأدوار وإسناد جماعي |
| حدود المحاولات | 7 | مصدر وهمي، توزيع مصادر، IPv6، تطبيع الحساب، مسارات وتحديات ونافذة زمنية |
| سياقات XSS | 12 | HTML وخصائص مقتبسة وغير مقتبسة، سلاسل وقوالب JavaScript، URL، DOM، تخزين وفك ترميز |
| حالات برمجية أخرى | 5 | SQLite SQLi، نماذج NoSQL وتقييم قالب وتحويل وSSRF |

هذه **50 حالة وليست 50 فئة مستقلة**؛ تضاف إلى 13 غرفة أساسية. تحتوي الأكاديمية على مسارات وبحث وفرز، ومحرر JSON، ومعاينة تطبيق محلي، وتلميحات، ودليل قابل للتنزيل واستنتاجات وعلامات إنجاز. كل الحالات مفتوحة بلا نقاط. صعوبة التعلم ليست تصنيف خطورة.

**Advanced academy:** 50 additional bilingual scenarios at `/academy`, including 16 payment, 10 authorization, 7 rate-limit, 12 XSS-context and 5 other code cases. Payment/provider decisions, IP sources, NoSQL, template, redirect and SSRF behavior are explicitly bounded fixtures. SQLi runs against real in-memory SQLite; XSS has actual sandboxed browser previews (11 execution checks and one href-policy inspection), with 36 context-specific payload/control samples. This is a local learning environment, not a scanner or an exhaustive exploit collection. See [the English guide](docs/academy.en.md) for controls, sample inputs and limitations.

### التحديث على Termux

أوقف الخادم القديم بـ Ctrl+C، ثم:

```bash
cd ~/Between-Bytes-Web-Labs
git pull --ff-only origin main
python app.py --port 8002
```

افتح **http://127.0.0.1:8002/academy**. تحقق من ظهور **WEB LABS · 0.9.2** وخمسة مختبرات رئيسية، مجموعها 50 حالة. إذا فشل `git pull` بسبب تعديلات محلية، احتفظ بها ولا تستخدم reset لحذفها.

### تنفيذ 0.9 والاستجابات

- إرسال JSON فعلي إلى `/academy/api/{group}/{case}/{variant}`، مع حالات HTTP فعلية وأخطاء أعمال ومعرف طلب.
- قراءة طلب الدفع وسجل معاملاته عبر `/academy/resource` بعد كل تغيير؛ تقييم التمرين منفصل في `/academy/evidence`.
- إشعارات المزود تستخدم HMAC-SHA256 على حدث محلي ثابت، والإيصالات سجلات مختبرية. لا اتصال ببوابة دفع أو تحصيل أموال.
- تكرار إشعار صحيح قد يرجع 200 دون أثر جديد؛ لا تعتبر كل 200 تجاوزاً ولا كل رفض تراجعاً عن معاملة سابقة صحيحة.
- أمثلة الكود داخل الشرح مقتطفات توضيحية؛ التنفيذ في `commerce.py` و`academy.py` و`academy_http.py`.

**v0.9:** five grouped application labs, deeper bilingual investigations, persisted checkout orders/transactions/entitlements and actual HTTP response statuses. Read [the guide](docs/academy.en.md) for the exact local provider, concurrency and browser boundaries.

### تصحيح استجابات الدفع · 0.9.1

القيم المخالفة في السعر والإجمالي والخصم والشحن والضريبة والتقريب تُرفض في المُصلحة بـ422 قبل أي تغيير. إعادة قسيمة مستخدمة تُرجع 409؛ الدفعات المختلطة 207 مع حالة كل عملية. إعادة إشعار دفع صحيح قد تبقى 200 دون أثر إضافي. الحقول الناقصة 400. لوحة قراءة المورد تعرض GET مستقلاً؛ لا تخلط 200 القراءة بحالة POST الدفع.

### المراجعة الشاملة · 0.9.2

راجعت مصفوفة HTTP الحالات المتقدمة الخمسين والغرف الأساسية الثلاث عشرة، مع اختبارات مدخلات خاطئة وثبات البيانات والمتصفح. [نتائج المراجعة ومصفوفة الاستجابات وحدودها](docs/audit-0.9.2.md).

A full local audit covers all 50 advanced cases and 13 foundation rooms, including explicit HTTP expectations, rejected-write invariants, malformed inputs and browser execution. See the [audit report](docs/audit-0.9.2.md) for exact outcomes and boundaries.
