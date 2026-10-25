# Between Bytes Web Labs · 0.11.0

مختبرات لتعلّم ثغرات تطبيقات الويب بالعربية والإنكليزية. اقرأ كيف تعمل الميزة، عدّل الطلب، افحص الأثر، ثم قارن النسخة الضعيفة بالمُصلحة. جميع الحالات مفتوحة، بلا نقاط أو شروط انتقال.

واجهة واحدة تجمع **9 مختبرات و72 حالة**. أُزيلت الواجهة القديمة بالكامل؛ تعيد الروابط القديمة المدعومة فتح الحالة المناسبة في الواجهة الحالية.

| المختبر / Lab | الحالات / Cases |
|---|---:|
| منطق الدفع / Payment logic | 16 |
| سياقات XSS / XSS contexts | 12 |
| الصلاحيات وIDOR / Access control | 10 |
| حدود المحاولات / Rate limits | 7 |
| SQL وNoSQL والقوالب / Code flaws | 3 |
| SSRF | 6 |
| CSRF | 6 |
| CORS | 6 |
| Open Redirect | 6 |

SSRF وCSRF وCORS وOpen Redirect **مختبرات مستقلة**؛ لكل منها قصص وطلبات سليمة وأمثلة مخالفة وتفسير نتائج وإصلاحات. [الدليل العربي](docs/academy.ar.md) · [English guide](docs/academy.en.md).

## مساحة العمل اليدوي الجديدة

داخل **كل حالة من الحالات الـ72**، افتح «مساحة العمل اليدوي». الشكل والشرح السابقان محفوظان، وأضيفت تبويبات:

- **التطبيق:** عدّل الحقول وأنواعها، أرسلها أو احذفها، وجرّب الطلب بنفسك.
- **الطلبات:** راجع طلبات POST المرسلة من المحرر، حمّل طلباً سابقاً، أعد إرساله، أو حدد طلبين لمقارنة المدخلات والاستجابات. الإعادة قد تغيّر حالة الجولة.
- **محرر HTTP:** عدّل الجسم والرؤوس المدعومة لمسار الحالة الحالية. Origin وCookie يبقيان تحت تحكم المتصفح.
- **الترميز:** حوّل URL وHTML وBase64 مع دعم UTF-8 ثم انقل الناتج إلى حقل تختاره.
- **المتصفح والنتائج:** افحص أثر المحاولة، ولقطة DOM الفعلية في XSS، وخطوات النقل أو نتائج العدّاد حسب المختبر.

في CSRF أضيفت تجربة متصفح فعلية للحالات الست: حساب الباحث وحساب المستخدم بجلستين منفصلتين، ومحرر HTML/JavaScript، ومعاينة على أصل محلي ثانٍ، وسجل خادم يبين الطلب والأثر. في CORS توجد تجربة مرافقة فعلية لعكس الأصل وقراءة البيانات أو منعها؛ تبقى أنماط مطابقة الأصول الست في نموذج السياسة.

[دليل الأدوات بالعربية](docs/studio.ar.md) · [Workspace guide](docs/studio.en.md).

## التشغيل على Termux

```bash
pkg update
pkg install python git
git clone https://github.com/khdertaysh1/Between-Bytes-Web-Labs.git
cd Between-Bytes-Web-Labs
python app.py --port 8002
```

افتح **http://127.0.0.1:8002/**. ستجد رقم الإصدار **0.11.0** أعلى الصفحة.

للتحديث، أوقف الخادم بـ **Ctrl+C** ثم نفّذ داخل مجلد المستودع:

```bash
git pull --ff-only origin main
python app.py --port 8002
```

على Linux/macOS استخدم Python 3.10+ وGit والأوامر نفسها؛ قد يكون اسم الأمر `python3`. لا توجد حزم Python إضافية مطلوبة. إذا منع Git التحديث بسبب تعديلات محلية، احتفظ بها قبل حل التعارض.

## كيف تستخدم المختبر؟

1. اختر موضوعاً ثم حالة من قائمة حالاته.
2. اقرأ «كيف تعمل الميزة؟» و«أين الخطأ؟».
3. شغّل الطلب السليم في النسخة المُصلحة لتعرف النتيجة الطبيعية.
4. جرّب المثال المخالف في النسخة الضعيفة ثم أرسله نفسه إلى المُصلحة.
5. اقرأ الأثر الفعلي، لا رمز HTTP وحده. احفظ استنتاجك أو نزّل دفتر الدليل.

الدفع يحفظ الطلب والمعاملات والاستحقاقات، وله قراءة مستقلة للحالة. لا يعني رفض طلب جديد التراجع عن عملية صحيحة سابقة؛ استخدم «جولة جديدة» للمقارنة من البداية. حالات العدّاد تحتاج استهلاك الميزانية في كل نسخة قبل محاولة التجاوز.

## What actually runs?

This is a local training application, not a website scanner. The server binds to `127.0.0.1`, uses synthetic accounts and does not contact payment providers or external targets.

- SQL exercises use real in-memory SQLite queries. XSS uses isolated browser previews, with 11 execution contexts and one URL-policy inspection; 36 payload/control samples are available.
- Payment operations persist local orders, transaction ledgers and entitlements. Rate-limit source addresses are fixture labels, not real IP changes.
- The JSON exercises in the four request-security labs are **closed policy models**. SSRF uses an in-memory transport trace, redirects show destination decisions without navigation, and CSRF/CORS use supplied origin/session inputs. Their results are not proof of real cross-origin browser exploitation, DNS rebinding or SameSite bypass.
- Companion browser practice adds actual CSRF requests for all six CSRF cases and real CORS origin-reflection read/block behavior. It uses separate scoped HttpOnly synthetic sessions and a learner-authored page on another loopback port. The ports are same-site; this does not demonstrate a SameSite bypass. Browser evidence and policy-model marks remain separate.
- CORS can correctly return HTTP 200 while denying cross-origin readability. CSRF rejection uses 403, 405 or 415 depending on token/origin, method or content type. A successful request is not automatically a security finding.

The previous foundation UI and its static assets have been removed. Legacy backend endpoints remain for compatibility and regression coverage; they do not expose the old interface. The [current verification report](docs/audit-0.11.0.md) records this release. The [0.9.2 audit](docs/audit-0.9.2.md) describes that historical release, not the current catalog.

## Validation

```bash
python -m unittest discover -s tests -q
```

Optional browser suites require Playwright and a Chromium installation. Set `BB_BROWSER_PATH` to the executable, start the server on port 8000, and run:

```bash
node tests/studio.cjs
node tests/studio_browser.cjs
node tests/studio_edges.cjs
node tests/academy.cjs
node tests/grouped.cjs
node tests/request_security.cjs
node tests/payment_status.cjs
node tests/audit_edges.cjs
node tests/payloads.cjs
```

## Automated checks and review

Updates are proposed on branches and PRs for owner review. The `Lab quality` workflow runs Python 3.10/3.13 checks, all browser groups and three regression-sensitivity experiments, then reports `quality-gate`. Dependencies/actions are pinned and CI has read-only repository permissions. Node remains development-only.

**Owner activation required:** a workflow alone does not protect main. Branch protection must require `quality-gate` and PRs; the connected integration cannot administer this setting. See [CONTRIBUTING.md](CONTRIBUTING.md) for the exact settings/REST body and the single-owner review limitation. [الشرح بالعربية](docs/quality.ar.md). Scheduled development tasks prepare PRs and do not merge them automatically.
