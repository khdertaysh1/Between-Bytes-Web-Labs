# Between Bytes Web Labs

مختبرات عربية لفهم ثغرات تطبيقات الويب: تجربة واضحة، سبب برمجي، وإصلاح يمكن التحقق منه.

**الإصدار الأول:** ثلاثة مختبرات مستقلة، كل واحد بنسخة ضعيفة `vulnerable` ونسخة مُصلحة `fixed`. يعمل المشروع محلياً على Python 3.10+ دون مكتبات خارجية، مع واجهة تناسب الهاتف.

| المختبر | الخطأ المتعمّد | ما يوضحه الإصلاح |
|---|---|---|
| User Enumeration | اختلاف حالة HTTP والرسالة حسب وجود الحساب | توحيد الاستجابة العامة |
| Rate Limit | الوثوق بـ X-Forwarded-For المرسل من العميل | حدود للحساب الموحّد ولمصدر الاتصال |
| Reset Email Abuse | إنشاء رسالة لكل طلب استعادة | مهلة للحساب وحد للمصدر مع استجابة عامة |

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

1. اختر User Enumeration والنسخة الضعيفة.
2. أرسل طلباً للبريد `alice@example.test` ثم `nobody@example.test`.
3. لاحظ اختلاف HTTP والرسالة. كرّر التجربة بالنسخة المُصلحة.
4. تابع [دليل المختبرات بالعربية](docs/lessons.ar.md) لتجارب تحديد المحاولات وصندوق البريد الوهمي.

الحسابات الوهمية الموجودة: `alice@example.test` و`bob@example.test`. لا توجد حسابات فعلية أو كلمات سر أو رسائل تُرسل للخارج. زر **تصفير المختبرات** يمسح العدّادات والبريد في النسختين، وإعادة التشغيل تمسح كل البيانات.

## الاختبارات

```bash
python -m unittest discover -s tests -v
```

تختبر سلوك النسختين، انقضاء المهلة بساعة وهمية، حدود الحساب والمصدر، وصندوق البريد ومسارات HTTP محلياً. لا تحتاج اتصالاً بالإنترنت.

## حدود المختبر

يرتبط الخادم بـ `127.0.0.1` فقط. لا تنشره على استضافة عامة أو تمرره عبر نفق. الدروس تحتوي أخطاء مقصودة. صندوق البريد أداة مراقبة محلية متاحة للمتدرّب، وليس واجهة لمستخدم خارجي. يقبل صندوق البريد الحسابين الوهميين فقط ويحتفظ بآخر 100 رسالة في الذاكرة؛ لا يحتوي التطبيق أي عميل SMTP.

النسخ المُصلحة أمثلة تعليمية مركّزة وليست نظام مصادقة جاهزاً للإنتاج: لا قاعدة بيانات، لا مصادقة فعلية، لا طوابير بريد أو تخزين موزّع. درس enumeration يعالج تسريب الحالة والرسالة ولا يثبت مقاومة فروقات التوقيت. اقرأ حدود كل إصلاح في الدليل.

## English

Three local, intentionally vulnerable web lessons with paired fixes: account enumeration, trusting spoofed proxy identity for rate limiting, and repeated reset-email generation. Python 3.10+, standard library only. Run `python app.py`, open `http://127.0.0.1:8000`, then compare `vulnerable` and `fixed` modes. All mail is captured in memory for two synthetic accounts; no external delivery or target scanner exists. See [English guide](docs/lessons.en.md).

Created for the Between Bytes community by [khdertaysh1](https://github.com/khdertaysh1).
