# حصة الملف بعد فك الترميز
افتح مختبر رفع الملفات ثم «حجم الملف بعد فك الترميز». الحساب والملف وهميان؛ لا حفظ على القرص ولا اتصال خارجي. حصة الملف التعليمية 32 بايتاً، وليست توصية لحجم الملفات في تطبيق حقيقي.

1. نفّذ الطلب السليم في المصلحة. راجع decoded_bytes وencoded_characters.
2. في أداة الترميز، اكتب 33 حرف A، حوّلها إلى Base64 وانقل الناتج إلى content دون تغيير filename أو content_type. أرسل الطلب في الضعيفة ثم نفسه في المصلحة.
3. جرّب 32 و34 حرفاً، ثم نصاً غير صالح مثل @@@. توقع 201 للحد المقبول و413 لتجاوز الحصة و422 للترميز غير الصالح.
4. نزّل دفتر الدليل وقارن revision قبل الرفض وبعده. مشاهدة المقارنة أو فتح التلميحات لا تمنح الإنجاز؛ تحتاج أثراً في الضعيفة ورفض المدخل نفسه في المصلحة وطلباً سليماً مقبولاً.

فك Base64 وحساب البايتات حقيقيان. التخزين عداد داخل الذاكرة، وليس رفعاً لنظام ملفات أو فك ضغط أو تحققاً من صور. الإصلاح يفرض الحصة قبل تعديل الحالة؛ يظل حد الطلب الخارجي ضرورياً لمنع استهلاك الذاكرة. التلميحات الثلاث خاصة بالتمرين وتظهر بالتدرج.

## Publication review · 2026-11-28
No published URL is documented in README, deployment workflows or repository homepage; has_pages is false. No public academy site was opened or guessed, so deployed counts and deployment lag remain unverified. Main has 96 cases. Pending HPP #3 and token #4 are preserved; this independent proposal has 97. Combining all three requires count 99 and review of count/version conflicts. Local UI, rather than an unverified deployment, informed the case-specific hint improvement.

لم نعثر على رابط نشر موثق. مراجعة هذا التمرين تخص النسخة المحلية؛ لا نؤكد عدد الحالات على موقع منشور. الاقتراحان السابقان HPP وToken ما زالا منفصلين؛ دمج الثلاثة يحتاج مراجعة الأعداد إلى 99 وتسوية تعارض الإصدار.
