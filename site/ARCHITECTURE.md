# Attend — خريطة البنية والتوثيق
تاريخ المراجعة: 17 نوفمبر 2026.

## حالة Graphify
استُخدم Graphify عبر list_repositories وgraphify_help. المتاح فقط bedotalha/motion3d وbedotalha/Motion3D_MediaPipeLab؛ Attend غير مفهرس في الاتصال الحالي، ولا يحتوي .git/config المحلي على remote. الخريطة التالية مستمدة من الملفات المحلية وليست علاقات مثبتة من رسم Graphify.
لإتاحة الفهرسة لاحقًا: ربط Attend بمستودع بعيد ونشر المصدر المعتمد، ثم تفعيله ضمن Repositories في https://app.graphify.com. تقارن commitSha بالإصدار المحلي قبل اعتماد النتائج. لم يُنشأ مستودع أو تُرفع ملفات في هذه المهمة.

## المكونات
| الملف | المسؤولية |
|---|---|
| index.html | واجهة الأستاذ والطالب وشاشة QR؛ إدارة المقررات والحضور والتقارير |
| server.js | خادم HTTP، المصادقة، API، التحقق وحفظ البيانات |
| data/attendance.sqlite | تخزين بيانات التطبيق والحضور محليًا |
| package.json | تشغيل Node مع experimental-sqlite واعتماد qrcode |
| ../run-attendance.cmd | تشغيل المشروع |

## مسارات التطبيق
- المصادقة: /api/auth-status و/api/setup و/api/login و/api/logout. تحمي requireInstructor مسارات الأستاذ؛ إدارة الحساب عبر /api/profile و/api/change-password.
- الحالة: GET وPUT /api/state، مع readState وwriteState للقراءة والحفظ.
- تسجيل الطالب: /api/public-session ثم POST /api/checkin؛ يتحقق من الجلسة وPIN والإقرار والطالب وسياسة الموقع والجهاز. تحسب attendanceTiming حالة التأخر، وتتحقق pinIsValid من الرمز.
- حفظ التسجيل: persistCheckin وflushPendingCheckinWrites وapplyCheckinWrite؛ تنسق waitForSessionCheckinWrites الانتظار عند إنهاء الجلسة.
- التحكم: /api/session/control و/api/session/end؛ expireSessions للإنهاء التلقائي. يعرض /api/session-display الرمز وتنتج /api/qr.svg صورة QR.
- الموقع: assessLocation وclassLocationConsensus وassessNetworkArea وتحديث تقييم الأقران. markSharedDevice يعلّم مشاركة معرّف المتصفح، وليس إثبات هوية الهاتف.

## لوحة التنبيه
تستدعي واجهة الجلسة الفعلية وتفاصيل الجلسة المفتوحة liveVerificationAlerts. تظهر اللوحة عند device=shared أو location.status=verify أو not_shared مع different_network. تأتي أسماء مستخدمي الجهاز من sharedDeviceNames وتفاصيل الموقع من locationSummary، ويظهر تلميح المتصفح الأصلي عبر title.
زر data-manual يستدعي manualStatus ثم manualAttendanceRecord وsaveDb؛ يعيد renderAll العرض بعد تأكيد الحفظ. يستخدم سجل الطالب نفسه ويحافظ على إشارات التحقق الأصلية.
startStateRefresh يجلب الحالة كل 3.5 ثانية عندما تكون الصفحة ظاهرة، مع مراعاة انتظار الحفظ الجاري وعدم استبدال الحالة أثناء المزامنة. startPinTicker يحدث عرض الرمز كل ثانية.
يوجد تعريف أقدم لـ renderSessions ثم إسناد لاحق renderSessions=function؛ الإسناد اللاحق هو المسار المستخدم. أُصلح ظهور اللوحة بربطها بالمسار الفعلي.
ملاحظة مراجعة: attachSessionRosterTools تختار أول .table-wrap؛ إضافة جدول التنبيهات قبل جدول الطلاب تستدعي اختبار محدد الجدول وأدوات البحث والتعديل الجماعي قبل اعتبارها متحققة. لم تُغير هذه المهمة كود التطبيق.

## الاختبارات وحدود الدليل
الملفات الموجودة: tests/course-import.cjs وcourse-isolation.cjs وsession-location.cjs وstudent-profile.cjs. لم تُشغّل خلال مهمة التوثيق، ولا يثبت جردها تغطية لوحة التنبيه.
في العمل السابق اجتاز JavaScript فحص الصياغة وقبل API ثمانية تسجيلات تجريبية، منها خمسة لطلاب موجودين، مع تأكيد إشارات الموقع والجهاز المشترك. لم يُنجز التحقق البصري أو حفظ تعديل الحالة من اللوحة أو اختبار التلميح وأدوات القائمة في المتصفح.

## المراجع المحلية
README.md وATTENDANCE-MVP-SPEC.md وindex.html وserver.js وpackage.json.

### متابعة تحديث لوحة التنبيه — 17 نوفمبر 2026
أُعيد ربط أدوات البحث والتصفية والتعديل الجماعي بجدول الطلاب الذي يحتوي صفوف data-session-roster-row، بدل اختيار أول جدول. تعرض لوحة التنبيه الحالات غير المراجعة فقط. يتيح زر «قبول جميع الحالات قيد المراجعة» اعتماد مراجعة الحالات الظاهرة للجلسة مع حفظ جماعي وسجل تدقيق واستعادة القيم عند فشل الحفظ. يحافظ الاعتماد على حالات الحضور الحالية، ويستخدم اشتقاق الحالة المعتاد للسجلات المصنفة verify. بعد الاعتماد أو تعديل الحالة إلى غير verify تختفي من لوحة التنبيه، مع بقاء إشارات الموقع والجهاز في السجل. اجتاز JavaScript فحص الصياغة، وأكد اختبار دوال المراجعة أن الحالة تظهر قبل المراجعة وتختفي بعد تعديلها أو اعتمادها. التحقق البصري وحفظ الاعتماد الجماعي عبر المتصفح لم ينفذا.
