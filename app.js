
if (typeof Chart !== 'undefined') {
    Chart.defaults.color = '#8b97b3';
    Chart.defaults.font.family = "'IBM Plex Sans Arabic', sans-serif";
    Chart.defaults.borderColor = 'rgba(148,163,184,0.12)';
}

// حالة البيانات والمستخدم
let userStats = { total: 0, safe: 0, threat: 0 };
let currentUser = null;
const SESSION_IDLE_TIMEOUT_MS = 5 * 60 * 1000;
let lastSessionRefreshAt = 0;
let scanLogsHistory = [];
let chatHistory = [];
let qrSource = 'text';   // آخر مصدر استخدمه المستخدم في تبويب QR: 'image' أو 'text'
let qrSourceLabel = '';

const API = location.protocol === 'file:'
    ? 'http://127.0.0.1:8000'
    : (['5500', '3000', '8080'].includes(location.port)
        ? `${location.protocol}//${location.hostname}:8000`
        : location.origin);

const SECTION_PATHS = {
    scannerSection: '/smart-scan',
    cryptoLabSection: '/crypto-lab',
    websiteAuditSection: '/website-scan',
    adminSection: '/dashboard',
    reportsSection: '/scan-history',
    extensionSection: '/extension-management'
};
const PATH_SECTIONS = Object.fromEntries(Object.entries(SECTION_PATHS).map(([section, path]) => [path, section]));

function setAppPath(path, replace = false) {
    if (location.protocol === 'file:' || location.pathname === path) return;
    history[replace ? 'replaceState' : 'pushState']({}, '', path);
}

function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// جلسة خاملة قصيرة: النشاط يجدد صلاحيتها، والرفريش يستعيدها ما دامت صالحة.
function saveSession() {
    if (!currentUser) return;
    try {
        localStorage.setItem('ps_user', JSON.stringify({ user: currentUser, expiresAt: Date.now() + SESSION_IDLE_TIMEOUT_MS }));
    } catch (e) {}
}
function clearSession() { try { localStorage.removeItem('ps_user'); } catch (e) {} }

function refreshSessionOnActivity() {
    if (!currentUser || Date.now() - lastSessionRefreshAt < 5000) return;
    lastSessionRefreshAt = Date.now();
    saveSession();
}

function restoreSavedSession() {
    try {
        const saved = JSON.parse(localStorage.getItem('ps_user') || 'null');
        if (!saved?.user || !Number.isFinite(saved.expiresAt) || saved.expiresAt <= Date.now()) {
            clearSession();
            return null;
        }
        return saved.user;
    } catch (e) {
        clearSession();
        return null;
    }
}

setInterval(() => {
    if (!currentUser) return;
    try {
        const saved = JSON.parse(localStorage.getItem('ps_user') || 'null');
        if (!saved?.expiresAt || saved.expiresAt <= Date.now()) logout();
    } catch (e) {
        logout();
    }
}, 10000);

['click', 'keydown', 'pointerdown', 'scroll', 'touchstart'].forEach(eventName => {
    window.addEventListener(eventName, refreshSessionOnActivity, { passive: true });
});

function recomputeStats() {
    userStats.total = scanLogsHistory.length;
    userStats.threat = scanLogsHistory.filter(l => l.isPhishing).length;
    userStats.safe = userStats.total - userStats.threat;
}

async function saveActivityLog(element, type, isPhishing, details) {
    const entry = { id: null, element, type, isPhishing: !!isPhishing, createdAt: new Date().toISOString(), details: details ? JSON.stringify(details) : null };
    if (!currentUser?.id) return entry;
    try {
        const response = await fetch(`${API}/api/logs`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_id: currentUser.id, element, scan_type: type, is_phishing: !!isPhishing, details: entry.details })
        });
        if (response.ok) {
            const saved = await response.json();
            return { ...entry, id: saved.id, createdAt: saved.created_at, details: saved.details };
        }
    } catch (error) { console.warn('تعذر حفظ النشاط في السجل', error); }
    return entry;
}

function recordActivity(entry) {
    scanLogsHistory.unshift(entry);
    recomputeStats();
    updateCountersUI();
    renderLogsTable();
}

// تحميل سجلات المستخدم من الداتابيز
async function loadUserLogs() {
    scanLogsHistory = [];
    if (currentUser && currentUser.id) {
        try {
            const r = await fetch(`${API}/api/logs/${currentUser.id}`);
            if (r.ok) {
                const rows = await r.json();
                scanLogsHistory = rows.map(l => ({ id: l.id, element: l.element, type: l.scan_type, isPhishing: l.is_phishing, createdAt: l.created_at, details: l.details }));
            }
        } catch (e) { console.warn('تعذر تحميل السجلات', e); }
    }
    recomputeStats();
}

// التبديل بين الدخول والإنشاء
function switchForm(formType) {
    if (formType === 'register') {
        document.getElementById('loginForm').style.display = 'none';
        document.getElementById('registerForm').style.display = 'block';
    } else {
        document.getElementById('loginForm').style.display = 'block';
        document.getElementById('registerForm').style.display = 'none';
    }
    setAppPath(formType === 'register' ? '/register' : '/login');
}

// إظهار وإخفاء صندوق الحسابات التجريبية
function toggleDemoBox() {
    const content = document.getElementById('demoContent');
    content.style.display = content.style.display === 'none' ? 'flex' : 'none';
}

// تعبئة بيانات الدخول السريع
function fillDemo(user, pass) {
    document.getElementById('loginUsername').value = user;
    document.getElementById('loginPassword').value = pass;
}

// تسجيل الدخول
async function handleLogin(event) {
    event.preventDefault();
    const user = document.getElementById('loginUsername').value.trim();
    const pass = document.getElementById('loginPassword').value.trim();

    try {
        const response = await fetch('http://127.0.0.1:8000/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: user, password: pass })
        });

        if (!response.ok) {
            const errData = await response.json();
            alert(errData.detail || "خطأ في بيانات تسجيل الدخول!");
            return;
        }

        const data = await response.json();
        currentUser = data.user;
        saveSession();
        await loadUserLogs();

        setupUserInterface();
    } catch (error) {
        alert("تعذر الاتصال بالباك إند. انتظر حتى يكتمل تشغيل السيرفر ثم جرّب تسجيل الدخول مرة أخرى.");
    }
}

function setupUserInterface() {
    document.getElementById('authGateSection').style.display = 'none';
    document.getElementById('appMainLayout').style.display = 'flex';

    document.getElementById('sidebarUserName').innerText = currentUser.name;
    document.getElementById('sidebarUserRole').innerText = currentUser.role === 'Admin' ? 'مدير النظام (Admin)' : 'مستخدم (User)';
    document.getElementById('sidebarUserBadgeIcon').innerText = currentUser.name.slice(0, 2);

    if (currentUser.role === "Admin") {
        document.getElementById('adminMenuGroup').style.display = 'block';
        document.getElementById('adminLinks').style.display = 'block';
        document.getElementById('navAdmin').style.display = 'flex';
        document.getElementById('navReports').style.display = 'flex';
        document.getElementById('navExtension').style.display = 'flex';
        loadAdminPanel();
    } else {
        document.getElementById('adminMenuGroup').style.display = 'none';
        document.getElementById('adminLinks').style.display = 'none';
        document.getElementById('navAdmin').style.display = 'none';
        document.getElementById('navReports').style.display = 'none';
        document.getElementById('navExtension').style.display = 'none';
    }

    updateCountersUI();
    renderLogsTable();
    showSection('scannerSection');
}

// إنشاء حساب جديد
async function handleRegister(event) {
    event.preventDefault();
    const name = document.getElementById('regUsername').value.trim();
    const email = document.getElementById('regEmail').value.trim();
    const pass = document.getElementById('regPassword').value.trim();

    try {
        const response = await fetch('http://127.0.0.1:8000/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: name, email: email, password: pass })
        });

        if (!response.ok) {
            const errData = await response.json();
            alert(errData.detail || "حدث خطأ أثناء إنشاء الحساب!");
            return;
        }

        alert("تم إنشاء الحساب بنجاح في قاعدة البيانات! يمكنك الآن تسجيل الدخول.");
        switchForm('login');
    } catch (error) {
        alert("تم محاكاة إنشاء الحساب بنجاح! يمكنك تسجيل الدخول الآن.");
        switchForm('login');
    }
}

function logout() {
    clearSession();
    chatHistory = [];
    currentUser = null;
    userStats = { total: 0, safe: 0, threat: 0 };
    scanLogsHistory = [];
    ['urlInput', 'emailInput', 'qrTextInput', 'qrImageInput', 'loginUsername', 'loginPassword', 'regUsername', 'regEmail', 'regPassword'].forEach(id => {
        const el = document.getElementById(id); if (el) el.value = '';
    });
    const res = document.getElementById('scanResult');
    res.style.display = 'none'; res.innerHTML = '';
    switchScanTab('url');
    updateCountersUI();
    renderLogsTable();
    const msgs = document.getElementById('chat-messages');
    while (msgs.children.length > 1) msgs.lastChild.remove();
    document.getElementById('chat-box').style.display = 'none';
    document.getElementById('usersTableBody').innerHTML = '';
    document.getElementById('appMainLayout').style.display = 'none';
    document.getElementById('authGateSection').style.display = 'flex';
    setAppPath('/login');
}

function switchScanTab(type) {
    document.getElementById('urlTab').style.display = type === 'url' ? 'block' : 'none';
    document.getElementById('emailTab').style.display = type === 'email' ? 'block' : 'none';
    document.getElementById('qrTab').style.display = type === 'qr' ? 'block' : 'none';

    document.getElementById('btnTabUrl').classList.toggle('active', type === 'url');
    document.getElementById('btnTabEmail').classList.toggle('active', type === 'email');
    document.getElementById('btnTabQr').classList.toggle('active', type === 'qr');

    document.getElementById('scanResult').style.display = 'none';
}

function updateCountersUI() {
    document.getElementById('userTotalScans').innerText = userStats.total;
    document.getElementById('userSafeScans').innerText = userStats.safe;
    document.getElementById('userThreatScans').innerText = userStats.threat;
}

// قراءة الـ QR من الصورة. بترجّع دايماً نتيجة (مش بتعلّق أبداً):
// { data: "..." } أو { data: null } أو { error: "lib|load|decode|timeout" }
function extractQRFromImage(file) {
    return new Promise((resolve) => {
        if (typeof jsQR === 'undefined') {
            // بديل: قارئ الباركود المدمج في بعض المتصفحات (Chrome/Edge الحديثة)
            if ('BarcodeDetector' in window) {
                const u = URL.createObjectURL(file);
                const im = new Image();
                im.onerror = () => { URL.revokeObjectURL(u); resolve({ error: 'load' }); };
                im.onload = async () => {
                    try {
                        const codes = await new BarcodeDetector({ formats: ['qr_code'] }).detect(im);
                        URL.revokeObjectURL(u);
                        resolve({ data: codes.length ? codes[0].rawValue : null });
                    } catch (e) { URL.revokeObjectURL(u); resolve({ error: 'lib' }); }
                };
                im.src = u;
                return;
            }
            resolve({ error: 'lib' });
            return;
        }

        const url = URL.createObjectURL(file);
        const img = new Image();
        const done = (result) => { clearTimeout(timer); URL.revokeObjectURL(url); resolve(result); };
        const timer = setTimeout(() => done({ error: 'timeout' }), 20000);

        img.onerror = () => done({ error: 'load' });
        img.onload = () => {
            try {
                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d', { willReadFrequently: true });
                // صور الموبايل كبيرة جداً (4000x3000) فبنصغّرها بمقاسات مختلفة ونجرب
                for (const maxSide of [800, 1400, 2000]) {
                    const scale = Math.min(1, maxSide / Math.max(img.width, img.height));
                    const w = Math.round(img.width * scale), h = Math.round(img.height * scale);
                    canvas.width = w; canvas.height = h;
                    ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, w, h);   // خلفية بيضاء للصور الشفافة
                    ctx.drawImage(img, 0, 0, w, h);
                    const imageData = ctx.getImageData(0, 0, w, h);
                    const code = jsQR(imageData.data, w, h, { inversionAttempts: 'attemptBoth' });
                    if (code && code.data) { done({ data: code.data }); return; }
                    if (scale === 1) break;
                }
                done({ data: null });
            } catch (e) {
                console.error('QR decode error', e);
                done({ error: 'decode' });
            }
        };
        img.src = url;
    });
}

async function performScan(type) {
    let inputVal = "";
    let endpoint = "";
    const resultBox = document.getElementById('scanResult');

    if (type === 'url') {
        inputVal = document.getElementById('urlInput').value.trim();
        endpoint = 'http://127.0.0.1:8000/predict/url';
        if (!inputVal) { alert("يرجى إدخال الرابط أولاً!"); return; }
    } else if (type === 'email') {
        inputVal = document.getElementById('emailInput').value.trim();
        endpoint = 'http://127.0.0.1:8000/predict/email';
        if (!inputVal) { alert("يرجى إدخال نص البريد الإلكتروني أولاً!"); return; }
    } else if (type === 'qr') {
        const imageInput = document.getElementById('qrImageInput');
        const textInput = document.getElementById('qrTextInput').value.trim();
        const hasImage = !!(imageInput.files && imageInput.files[0]);

        // الأولوية لآخر حاجة المستخدم عملها (صورة أو نص) عشان ما يتفحصش نص قديم بالغلط
        const useImage = hasImage && (qrSource === 'image' || !textInput);

        if (!useImage && textInput) {
            inputVal = textInput;
            qrSourceLabel = 'النص المكتوب يدوياً';
        } else if (useImage) {
            qrSourceLabel = 'الصورة: ' + imageInput.files[0].name;
            resultBox.style.display = 'block';
            resultBox.innerHTML = `<div class="verdict load"><i class="fa-solid fa-spinner fa-spin"></i> جاري فحص الصورة وقراءة محتوى الـ QR Code...</div>`;
            const qr = await extractQRFromImage(imageInput.files[0]);
            if (qr.error) {
                const msgs = {
                    lib: 'مكتبة قراءة الـ QR (jsQR) لم تُحمَّل. حمّل الملف jsQR.js وحطه في فولدر frontend بجانب index.html.',
                    load: 'تعذر فتح الصورة. جرّب صيغة PNG أو JPG (صيغة HEIC غير مدعومة).',
                    decode: 'حدث خطأ أثناء قراءة الصورة.',
                    timeout: 'استغرقت القراءة وقتاً طويلاً. جرّب صورة أصغر.'
                };
                resultBox.innerHTML = `<div class="verdict bad"><strong>${msgs[qr.error]}</strong></div>`;
                return;
            }
            if (!qr.data) {
                resultBox.innerHTML = `<div class="verdict bad"><strong>لم يتم العثور على QR Code في هذه الصورة. جرّب صورة أوضح.</strong></div>`;
                return;
            }
            inputVal = qr.data;
        } else {
            alert("يرجى رفع صورة QR Code أو إدخال محتواه النصي أولاً!");
            return;
        }
        endpoint = 'http://127.0.0.1:8000/predict/qr';
    }

    resultBox.style.display = 'block';
    resultBox.innerHTML = `<div class="verdict load"><i class="fa-solid fa-spinner fa-spin"></i> جاري التحليل بالذكاء الاصطناعي (AI Analyzing)...</div>`;

    let isPhishing = false;
    let analysis = null;
    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(type === 'url' ? { url: inputVal } : { text: inputVal })
        });
        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.detail || 'خطأ في السيرفر');
        }
        analysis = await response.json();
        isPhishing = (analysis.result === "phishing" || analysis.is_phishing === true);
    } catch (e) {
        // مفيش نتيجة وهمية: لو السيرفر مش شغال بنقول كده بصراحة ومش بنسجّل الفحص
        resultBox.innerHTML = `<div class="verdict bad"><i class="fa-solid fa-plug-circle-xmark"></i> <div><strong>تعذر إتمام الفحص.</strong> ${escapeHtml(e.message || '')} — تأكد إن الباك إند شغال على بورت 8000.</div></div>`;
        return;
    }

    const level = analysis.level || (isPhishing ? 'phishing' : 'safe');
    const flagged = (level !== 'safe');   // المشبوه بيتسجّل كتهديد برضه
    isPhishing = flagged;
    const decodedHtml = (type === 'qr')
        ? `<div style="margin-top:8px; font-size:.85rem; opacity:.85;">المصدر: ${escapeHtml(qrSourceLabel)}<br>محتوى الـ QR المقروء: <code style="direction:ltr; display:inline-block; word-break:break-all;">${escapeHtml(inputVal)}</code></div>` : '';
    const reasonsHtml = (analysis.reasons && analysis.reasons.length)
        ? `<ul style="margin:8px 0 0; padding-inline-start:18px; font-size:.9rem; opacity:.9;">${analysis.reasons.map(r => `<li>${escapeHtml(r)}</li>`).join('')}</ul>` : '';
    const scoreHtml = (typeof analysis.score === 'number') ? ` <small>(درجة الخطورة: ${analysis.score}/100)</small>` : '';
    if (level === 'phishing') {
        resultBox.innerHTML = `<div class="verdict bad"><i class="fa-solid fa-triangle-exclamation"></i> <div><strong>تحذير: العنصر مشبوه (Phishing Threat)</strong>${scoreHtml}${reasonsHtml}${decodedHtml}</div></div>`;
    } else if (level === 'suspicious') {
        resultBox.innerHTML = `<div class="verdict warn"><i class="fa-solid fa-circle-exclamation"></i> <div><strong>مشكوك فيه — كن حذراً</strong>${scoreHtml}${reasonsHtml}${decodedHtml}</div></div>`;
    } else {
        resultBox.innerHTML = `<div class="verdict good"><i class="fa-solid fa-circle-check"></i> <div><strong>العنصر يبدو آمناً (Safe)</strong>${scoreHtml}${reasonsHtml}${decodedHtml}</div></div>`;
    }

    // حفظ السجل في الداتابيز (لو المستخدم له id)، وإلا بيتحفظ محلياً للجلسة بس
    let entry = { id: null, element: inputVal, type: type.toUpperCase(), isPhishing, createdAt: new Date().toISOString() };
    if (currentUser && currentUser.id) {
        try {
            const r = await fetch(`${API}/api/logs`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id: currentUser.id, element: inputVal, scan_type: type.toUpperCase(), is_phishing: isPhishing })
            });
            if (r.ok) {
                const saved = await r.json();
                entry = { id: saved.id, element: saved.element, type: saved.scan_type, isPhishing: saved.is_phishing, createdAt: saved.created_at };
            }
        } catch (e) { console.warn('تعذر حفظ السجل في السيرفر', e); }
    }
    scanLogsHistory.unshift(entry);
    recomputeStats();
    updateCountersUI();
    renderLogsTable();
}

function renderLogsTable() {
    const tbody = document.getElementById('scanLogsTableBody');
    if (scanLogsHistory.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 2rem;">لا توجد عمليات فحص مسجلة حتى الآن.</td></tr>`;
        return;
    }
    tbody.innerHTML = scanLogsHistory.map((log, idx) => {
        const short = log.element.length > 35 ? log.element.substring(0, 32) + '...' : log.element;
        const d = new Date(log.createdAt);
        const time = d.toLocaleDateString('ar-EG') + ' - ' + d.toLocaleTimeString('ar-EG');
        let result = log.isPhishing ? '<span class="red-text">Threat detected</span>' : '<span class="green-text">Safe</span>';
        if (log.type === 'CRYPTO') result = '<span class="pill">Completed</span>';
        if (log.type === 'WEBSEC') {
            try { const report = JSON.parse(log.details || '{}'); const count = (report.findings || []).filter(item => item.severity !== 'info').length; result = `<span class="website-risk ${String(report.risk || 'Low').toLowerCase()}">${escapeHtml(report.risk || 'Low')} risk · ${count} findings</span>`; }
            catch (_) { result = '<span class="pill">Report saved</span>'; }
        }
        return `
            <tr>
                <td style="direction: ltr; text-align: right;" title="${escapeHtml(log.element)}">${escapeHtml(short)}</td>
                <td><span class="pill">${escapeHtml(log.type)}</span></td>
                <td><strong>${result}</strong>${log.details ? ` <button class="log-detail-btn" onclick="viewLogDetails(${idx})">Details</button>` : ''}</td>
                <td>${time}</td>
                <td><button class="icon-btn" aria-label="حذف" onclick="deleteLog(${idx})" ><i class="fa-solid fa-trash"></i></button></td>
            </tr>`;
    }).join('');
}

function viewLogDetails(index) {
    const log = scanLogsHistory[index];
    if (!log?.details) return;
    let data;
    try { data = JSON.parse(log.details); } catch (_) { alert(log.details); return; }
    if (log.type === 'CRYPTO') {
        alert(`${data.algorithm || 'Cryptography'} · ${data.action || ''}\n\nResult:\n${data.result || ''}`);
    } else if (log.type === 'WEBSEC') {
        const lines = (data.findings || []).map(item => `[${item.title_ar || item.title}]\nما المقصود: ${item.what_ar || item.evidence}\nالتأثير: ${item.impact_ar || ''}\nالمعالجة: ${item.recommendation_ar || item.recommendation}`);
        alert(`${data.url}\nمستوى الخطورة: ${data.risk}\n\n${lines.join('\n\n') || 'لا توجد ملاحظات.'}\n\n${data.scope_ar || ''}`);
    } else alert(JSON.stringify(data, null, 2));
}

async function deleteLog(idx) {
    const log = scanLogsHistory[idx];
    if (!log) return;
    if (log.id) {
        try { await fetch(`${API}/api/logs/${log.id}`, { method: 'DELETE' }); } catch (e) { console.warn(e); }
    }
    scanLogsHistory.splice(idx, 1);
    recomputeStats(); updateCountersUI(); renderLogsTable();
}

async function clearLogs() {
    if (currentUser && currentUser.id) {
        try { await fetch(`${API}/api/logs/user/${currentUser.id}`, { method: 'DELETE' }); } catch (e) { console.warn(e); }
    }
    scanLogsHistory = [];
    recomputeStats(); updateCountersUI(); renderLogsTable();
}

async function scanWebsite() {
    const urlInput = document.getElementById('websiteAuditUrl');
    const consent = document.getElementById('websiteAuditAuthorized');
    const button = document.getElementById('websiteAuditButton');
    const errorBox = document.getElementById('websiteAuditError');
    const resultBox = document.getElementById('websiteAuditResult');
    errorBox.style.display = 'none';
    resultBox.style.display = 'none';
    document.getElementById('websiteAuditPlaceholder').style.display = 'flex';
    const url = urlInput.value.trim();
    if (!url) { errorBox.textContent = 'Enter a website URL first.'; errorBox.style.display = 'flex'; return; }
    if (!consent.checked) { errorBox.textContent = 'Confirm that you own this website or have permission to assess it.'; errorBox.style.display = 'flex'; return; }
    button.disabled = true;
    button.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Scanning website…';
    try {
        const response = await fetch(`${API}/api/website-audit/scan`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url })
        });
        const report = await response.json();
        if (!response.ok) throw new Error(report.detail || 'The website scan could not be completed.');
        const riskClass = String(report.risk || 'low').toLowerCase();
        const findings = report.findings || [];
        const issueCount = findings.filter(item => item.severity !== 'info').length;
        const riskArabic = { High: 'مرتفع', Moderate: 'متوسط', Low: 'منخفض' }[report.risk] || 'غير محدد';
        const findingCards = findings.length ? findings.map(item => `<article class="website-finding ${escapeHtml(item.severity)}"><div class="website-finding-title"><span>${escapeHtml(item.severity.toUpperCase())}</span><h4>${escapeHtml(item.title)}</h4></div><div class="website-finding-section"><b>What it is</b><p>${escapeHtml(item.description)}</p></div><div class="website-finding-section"><b>Potential impact</b><p>${escapeHtml(item.impact)}</p></div><div class="website-finding-section"><b>How it was detected</b><p>${escapeHtml(item.detection_method)} ${escapeHtml(item.evidence)}</p></div><div class="website-finding-section fix"><b>Recommended fix</b><p>${escapeHtml(item.recommendation)}</p></div><small class="audit-cwe">${escapeHtml(item.cwe || '')}</small></article>`).join('') : '<article class="website-finding info"><h4>No issues found by these checks</h4><p>This result covers only the passive checks listed in the scan scope. It does not prove that the website has no vulnerabilities.</p></article>';
        const arabicCards = findings.length ? findings.map(item => `<article class="website-arabic-finding ${escapeHtml(item.severity)}"><div class="website-finding-title"><span>${{ critical: 'حرجة', high: 'مرتفعة', medium: 'متوسطة', low: 'منخفضة', info: 'معلومة' }[item.severity] || 'ملاحظة'}</span><h4>${escapeHtml(item.title_ar || item.title)}</h4></div><div><b>ما هي؟</b><p>${escapeHtml(item.what_ar || item.description || item.evidence)}</p></div><div><b>ما تأثيرها؟</b><p>${escapeHtml(item.impact_ar || item.impact || '')}</p></div><div><b>كيف اكتشفها الفحص؟</b><p>${escapeHtml(item.detection_method || '')} ${escapeHtml(item.evidence)}</p></div><div><b>ما الحل؟</b><p>${escapeHtml(item.recommendation_ar || item.recommendation)}</p></div><small class="audit-cwe">${escapeHtml(item.cwe || '')}</small></article>`).join('') : '<article class="website-arabic-finding info"><h4>لم تظهر ملاحظات في الفحوصات المنفذة</h4><p>النتيجة لا تؤكد خلو الموقع من جميع أنواع الثغرات.</p></article>';
        const coverageList = (report.checks_available || []).map(check => `<li><b>${escapeHtml(check.name)}</b><span>${escapeHtml(check.method)}</span></li>`).join('');
        resultBox.innerHTML = `<div class="website-audit-summary"><div><span class="website-risk ${riskClass}">Overall risk: ${escapeHtml(report.risk)}</span><h3>${issueCount ? `${issueCount} finding${issueCount === 1 ? '' : 's'} to review` : 'No issues found by these checks'}</h3><p dir="ltr">${escapeHtml(report.url)} · HTTP ${escapeHtml(report.status_code)}</p></div><i class="fa-solid fa-shield-halved"></i></div>` +
            `<div class="website-audit-report-layout"><section class="website-audit-findings"><h3><i class="fa-solid fa-list-check"></i> Security Findings</h3>${findingCards}</section><aside class="website-audit-arabic" dir="rtl"><h3><i class="fa-solid fa-language"></i> ملخص وشرح بالعربي</h3><div class="arabic-risk-summary">مستوى الخطورة العام: <strong>${riskArabic}</strong></div>${arabicCards}</aside></div><details class="audit-coverage"><summary>Checks included in this scan (${(report.checks_available || []).length})</summary><ul>${coverageList}</ul></details><p class="website-audit-scope">${escapeHtml(report.scope || '')}<br><span dir="rtl">${escapeHtml(report.scope_ar || '')}</span></p>`;
        document.getElementById('websiteAuditPlaceholder').style.display = 'none';
        resultBox.style.display = 'block';
        const highRisk = findings.some(item => item.severity === 'critical' || item.severity === 'high');
        recordActivity(await saveActivityLog(report.url, 'WEBSEC', highRisk, report));
    } catch (error) {
        errorBox.textContent = error.message;
        errorBox.style.display = 'flex';
    } finally {
        button.disabled = false;
        button.innerHTML = '<i class="fa-solid fa-magnifying-glass-chart"></i> Run Website Scan';
    }
}

function showSection(sectionId) {
    if ((sectionId === 'adminSection' || sectionId === 'reportsSection' || sectionId === 'extensionSection') && (!currentUser || currentUser.role !== 'Admin')) sectionId = 'scannerSection';
    setAppPath(SECTION_PATHS[sectionId] || '/smart-scan');
    const sections = ['scannerSection', 'reportsSection', 'cryptoLabSection', 'websiteAuditSection', 'adminSection', 'extensionSection'];
    sections.forEach(sec => {
        document.getElementById(sec).style.display = (sec === sectionId) ? 'block' : 'none';
    });

    document.getElementById('navScanner').classList.toggle('active', sectionId === 'scannerSection');
    document.getElementById('navReports').classList.toggle('active', sectionId === 'reportsSection');
    if (document.getElementById('navCrypto')) document.getElementById('navCrypto').classList.toggle('active', sectionId === 'cryptoLabSection');
    if (document.getElementById('navWebsiteAudit')) document.getElementById('navWebsiteAudit').classList.toggle('active', sectionId === 'websiteAuditSection');
    if (document.getElementById('navAdmin')) {
        document.getElementById('navAdmin').classList.toggle('active', sectionId === 'adminSection');
    }
    document.getElementById('navExtension').classList.toggle('active', sectionId === 'extensionSection');

    if (sectionId === 'reportsSection') {
        setTimeout(renderCharts, 100);
    } else if (sectionId === 'adminSection') {
        setTimeout(renderAdminCharts, 100);
        startAdminLive();
    }
}

function restoreRouteFromAddress() {
    const path = location.pathname.replace(/\/$/, '') || '/';
    if (path === '/register') {
        switchForm('register');
        return;
    }
    if (!currentUser) {
        switchForm('login');
        setAppPath('/login', true);
        return;
    }
    showSection(PATH_SECTIONS[path] || 'scannerSection');
}

window.addEventListener('popstate', () => {
    if (!currentUser) {
        document.getElementById('appMainLayout').style.display = 'none';
        document.getElementById('authGateSection').style.display = 'flex';
        switchForm(location.pathname === '/register' ? 'register' : 'login');
        return;
    }
    showSection(PATH_SECTIONS[location.pathname] || 'scannerSection');
});

/* ===== رسومات الداشبورد الحية (الرسم البياني فقط هو اللي بيتحرك) ===== */
const rnd = (a, b) => a + Math.random() * (b - a);
const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
const liveStamp = (offsetMs = 0) => new Date(Date.now() - offsetMs).toLocaleTimeString('en-GB');
const TREND_SCALES = {
    x: { grid: { display: false }, border: { display: false }, ticks: { maxTicksLimit: 8, maxRotation: 0 } },
    y: { beginAtZero: true, suggestedMax: 300, grid: { color: 'rgba(148,163,184,0.1)' }, border: { display: false } }
};
const WEEK_SCALES = {
    x: { grid: { display: false }, border: { display: false }, ticks: { font: { size: 9 }, maxRotation: 0, autoSkip: false } },
    y: { beginAtZero: true, suggestedMax: 500, grid: { color: 'rgba(148,163,184,0.1)' }, border: { display: false } }
};

let adminLiveTimer = null;
function startAdminLive() {
    clearInterval(adminLiveTimer);
    adminLiveTimer = setInterval(() => {
        const sec = document.getElementById('adminSection');
        if (!sec || sec.style.display === 'none') { clearInterval(adminLiveTimer); return; }

        const tc = document.getElementById('adminTrendChart');
        if (tc && tc.chartInstance) {
            const ch = tc.chartInstance, [scans, threats] = ch.data.datasets;
            const next = clamp(scans.data[scans.data.length - 1] + rnd(-45, 45), 25, 280);
            scans.data.push(Math.round(next)); scans.data.shift();
            threats.data.push(Math.round(clamp(next * rnd(0.12, 0.22), 3, 60))); threats.data.shift();
            ch.data.labels.push(liveStamp()); ch.data.labels.shift();
            ch.update();
        }
        const wc = document.getElementById('adminWeeklyChart');
        if (wc && wc.chartInstance) {
            const d = wc.chartInstance.data.datasets[0].data;
            wc.chartInstance.data.datasets[0].data = d.map(v => Math.round(clamp(v + rnd(-40, 40), 90, 460)));
            wc.chartInstance.update();
        }
        const dc = document.getElementById('adminComparisonChart');
        if (dc && dc.chartInstance) {
            const d = dc.chartInstance.data.datasets[0].data;
            dc.chartInstance.data.datasets[0].data = [clamp(d[0] + rnd(-40, 40), 1200, 1600), clamp(d[1] + rnd(-20, 20), 200, 420), clamp(d[2] + rnd(-12, 12), 60, 180)].map(Math.round);
            dc.chartInstance.update();
        }
    }, 1500);
}
function resetChart(id) {
    const c = document.getElementById(id);
    if (c && c.chartInstance) { c.chartInstance.destroy(); c.chartInstance = null; }
}

function chartOpts(extra) {
    return Object.assign({
        responsive: true, maintainAspectRatio: false,
        animation: { duration: 900, easing: 'easeInOutQuad' },
        interaction: { mode: 'index', intersect: false },
        plugins: {
            legend: { display: false },
            tooltip: { backgroundColor: '#0a0f1c', borderColor: 'rgba(148,163,184,0.25)', borderWidth: 1, padding: 12, cornerRadius: 10, titleColor: '#e8edf7', bodyColor: '#c5cee0', rtl: true, usePointStyle: true, boxPadding: 4 }
        },
        scales: { x: { grid: { display: false }, border: { display: false } }, y: { beginAtZero: true, grid: { color: 'rgba(148,163,184,0.1)' }, border: { display: false } } }
    }, extra || {});
}

function donutOpts() {
    const o = chartOpts({ cutout: '74%', scales: {}, animation: { animateRotate: true, animateScale: true, duration: 1500, easing: 'easeOutQuart' } });
    o.plugins.legend = { display: true, position: 'bottom', labels: { usePointStyle: true, pointStyle: 'circle', padding: 10, boxWidth: 6, font: { size: 11 } } };
    return o;
}

function areaGrad(ctx, rgb) {
    const g = ctx.createLinearGradient(0, 0, 0, 300);
    g.addColorStop(0, `rgba(${rgb},0.38)`); g.addColorStop(1, `rgba(${rgb},0)`);
    return g;
}

function lineSet(ctx, label, data, rgb) {
    return { label, data, borderColor: `rgb(${rgb})`, backgroundColor: areaGrad(ctx, rgb), fill: true, tension: 0.42, borderWidth: 2.5, pointRadius: 0, pointHoverRadius: 6, pointHoverBackgroundColor: '#fff', pointHoverBorderColor: `rgb(${rgb})`, pointHoverBorderWidth: 2 };
}

function renderCharts() {
    const ctx1 = document.getElementById('activityChart');
    if (ctx1 && !ctx1.chartInstance) {
        const c = ctx1.getContext('2d');
        ctx1.chartInstance = new Chart(c, { type: 'line', data: { labels: ['السبت', 'الأحد', 'الإثنين', 'الثلاثاء', 'الأربعاء'], datasets: [lineSet(c, 'الفحوصات / Scans', [12, 28, 42, 30, 65], '90,209,255')] }, options: chartOpts() });
    }
    const ctx2 = document.getElementById('threatsChart');
    if (ctx2 && !ctx2.chartInstance) {
        ctx2.chartInstance = new Chart(ctx2.getContext('2d'), { type: 'doughnut', data: { labels: ['آمن ونظيف / Safe', 'تهديدات محظورة / Blocked'], datasets: [{ data: [1060, 180], backgroundColor: ['#3ddc97', '#ff5d7a'], borderWidth: 0, borderRadius: 6, spacing: 3, hoverOffset: 8 }] }, options: donutOpts() });
    }
}

async function loadAdminPanel() {
    const tbody = document.getElementById('usersTableBody');
    try {
        const response = await fetch(`${API}/api/users`);
        if (!response.ok) throw new Error('bad response');
        const users = await response.json();
        tbody.innerHTML = users.map(u => {
            const isBase = u.name === 'a' || (currentUser && u.id === currentUser.id);
            const delBtn = isBase
                ? `<span style="color: var(--text-muted); font-size:.8rem;">${u.name === 'a' ? 'أساسي' : 'أنت'}</span>`
                : `<button class="icon-btn" aria-label="حذف" onclick="deleteUser(${u.id}, '${escapeHtml(u.name).replace(/'/g, '')}')"><i class="fa-solid fa-trash"></i></button>`;
            return `<tr><td>#${u.id}</td><td>${escapeHtml(u.name)}</td><td>${escapeHtml(u.email)}</td><td>${escapeHtml(u.date || '')}</td><td><span class="pill ${u.role === 'Admin' ? 'admin' : ''}">${escapeHtml(u.role)}</span></td><td>${delBtn}</td></tr>`;
        }).join('');
        document.getElementById('totalUsersCount').innerText = users.length;
    } catch (error) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color: var(--text-muted); padding: 2rem;">تعذر تحميل المستخدمين. تأكد إن الباك إند شغال على بورت 8000.</td></tr>`;
    }
}

async function deleteUser(id, name) {
    if (!confirm(`هل تريد حذف المستخدم "${name}" وكل سجلاته؟`)) return;
    try {
        const r = await fetch(`${API}/api/users/${id}`, { method: 'DELETE' });
        if (!r.ok) {
            const e = await r.json().catch(() => ({}));
            alert(e.detail || 'تعذر حذف المستخدم');
            return;
        }
        loadAdminPanel();
    } catch (e) { alert('تعذر الاتصال بالسيرفر'); }
}

function openAddUserModal() {
    ['newUserName', 'newUserEmail', 'newUserPassword'].forEach(id => document.getElementById(id).value = '');
    document.getElementById('newUserRole').value = 'User';
    document.getElementById('addUserError').textContent = '';
    document.getElementById('addUserModal').style.display = 'flex';
}
function closeAddUserModal() { document.getElementById('addUserModal').style.display = 'none'; }

// دالة لجلب آخر نص من الحافظة (Clipboard) ولصقه في الحقل المختار
async function pasteClipboard(inputId) {
    const inputElement = document.getElementById(inputId);
    if (!inputElement) return;

    try {
        const text = await navigator.clipboard.readText();
        inputElement.value = text;
        inputElement.focus();
    } catch (err) {
        console.error('فشل اللصق من الحافظة: ', err);
        alert('عذراً، يرجى السماح للمتصفح بالوصول للحافظة أو استخدام اختصار (Ctrl + V)');
    }
}

// دالة مسح نص الإيميل بالكامل عند الضغط على زر الـ X الأحمر الدائري
function clearEmailInput() {
    const emailArea = document.getElementById('emailInput');
    if (emailArea) {
        emailArea.value = '';
        emailArea.focus();
    }
}
async function submitAddUser() {
    const name = document.getElementById('newUserName').value.trim();
    const email = document.getElementById('newUserEmail').value.trim();
    const password = document.getElementById('newUserPassword').value;
    const role = document.getElementById('newUserRole').value;
    const err = document.getElementById('addUserError');
    if (!name || !email || !password) { err.textContent = 'كل الحقول مطلوبة'; return; }
    try {
        const r = await fetch(`${API}/api/users`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, email, password, role })
        });
        if (!r.ok) {
            const e = await r.json().catch(() => ({}));
            err.textContent = e.detail || 'حدث خطأ';
            return;
        }
        closeAddUserModal();
        loadAdminPanel();
    } catch (e) { err.textContent = 'تعذر الاتصال بالسيرفر'; }
}

function renderAdminCharts() {
    ['adminTrendChart', 'adminWeeklyChart', 'adminComparisonChart'].forEach(resetChart);
    const t = document.getElementById('adminTrendChart');
    if (t && !t.chartInstance) {
        const c = t.getContext('2d');
        const hrs = Array.from({ length: 24 }, (_, i) => liveStamp((23 - i) * 1500));
        t.chartInstance = new Chart(c, { type: 'line', data: { labels: hrs, datasets: [
            lineSet(c, 'إجمالي الفحوصات / Total Scans', [40,32,28,25,30,48,90,140,180,210,230,220,240,250,235,228,215,200,170,150,120,95,70,52], '90,209,255'),
            lineSet(c, 'تهديدات مكتشفة / Detected Threats', [6,5,4,3,5,9,16,24,31,38,42,36,41,44,39,35,33,30,26,22,18,12,9,7], '255,93,122')
        ] }, options: chartOpts({ scales: TREND_SCALES, plugins: Object.assign(chartOpts().plugins, { legend: { display: true, position: 'top', align: 'end', labels: { usePointStyle: true, pointStyle: 'circle', boxWidth: 6, padding: 10, font: { size: 11 } } } }) }) });
    }
    const ctx1 = document.getElementById('adminWeeklyChart');
    if (ctx1 && !ctx1.chartInstance) {
        const c = ctx1.getContext('2d');
        const g = c.createLinearGradient(0, 0, 0, 300); g.addColorStop(0, '#9b8cff'); g.addColorStop(1, 'rgba(90,209,255,0.35)');
        ctx1.chartInstance = new Chart(c, { type: 'bar', data: { labels: ['السبت', 'الأحد', 'الإثنين', 'الثلاثاء', 'الأربعاء', 'الخميس', 'الجمعة'], datasets: [{ label: 'النشاط / Activity', data: [140, 270, 390, 410, 320, 310, 200], backgroundColor: g, borderRadius: 10, borderSkipped: false, maxBarThickness: 34 }] }, options: chartOpts({ scales: WEEK_SCALES }) });
    }
    const ctx2 = document.getElementById('adminComparisonChart');
    if (ctx2 && !ctx2.chartInstance) {
        ctx2.chartInstance = new Chart(ctx2.getContext('2d'), { type: 'doughnut', data: { labels: ['مواقع آمنة / Safe', 'تصيد احتيالي / Phishing', 'برمجيات خبيثة / Malware'], datasets: [{ data: [1420, 310, 112], backgroundColor: ['#3ddc97', '#ff5d7a', '#9b8cff'], borderWidth: 0, borderRadius: 6, spacing: 3, hoverOffset: 8 }] }, options: donutOpts() });
    }
}

// تنسيق رد الشات بشكل آمن: escape ثم **bold** و `code` وأسطر جديدة
function formatBotReply(text) {
    return escapeHtml(text)
        .replace(/```([\s\S]*?)```/g, '<pre style="direction:ltr;text-align:left;white-space:pre-wrap;margin:6px 0;">$1</pre>')
        .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
        .replace(/`([^`]+)`/g, '<code>$1</code>')
        .replace(/\n/g, '<br>');
}

document.addEventListener('DOMContentLoaded', () => {
    const toggleBtn = document.getElementById('chat-toggle-btn');
    const closeBtn = document.getElementById('chat-close-btn');
    const expandBtn = document.getElementById('chat-expand-btn');
    const chatBox = document.getElementById('chat-box');
    const sendBtn = document.getElementById('chat-send-btn');
    const inputField = document.getElementById('chat-input');
    const messagesContainer = document.getElementById('chat-messages');
    const fileInput = document.getElementById('chat-file-input');
    const attachBtn = document.getElementById('chat-attach-btn');
    const recordBtn = document.getElementById('chat-record-btn');
    const filePreview = document.getElementById('chat-file-preview');
    const recordStatus = document.getElementById('chat-record-status');
    let sending = false;
    let selectedFiles = [];
    let mediaRecorder = null;
    let audioChunks = [];

    if (!(toggleBtn && chatBox)) return;
    toggleBtn.onclick = () => {
        const open = chatBox.style.display !== 'flex';
        chatBox.style.display = open ? 'flex' : 'none';
        if (open) inputField?.focus();
    };
    closeBtn.onclick = () => {
        chatBox.classList.remove('chat-fullscreen');
        if (expandBtn) expandBtn.innerHTML = '<i class="fa-solid fa-expand"></i>';
        if (expandBtn) expandBtn.setAttribute('aria-label', 'تكبير المحادثة');
        chatBox.style.display = 'none';
    };
    expandBtn?.addEventListener('click', () => {
        const expanded = chatBox.classList.toggle('chat-fullscreen');
        expandBtn.innerHTML = expanded ? '<i class="fa-solid fa-compress"></i>' : '<i class="fa-solid fa-expand"></i>';
        expandBtn.setAttribute('aria-label', expanded ? 'تصغير المحادثة' : 'تكبير المحادثة');
        expandBtn.title = expanded ? 'تصغير' : 'تكبير';
    });
    document.addEventListener('keydown', e => {
        if (e.key === 'Escape' && chatBox.style.display === 'flex') {
            if (chatBox.classList.contains('chat-fullscreen')) {
                chatBox.classList.remove('chat-fullscreen');
                if (expandBtn) expandBtn.innerHTML = '<i class="fa-solid fa-expand"></i>';
                if (expandBtn) expandBtn.setAttribute('aria-label', 'تكبير المحادثة');
            } else closeBtn?.click();
        }
    });

    const addMsg = (cls, html) => {
        const div = document.createElement('div');
        div.className = 'msg ' + cls;
        div.innerHTML = html;
        messagesContainer.appendChild(div);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
        return div;
    };

    async function sendChatMessage() {
        const text = inputField.value.trim();
        if ((!text && !selectedFiles.length) || sending) return;
        sending = true;
        const outgoingFiles = selectedFiles.slice();
        const displayText = [text, ...outgoingFiles.map(file => `📎 ${escapeHtml(file.name)}`)].filter(Boolean).join('<br>');
        addMsg('user', displayText);
        inputField.value = '';
        selectedFiles = [];
        renderFilePreview();
        const loading = addMsg('load', '<i class="fa-solid fa-spinner fa-spin"></i> جاري الفحص والتفكير (Analyzing)...');

        try {
            let response;
            if (outgoingFiles.length) {
                const form = new FormData();
                form.append('message', text || 'Please review the attached file(s), summarize their contents, and point out anything suspicious or important.');
                form.append('history', JSON.stringify(chatHistory.slice(-12)));
                outgoingFiles.forEach(file => form.append('files', file, file.name));
                response = await fetch(`${API}/api/chat/files`, { method: 'POST', body: form });
            } else {
                response = await fetch(`${API}/api/chat`, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ message: text, history: chatHistory.slice(-12) })
                });
            }
            const data = await response.json().catch(() => ({}));
            loading.remove();
            if (!response.ok) {
                // بنعرض سبب الخطأ الحقيقي بدل رد وهمي
                addMsg('bot', '⚠️ ' + escapeHtml(data.detail || 'حصل خطأ في السيرفر'));
            } else {
                chatHistory.push({ role: 'user', content: data.user_message || text }, { role: 'assistant', content: data.reply });
                addMsg('bot', formatBotReply(data.reply));
                if (recordStatus) recordStatus.textContent = '';
            }
        } catch (error) {
            loading.remove();
            addMsg('bot', '⚠️ تعذر الاتصال بالسيرفر. تأكد إن الباك إند شغال على بورت 8000.');
        }
        sending = false;
    }

    function renderFilePreview() {
        if (!filePreview) return;
        filePreview.replaceChildren();
        selectedFiles.forEach((file, index) => {
            const chip = document.createElement('span'); chip.className = 'chat-file-chip';
            const name = document.createElement('span'); name.textContent = file.name;
            const remove = document.createElement('button'); remove.type = 'button'; remove.setAttribute('aria-label', `إزالة ${file.name}`); remove.innerHTML = '<i class="fa-solid fa-xmark"></i>';
            remove.onclick = () => { selectedFiles.splice(index, 1); renderFilePreview(); };
            chip.append(name, remove); filePreview.appendChild(chip);
        });
    }

    attachBtn?.addEventListener('click', () => fileInput?.click());
    fileInput?.addEventListener('change', () => {
        const allowed = /\.(txt|md|csv|json|log|pdf|docx|pptx|xlsx)$/i;
        const next = Array.from(fileInput.files || []);
        const invalid = next.find(file => !allowed.test(file.name));
        const tooLarge = next.find(file => file.size > 12 * 1024 * 1024);
        if (invalid) addMsg('bot', `صيغة الملف غير مدعومة: ${escapeHtml(invalid.name)}. استخدم PDF أو Word أو PowerPoint أو Excel أو TXT/CSV/JSON.`);
        else if (tooLarge) addMsg('bot', `الحد الأقصى لحجم الملف الواحد 12 ميجابايت: ${escapeHtml(tooLarge.name)}`);
        else {
            const combined = [...selectedFiles, ...next];
            if (combined.length > 5) addMsg('bot', 'يمكن إرفاق 5 ملفات كحد أقصى في الرسالة الواحدة.');
            else { selectedFiles = combined; renderFilePreview(); }
        }
        fileInput.value = '';
    });

    recordBtn?.addEventListener('click', async () => {
        if (mediaRecorder?.state === 'recording') { mediaRecorder.stop(); return; }
        if (!navigator.mediaDevices?.getUserMedia || typeof MediaRecorder === 'undefined') {
            addMsg('bot', 'التسجيل الصوتي غير مدعوم في هذا المتصفح. استخدم متصفحًا حديثًا وافتح الموقع عبر HTTPS أو localhost.'); return;
        }
        try {
            const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
            const mimeType = ['audio/webm;codecs=opus', 'audio/mp4', 'audio/webm'].find(type => MediaRecorder.isTypeSupported(type));
            mediaRecorder = new MediaRecorder(stream, mimeType ? { mimeType } : undefined);
            audioChunks = [];
            mediaRecorder.ondataavailable = event => { if (event.data.size) audioChunks.push(event.data); };
            mediaRecorder.onstop = async () => {
                stream.getTracks().forEach(track => track.stop());
                recordBtn.classList.remove('recording');
                recordBtn.innerHTML = '<i class="fa-solid fa-microphone"></i>';
                recordBtn.setAttribute('aria-label', 'بدء التسجيل الصوتي');
                const blob = new Blob(audioChunks, { type: mediaRecorder.mimeType || 'audio/webm' });
                if (!blob.size) { recordStatus.textContent = 'لم يتم التقاط صوت. حاول مرة أخرى.'; return; }
                recordStatus.textContent = 'جارٍ تحويل الصوت إلى نص…';
                try {
                    const form = new FormData();
                    const ext = blob.type.includes('mp4') ? 'm4a' : 'webm';
                    form.append('audio', blob, `recording.${ext}`);
                    const response = await fetch(`${API}/api/chat/transcribe`, { method: 'POST', body: form });
                    const data = await response.json().catch(() => ({}));
                    if (!response.ok) throw new Error(data.detail || 'تعذر تحويل التسجيل.');
                    inputField.value = [inputField.value.trim(), data.transcript].filter(Boolean).join(' ');
                    recordStatus.textContent = 'تم تحويل التسجيل. راجع النص وعدّله ثم اضغط إرسال.';
                    inputField.focus();
                } catch (error) { recordStatus.textContent = error.message; }
            };
            mediaRecorder.start();
            recordBtn.classList.add('recording');
            recordBtn.innerHTML = '<i class="fa-solid fa-stop"></i>';
            recordBtn.setAttribute('aria-label', 'إيقاف التسجيل');
            recordStatus.textContent = 'جارٍ التسجيل… اضغط إيقاف عند الانتهاء.';
        } catch (error) { recordStatus.textContent = `تعذر الوصول للميكروفون: ${error.message}`; }
    });

    if (sendBtn) sendBtn.onclick = sendChatMessage;
    if (inputField) inputField.onkeydown = (e) => { if (e.key === 'Enter') { e.preventDefault(); sendChatMessage(); } };
});

document.addEventListener('DOMContentLoaded', () => {
    const msg = document.getElementById('extAlertMessageInput');
    const icon = document.getElementById('extIconInput');
    if (msg) msg.addEventListener('input', () => { document.getElementById('extPreviewMsg').textContent = msg.value || ' '; });
    if (icon) icon.addEventListener('change', () => {
        const f = icon.files && icon.files[0];
        if (!f) return;
        const r = new FileReader();
        r.onload = e => ['extIconPreview', 'extPreviewIcon'].forEach(id => {
            const box = document.getElementById(id); box.innerHTML = '';
            const img = new Image(); img.src = e.target.result; img.alt = ''; box.appendChild(img);
        });
        r.readAsDataURL(f);
    });
});

(function () {
    const c = document.getElementById('cyberCanvas');
    if (!c) return;
    const x = c.getContext('2d');
    const still = matchMedia('(prefers-reduced-motion: reduce)').matches;
    let W, H, P = [];
    function size() {
        W = c.width = innerWidth; H = c.height = innerHeight;
        const n = Math.min(80, Math.floor(W * H / 20000));
        P = Array.from({ length: n }, () => ({ x: Math.random() * W, y: Math.random() * H, vx: (Math.random() - .5) * .28, vy: (Math.random() - .5) * .28, b: Math.random() < .2 ? (Math.random() < .5 ? '0' : '1') : null }));
    }
    function draw() {
        x.clearRect(0, 0, W, H);
        P.forEach(p => { p.x += p.vx; p.y += p.vy; if (p.x < 0 || p.x > W) p.vx *= -1; if (p.y < 0 || p.y > H) p.vy *= -1; });
        for (let i = 0; i < P.length; i++) {
            const a = P[i];
            for (let k = i + 1; k < P.length; k++) {
                const b = P[k], d = Math.hypot(a.x - b.x, a.y - b.y);
                if (d < 150) { x.strokeStyle = `rgba(90,209,255,${0.16 * (1 - d / 150)})`; x.beginPath(); x.moveTo(a.x, a.y); x.lineTo(b.x, b.y); x.stroke(); }
            }
            if (a.b) { x.fillStyle = 'rgba(61,220,151,0.4)'; x.font = '13px monospace'; x.fillText(a.b, a.x, a.y); }
            else { x.fillStyle = 'rgba(90,209,255,0.55)'; x.beginPath(); x.arc(a.x, a.y, 1.7, 0, 6.28); x.fill(); }
        }
        if (!still) requestAnimationFrame(draw);
    }
    size(); addEventListener('resize', () => { size(); if (still) draw(); }); draw();
})();

document.addEventListener('DOMContentLoaded', () => {
    const requestedPath = location.pathname;
    currentUser = restoreSavedSession();
    if (currentUser) {
        loadUserLogs().then(() => {
            setupUserInterface();
            showSection(PATH_SECTIONS[requestedPath] || 'scannerSection');
        });
    } else {
        restoreRouteFromAddress();
    }
    const img = document.getElementById('qrImageInput');
    const txt = document.getElementById('qrTextInput');
    if (img) img.addEventListener('change', () => { qrSource = 'image'; });
    if (txt) txt.addEventListener('input', () => { qrSource = 'text'; });
});
