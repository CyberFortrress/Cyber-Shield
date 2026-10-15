/* ============================================================
   Cryptography Lab — منطق واجهة معمل التشفير
   يجلب الفهرس من الخادم ويبني الحقول ديناميكياً حسب الخوارزمية
   ============================================================ */
const CRYPTO_API = (location.protocol === 'file:' || ['5500', '3000', '8080'].includes(location.port)) ? 'http://127.0.0.1:8000' : location.origin;

let cryptoCatalog = null;          // الفهرس القادم من الخادم
let cryptoCategory = 'substitution';
let cryptoAlgorithm = 'additive';
let lastCryptoResult = '';         // آخر نتيجة لزر النسخ

/* ---------- جلب الفهرس وبناء الواجهة ---------- */
async function initCryptoLab() {
    try {
        const r = await fetch(`${CRYPTO_API}/api/crypto/algorithms`);
        if (!r.ok) throw new Error('فشل تحميل فهرس الخوارزميات');
        cryptoCatalog = await r.json();
    } catch (e) {
        const tabs = document.getElementById('cryptoCategoryTabs');
        if (tabs) tabs.innerHTML = `<div style="color:var(--accent-red);font-size:.9rem;padding:.6rem;">تعذر الاتصال بالخادم لتحميل المعمل: ${escapeHtml(e.message)}</div>`;
        return;
    }
    renderCryptoCategories();
    selectCryptoCategory('substitution');
}

function renderCryptoCategories() {
    const tabs = document.getElementById('cryptoCategoryTabs');
    tabs.innerHTML = cryptoCatalog.categories.map(c => `
        <button class="toggle-btn" id="cryptoCat_${c.id}" onclick="selectCryptoCategory('${c.id}')">
            <i class="fa-solid ${c.icon}"></i> ${c.name_ar}
        </button>`).join('');
}

function selectCryptoCategory(catId) {
    cryptoCategory = catId;
    cryptoCatalog.categories.forEach(c => {
        const b = document.getElementById('cryptoCat_' + c.id);
        if (b) b.classList.toggle('active', c.id === catId);
    });
    const cat = cryptoCatalog.categories.find(c => c.id === catId);
    const grid = document.getElementById('cryptoAlgGrid');
    grid.innerHTML = cat.algorithms.map(a => `
        <button class="crypto-alg-btn" id="cryptoAlg_${a.id}" onclick="selectCryptoAlgorithm('${a.id}')" title="${escapeHtml(a.name)}">
            <strong>${escapeHtml(a.name)}</strong>
        </button>`).join('');
    selectCryptoAlgorithm(cat.algorithms[0].id);
}

function getCurrentAlgorithm() {
    const cat = cryptoCatalog.categories.find(c => c.id === cryptoCategory);
    return cat.algorithms.find(a => a.id === cryptoAlgorithm);
}

function selectCryptoAlgorithm(algId) {
    cryptoAlgorithm = algId;
    const cat = cryptoCatalog.categories.find(c => c.id === cryptoCategory);
    cat.algorithms.forEach(a => {
        const b = document.getElementById('cryptoAlg_' + a.id);
        if (b) b.classList.toggle('active', a.id === algId);
    });
    const alg = getCurrentAlgorithm();

    // الوصف والتصنيف الفرعي
    document.getElementById('cryptoAlgDesc').innerHTML = `
        <span class="pill">${escapeHtml(alg.sub)}</span>
        <span class="crypto-desc-text">${escapeHtml(alg.desc)}</span>`;

    // الحقول الديناميكية حسب المعلمات
    renderCryptoParams(alg);

    // خوارزميات التجزئة: لا يوجد فك تشفير
    document.getElementById('btnDecrypt').style.display = alg.hash_only ? 'none' : '';
    document.getElementById('btnEncrypt').innerHTML = alg.hash_only
        ? '<i class="fa-solid fa-fingerprint"></i> Hash | احسب البصمة'
        : '<i class="fa-solid fa-lock"></i> Encrypt | تشفير';

    // ملصق حقل النص
    document.getElementById('cryptoTextLabel').textContent =
        alg.hash_only ? 'النص المراد حساب بصمته | Input' : 'النص | Text';

    hideCryptoError();
}

function renderCryptoParams(alg) {
    const box = document.getElementById('cryptoParams');
    if (!alg.params || !alg.params.length) { box.innerHTML = ''; return; }
    box.innerHTML = alg.params.map(prm => {
        const req = prm.required ? ' <b style="color:var(--accent-red)">*</b>' : ' <small style="color:var(--text-muted)">(اختياري)</small>';
        if (prm.type === 'matrix') {
            return `<div class="crypto-param">
                <label class="input-label" for="cryptoParam_${prm.name}">${escapeHtml(prm.label)}${req}</label>
                <textarea id="cryptoParam_${prm.name}" class="crypto-matrix-input" dir="ltr" rows="3" placeholder="${escapeHtml(prm.placeholder || '')}"></textarea>
            </div>`;
        }
        return `<div class="crypto-param">
            <label class="input-label" for="cryptoParam_${prm.name}">${escapeHtml(prm.label)}${req}</label>
            <div class="input-with-icon">
                <i class="fa-solid ${prm.type === 'number' ? 'fa-hashtag' : 'fa-key'}"></i>
                <input type="${prm.type === 'number' ? 'number' : 'text'}" id="cryptoParam_${prm.name}"
                       dir="ltr" placeholder="${escapeHtml(prm.placeholder || '')}"
                       ${prm.min !== undefined ? `min="${prm.min}"` : ''} ${prm.max !== undefined ? `max="${prm.max}"` : ''}>
            </div>
        </div>`;
    }).join('');
}

function collectCryptoParams() {
    const alg = getCurrentAlgorithm();
    const params = {};
    (alg.params || []).forEach(prm => {
        const el = document.getElementById('cryptoParam_' + prm.name);
        if (el && el.value.trim() !== '') params[prm.name] = el.value.trim();
    });
    return params;
}

/* ---------- تنفيذ العملية عبر المسار الموحد ---------- */
async function runCrypto(action) {
    hideCryptoError();
    const text = document.getElementById('cryptoText').value;
    const alg = getCurrentAlgorithm();

    // تحقق سريع من الحقول الإلزامية قبل الإرسال
    for (const prm of (alg.params || [])) {
        if (prm.required) {
            const el = document.getElementById('cryptoParam_' + prm.name);
            if (!el || !el.value.trim()) { showCryptoError(`الحقل «${prm.label}» مطلوب لهذه الخوارزمية.`); return; }
        }
    }
    if (!text.trim()) { showCryptoError('أدخل النص أولاً.'); return; }

    const btn = document.getElementById(action === 'encrypt' ? 'btnEncrypt' : 'btnDecrypt');
    const oldHtml = btn.innerHTML;
    btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> جارٍ التنفيذ...';
    btn.disabled = true;

    try {
        const r = await fetch(`${CRYPTO_API}/api/crypto/run`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ algorithm: cryptoAlgorithm, action, text, params: collectCryptoParams() })
        });
        const data = await r.json();
        if (!r.ok) throw new Error(data.detail || 'حدث خطأ غير متوقع في الخادم.');
        renderCryptoResult(data);
        if (typeof saveActivityLog === 'function' && typeof recordActivity === 'function') {
            const entry = await saveActivityLog(`${data.algorithm_name} · ${action}`, 'CRYPTO', false, {
                algorithm: data.algorithm_name, algorithm_id: data.algorithm, action, result: data.result
            });
            recordActivity(entry);
        }
    } catch (e) {
        showCryptoError(e.message);
        document.getElementById('cryptoResultCard').style.display = 'none';
    } finally {
        btn.innerHTML = oldHtml;
        btn.disabled = false;
    }
}

/* ---------- عرض النتيجة والخطوات ---------- */
function renderCryptoResult(data) {
    lastCryptoResult = data.result || '';
    const card = document.getElementById('cryptoResultCard');
    card.style.display = 'block';

    const actionBadge = data.action === 'encrypt'
        ? '<span class="pill">Encrypted | مشفّر</span>'
        : '<span class="pill" style="background:rgba(61,220,151,.12);color:var(--accent-green)">Decrypted | مفكوك</span>';
    document.getElementById('cryptoResult').innerHTML =
        `<div class="crypto-result-head">${actionBadge}<b>${escapeHtml(data.algorithm_name)}</b></div>` +
        `<code>${escapeHtml(data.result)}</code>`;

    // المخرجات الإضافية (مفتاح OTP المولد، مفاتيح RSA، مصفوفة Playfair...)
    const ex = data.extras || {};
    let extrasHtml = '';
    if (ex.key && cryptoAlgorithm === 'otp') {
        extrasHtml += extraRow('المفتاح المستخدم (احتفظ به لفك التشفير)', ex.key, true);
    }
    if (cryptoAlgorithm === 'rsa') {
        if (ex.n) extrasHtml += extraRow('n', ex.n, false);
        if (ex.e) extrasHtml += extraRow('e (المفتاح العام)', ex.e, false);
        if (ex.d) extrasHtml += extraRow('d (المفتاح الخاص)', ex.d, true);
        // تعبئة حقول n/e/d تلقائياً لتسهيل فك التشفير لاحقاً
        ['n', 'e', 'd'].forEach(k => {
            const el = document.getElementById('cryptoParam_' + k);
            if (el && ex[k]) el.value = ex[k];
        });
    }
    if (ex.iv_hex) extrasHtml += extraRow('IV (hex)', ex.iv_hex, false);
    if (ex.matrix) extrasHtml += `<div class="crypto-extra-row"><span>المصفوفة:</span><code dir="ltr">${ex.matrix.map(r => escapeHtml(Array.isArray(r) ? r.join(' ') : r)).join(' | ')}</code></div>`;
    document.getElementById('cryptoExtras').innerHTML = extrasHtml;

    // خطوات الحل
    document.getElementById('cryptoSteps').innerHTML =
        (data.steps || []).map((s, i) => {
            const mono = /^[\s\[{(0-9A-Za-z+\-×*⁻¹ᵉᵈmod=≡→←,.\/:()]/.test(s);
            return `<div class="crypto-step"><span class="crypto-step-num">${i + 1}</span><div class="crypto-step-text" dir="${mono ? 'ltr' : 'auto'}">${escapeHtml(s)}</div></div>`;
        }).join('');

    card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function extraRow(label, value, highlight) {
    return `<div class="crypto-extra-row${highlight ? ' hl' : ''}">
        <span>${escapeHtml(label)}:</span>
        <code dir="ltr">${escapeHtml(String(value))}</code>
    </div>`;
}

function copyCryptoResult() {
    if (!lastCryptoResult) return;
    const btn = document.getElementById('btnCopyResult');
    navigator.clipboard.writeText(lastCryptoResult).then(() => {
        const old = btn.innerHTML;
        btn.innerHTML = '<i class="fa-solid fa-check"></i> تم النسخ';
        setTimeout(() => { btn.innerHTML = old; }, 1500);
    }).catch(() => {
        // بديل للمتصفحات القديمة
        const ta = document.createElement('textarea');
        ta.value = lastCryptoResult;
        document.body.appendChild(ta); ta.select();
        document.execCommand('copy'); ta.remove();
    });
}

function showCryptoError(msg) {
    const box = document.getElementById('cryptoError');
    box.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> <span>${escapeHtml(msg)}</span>`;
    box.style.display = 'flex';
}
function hideCryptoError() {
    const box = document.getElementById('cryptoError');
    if (box) box.style.display = 'none';
}

/* ---------- تشغيل عند جاهزية الصفحة ---------- */
document.addEventListener('DOMContentLoaded', initCryptoLab);
if (document.readyState !== 'loading') initCryptoLab();
