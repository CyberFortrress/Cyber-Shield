/* Secure file encryption stays in the browser; files are never sent to the API. */
(() => {
    const MAX_FILE_BYTES = 50 * 1024 * 1024;
    const PBKDF2_ITERATIONS = 310000;
    const MAGIC = new Uint8Array([67, 83, 69, 78, 67, 48, 49, 10]); // CSENC01\n
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    let resultBlob = null;
    let resultName = '';
    let busy = false;

    window.clearCryptoFileResult = function () {
        resultBlob = null;
        resultName = '';
        byId('cryptoFileDownloadWrap').style.display = 'none';
        byId('btnCopyResult').style.display = '';
        byId('cryptoFileInput').value = '';
        byId('cryptoFilePassword').value = '';
    };

    function byId(id) { return document.getElementById(id); }

    window.setCryptoFileMode = function (mode) {
        const decrypt = mode === 'decrypt';
        byId('cryptoFilePassword').type = 'password';
        byId('cryptoFilePasswordToggle').innerHTML = '<i class="fa-solid fa-eye"></i>';
        byId('cryptoFilePasswordToggle').setAttribute('aria-label', 'إظهار كلمة المرور');
        byId('cryptoFilePasswordToggle').setAttribute('title', 'إظهار كلمة المرور');
        byId('cryptoFilePasswordToggle').setAttribute('aria-pressed', 'false');
        byId('cryptoFileInputLabel').textContent = decrypt ? 'اختار ملف .csenc لفك تشفيره' : 'اختار الملف المراد تشفيره';
        byId('cryptoFileInput').accept = decrypt ? '.csenc,application/octet-stream' : '';
        byId('cryptoFilePassword').placeholder = decrypt ? 'أدخل كلمة المرور المستخدمة في التشفير' : 'كلمة مرور قوية — 12 حرفًا على الأقل';
        byId('cryptoFilePassword').autocomplete = decrypt ? 'current-password' : 'new-password';
        byId('cryptoFileHint').textContent = decrypt
            ? 'اختر ملف .csenc وكلمة المرور الأصلية. الملف التالف أو كلمة المرور الخاطئة سيؤديان إلى رفض فك التشفير.'
            : 'الحد الأقصى 50 ميجابايت. احتفظ بكلمة المرور؛ لا توجد طريقة لاستعادتها إذا فُقدت.';
    };

    window.toggleCryptoFilePassword = function () {
        const input = byId('cryptoFilePassword');
        const toggle = byId('cryptoFilePasswordToggle');
        const show = input.type === 'password';
        input.type = show ? 'text' : 'password';
        toggle.innerHTML = `<i class="fa-solid ${show ? 'fa-eye-slash' : 'fa-eye'}"></i>`;
        toggle.setAttribute('aria-label', show ? 'إخفاء كلمة المرور' : 'إظهار كلمة المرور');
        toggle.setAttribute('title', show ? 'إخفاء كلمة المرور' : 'إظهار كلمة المرور');
        toggle.setAttribute('aria-pressed', String(show));
        input.focus();
    };

    async function deriveKey(password, salt) {
        const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
        return crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
            material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
        );
    }

    function safeFileName(name) {
        const cleaned = name.replace(/[\\/:*?"<>|\u0000-\u001f]/g, '_').replace(/^\.+$/, 'file').slice(0, 240);
        return cleaned || 'decrypted-file';
    }

    function formatBytes(bytes) {
        if (bytes < 1024) return `${bytes} B`;
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
        return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    }

    function renderFileResult(action, inputFile, outputBytes, mimeType) {
        resultBlob = new Blob([outputBytes], { type: mimeType || 'application/octet-stream' });
        resultName = action === 'encrypt' ? `${inputFile.name}.csenc` : resultName;
        const card = byId('cryptoResultCard');
        card.style.display = 'block';
        byId('cryptoFileDownloadWrap').style.display = 'flex';
        byId('btnCopyResult').style.display = 'none';
        byId('cryptoResult').innerHTML = `<div class="crypto-result-head"><span class="pill">${action === 'encrypt' ? 'Encrypted | تم التشفير' : 'Decrypted | تم فك التشفير'}</span><b>AES-256-GCM — تشفير الملفات</b></div><code>${escapeHtml(resultName)}</code>`;
        byId('cryptoExtras').innerHTML = `<div class="crypto-extra-row"><span>الملف الأصلي</span><code>${escapeHtml(inputFile.name)}</code></div><div class="crypto-extra-row"><span>حجم الملف الناتج</span><code>${formatBytes(outputBytes.length)}</code></div><div class="crypto-extra-row"><span>المعالجة</span><code>محليًا داخل المتصفح — لم يُرفع إلى الخادم</code></div>`;
        byId('cryptoSteps').innerHTML = [
            'اشتُق مفتاح من كلمة المرور باستخدام PBKDF2 مع SHA-256 وملح عشوائي.',
            'عولجت بيانات الملف بخوارزمية AES-256-GCM مع التحقق من سلامة البيانات.',
            action === 'encrypt' ? 'نزّل الملف المشفّر واحتفظ بكلمة المرور لفكّه لاحقًا.' : 'أُعيد الملف إلى صيغته الأصلية؛ نزّله من الزر أدناه.'
        ].map((step, i) => `<div class="crypto-step"><span class="crypto-step-num">${i + 1}</span><div class="crypto-step-text">${escapeHtml(step)}</div></div>`).join('');
        byId('cryptoFileDownload').innerHTML = `<i class="fa-solid fa-download"></i> تنزيل ${action === 'encrypt' ? 'الملف المشفّر' : 'الملف المفكوك'}`;
        card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    window.downloadCryptoFileResult = function () {
        if (!resultBlob || !resultName) return;
        const url = URL.createObjectURL(resultBlob);
        const link = document.createElement('a');
        link.href = url;
        link.download = resultName;
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 30000);
    };

    window.processCryptoFile = async function (action) {
        if (busy) return;
        const workspaceVersion = window.accountWorkspaceVersion || 0;
        const file = byId('cryptoFileInput').files[0];
        const password = byId('cryptoFilePassword').value;
        if (!crypto?.subtle) return showCryptoError('التشفير الآمن غير متاح هنا. افتح الموقع عبر localhost أو HTTPS.');
        if (!file) return showCryptoError('اختار ملفًا أولًا.');
        const allowedSize = action === 'decrypt' ? MAX_FILE_BYTES + 4096 : MAX_FILE_BYTES;
        if (file.size > allowedSize) return showCryptoError('حجم الملف أكبر من الحد المسموح (50 ميجابايت).');
        if (action === 'encrypt' && password.length < 12) return showCryptoError('استخدم كلمة مرور لا تقل عن 12 حرفًا.');
        if (!password) return showCryptoError('أدخل كلمة المرور.');

        setCryptoFileMode(action);
        byId('cryptoResultCard').style.display = 'none';
        byId('cryptoFileDownloadWrap').style.display = 'none';
        resultBlob = null;
        resultName = '';
        const button = byId(action === 'encrypt' ? 'btnEncrypt' : 'btnDecrypt');
        const oldHtml = button.innerHTML;
        busy = true;
        button.disabled = true;
        button.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> جارٍ التنفيذ...';
        try {
            if (action === 'encrypt') {
                const salt = crypto.getRandomValues(new Uint8Array(16));
                const iv = crypto.getRandomValues(new Uint8Array(12));
                const key = await deriveKey(password, salt);
                const metadata = encoder.encode(JSON.stringify({ name: file.name, type: file.type || 'application/octet-stream' }));
                const original = new Uint8Array(await file.arrayBuffer());
                const payload = new Uint8Array(4 + metadata.length + original.length);
                new DataView(payload.buffer).setUint32(0, metadata.length, false);
                payload.set(metadata, 4);
                payload.set(original, 4 + metadata.length);
                const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: MAGIC, tagLength: 128 }, key, payload));
                const output = new Uint8Array(MAGIC.length + salt.length + iv.length + encrypted.length);
                output.set(MAGIC, 0); output.set(salt, 8); output.set(iv, 24); output.set(encrypted, 36);
                if (workspaceVersion !== (window.accountWorkspaceVersion || 0)) return;
                renderFileResult(action, file, output);
            } else {
                const packed = new Uint8Array(await file.arrayBuffer());
                if (packed.length < 52 || !MAGIC.every((byte, i) => packed[i] === byte)) throw new Error('صيغة الملف غير صحيحة أو الملف ليس ملف .csenc صالحًا.');
                const salt = packed.slice(8, 24), iv = packed.slice(24, 36), encrypted = packed.slice(36);
                const key = await deriveKey(password, salt);
                let plain;
                try { plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: MAGIC, tagLength: 128 }, key, encrypted)); }
                catch { throw new Error('فشل فك التشفير. تحقق من كلمة المرور أو سلامة الملف.'); }
                if (plain.length < 4) throw new Error('البيانات داخل الملف غير مكتملة.');
                const metaLength = new DataView(plain.buffer, plain.byteOffset, plain.byteLength).getUint32(0, false);
                if (metaLength > plain.length - 4) throw new Error('بيانات الملف غير صالحة.');
                let metadata;
                try { metadata = JSON.parse(decoder.decode(plain.slice(4, 4 + metaLength))); }
                catch { throw new Error('تعذر قراءة بيانات الملف الأصلية.'); }
                resultName = safeFileName(metadata.name || 'decrypted-file');
                if (workspaceVersion !== (window.accountWorkspaceVersion || 0)) return;
                renderFileResult(action, file, plain.slice(4 + metaLength), metadata.type || 'application/octet-stream');
            }
        } catch (error) {
            if (workspaceVersion === (window.accountWorkspaceVersion || 0)) showCryptoError(error.message || 'حدث خطأ أثناء معالجة الملف.');
        } finally {
            busy = false;
            if (workspaceVersion === (window.accountWorkspaceVersion || 0)) {
                button.disabled = false;
                button.innerHTML = oldHtml;
            }
        }
    };
})();
