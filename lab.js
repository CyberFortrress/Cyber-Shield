/* Simulation Lab: a section of index.html (16 labs, Arabic/English).
 * Security rules for this file: no innerHTML/outerHTML/insertAdjacentHTML/document.write/eval; every server- or
 * user-derived string goes through textContent; frames are sandboxed (allow-scripts only, never allow-same-origin)
 * and are trusted only through strictly validated postMessage. `API` comes from app.js. */
(function () {
    'use strict';
    const KEY_RE = /^[a-z0-9_-]{1,32}$/, ID_RE = /^[a-z0-9-]{1,40}$/, FRAME_RE = /^\/lab\/frame\/[a-z0-9-]{1,40}\/(vulnerable|fixed)$/;
    const MAX_URL = 2048;

    // ---------- UI strings (the lab content itself comes localized from the API) ----------
    const L = {
        home: ['نبذة عنا', 'Overview'], all: ['كل المختبرات', 'All labs'], backScan: ['العودة لنتيجة الفحص', 'Back to scan result'], badge: ['🎓 محاكاة تعليمية', '🎓 Educational Simulation'],
        intro1: ['مختبر المحاكاة التعليمي', 'Educational Simulation Lab'],
        intro2: ['16 مختبراً تفاعلياً تشرح كيف تعمل الثغرات والخدع التي يرصدها الفحص، عبر أمثلة اصطناعية معزولة. هذه الأمثلة تشرح الفكرة ولا تثبت أن موقعاً بعينه معرّض للاستغلال.',
            '16 interactive labs explaining how the flaws and tricks found by the scanner work, using isolated synthetic examples. They explain the idea and do not prove that any particular site is exploitable.'],
        foundTitle: ['مؤشرات رُصدت في الرابط الذي فحصته', 'Indicators found in the URL you scanned'], open: ['افتح', 'Open'], openSim: ['استكشف الثغرة (Open Safe Simulation)', 'Explore the vulnerability (Open Safe Simulation)'],
        openEdu: ['افتح مثالاً تعليمياً', 'Open an educational example'], browse: ['تصفّح مختبر المحاكاة', 'Browse the Simulation Lab'],
        interactive: ['تفاعلي', 'Interactive'], staticT: ['شرح ثابت', 'Static explanation'], sevTitle: ['خطورة هذا النوع', 'Severity of this class'],
        sev: { high: ['عالية', 'High'], medium: ['متوسطة', 'Medium'], low: ['منخفضة', 'Low'], info: ['معلومة', 'Info'] },
        conf: { observed: ['مرصود (Observed)', 'Observed'], potential: ['محتمل (Potential)', 'Potential'], educational: ['تعليمي فقط (Educational)', 'Educational only'] },
        sideA: ['أ. ما رصده الفحص فعلاً (Observed)', 'A. What the scan actually found (Observed)'], sideB: ['ب. المحاكاة التعليمية (Simulated)', 'B. The educational simulation (Simulated)'],
        sandboxNote: ['بيانات اصطناعية داخل sandbox معزول: بلا شبكة ولا كوكيز ولا تخزين، ولا تنقّل لوجهات خارجية.', 'Synthetic data inside an isolated sandbox: no network, cookies or storage, and no navigation to external destinations.'],
        noObs: ['لا يوجد مؤشر مرصود في نتيجة الفحص مرتبط بهذه المحاكاة، ولذلك تُعرض كمثال تعليمي عام.', 'The scan result has no observed indicator tied to this simulation, so it is shown as a general educational example.'],
        noCtx: ['لم تُفتح هذه الصفحة من نتيجة فحص، فلا توجد أدلة مرتبطة بها.', 'This page was not opened from a scan result, so there is no evidence attached.'],
        establishes: ['ما يثبته: ', 'What it establishes: '], limits: ['حدود الاستنتاج: ', 'Limits: '], sevLbl: ['الخطورة: ', 'Severity: '], origScan: ['نتيجة الفحص الأصلية (محفوظة كما هي)', 'Original scan result (kept as-is)'],
        verdict: ['الحكم: ', 'Verdict: '], score: ['الدرجة: ', 'Score: '], vulnerable: ['ضعيف', 'Vulnerable'], fixed: ['مُصحَّح', 'Fixed'], compare: ['مقارنة جنباً إلى جنب', 'Side by side'],
        reset: ['↺ إعادة ضبط', '↺ Reset'], run: ['تشغيل', 'Run'], vcode: ['الكود الضعيف (Vulnerable)', 'Vulnerable code'], fcode: ['الكود المُصحَّح (Fixed)', 'Fixed code'],
        inputNote: ['المدخل يُرسل إلى الإطار المعزول كبيانات فقط. الحد الأقصى 300 حرف، ويفحصه حارس المختبر قبل العرض.', 'The input is sent to the isolated frame as data only. Maximum 300 characters, checked by the lab guard before display.'],
        noInput: ['هذه المحاكاة تفاعلية مباشرة داخل الإطار (بدون مدخلات).', 'This simulation is interactive inside the frame (no input needed).'],
        whyLines: ['لماذا هذه الأسطر مشكلة؟', 'Why are these lines a problem?'], whyHint: ['اضغط أي بند لتظليل الأسطر المقابلة، أو اضغط سطراً مظلّلاً في الكود.', 'Click an item to highlight its lines, or click a highlighted line in the code.'],
        how: ['كيف تعمل؟', 'How does it work?'], impact: ['الأثر', 'Impact'], fix: ['المعالجة (Remediation)', 'Remediation'], cmp: ['مقارنة', 'Comparison'], log: ['سجل الأحداث', 'Event log'],
        lines: ['الأسطر: ', 'Lines: '], outside: ['(يخص عنصراً خارج الكود المعروض)', '(refers to something outside the displayed code)'],
        staticTitle: ['شرح ثابت (Static)', 'Static explanation'], staticBody: ['هذه الحالة لا يمكن محاكاتها بأمان داخل المتصفح، لذلك نعرض شرحاً ومثال إصلاح فقط.', 'This case cannot be simulated safely in the browser, so only an explanation and a fix example are shown.'],
        navBlocked: ['تم حجب تنقّل غير متوقع داخل المحاكاة. اضغط إعادة ضبط.', 'An unexpected navigation inside the simulation was blocked. Press Reset.'],
        loadErr: ['تعذر تحميل المختبر. تأكد أن الباك إند يعمل.', 'Could not load the lab. Make sure the backend is running.'], educationalWhy: ['مثال تعليمي عام', 'General educational example'],
        simTag: ['محاكاة تعليمية', 'EDUCATIONAL SIMULATION'],
        sandboxIntro: ['المؤشرات مستخرجة من نص الرابط فقط (لم يتم فتح الموقع). المحاكاة أمثلة اصطناعية معزولة ولا تثبت أن الموقع قابل للاستغلال.', 'Indicators are derived from the URL text only (the site was not opened). Simulations are isolated synthetic examples and do not prove the site is exploitable.'],
        findTitle: ['🔬 اكتشف ما وراء النتيجة (Simulation Lab)', '🔬 Look behind the result (Simulation Lab)'],
    };
    const lang = () => window.CS_I18N && window.CS_I18N.lang === 'ar' ? 0 : 1;
    const T = (k) => L[k][lang()];
    const pick = (o, base) => o[base + (lang() ? '_en' : '_ar')];

    function h(tag, props, ...kids) {
        const el = document.createElement(tag);
        for (const [k, v] of Object.entries(props || {})) {
            if (v === undefined || v === null || v === false) continue;
            if (k === 'class') el.className = v; else if (k === 'text') el.textContent = v;
            else if (k.startsWith('on')) el.addEventListener(k.slice(2), v); else el.setAttribute(k, v);
        }
        for (const kid of kids.flat()) if (kid) el.append(kid);
        return el;
    }
    const root = () => document.getElementById('labRoot');
    const api = async (path, opts) => { const r = await fetch(API + path, opts); if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); };
    const validUrl = (u) => typeof u === 'string' && u.length > 0 && u.length <= MAX_URL && !/[\x00-\x1f\x7f]/.test(u);

    // ---------- syntax highlighting (token spans via textContent) ----------
    const RULES = {
        javascript: [['com', /\/\/.*/y], ['str', /"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/y], ['kw', /\b(?:function|var|let|const|return|if|else|try|catch|new|throw|for)\b/y], ['num', /\b\d+\b/y]],
        html: [['com', /<!--.*?-->/y], ['tag', /<\/?[a-zA-Z][\w-]*|\/?>/y], ['str', /"[^"]*"|'[^']*'/y], ['attr', /[\w:-]+(?==)/y]],
        nginx: [['com', /#.*/y], ['str', /"[^"]*"/y], ['kw', /\b(?:server|listen|server_name|location|return|add_header|proxy_pass|ssl)\b/y], ['num', /\b\d+\b/y]],
    };
    function tokenizeInto(parent, line, language) {
        const rules = RULES[language] || []; let i = 0, plain = '';
        const flush = () => { if (plain) { parent.append(document.createTextNode(plain)); plain = ''; } };
        while (i < line.length) {
            let hit = null;
            for (const [cls, re] of rules) { re.lastIndex = i; const m = re.exec(line); if (m && m.index === i && m[0].length) { hit = [cls, m[0]]; break; } }
            if (hit) { flush(); parent.append(h('span', { class: 'tk-' + hit[0], text: hit[1] })); i += hit[1].length; } else { plain += line[i]; i++; }
        }
        flush();
    }

    // ---------- state ----------
    const S = { view: 'home', demo: null, ctx: { finding: null, url: null, scan: null, fromScan: false }, mode: 'vulnerable', codeVariant: 'vulnerable', input: '', frames: {}, active: null };
    let nonce = 0, rendering = false, rerender = false, indexCache = null, lastFindings = null;

    // ---------- public API used by app.js ----------
    function renderFindings(container, analysis, scannedUrl) {
        const findings = analysis.findings || [], edu = analysis.educational_only || [];
        container.querySelectorAll('.lab-findings').forEach((n) => n.remove());
        const box = h('div', { class: 'lab-findings' }, h('h4', { text: T('findTitle') }), h('p', { class: 'lab-muted', text: T('sandboxIntro') }));
        findings.forEach((f) => box.append(h('div', { class: 'lab-finding' },
            h('span', { class: 'pill-sev sev-' + f.severity, text: T('sevLbl') + L.sev[f.severity][lang()] }), h('span', { class: 'pill-conf conf-' + f.confidence, text: L.conf[f.confidence][lang()] }),
            h('strong', { text: f.title_en || pick(f, 'title') }), evidenceList(f), h('div', { class: 'lab-muted', text: pick(f, 'limitations') }),
            h('button', { type: 'button', class: 'go', onclick: () => open({ demo: f.demo_id, finding: f.id, url: scannedUrl, scan: analysis, fromScan: true }), text: T('openSim') }))));
        edu.forEach((e) => box.append(h('div', { class: 'lab-finding' }, h('span', { class: 'pill-conf conf-educational', text: L.conf.educational[lang()] }), h('div', { text: pick(e, 'why') }),
            h('button', { type: 'button', class: 'go', onclick: () => open({ demo: e.demo_id, url: scannedUrl, scan: analysis, fromScan: true }), text: T('openEdu') }))));
        if (!findings.length && !edu.length) box.append(h('button', { type: 'button', class: 'go', onclick: () => open({ url: scannedUrl, scan: analysis, fromScan: true }), text: T('browse') }));
        container.append(box);
        container.dataset.labFindings = '1';
        lastFindings = { container, analysis, scannedUrl };            // re-drawn when the UI language changes
    }
    function evidenceList(f) {
        return h('ul', {}, f.evidence.map((e) => h('li', {}, h('span', { class: 'lab-muted', text: (lang() ? e.label : e.label_ar) + ': ' }), h('code', { class: 'ev', text: e.value }))));
    }

    // open the lab (demo === undefined shows the list)
    function open(opts) {
        opts = opts || {};
        S.ctx = { finding: /^[a-z_]{1,40}(:\d{1,2})?$/.test(opts.finding || '') ? opts.finding : null, url: validUrl(opts.url) ? opts.url : null, scan: opts.scan || null, fromScan: !!opts.fromScan };
        S.view = opts.demo && ID_RE.test(opts.demo) ? opts.demo : 'home'; S.pending = true;
        if (typeof showSection === 'function' && document.getElementById('labSection').style.display === 'none') { showSection('labSection'); return; }
        render();
    }
    function onShow() {
        if (!S.pending) { S.view = 'home'; S.ctx = { finding: null, url: null, scan: null, fromScan: false }; }   // opened from the sidebar: show the list
        S.pending = false; render();
    }

    // ---------- chrome shared by both views ----------
    function topbar() {
        const left = h('div', { class: 'lab-nav' },
            h('button', { type: 'button', class: 'lab-btn primary', onclick: () => showSection('overviewSection'), text: '← ' + T('home') }),
            S.view !== 'home' ? h('button', { type: 'button', class: 'lab-btn', onclick: () => { S.view = 'home'; render(); }, text: T('all') }) : null,
            S.ctx.fromScan ? h('button', { type: 'button', class: 'lab-btn', onclick: () => showSection('scannerSection'), text: T('backScan') }) : null);
        return h('div', { class: 'lab-topbar' }, left, h('span', { class: 'edu-badge', text: T('badge') }));
    }

    // ---------- list view ----------
    async function renderHome() {
        const data = await api('/api/lab/demos?lang=' + (lang() ? 'en' : 'ar'));
        const kids = [topbar(), h('div', { class: 'lab-card' }, h('h2', { text: T('intro1') }), h('p', { text: T('intro2') }))];
        const sc = S.ctx.scan;
        if (sc && (sc.findings || []).length) {
            kids.push(h('div', { class: 'lab-card' }, h('h3', { text: T('foundTitle') }), sc.findings.map((f) => h('div', { class: 'lab-finding' },
                h('span', { class: 'pill-conf conf-' + f.confidence, text: L.conf[f.confidence][lang()] }), h('strong', { text: f.title_en || pick(f, 'title') }), evidenceList(f),
                h('button', { type: 'button', class: 'go', onclick: () => open({ demo: f.demo_id, finding: f.id, url: S.ctx.url, scan: sc, fromScan: true }), text: T('openSim') })))));
        }
        kids.push(h('div', { class: 'demo-grid' }, data.demos.map((d, i) => h('div', { class: 'lab-card demo-card' },
            h('div', { class: 'demo-num', text: String(i + 1).padStart(2, '0') }), h('h3', { text: d.title_en || d.title }),
            h('span', { class: 'pill-sev sev-' + d.severity, text: L.sev[d.severity][lang()] }), h('span', { class: 'lab-muted', text: d.category + ' · ' + (d.kind === 'static' ? T('staticT') : T('interactive')) }),
            h('p', { text: d.summary }), h('button', { type: 'button', class: 'go', onclick: () => { S.view = d.id; S.ctx.finding = null; render(); }, text: T('open') })))));
        root().replaceChildren(...kids);
    }

    // ---------- demo view ----------
    function contextCard(demo) {
        const sc = S.ctx.scan, list = (sc && sc.findings) || [];
        const f = S.ctx.finding ? list.find((x) => x.id === S.ctx.finding && x.demo_id === demo.id) : list.find((x) => x.demo_id === demo.id);
        const a = h('div', { class: 'lab-card ab-a' }, h('h3', { text: T('sideA') }));
        if (f) {
            a.append(h('div', {}, h('span', { class: 'pill-sev sev-' + f.severity, text: T('sevLbl') + L.sev[f.severity][lang()] }), h('span', { class: 'pill-conf conf-' + f.confidence, text: L.conf[f.confidence][lang()] })),
                h('p', { text: f.title_en || pick(f, 'title') }), evidenceList(f), h('p', { text: T('establishes') + pick(f, 'establishes') }), h('p', { class: 'lab-muted', text: T('limits') + pick(f, 'limitations') }));
        } else {
            a.append(h('p', { text: S.ctx.url ? T('noObs') : T('noCtx') }));
            if (S.ctx.url) a.append(h('p', {}, h('span', { class: 'pill-conf conf-educational', text: L.conf.educational[lang()] })));
        }
        if (sc) a.append(h('details', {}, h('summary', { text: T('origScan') }), h('p', {}, h('code', { class: 'ev', text: S.ctx.url || '' })),
            h('p', { text: T('verdict') + sc.level + ' | ' + T('score') + sc.score + '/100' }), h('ul', {}, (sc.reasons || []).map((r) => h('li', { text: window.CS_I18N ? CS_I18N.t(r) : r })))));
        const b = h('div', { class: 'lab-card ab-b' }, h('h3', { text: T('sideB') }), h('p', { text: demo.disclaimer }), h('p', { class: 'lab-muted', text: T('sandboxNote') }));
        return h('div', { class: 'ab-grid' }, a, b);
    }
    function renderCode() {
        const v = S.demo.variants[S.codeVariant], body = S.codeEl; body.replaceChildren();
        const keyByLine = {}; v.highlights.forEach((hl) => hl.lines.forEach((n) => { keyByLine[n] = hl.key; }));
        v.code.split('\n').forEach((text, idx) => {
            const n = idx + 1, key = keyByLine[n], on = S.active && S.active.variant === S.codeVariant && S.active.key === key;
            const src = h('span', { class: 'src' }); tokenizeInto(src, text, v.language);
            const line = h('div', { class: 'code-line' + (key ? ' hl' : '') + (on ? ' active' : ''), 'data-line': String(n) }, h('span', { class: 'ln', text: String(n) }), src);
            if (key) line.addEventListener('click', () => activate(S.codeVariant, key));
            body.append(line);
        });
        S.tabs.forEach((t) => t.setAttribute('aria-selected', String(t.dataset.v === S.codeVariant)));
    }
    function renderExplanations() {
        const wrap = S.explEl; wrap.replaceChildren();
        for (const variant of ['vulnerable', 'fixed']) {
            if (S.mode !== 'compare' && S.mode !== variant) continue;
            wrap.append(h('h4', { text: variant === 'vulnerable' ? T('vcode') : T('fcode') }));
            S.demo.variants[variant].highlights.forEach((hl) => {
                const on = S.active && S.active.variant === variant && S.active.key === hl.key;
                wrap.append(h('button', { type: 'button', class: 'expl-item' + (on ? ' active' : ''), 'aria-pressed': String(!!on), onclick: () => activate(variant, hl.key) }, h('div', { text: hl.explanation }),
                    hl.lines.length ? h('div', { class: 'lab-muted', text: T('lines') + hl.lines.join(', ') }) : h('div', { class: 'nolines', text: T('outside') })));
            });
        }
    }
    function activate(variant, key) {
        if (!KEY_RE.test(key) || !S.demo.variants[variant] || !S.demo.variants[variant].highlights.some((x) => x.key === key)) return;
        S.active = { variant, key }; S.codeVariant = variant; renderCode(); renderExplanations();
        const el = S.codeEl.querySelector('.code-line.active'); if (el) el.scrollIntoView({ block: 'nearest' });
    }
    function addLog(variant, text) {
        S.logEl.append(h('div', { text: '[' + variant + '] ' + String(text).slice(0, 200) }));
        while (S.logEl.children.length > 30) S.logEl.firstChild.remove();
        S.logEl.scrollTop = S.logEl.scrollHeight;
    }
    function buildFrame(variant) {
        const path = S.demo.variants[variant].frame_url;
        if (!FRAME_RE.test(path)) throw new Error('bad frame path');
        const el = h('iframe', { sandbox: 'allow-scripts', referrerpolicy: 'no-referrer', title: 'Educational simulation: ' + variant });
        const entry = { variant, el, ready: false, expectedLoads: 1 };
        el.addEventListener('load', () => {
            if (entry.expectedLoads > 0) { entry.expectedLoads--; return; }
            el.removeAttribute('src'); entry.ready = false; addLog(variant, T('navBlocked'));       // frame navigated by itself: blank it
        });
        el.src = API + path + '?lang=' + (lang() ? 'en' : 'ar') + '&r=' + (++nonce);
        S.frames[variant] = entry; return entry;
    }
    function sendInput(value) {
        S.input = value;
        Object.values(S.frames).forEach((f) => { if (f.ready && f.el.contentWindow) f.el.contentWindow.postMessage({ lab: 1, type: 'input', value }, '*'); });
    }
    window.addEventListener('message', (e) => {
        if (!S.demo) return;
        const entry = Object.values(S.frames).find((f) => f.el.contentWindow && f.el.contentWindow === e.source);
        if (!entry || e.origin !== 'null') return;                                  // sandboxed frames have an opaque origin
        const d = e.data;
        if (!d || d.lab !== 1 || d.demo !== S.demo.id || d.variant !== entry.variant) return;
        if (d.type === 'ready') { entry.ready = true; if (S.demo.input) sendInput(S.input); }
        else if (d.type === 'hl' && typeof d.key === 'string') activate(entry.variant, d.key);
        else if (d.type === 'log' && typeof d.text === 'string') addLog(entry.variant, d.text);
    });
    function mountFrames() {
        S.frames = {}; S.previewEl.replaceChildren();
        if (S.demo.kind === 'static') { S.previewEl.append(h('div', { class: 'lab-card' }, h('h3', { text: T('staticTitle') }), h('p', { text: T('staticBody') }))); return; }
        (S.mode === 'compare' ? ['vulnerable', 'fixed'] : [S.mode]).forEach((v) => {
            const entry = buildFrame(v);
            S.previewEl.append(h('div', { class: 'lab-browser' },
                h('div', { class: 'lab-bar' }, h('span', { text: 'lab://' + S.demo.id + '/' + v }), h('span', { class: 'sim-tag', text: T('simTag') })),
                h('div', { class: 'frame-label ' + (v === 'vulnerable' ? 'v' : 'f'), text: v === 'vulnerable' ? T('vcode') : T('fcode') }), entry.el));
        });
    }
    function setMode(mode) {
        S.mode = mode; S.active = null; if (mode !== 'compare') S.codeVariant = mode;
        S.modeBtns.forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.m === mode)));
        mountFrames(); renderCode(); renderExplanations();
    }
    function reset() {
        S.active = null; S.logEl.replaceChildren(); S.input = S.demo.input ? S.demo.input.default : '';
        if (S.inputEl) S.inputEl.value = S.input;
        mountFrames(); renderCode(); renderExplanations();
    }
    function inputCard(demo) {
        S.inputEl = null;
        if (!demo.input) return h('div', { class: 'lab-card' }, h('p', { class: 'lab-muted', text: demo.kind === 'static' ? '' : T('noInput') }));
        const inp = h('input', { type: 'text', maxlength: '300', 'aria-label': demo.input.label, autocomplete: 'off', spellcheck: 'false', dir: 'ltr' });
        inp.value = S.input || demo.input.default; S.inputEl = inp; S.input = inp.value;
        const run = () => sendInput(inp.value);
        inp.addEventListener('keydown', (e) => { if (e.key === 'Enter') run(); });
        const presets = demo.input.presets.slice();
        if (S.ctx.url && ['url-anatomy', 'homograph', 'ssrf'].includes(demo.id)) presets.push({ id: 'scanned', label: lang() ? 'The URL you scanned' : 'الرابط الذي فحصته', value: S.ctx.url.slice(0, 300) });
        return h('div', { class: 'lab-card input-panel' }, h('h3', { text: demo.input.label }),
            h('div', { class: 'row' }, inp, h('button', { type: 'button', class: 'lab-btn primary', onclick: run, text: T('run') })),
            h('div', { class: 'row' }, presets.map((p) => h('button', { type: 'button', class: 'chip', onclick: () => { inp.value = p.value; run(); }, text: p.label }))), h('p', { class: 'lab-muted', text: T('inputNote') }));
    }
    async function renderDemo(id) {
        const demo = await api('/api/lab/demos/' + id + '?lang=' + (lang() ? 'en' : 'ar'));
        const keepMode = (S.demo && S.demo.id === id) ? S.mode : 'vulnerable';
        S.demo = demo; S.mode = keepMode; S.codeVariant = keepMode === 'fixed' ? 'fixed' : 'vulnerable'; S.active = null;
        S.previewEl = h('div', { class: 'preview-col' }); S.codeEl = h('div', { class: 'code-body', role: 'region', 'aria-label': 'source code' });
        S.tabs = ['vulnerable', 'fixed'].map((v) => h('button', { type: 'button', role: 'tab', 'data-v': v, text: v === 'vulnerable' ? T('vcode') : T('fcode'), onclick: () => { S.codeVariant = v; S.active = null; renderCode(); renderExplanations(); } }));
        S.explEl = h('div', { class: 'expl-list' }); S.logEl = h('div', { class: 'lab-log', 'aria-live': 'polite' });
        S.modeBtns = [['vulnerable', 'vulnerable'], ['fixed', 'fixed'], ['compare', 'compare']].map(([m, k]) => h('button', { type: 'button', 'data-m': m, 'aria-pressed': String(m === keepMode), text: T(k), onclick: () => setMode(m) }));
        indexCache = indexCache || (await api('/api/lab/demos?lang=en')).demos.map((d) => d.id);
        const idx = indexCache.indexOf(id) + 1;
        const toolbar = h('div', { class: 'toolbar' }, demo.kind === 'static' ? null : h('div', { class: 'seg', role: 'group' }, S.modeBtns), demo.kind === 'static' ? null : h('button', { type: 'button', class: 'lab-btn', onclick: reset, text: T('reset') }));
        document.title = demo.title;
        root().replaceChildren(topbar(),
            h('div', { class: 'lab-card' }, h('h2', { text: String(idx).padStart(2, '0') + ' · ' + (demo.title_en || demo.title) }), h('div', {}, h('span', { class: 'pill-sev sev-' + demo.severity, text: T('sevTitle') + ': ' + L.sev[demo.severity][lang()] }), h('span', { class: 'lab-muted', text: demo.category })), h('p', { text: demo.summary })),
            contextCard(demo), h('div', { class: 'lab-gap' }), toolbar, inputCard(demo),
            h('div', { class: 'stage' }, S.previewEl, h('div', { class: 'code-panel' }, h('div', { class: 'code-tabs', role: 'tablist' }, S.tabs), S.codeEl)),
            h('div', { class: 'lab-card' }, h('h3', { text: T('whyLines') }), h('p', { class: 'lab-muted', text: T('whyHint') }), S.explEl),
            h('div', { class: 'lab-card' }, h('h3', { text: T('how') }), h('ul', {}, demo.how_it_works.map((t) => h('li', { text: t }))), h('h3', { text: T('impact') }), h('p', { text: demo.impact })),
            h('div', { class: 'lab-card' }, h('h3', { text: T('fix') }), h('ul', {}, demo.mitigation.map((t) => h('li', { text: t }))), h('h3', { text: T('cmp') }), h('p', { text: demo.comparison })),
            demo.kind === 'static' ? null : h('div', { class: 'lab-card' }, h('h3', { text: T('log') }), S.logEl), h('div', { class: 'warn-box', text: demo.disclaimer }));
        setMode(keepMode);
    }

    async function render() {
        if (rendering) { rerender = true; return; }                      // a request arriving mid-render is queued, never dropped
        rendering = true;
        try { if (S.view === 'home') { S.demo = null; await renderHome(); } else await renderDemo(S.view); }
        catch (e) { root().replaceChildren(topbar(), h('div', { class: 'warn-box', text: T('loadErr') })); }
        finally { rendering = false; }
        if (rerender) { rerender = false; return render(); }
        const sec = document.getElementById('labSection'); if (sec && sec.scrollIntoView) window.scrollTo({ top: 0 });
    }

    window.addEventListener('cs-lang-change', () => {
        if (lastFindings && lastFindings.container.isConnected && lastFindings.container.querySelector('.lab-findings')) renderFindings(lastFindings.container, lastFindings.analysis, lastFindings.scannedUrl);
        const sec = document.getElementById('labSection');
        const rootEl = root();
        if (rootEl) { rootEl.dir = lang() ? 'ltr' : 'rtl'; rootEl.lang = lang() ? 'en' : 'ar'; }
        if (sec && sec.style.display !== 'none') render(); });
    window.CyberLab = { open, renderFindings, onShow, _state: S };
})();
