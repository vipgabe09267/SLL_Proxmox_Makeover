/* Native Proxmox Makeover controls. Supports the installed 0.1.0 and beta APIs. */
(function () {
    if (!window.Ext || !window.Proxmox || !window.PVE) return;
    const html = value => Ext.String.htmlEncode(String(value ?? '')).replace(/`/g, '&#96;');
    const copy = value => JSON.parse(JSON.stringify(value));
    const defaults = { background: '#141716', surface: '#1b201e', raised: '#242b26', border: '#343c36',
        accent: '#d5b98c', secondary: '#bac8ad', text: '#eeede6', muted: '#a5ada7' };
    const fontFamilies = Object.freeze({
        default: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
        system: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
        'dm-sans': '"SLL DM Sans", sans-serif', oxanium: '"SLL Oxanium", sans-serif',
        serif: 'Georgia, "Times New Roman", serif', monospace: 'ui-monospace, "DejaVu Sans Mono", monospace',
    });
    const fontPresets = [['default', 'Default'], ['system', 'System sans'], ['dm-sans', 'DM Sans'],
        ['oxanium', 'Oxanium'], ['serif', 'Georgia'], ['monospace', 'Monospace']];
    const font = name => Object.hasOwn(fontFamilies, name) ? fontFamilies[name] : fontFamilies.default;
    function responseError(response) {
        try {
            const decoded = Ext.decode(response.responseText);
            if (decoded?.errors) return Object.entries(decoded.errors).map(([key, value]) => html(key) + ': ' + html(value)).join('<br>');
            if (decoded?.message) return html(decoded.message);
        } catch (_error) { /* Do not expose untrusted response bodies. */ }
        return html(response.statusText || 'Request failed');
    }
    function request(method, path, payload) {
        return new Promise((resolve, reject) => {
            const options = { url: '/api2/json/sll-customs' + path, method, timeout: 120000,
                success: response => {
                    try { resolve(Ext.decode(response.responseText).data); }
                    catch (_error) { reject('The server returned an invalid response.'); }
                }, failure: response => reject(responseError(response)) };
            if (method !== 'GET') {
                options.headers = { CSRFPreventionToken: Proxmox.CSRFPreventionToken };
                options.jsonData = payload;
            }
            Ext.Ajax.request(options);
        });
    }
    function base64(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onerror = () => reject('The image could not be read.');
            reader.onload = () => resolve(String(reader.result).split(',')[1]);
            reader.readAsDataURL(file);
        });
    }
    function readable(foreground, background) {
        const rgb = hex => hex.slice(1).match(/../g).map(x => parseInt(x, 16) / 255)
            .map(x => x <= .04045 ? x / 12.92 : ((x + .055) / 1.055) ** 2.4);
        const lum = hex => rgb(hex).reduce((sum, x, i) => sum + x * [.2126, .7152, .0722][i], 0);
        const contrast = (a, b) => (Math.max(lum(a), lum(b)) + .05) / (Math.min(lum(a), lum(b)) + .05);
        return contrast(foreground, background) >= 4.5 ? foreground :
            (contrast('#111512', background) >= contrast('#ffffff', background) ? '#111512' : '#ffffff');
    }
    function paletteVariables(colors) {
        const c = { ...defaults, ...colors };
        return { '--pm-bg': c.background, '--pm-surface': c.surface, '--pm-raised': c.raised,
            '--pm-border': c.border, '--pm-accent': c.accent, '--pm-secondary': c.secondary,
            '--pm-text': readable(c.text, c.surface), '--pm-muted': readable(c.muted, c.surface),
            '--pm-on-bg': readable(c.text, c.background), '--pm-on-raised': readable(c.text, c.raised),
            '--pm-on-accent': readable(c.background, c.accent) };
    }
    window.SLLMakeoverPalette = { readable, variables: paletteVariables };

    function hexToHsv(hex) {
        const channels = /^#[0-9a-f]{6}$/i.test(hex) ? hex.slice(1).match(/../g).map(x => parseInt(x, 16) / 255) : [0, 0, 0];
        const [r, g, b] = channels, high = Math.max(...channels), low = Math.min(...channels), delta = high - low;
        let hue = 0;
        if (delta) {
            if (high === r) hue = (g - b) / delta % 6;
            else if (high === g) hue = (b - r) / delta + 2;
            else hue = (r - g) / delta + 4;
            hue *= 60;
        }
        return { h: (hue + 360) % 360, s: high ? delta / high : 0, v: high };
    }
    function hsvToRgb(h, s, v) {
        h = (h % 360 + 360) % 360;
        s = Math.min(1, Math.max(0, s)); v = Math.min(1, Math.max(0, v));
        const chroma = v * s, x = chroma * (1 - Math.abs(h / 60 % 2 - 1)), offset = v - chroma;
        const rgb = h < 60 ? [chroma, x, 0] : h < 120 ? [x, chroma, 0] : h < 180 ? [0, chroma, x] :
            h < 240 ? [0, x, chroma] : h < 300 ? [x, 0, chroma] : [chroma, 0, x];
        return rgb.map(value => Math.round((value + offset) * 255));
    }
    function hsvToHex(color) {
        return '#' + hsvToRgb(color.h, color.s, color.v).map(value => value.toString(16).padStart(2, '0')).join('');
    }
    function mountColorWheel(panel, field, label) {
        const root = panel.getEl().dom;
        const canvas = root.querySelector('.pm-color-wheel-canvas');
        const marker = root.querySelector('.pm-color-wheel-marker');
        const slider = root.querySelector('.pm-color-value input');
        const readout = root.querySelector('.pm-color-readout');
        const context = canvas.getContext('2d');
        const owner = panel.up('sllMakeoverWindow');
        const size = 180, scale = Math.max(1, Math.min(2, window.devicePixelRatio || 1));
        canvas.width = Math.round(size * scale); canvas.height = canvas.width;
        canvas.style.width = size + 'px'; canvas.style.height = size + 'px'; canvas.style.touchAction = 'none';
        let color = hexToHsv(field.getValue()), pointer = null, disposed = false, committing = false;
        const listeners = [];
        const on = (element, type, handler, options) => {
            element.addEventListener(type, handler, options);
            listeners.push(() => element.removeEventListener(type, handler, options));
        };
        const canEdit = () => !disposed && !panel.destroyed && !field.destroyed && !field.readOnly && !field.disabled &&
            owner && !owner.destroyed && !owner.busy && owner.canModify;
        function draw() {
            if (disposed || !context) return;
            const pixels = canvas.width, center = pixels / 2, radius = center - scale;
            const image = context.createImageData(pixels, pixels);
            for (let y = 0; y < pixels; y++) for (let x = 0; x < pixels; x++) {
                const dx = x + .5 - center, dy = y + .5 - center, distance = Math.hypot(dx, dy);
                if (distance > radius) continue;
                const h = (Math.atan2(dy, dx) * 180 / Math.PI + 360) % 360;
                // Keep the hue/saturation disc visible even when the selected
                // output is black. The separate slider controls output value.
                const rgb = hsvToRgb(h, distance / radius, 1), offset = (y * pixels + x) * 4;
                image.data[offset] = rgb[0]; image.data[offset + 1] = rgb[1]; image.data[offset + 2] = rgb[2];
                image.data[offset + 3] = Math.min(255, Math.round((radius - distance) / scale * 255));
            }
            context.putImageData(image, 0, 0);
        }
        function sync() {
            if (disposed) return;
            const diameter = canvas.clientWidth || size, center = diameter / 2, radius = center - diameter / size;
            marker.style.left = canvas.offsetLeft + center + Math.cos(color.h * Math.PI / 180) * color.s * radius + 'px';
            marker.style.top = canvas.offsetTop + center + Math.sin(color.h * Math.PI / 180) * color.s * radius + 'px';
            marker.style.backgroundColor = hsvToHex({ ...color, v: 1 });
            const description = 'Hue ' + Math.round(color.h) % 360 + ' degrees, saturation ' + Math.round(color.s * 100) + ' percent, brightness ' + Math.round(color.v * 100) + ' percent';
            canvas.setAttribute('aria-valuenow', String(Math.floor(color.h)));
            canvas.setAttribute('aria-valuetext', description);
            slider.value = String(Math.round(color.v * 100));
            slider.setAttribute('aria-valuetext', Math.round(color.v * 100) + ' percent');
            readout.textContent = hsvToHex(color).toUpperCase();
        }
        function commit() {
            if (!canEdit()) return;
            committing = true;
            field.setValue(hsvToHex(color));
            committing = false;
            sync();
        }
        function position(event) {
            if (!canEdit()) return;
            const box = canvas.getBoundingClientRect(), center = box.width / 2, radius = center - box.width / size;
            const dx = event.clientX - box.left - center, dy = event.clientY - box.top - box.height / 2;
            color.h = (Math.atan2(dy, dx) * 180 / Math.PI + 360) % 360;
            color.s = Math.min(1, Math.hypot(dx, dy) / radius);
            commit();
        }
        on(canvas, 'pointerdown', event => {
            if (event.button !== 0 || !canEdit() || pointer !== null) return;
            pointer = event.pointerId;
            canvas.setPointerCapture(pointer); canvas.focus();
            event.preventDefault(); position(event);
        });
        on(canvas, 'pointermove', event => { if (pointer === event.pointerId) { event.preventDefault(); position(event); } });
        const release = event => {
            if (pointer !== event.pointerId) return;
            if (event.type === 'pointerup') position(event);
            if (canvas.hasPointerCapture(pointer)) canvas.releasePointerCapture(pointer);
            pointer = null;
        };
        on(canvas, 'pointerup', release); on(canvas, 'pointercancel', release);
        on(canvas, 'lostpointercapture', () => { pointer = null; });
        on(canvas, 'keydown', event => {
            if (!canEdit()) return;
            const step = event.shiftKey ? 10 : 1;
            if (event.key === 'ArrowLeft') color.h = (color.h - step + 360) % 360;
            else if (event.key === 'ArrowRight') color.h = (color.h + step) % 360;
            else if (event.key === 'ArrowUp') color.s = Math.min(1, color.s + step / 100);
            else if (event.key === 'ArrowDown') color.s = Math.max(0, color.s - step / 100);
            else return;
            event.preventDefault(); event.stopPropagation(); commit();
        });
        on(slider, 'input', () => {
            if (!canEdit()) { sync(); return; }
            color.v = Number(slider.value) / 100; commit();
        });
        const externalChange = (input, value) => {
            if (!committing && /^#[0-9a-f]{6}$/i.test(value)) { color = hexToHsv(value); sync(); }
        };
        field.on('change', externalChange);
        const dispose = () => {
            if (disposed) return;
            disposed = true;
            if (pointer !== null && canvas.hasPointerCapture(pointer)) canvas.releasePointerCapture(pointer);
            listeners.forEach(remove => remove());
            if (!field.destroyed) field.un('change', externalChange);
        };
        panel.on('beforedestroy', dispose, null, { single: true });
        canvas.setAttribute('aria-label', label + ' hue and saturation. Left and right arrows change hue; up and down change saturation. Hold Shift for larger steps.');
        sync(); draw();
    }

    Ext.define('SLL.window.Makeover', {
        extend: 'Ext.window.Window', alias: 'widget.sllMakeoverWindow',
        title: 'Proxmox Makeover', iconCls: 'fa fa-paint-brush', modal: true, constrain: true,
        width: Math.min(1060, Ext.Element.getViewportWidth() - 16),
        height: Math.min(760, Ext.Element.getViewportHeight() - 16), minWidth: 280, minHeight: 280,
        layout: 'fit', cls: 'sll-makeover-window', closeAction: 'destroy',
        initComponent: function () {
            const me = this;
            me.returnUrl = location.pathname + location.search + location.hash;
            me.files = {}; me.objectUrls = {}; me.fileErrors = {}; me.pendingFiles = new Set(); me.previewMode = 'login'; me.ready = false;
            me.content = Ext.create('Ext.panel.Panel', { border: false, layout: { type: 'vbox', align: 'stretch' }, html: 'Loading configuration…', bodyPadding: 12 });
            Ext.apply(me, {
                items: [me.content],
                buttons: [
                    { text: 'Reset edits', itemId: 'resetButton', disabled: true, handler: () => me.resetEdits() }, '->',
                    { text: 'Close', handler: () => me.close() },
                    { text: 'Apply', ariaLabel: 'Apply', itemId: 'applyButton', disabled: true, handler: () => me.applyChanges() },
                ],
                listeners: {
                    show: () => { history.pushState({ sllCustoms: true }, '', '/SLL-Customs'); me.loadState(); },
                    beforeclose: () => {
                        if (me.busy && !me.forceClose) return false;
                        if (!me.forceClose && me.isDirty()) {
                            Ext.Msg.confirm('Discard changes?', 'Discard the unsaved appearance changes?', answer => {
                                if (answer === 'yes') { me.forceClose = true; me.close(); }
                            });
                            return false;
                        }
                        return true;
                    },
                    destroy: () => {
                        Object.values(me.objectUrls).forEach(url => URL.revokeObjectURL(url));
                        window.removeEventListener('beforeunload', me.unloadHandler);
                        if (/^\/SLL-Customs\/?$/.test(location.pathname)) history.replaceState({}, '', me.returnUrl.startsWith('/SLL-Customs') ? '/' : me.returnUrl);
                    },
                    resize: () => me.adjustLayout(),
                },
            });
            me.callParent(arguments);
            me.unloadHandler = event => { if (me.isDirty()) { event.preventDefault(); event.returnValue = ''; } };
            window.addEventListener('beforeunload', me.unloadHandler);
            me.mon(Ext.GlobalEvents, 'resize', () => {
                const viewWidth = Ext.Element.getViewportWidth(), viewHeight = Ext.Element.getViewportHeight();
                const width = Math.min(1060, viewWidth - 16), height = Math.min(760, viewHeight - 16);
                // The native workspace aligns modals before their new size is
                // rendered. Retire that cached old-size alignment after layout.
                if (me.makeoverResizeAfterLayout) me.un('afterlayout', me.makeoverResizeAfterLayout);
                if (me.makeoverResizePosition) me.mun(Ext.GlobalEvents, 'idle', me.makeoverResizePosition);
                const position = me.makeoverResizePosition = () => {
                    if (me.makeoverResizePosition !== position) return;
                    me.makeoverResizePosition = null;
                    if (!me.destroyed) { me.clearAlignEl(); me.setPosition(Math.floor((viewWidth - width) / 2), Math.floor((viewHeight - height) / 2)); }
                };
                const afterLayout = me.makeoverResizeAfterLayout = () => {
                    // Container afterlayout precedes the final context writes;
                    // native idle runs once those rendered positions settle.
                    if (me.makeoverResizePosition === position) me.mon(Ext.GlobalEvents, 'idle', position, null, { single: true });
                };
                me.on('afterlayout', afterLayout, null, { single: true });
                me.setSize(width, height); me.updateLayout();
            });
        },
        loadState: function () {
            const me = this;
            request('GET', '/config').then(state => {
                if (me.destroyed) return;
                me.currentState = state; me.original = copy(state.config); me.draft = copy(state.config);
                me.legacy = state.version === '0.1.0' || Number(state.config.schema_version || 1) < 2;
                me.fontsSupported = !me.legacy && state.font_selection === true;
                const caps = Ext.state.Manager.get('GuiCap');
                me.canModify = typeof state.can_modify === 'boolean' ? state.can_modify : Boolean(caps?.dc?.['Sys.Modify']);
                me.ready = true; me.buildControls();
            }).catch(error => { Ext.Msg.alert('Unable to open Makeover', error); me.forceClose = true; me.close(); });
        },
        field: function (name, label, maxLength, extra = {}) {
            const me = this;
            return Ext.apply({ xtype: 'textfield', name, fieldLabel: label, maxLength, allowBlank: false, enforceMaxLength: true,
                value: me.draft[name], readOnly: !me.canModify,
                listeners: { change: (field, value) => me.changeValue(name, value) } }, extra);
        },
        panel: function (title, items, extra = {}) {
            return Ext.apply({ xtype: 'panel', title, border: false, bodyPadding: 10, scrollable: 'y',
                layout: 'anchor', defaults: { anchor: '100%' }, items }, extra);
        },
        fontField: function (name, label) {
            const me = this;
            return { xtype: 'combobox', name: 'font_' + name, fieldLabel: label,
                store: { fields: ['id', 'label'], data: fontPresets.map(([id, label]) => ({ id, label })) },
                valueField: 'id', displayField: 'label', queryMode: 'local', editable: false,
                forceSelection: true, allowBlank: false, value: me.draft.fonts?.[name] || 'default',
                disabled: !me.canModify || !me.fontsSupported,
                listeners: { change: (field, value) => {
                    if (!me.rebuilding && !me.busy && me.canModify && me.fontsSupported && Object.hasOwn(fontFamilies, value)) {
                        me.draft.fonts = { login: 'default', dashboard: 'default', ...me.draft.fonts, [name]: value };
                        me.updatePreviewColors(); me.updateActions();
                    }
                } } };
        },
        preview: function (itemId, title, controls = true) {
            const me = this;
            return Ext.create('Ext.panel.Panel', { itemId, title, border: true, bodyPadding: 8,
                cls: 'pm-native-preview-panel', scrollable: 'y', html: '<div class="pm-preview"></div>',
                tbar: controls ? [
                    { text: 'Preview login', ariaLabel: 'Preview login', handler: () => me.showPreview('login') },
                    { text: 'Preview dashboard', ariaLabel: 'Preview dashboard', handler: () => me.showPreview('dashboard') },
                ] : undefined,
                listeners: { afterrender: () => me.renderPreviews() } });
        },
        buildControls: function () {
            const me = this;
            me.rebuilding = true;
            me.content.removeAll(true); me.content.update(''); me.content.bodyPadding = 0;
            me.content.body?.setStyle('padding', '0');
            me.content.setLayout({ type: 'vbox', align: 'stretch' });
            const fieldDefaults = { labelWidth: 108, labelAlign: 'top', anchor: '100%', msgTarget: 'side' };
            me.forms = [];
            const appearance = Ext.create('Ext.form.Panel', {
                title: 'Appearance', itemId: 'appearanceTab', border: false, bodyPadding: 10, scrollable: 'y',
                layout: 'anchor', fieldDefaults, defaults: { anchor: '100%' },
                items: [
                    { xtype: 'fieldset', title: 'Brand', layout: 'anchor', defaults: { anchor: '100%' }, items: [
                        me.field('company_name', 'Company name', 80),
                        me.field('website_url', 'Company website', 512, { validator: value => /^https:\/\/[^\s]+$/i.test(value) || 'Use a complete HTTPS address.' }),
                    ] },
                    { xtype: 'fieldset', title: 'Artwork', layout: 'anchor', defaults: { anchor: '100%' }, items: [
                        ...['logo', 'favicon'].map(kind => ({ xtype: 'filefield', itemId: kind + 'File', name: kind,
                            fieldLabel: kind === 'logo' ? 'Dashboard / login logo' : 'Favicon / icon', buttonText: 'Choose PNG', accept: 'image/png',
                            disabled: !me.canModify, listeners: { change: field => me.selectFile(field, kind) } })),
                        { xtype: 'component', cls: 'pm-native-note', html: 'PNG only, 64–4096 px, up to 3 MiB. The favicon must be square. Changes appear in the preview before Apply.' },
                    ] },
                    { xtype: 'fieldset', title: 'Fonts', layout: 'anchor', defaults: { anchor: '100%' }, items: [
                        me.fontField('login', 'Login font'), me.fontField('dashboard', 'Dashboard font'),
                        ...(!me.fontsSupported ? [{ xtype: 'component', cls: 'pm-native-note', html: 'Font selection requires the matching Makeover backend.' }] : []),
                    ] },
                    { xtype: 'fieldset', title: 'Colors', layout: 'anchor', defaults: { anchor: '100%' }, items: [
                        ...Object.entries({ background: 'Background', surface: 'Panels', raised: 'Raised panels', border: 'Borders',
                            accent: 'Accent', secondary: 'Secondary', text: 'Text', muted: 'Muted text' }).map(([name, label]) => ({
                            xtype: 'fieldcontainer', fieldLabel: label, labelAlign: 'left', labelWidth: 90, layout: 'hbox',
                            items: [
                                { xtype: 'textfield', name: 'color_' + name, value: me.draft.colors[name], flex: 1, maxWidth: 110, minWidth: 60,
                                    allowBlank: false, maxLength: 7, regex: /^#[0-9a-f]{6}$/i, regexText: 'Use a six-digit hex color.', readOnly: !me.canModify,
                                    ariaLabel: label + ' hex color', listeners: { change: (field, value) => {
                                        if (/^#[0-9a-f]{6}$/i.test(value) && !me.rebuilding && !me.busy) { me.draft.colors[name] = value; me.updatePreviewColors(); me.updateActions(); me.updateSwatch(name); }
                                    } } },
                                { xtype: 'button', itemId: 'colorButton_' + name, text: 'Choose', ariaLabel: 'Choose ' + label.toLowerCase() + ' color',
                                    iconCls: 'fa fa-square', margin: '0 0 0 6', disabled: !me.canModify,
                                    handler: button => {
                                        // Keep the native picker in the form's layout. This avoids
                                        // floating-menu differences across Proxmox's ExtJS builds.
                                        const group = button.up('fieldset');
                                        const row = button.up('fieldcontainer');
                                        const previous = group.down('[sllColorWheel=true]');
                                        const wasThis = previous?.itemId === 'wheel_' + name;
                                        previous?.destroy();
                                        if (wasThis) return;
                                        group.insert(group.items.indexOf(row) + 1, {
                                            xtype: 'panel', itemId: 'wheel_' + name, cls: 'pm-color-wheel-panel', sllColorWheel: true, title: label + ' color',
                                            anchor: undefined, width: 208, border: false, bodyPadding: 8, margin: '4 0 8 0',
                                            html: '<div class="pm-color-wheel"><canvas class="pm-color-wheel-canvas" width="180" height="180" tabindex="0" role="slider" aria-valuemin="0" aria-valuemax="359"></canvas>' +
                                                '<span class="pm-color-wheel-marker" aria-hidden="true"></span>' +
                                                '<label class="pm-color-value"><span>Brightness</span><input type="range" min="0" max="100" step="1" aria-label="' + html(label) + ' brightness"></label>' +
                                                '<div class="pm-color-readout" aria-live="polite"></div></div>',
                                            listeners: { afterrender: panel => {
                                                mountColorWheel(panel, appearance.getForm().findField('color_' + name), label);
                                                Ext.defer(() => {
                                                    if (!panel.destroyed) appearance.getScrollable()?.scrollIntoView(panel.getEl(), false, false);
                                                }, 1);
                                            } },
                                        });
                                    },
                                    listeners: { afterrender: () => me.updateSwatch(name) } },
                            ],
                        })),
                        { xtype: 'button', text: 'Reset palette', margin: '4 0 6 0', disabled: !me.canModify, handler: () => {
                            for (const [name, value] of Object.entries(defaults)) appearance.getForm().findField('color_' + name).setValue(value);
                        } },
                    ] },
                    { xtype: 'checkbox', name: 'show_storage_panel', boxLabel: 'Show disks and storage on node Summary', checked: me.draft.show_storage_panel,
                        disabled: !me.canModify, listeners: { change: (field, value) => me.changeValue('show_storage_panel', value) } },
                ],
            });
            me.forms.push(appearance);
            me.inlinePreview = me.preview('loginInlinePreview', 'Login preview', false);
            me.inlinePreview.setHeight(425);
            const login = Ext.create('Ext.form.Panel', {
                title: 'Login', itemId: 'loginTab', border: false, bodyPadding: 10, scrollable: 'y',
                layout: 'anchor', fieldDefaults, defaults: { anchor: '100%' },
                items: [
                    { xtype: 'button', text: 'Set up passkey sign-in', ariaLabel: 'Set up passkey sign-in', iconCls: 'fa fa-key', margin: '0 0 10 0',
                        disabled: !window.SLLMakeoverLoginPasskeys?.openManager,
                        handler: () => window.SLLMakeoverLoginPasskeys?.openManager() },
                    me.field('login_heading', 'Welcome heading', 100), me.field('login_subtitle', 'Welcome message', 240),
                    me.field('login_eyebrow', 'Small label', 100), me.field('page_title', 'Browser tab title', 160), me.field('footer_text', 'Footer text', 120),
                    { xtype: 'component', cls: 'pm-native-note', html: 'Native Proxmox controls continue to handle passwords, realms, languages and two-factor authentication.' },
                    me.inlinePreview,
                ], listeners: { activate: () => { me.previewMode = 'login'; me.renderPreviews(); } },
            });
            me.forms.push(login);
            let security;
            try { security = window.SLLMakeoverLoginPasskeys?.createSecurityPanel() || window.SLLMakeoverNativeSecurity?.createPanel({ ownerWindow: me }); }
            catch (_error) { /* Native security tooling remains independently available. */ }
            if (!security) security = me.panel('Security keys', [{ xtype: 'component', html: 'Native security-key tools are not available in this frontend build.' },
                { xtype: 'button', text: 'Open native TFA settings', margin: '10 0 0 0', handler: () => me.openNativeTFA() }]);
            const updates = Ext.create('Ext.form.Panel', {
                title: 'Updates', itemId: 'updatesTab', border: false, bodyPadding: 12, scrollable: 'y',
                items: [
                    { xtype: 'checkbox', name: 'update_safe', boxLabel: 'Reapply appearance after Proxmox updates',
                        checked: me.draft.update_safe !== false, disabled: !me.canModify || me.legacy,
                        listeners: { change: (field, value) => { if (!me.legacy) me.changeValue('update_safe', value); } } },
                    { xtype: 'component', cls: 'pm-native-note', html: 'This repairs appearance after package replacement. It does not upgrade Proxmox or schedule maintenance.' },
                    { xtype: 'component', cls: 'pm-native-note', html: me.legacy ? 'Backend upgrade pending. This control becomes available after the backend extension is activated; existing appearance repair remains as configured.' : 'Turning this off disables automatic appearance repair only.' },
                ],
            });
            me.forms.push(updates);
            me.mobilePreview = me.preview('previewTab', 'Preview');
            me.sidePreview = me.preview('sidePreview', 'Preview'); me.sidePreview.setWidth(350);
            me.tabs = Ext.create('Ext.tab.Panel', { flex: 1, border: false, itemId: 'makeoverTabs',
                items: [appearance, login, security, updates, me.mobilePreview],
                listeners: { tabchange: () => me.renderPreviews() } });
            me.status = Ext.create('Ext.Component', { itemId: 'makeoverStatus', padding: '7 10', cls: 'pm-native-status', ariaRole: 'status' });
            me.banner = Ext.create('Ext.Component', { padding: '7 10', cls: 'pm-native-banner', hidden: !me.legacy,
                html: '<strong>Backend upgrade pending.</strong> Presentation settings work now. Large artwork uploads and update protection require backend activation.' });
            me.content.add([me.banner, me.status, { xtype: 'container', layout: { type: 'hbox', align: 'stretch' }, flex: 1,
                items: [me.tabs, me.sidePreview] }]);
            me.rebuilding = false; me.adjustLayout(); me.renderPreviews(); me.updateActions();
            for (const name of Object.keys(defaults)) me.updateSwatch(name);
        },
        changeValue: function (name, value) {
            const me = this;
            if (me.rebuilding || !me.canModify || me.busy || !me.ready) return;
            if (name === 'company_name') {
                const old = me.draft.company_name;
                if (me.draft.footer_text === old) {
                    me.draft.footer_text = value;
                    me.forms?.[1]?.getForm().findField('footer_text')?.setValue(value);
                }
                if (me.draft.page_title === 'Infrastructure - ' + old + ' | ' + me.draft.product_label) {
                    me.draft.page_title = 'Infrastructure - ' + value + ' | ' + me.draft.product_label;
                    me.forms?.[1]?.getForm().findField('page_title')?.setValue(me.draft.page_title);
                }
            }
            me.draft[name] = value; me.renderPreviews(); me.updateActions();
        },
        updateSwatch: function (name) {
            const button = this.down('#colorButton_' + name);
            if (button?.rendered) button.getEl().down('.x-btn-icon-el')?.setStyle('color', this.draft.colors[name]);
        },
        adjustLayout: function () {
            const me = this;
            if (!me.sidePreview || !me.tabs || me.rebuilding) return;
            const compact = me.getWidth() < 760;
            me.sidePreview.setHidden(compact);
            me.mobilePreview.tab?.setHidden(!compact);
            me.inlinePreview.setHidden(!compact);
            if (!compact && me.tabs.getActiveTab() === me.mobilePreview) me.tabs.setActiveTab(0);
            me.updateLayout();
        },
        showPreview: function (mode) {
            this.previewMode = mode;
            if (this.getWidth() < 760 && this.tabs) this.tabs.setActiveTab(this.mobilePreview);
            this.renderPreviews();
        },
        isDirty: function () {
            return this.ready && (JSON.stringify(this.draft) !== JSON.stringify(this.original) || Object.keys(this.files).length > 0);
        },
        legacyArtworkTooLarge: function () {
            return this.legacy && Object.values(this.files).reduce((sum, file) => sum + Math.ceil(file.size / 3) * 4, 10000) > 480 * 1024;
        },
        updateActions: function () {
            if (!this.ready || !this.status) return;
            const blocked = this.legacyArtworkTooLarge();
            const fileError = Object.values(this.fileErrors).join(' ');
            this.down('#applyButton').setDisabled(!this.canModify || !this.isDirty() || this.busy || this.pendingFiles.size > 0 || blocked || Boolean(fileError));
            this.down('#resetButton').setDisabled(!this.canModify ||
                (!this.isDirty() && !fileError && this.pendingFiles.size === 0) || this.busy);
            let message = !this.canModify ? 'Read only: Sys.Modify is required to change appearance.' :
                (this.isDirty() ? 'Unsaved changes. Preview is local until Apply.' : 'Appearance settings loaded.');
            if (blocked) message = 'This artwork can be previewed, but is too large for the active backend. Use smaller PNGs (combined under 350 KiB) or activate the updated backend, then reopen Makeover.';
            if (this.pendingFiles.size) message = 'Checking selected artwork…';
            if (fileError) message = fileError;
            if (this.status.lastMakeoverMessage !== message) {
                this.status.update(html(message));
                this.status.lastMakeoverMessage = message;
            }
        },
        selectFile: async function (field, kind) {
            const me = this;
            if (!me.canModify || me.busy) return;
            const input = field.fileInputEl?.dom;
            const file = input?.files?.[0];
            const selection = field.pmSelection = (field.pmSelection || 0) + 1;
            delete me.files[kind]; delete me.fileErrors[kind]; me.pendingFiles.delete(kind);
            if (me.objectUrls[kind]) { URL.revokeObjectURL(me.objectUrls[kind]); delete me.objectUrls[kind]; }
            me.renderPreviews();
            if (!file) { me.updateActions(); return; }
            me.pendingFiles.add(kind); me.updateActions();
            let temporary;
            try {
                if (file.size > 3 * 1024 * 1024) throw new Error('Choose a PNG no larger than 3 MiB.');
                const signature = new Uint8Array(await file.slice(0, 8).arrayBuffer());
                if (signature.join(',') !== '137,80,78,71,13,10,26,10') throw new Error('Choose a PNG image.');
                temporary = URL.createObjectURL(file);
                const image = new Image(); image.src = temporary; await image.decode();
                if (image.width < 64 || image.height < 64 || image.width > 4096 || image.height > 4096) throw new Error('PNG dimensions must be between 64 and 4096 pixels.');
                if (kind === 'favicon' && image.width !== image.height) throw new Error('Choose a square PNG for the favicon.');
                if (me.destroyed || field.destroyed || field.pmSelection !== selection || input.files[0] !== file) return;
                if (me.objectUrls[kind]) URL.revokeObjectURL(me.objectUrls[kind]);
                me.objectUrls[kind] = temporary; temporary = undefined; me.files[kind] = file;
                me.renderPreviews();
            } catch (error) {
                if (!me.destroyed && !field.destroyed && field.pmSelection === selection) me.fileErrors[kind] = error.message || 'The image could not be previewed.';
            } finally {
                if (temporary) URL.revokeObjectURL(temporary);
                if (!me.destroyed && !field.destroyed && field.pmSelection === selection) { me.pendingFiles.delete(kind); me.updateActions(); }
            }
        },
        renderPreviews: function () {
            const me = this;
            if (!me.ready || !me.draft) return;
            for (const panel of [me.sidePreview, me.mobilePreview, me.inlinePreview]) {
                if (!panel?.rendered) continue;
                const mode = panel === me.inlinePreview ? 'login' : me.previewMode;
                panel.update('<div class="pm-preview">' + me.previewHtml(mode) + '</div>');
                if (panel !== me.mobilePreview) panel.setTitle(mode === 'login' ? 'Login preview' : 'Dashboard preview');
            }
            me.updatePreviewColors();
        },
        updatePreviewColors: function () {
            if (!this.ready || !this.draft) return;
            const variables = { ...paletteVariables(this.draft.colors),
                '--pm-login-font': font(this.draft.fonts?.login),
                '--pm-login-heading-font': !this.draft.fonts?.login || this.draft.fonts.login === 'default' ? fontFamilies.serif : font(this.draft.fonts.login),
                '--pm-dashboard-font': font(this.draft.fonts?.dashboard) };
            for (const panel of [this.sidePreview, this.mobilePreview, this.inlinePreview]) {
                const element = panel?.rendered && panel.getEl()?.dom.querySelector('.pm-preview');
                if (element) for (const [key, value] of Object.entries(variables)) element.style.setProperty(key, value);
            }
        },
        previewHtml: function (mode) {
            const c = this.draft;
            const version = encodeURIComponent(this.currentState.revision || 'preview');
            const logo = html(this.objectUrls.logo || '/pve2/images/SLS_Proxmox.png?v=' + version);
            const icon = html(this.objectUrls.favicon || '/pve2/images/SLS_Proxmox_Favicon.png?v=' + version);
            const brand = '<img class="pm-sample-logo" src="' + logo + '" alt="' + html(c.company_name) + ' logo">';
            const browser = '<div class="pm-sample-browser"><img src="' + icon + '" alt="">' + html(c.page_title) + '</div>';
            if (mode === 'login') return browser + '<div class="pm-sample-login"><div class="pm-sample-card">' + brand +
                '<span class="pm-sample-eyebrow">' + html(c.login_eyebrow) + '</span><h3>' + html(c.login_heading) + '</h3><p>' + html(c.login_subtitle) + '</p>' +
                '<div class="pm-sample-form"><span>Username</span><div>admin</div><span>Password</span><div>••••••••</div><span>Realm</span><div>Linux PAM</div></div>' +
                '<div class="pm-sample-submit">Sign in with password</div>' + (window.SLLMakeoverLoginPasskeys ? '<div style="text-align:center;margin-top:6px">or</div><div class="pm-sample-submit pm-sample-passkey">Sign in with passkey</div>' : '') +
                '<footer>' + html(c.footer_text) + '<small>Powered by ' + html(c.product_label) + '</small></footer></div></div>';
            return browser + '<div class="pm-sample-dashboard"><header>' + brand + '<span>' + html(c.company_name) + '</span></header>' +
                '<div class="pm-sample-workspace"><nav><strong>Datacenter</strong><span>▾ node</span><span>▸ guest</span></nav><main><h3>Node Summary</h3>' +
                '<div class="pm-sample-stats"><div>CPU usage<strong>12%</strong><i></i></div><div>Memory<strong>36%</strong><i></i></div></div>' +
                (c.show_storage_panel ? '<article><h4>Disks and storage</h4><p>Physical disks</p><div class="pm-sample-disk"><span>Storage usage</span><strong>42%</strong></div><i></i></article>' : '') +
                '<article><h4>Host system (/)</h4><p>Native Proxmox controls.</p></article></main></div></div>';
        },
        resetEdits: function () {
            if (!this.canModify || this.busy) return;
            this.draft = copy(this.original); this.files = {}; this.pendingFiles.clear(); this.fileErrors = {};
            Object.values(this.objectUrls).forEach(url => URL.revokeObjectURL(url)); this.objectUrls = {};
            this.buildControls();
        },
        openNativeTFA: function () {
            const me = this;
            const open = () => {
                const workspace = Ext.ComponentQuery.query('pveStdWorkspace')[0];
                if (!workspace) return;
                Ext.state.Manager.getProvider().set('dctab', { value: 'tfa' }, true); workspace.selectById('root');
                me.forceClose = true; me.close();
            };
            if (me.isDirty()) Ext.Msg.confirm('Discard changes?', 'Open native TFA settings and discard the unsaved appearance changes?', answer => { if (answer === 'yes') open(); });
            else open();
        },
        applyChanges: async function () {
            const me = this;
            if (!me.canModify || me.busy || me.pendingFiles.size || Object.keys(me.fileErrors).length || me.legacyArtworkTooLarge() || !me.isDirty()) return;
            for (const form of me.forms) if (!form.getForm().isValid()) { me.tabs.setActiveTab(form); return; }
            const submitted = copy(me.draft);
            if (me.legacy) { submitted.schema_version = 1; delete submitted.update_safe; }
            if (!me.fontsSupported) delete submitted.fonts;
            me.busy = true; me.updateActions(); me.setLoading('Applying appearance…'); me.tabs.setDisabled(true);
            try {
                const payload = { config_json: JSON.stringify(submitted) };
                if (!me.legacy) payload.expected_revision = me.currentState.revision;
                for (const kind of ['logo', 'favicon']) {
                    const file = me.files[kind]; if (!file) continue;
                    if (me.legacy) { payload[kind + '_base64'] = await base64(file); continue; }
                    let uploadId;
                    const chunkSize = 192 * 1024;
                    for (let offset = 0, index = 0; offset < file.size; offset += chunkSize, index++) {
                        const chunk = { kind, index, total_size: file.size, expected_revision: me.currentState.revision,
                            content_base64: await base64(file.slice(offset, offset + chunkSize)) };
                        if (me.destroyed) return;
                        if (uploadId) chunk.upload_id = uploadId;
                        me.setLoading('Uploading ' + (kind === 'logo' ? 'logo' : 'favicon') + '… ' + Math.round(offset / file.size * 100) + '%');
                        const staged = await request('POST', '/upload', chunk);
                        if (me.destroyed) return;
                        if (!/^[0-9a-f]{32}$/.test(staged.upload_id || '') || (uploadId && staged.upload_id !== uploadId) ||
                            Boolean(staged.complete) !== (offset + chunkSize >= file.size)) throw 'The image upload could not be verified. The running appearance has not changed.';
                        uploadId = staged.upload_id;
                    }
                    payload[kind + '_upload_id'] = uploadId;
                }
                if (new TextEncoder().encode(JSON.stringify(payload)).length > 480 * 1024) throw 'The selected artwork exceeds the active backend request limit. Use smaller PNGs or activate the updated backend.';
                if (me.destroyed) return;
                me.setLoading('Applying appearance…');
                const result = await request('PUT', '/apply', payload);
                if (me.destroyed) return;
                me.original = copy(me.draft); me.files = {}; me.updateActions();
                const warnings = Array.isArray(result?.warnings) ? result.warnings : [];
                const notice = 'The appearance was saved. Reload to use the new version.' +
                    (warnings.length ? '<br><br><strong>Follow-up needed:</strong><br>' + warnings.map(value => html(value)).join('<br>') : '');
                Ext.Msg.alert('Appearance applied', notice, () => { me.forceClose = true; location.assign('/'); });
            } catch (error) {
                if (!me.destroyed) Ext.Msg.alert('Changes not applied', error + '<br><br>Your preview is preserved. If another administrator changed the appearance, reopen Makeover to load the latest settings.');
            } finally {
                if (!me.destroyed) { me.busy = false; me.tabs.setDisabled(false); me.setLoading(false); me.updateActions(); }
            }
        },
    });
    function openMakeover() {
        if (!Proxmox.UserName) return;
        const existing = Ext.ComponentQuery.query('sllMakeoverWindow')[0];
        if (existing) { existing.toFront(); return; }
        Ext.create('SLL.window.Makeover').show();
    }
    function installButton(attempt) {
        const workspace = Ext.ComponentQuery.query('pveStdWorkspace')[0];
        const header = workspace?.down('[region=north]');
        if (!header) { if (attempt < 20) Ext.defer(() => installButton(attempt + 1), 250); return; }
        if (!Proxmox.UserName) { header.down('#sllMakeoverButton')?.setHidden(true); return; }
        if (!header.down('#sllMakeoverButton')) {
            const userButton = Ext.getCmp('userinfo');
            header.insert(userButton ? header.items.indexOf(userButton) : header.items.getCount(), {
                xtype: 'button', ui: 'default', cls: 'sll-makeover-launch', itemId: 'sllMakeoverButton', text: 'Proxmox Makeover', ariaLabel: 'Proxmox Makeover',
                tooltip: 'Proxmox Makeover by Southland Labs', iconCls: 'fa fa-paint-brush', margin: '0 5 0 0', handler: openMakeover,
            });
        }
        header.down('#sllMakeoverButton')?.setHidden(false);
        if (new URLSearchParams(location.search).get('sll-customs') === '1') Ext.defer(openMakeover, 100);
    }
    const nativeWorkspace = Ext.ClassManager.get('PVE.Workspace');
    if (nativeWorkspace) Ext.override(nativeWorkspace, {
        updateLoginData: function () {
            this.callParent(arguments);
            Ext.defer(() => installButton(0), 50);
        },
        showLogin: function () {
            this.callParent(arguments);
            this.down('#sllMakeoverButton')?.setHidden(true);
            for (const window of Ext.ComponentQuery.query('sllMakeoverWindow')) {
                window.forceClose = true; window.close();
            }
        },
    });
    window.SLLMakeoverOpen = openMakeover;
    Ext.onReady(() => installButton(0));
})();
