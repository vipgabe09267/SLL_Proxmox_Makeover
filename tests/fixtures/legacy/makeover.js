/* Proxmox Makeover by Southland Labs: authenticated settings UI. */
(function () {
    if (!window.Ext || !window.Proxmox || !window.PVE) return;

    const apiBase = '/api2/json/sll-customs';
    const html = value => Ext.String.htmlEncode(String(value ?? ''));

    function responseError(response) {
        try {
            const decoded = Ext.decode(response.responseText);
            if (decoded?.errors) {
                return Object.entries(decoded.errors)
                    .map(([key, value]) => html(key) + ': ' + html(value))
                    .join('<br>');
            }
            if (decoded?.message) return html(decoded.message);
        } catch (_error) {
            // Fall through to the status text without exposing response bodies.
        }
        return html(response.statusText || 'Request failed');
    }

    function request(method, path, payload) {
        return new Promise((resolve, reject) => {
            const options = {
                url: apiBase + path,
                method,
                timeout: 120000,
                success: response => {
                    try {
                        resolve(Ext.decode(response.responseText).data);
                    } catch (_error) {
                        reject('The server returned an invalid response.');
                    }
                },
                failure: response => reject(responseError(response)),
            };
            if (method !== 'GET') {
                options.headers = { CSRFPreventionToken: Proxmox.CSRFPreventionToken };
                options.jsonData = payload;
            }
            Ext.Ajax.request(options);
        });
    }

    function nativeGet(path) {
        return new Promise((resolve, reject) => {
            Proxmox.Utils.API2Request({
                url: path,
                method: 'GET',
                success: response => resolve(response.result.data),
                failure: response => reject(responseError(response)),
            });
        });
    }

    function fileAsBase64(file) {
        if (!file) return Promise.resolve(undefined);
        if (file.type && file.type !== 'image/png') {
            return Promise.reject('Only PNG image files are accepted.');
        }
        if (file.size > 3 * 1024 * 1024) {
            return Promise.reject('Each image must be 3 MiB or smaller.');
        }
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onerror = () => reject('The selected image could not be read.');
            reader.onload = () => {
                const result = String(reader.result || '');
                const comma = result.indexOf(',');
                if (comma < 0) return reject('The selected image could not be encoded.');
                resolve(result.slice(comma + 1));
            };
            reader.readAsDataURL(file);
        });
    }

    Ext.define('SLL.window.Makeover', {
        extend: 'Ext.window.Window',
        alias: 'widget.sllMakeoverWindow',
        title: 'Proxmox Makeover by Southland Labs',
        iconCls: 'fa fa-paint-brush',
        modal: true,
        width: Math.min(880, Ext.Element.getViewportWidth() - 30),
        height: Math.min(780, Ext.Element.getViewportHeight() - 30),
        minWidth: 560,
        minHeight: 500,
        layout: 'fit',
        closeAction: 'destroy',
        cls: 'sll-makeover-window',

        initComponent: function () {
            const me = this;
            me.returnUrl = location.pathname + location.search + location.hash;
            me.formPanel = Ext.create('Ext.form.Panel', {
                bodyPadding: 18,
                border: false,
                scrollable: 'y',
                fieldDefaults: {
                    anchor: '100%',
                    labelWidth: 175,
                    msgTarget: 'side',
                },
                items: [
                    {
                        xtype: 'component',
                        cls: 'sll-makeover-intro',
                        html: '<h2>Presentation controls</h2>' +
                            '<p>This foundation manages the local Proxmox wordmark, favicon, dashboard theme, ' +
                            'storage panel and custom login presentation. Native authentication, permissions, ' +
                            'realms and two-factor settings remain controlled by Proxmox.</p>',
                    },
                    {
                        xtype: 'fieldset',
                        title: 'Identity',
                        defaults: { xtype: 'textfield', anchor: '100%', allowBlank: false },
                        items: [
                            { name: 'company_name', fieldLabel: 'Company name', maxLength: 80 },
                            { name: 'project_name', fieldLabel: 'Customizer name', maxLength: 80 },
                            { name: 'product_label', fieldLabel: 'Product label', maxLength: 80 },
                            { name: 'page_title', fieldLabel: 'Browser title', maxLength: 160 },
                            {
                                name: 'website_url', fieldLabel: 'Company website', maxLength: 512,
                                regex: /^https:\/\/[^\s]+$/i,
                                regexText: 'Use a complete HTTPS URL.',
                            },
                        ],
                    },
                    {
                        xtype: 'fieldset',
                        title: 'Login page',
                        defaults: { xtype: 'textfield', anchor: '100%', allowBlank: false },
                        items: [
                            { name: 'login_eyebrow', fieldLabel: 'Eyebrow', maxLength: 100 },
                            { name: 'login_heading', fieldLabel: 'Heading', maxLength: 100 },
                            { name: 'login_subtitle', fieldLabel: 'Description', maxLength: 240 },
                            { name: 'footer_text', fieldLabel: 'Footer', maxLength: 120 },
                        ],
                    },
                    {
                        xtype: 'fieldset',
                        title: 'Theme colors',
                        layout: 'column',
                        defaults: {
                            xtype: 'textfield',
                            columnWidth: 0.5,
                            margin: '0 12 8 0',
                            allowBlank: false,
                            regex: /^#[0-9a-f]{6}$/i,
                            regexText: 'Use a six-digit hex color such as #141716.',
                            maxLength: 7,
                        },
                        items: [
                            { name: 'color_background', fieldLabel: 'Background' },
                            { name: 'color_surface', fieldLabel: 'Surface' },
                            { name: 'color_raised', fieldLabel: 'Raised surface' },
                            { name: 'color_border', fieldLabel: 'Borders' },
                            { name: 'color_accent', fieldLabel: 'Accent' },
                            { name: 'color_secondary', fieldLabel: 'Secondary' },
                            { name: 'color_text', fieldLabel: 'Text' },
                            { name: 'color_muted', fieldLabel: 'Muted text' },
                        ],
                    },
                    {
                        xtype: 'fieldset',
                        title: 'Dashboard',
                        items: [{
                            xtype: 'checkbox',
                            name: 'show_storage_panel',
                            inputValue: '1',
                            uncheckedValue: '0',
                            boxLabel: 'Show the Southland physical-disk and storage panel on node Summary',
                        }],
                    },
                    {
                        xtype: 'fieldset',
                        title: 'Security keys (native Proxmox)',
                        items: [
                            {
                                xtype: 'component',
                                itemId: 'webauthnStatus',
                                cls: 'sll-makeover-security-key',
                                html: '<p>Checking the native WebAuthn relying-party configuration…</p>',
                            },
                            {
                                xtype: 'button',
                                text: 'Open native TFA / security-key settings',
                                iconCls: 'fa fa-key',
                                handler: () => me.openNativeTFA(),
                            },
                            {
                                xtype: 'component',
                                cls: 'sll-makeover-safety',
                                html: '<span class="fa fa-lock"></span> Enrollment and credential material stay ' +
                                    'inside Proxmox’s native TFA workflow. Proxmox Makeover only displays the ' +
                                    'non-secret relying-party status and links to that native screen.',
                            },
                        ],
                    },
                    {
                        xtype: 'fieldset',
                        title: 'Local artwork',
                        defaults: { anchor: '100%' },
                        items: [
                            {
                                xtype: 'displayfield',
                                itemId: 'assetStatus',
                                fieldLabel: 'Current files',
                                value: 'Loading…',
                            },
                            {
                                xtype: 'filefield',
                                itemId: 'logoFile',
                                fieldLabel: 'Dashboard/login logo',
                                buttonText: 'Choose PNG',
                                accept: 'image/png',
                            },
                            {
                                xtype: 'filefield',
                                itemId: 'faviconFile',
                                fieldLabel: 'Favicon/icon',
                                buttonText: 'Choose PNG',
                                accept: 'image/png',
                            },
                            {
                                xtype: 'component',
                                cls: 'sll-makeover-safety',
                                html: '<span class="fa fa-shield"></span> PNG files are validated for size, ' +
                                    'dimensions, structure and CRC. Arbitrary CSS, JavaScript, SVG and filesystem ' +
                                    'paths are deliberately not accepted.',
                            },
                        ],
                    },
                ],
            });

            Ext.apply(me, {
                items: [me.formPanel],
                buttons: [
                    {
                        text: 'Apply changes',
                        itemId: 'applyButton',
                        iconCls: 'fa fa-check',
                        handler: () => me.applyChanges(),
                    },
                    { text: 'Close', handler: () => me.close() },
                ],
                listeners: {
                    show: () => {
                        history.pushState({ sllCustoms: true }, '', '/SLL-Customs');
                        me.loadState();
                    },
                    destroy: () => {
                        if (location.pathname === '/SLL-Customs' || location.pathname === '/SLL-Customs/') {
                            history.replaceState({}, '', me.returnUrl.startsWith('/SLL-Customs') ? '/' : me.returnUrl);
                        }
                    },
                },
            });
            me.callParent(arguments);
        },

        setBusy: function (busy) {
            this.setLoading(busy ? 'Applying validated settings…' : false);
            this.down('#applyButton')?.setDisabled(busy);
        },

        loadState: function () {
            const me = this;
            me.setLoading('Loading configuration…');
            me.loadWebAuthnStatus();
            request('GET', '/config').then(state => {
                me.currentState = state;
                const config = state.config;
                me.formPanel.getForm().setValues({
                    company_name: config.company_name,
                    project_name: config.project_name,
                    product_label: config.product_label,
                    page_title: config.page_title,
                    website_url: config.website_url,
                    login_eyebrow: config.login_eyebrow,
                    login_heading: config.login_heading,
                    login_subtitle: config.login_subtitle,
                    footer_text: config.footer_text,
                    show_storage_panel: config.show_storage_panel ? '1' : '0',
                    color_background: config.colors.background,
                    color_surface: config.colors.surface,
                    color_raised: config.colors.raised,
                    color_border: config.colors.border,
                    color_accent: config.colors.accent,
                    color_secondary: config.colors.secondary,
                    color_text: config.colors.text,
                    color_muted: config.colors.muted,
                });
                const logo = state.assets.logo;
                const icon = state.assets.favicon;
                me.down('#assetStatus').setValue(
                    'Logo ' + html(logo.width + '×' + logo.height) + ' · ' + html(logo.bytes) + ' bytes<br>' +
                    'Icon ' + html(icon.width + '×' + icon.height) + ' · ' + html(icon.bytes) + ' bytes'
                );
            }).catch(error => {
                Ext.Msg.alert('Unable to load Proxmox Makeover', error);
                me.close();
            }).finally(() => me.setLoading(false));
        },

        loadWebAuthnStatus: function () {
            const target = this.down('#webauthnStatus');
            nativeGet('/cluster/options').then(options => {
                const webauthn = options.webauthn;
                if (!webauthn?.id || !webauthn?.origin) {
                    target.update('<p><strong>Not configured.</strong> Configure WebAuthn in Proxmox before enrolling a key.</p>');
                    return;
                }
                target.update('<p><strong>WebAuthn is configured.</strong></p>' +
                    '<dl><dt>Relying-party ID</dt><dd>' + html(webauthn.id) + '</dd>' +
                    '<dt>Origin</dt><dd>' + html(webauthn.origin) + '</dd>' +
                    '<dt>Name</dt><dd>' + html(webauthn.rp || 'Proxmox VE') + '</dd></dl>');
            }).catch(error => {
                target.update('<p>Native WebAuthn status could not be read for this account: ' + html(error) + '</p>');
            });
        },

        openNativeTFA: function () {
            const workspace = Ext.ComponentQuery.query('pveStdWorkspace')[0];
            if (!workspace) return;
            Ext.state.Manager.getProvider().set('dctab', { value: 'tfa' }, true);
            workspace.selectById('root');
            this.close();
        },

        configFromForm: function () {
            const value = this.formPanel.getForm().getValues();
            return {
                schema_version: 1,
                company_name: value.company_name,
                project_name: value.project_name,
                product_label: value.product_label,
                page_title: value.page_title,
                login_eyebrow: value.login_eyebrow,
                login_heading: value.login_heading,
                login_subtitle: value.login_subtitle,
                footer_text: value.footer_text,
                website_url: value.website_url,
                show_storage_panel: value.show_storage_panel === '1',
                colors: {
                    background: value.color_background,
                    surface: value.color_surface,
                    raised: value.color_raised,
                    border: value.color_border,
                    accent: value.color_accent,
                    secondary: value.color_secondary,
                    text: value.color_text,
                    muted: value.color_muted,
                },
            };
        },

        selectedFile: function (itemId) {
            const field = this.down('#' + itemId);
            return field?.fileInputEl?.dom?.files?.[0];
        },

        applyChanges: function () {
            const me = this;
            const form = me.formPanel.getForm();
            if (!form.isValid()) return;
            me.setBusy(true);
            Promise.all([
                fileAsBase64(me.selectedFile('logoFile')),
                fileAsBase64(me.selectedFile('faviconFile')),
            ]).then(([logo, favicon]) => {
                const payload = { config_json: JSON.stringify(me.configFromForm()) };
                if (logo) payload.logo_base64 = logo;
                if (favicon) payload.favicon_base64 = favicon;
                return request('PUT', '/apply', payload);
            }).then(() => {
                Ext.Msg.alert(
                    'Proxmox Makeover',
                    'The local presentation was validated and applied. The page will reload to use the new version.',
                    () => location.assign('/'),
                );
            }).catch(error => {
                Ext.Msg.alert('Changes not applied', error);
                me.setBusy(false);
            });
        },
    });

    function openMakeover() {
        if (!Proxmox.UserName) return;
        const existing = Ext.ComponentQuery.query('sllMakeoverWindow')[0];
        if (existing) {
            existing.show();
            existing.toFront();
            return;
        }
        Ext.create('SLL.window.Makeover').show();
    }

    function installButton(attempt) {
        if (!Proxmox.UserName) return;
        const workspace = Ext.ComponentQuery.query('pveStdWorkspace')[0];
        const header = workspace?.down('[region=north]');
        if (!header) {
            if (attempt < 20) Ext.defer(() => installButton(attempt + 1), 250);
            return;
        }
        if (!header.down('#sllMakeoverButton')) {
            const userButton = Ext.getCmp('userinfo');
            const index = userButton ? header.items.indexOf(userButton) : header.items.getCount();
            header.insert(index, {
                xtype: 'button',
                itemId: 'sllMakeoverButton',
                text: 'Proxmox Makeover',
                tooltip: 'Proxmox Makeover by Southland Labs',
                iconCls: 'fa fa-paint-brush',
                margin: '0 5 0 0',
                handler: openMakeover,
            });
        }
        if (new URLSearchParams(location.search).get('sll-customs') === '1') {
            Ext.defer(openMakeover, 100);
        }
    }

    Ext.onReady(() => installButton(0));
})();
