/* Southland Labs presentation layer. Native Proxmox authentication is unchanged. */
(function () {
    // Ext JS callParent uses Function.caller; these overrides must remain non-strict.
    if (new URLSearchParams(location.search).get('sls-branding') === 'off') {
        document.getElementById('sls-base-theme')?.remove();
        document.getElementById('sls-branding-css')?.remove();
        return;
    }
    document.documentElement.classList.add('sls-brand');
    if (!window.Ext || !window.PVE) return;
    const config = window.SLLMakeoverConfig || {};
    const companyName = config.company_name || 'Southland Labs';
    const projectName = config.project_name || 'Proxmox Makeover';
    const productLabel = config.product_label || 'Proxmox VE';
    const websiteUrl = config.website_url || 'https://southlandlabs.dev/';
    const encode = value => Ext.String.htmlEncode(String(value ?? ''));
    const encodeAttribute = value => encode(value).replace(/`/g, '&#96;');
    document.title = config.page_title || ((window.Proxmox?.NodeName || 'Infrastructure') +
        ' - ' + companyName + ' | ' + productLabel);
    for (const [name, value] of Object.entries(config.colors || {})) {
        const variables = {
            background: '--sls-bg', surface: '--sls-surface', raised: '--sls-raised',
            border: '--sls-border', accent: '--sls-accent', secondary: '--sls-violet',
            text: '--sls-text', muted: '--sls-muted',
        };
        if (variables[name] && /^#[0-9a-f]{6}$/i.test(value)) {
            document.documentElement.style.setProperty(variables[name], value);
        }
    }
    const themeColor = document.querySelector('meta[name="theme-color"]');
    if (themeColor && /^#[0-9a-f]{6}$/i.test(config.colors?.background || '')) {
        themeColor.content = config.colors.background;
    }
    const asset = '/pve2/images/';
    const assetVersion = new URL(document.currentScript.src).searchParams.get('v') || 'current';
    const logoUrl = asset + 'SLS_Proxmox.png?v=' + encodeURIComponent(assetVersion);
    const faviconUrl = asset + 'SLS_Proxmox_Favicon.png?v=' + encodeURIComponent(assetVersion);
    for (const icon of document.querySelectorAll('link[rel~="icon"],link[rel="apple-touch-icon"]')) {
        icon.href = faviconUrl;
        icon.type = 'image/png';
        icon.setAttribute('sizes', '1254x1254');
    }

    function showScene() {
        document.body.classList.add('sls-login-active');
        if (document.getElementById('sls-login-scene')) return;
        const scene = document.createElement('div');
        scene.id = 'sls-login-scene';
        scene.setAttribute('aria-hidden', 'true');
        scene.innerHTML = '<div class="sls-scene-brand">' + encode(companyName) +
            '<span>' + encode(projectName) + '</span></div>' +
            '<div class="sls-scene-label">' + encode(productLabel) + '</div>' +
            '<div class="sls-scene-bottom">' + encode(config.footer_text || companyName) + '</div>';
        document.body.appendChild(scene);
    }

    for (const name of ['PMX.image.LogoSVG', 'PMX.image.Logo']) {
        const logo = Ext.ClassManager.get(name);
        if (!logo) continue;
        Ext.override(logo, {
            width: 204,
            height: 76,
            alt: companyName + ' - ' + productLabel,
            autoEl: { tag: 'a', href: websiteUrl, target: '_blank', rel: 'noopener noreferrer' },
            initComponent: function () {
                this.prefix = '';
                this.src = logoUrl;
                this.callParent(arguments);
                this.addCls('sls-logo');
            },
        });
    }

    const login = Ext.ClassManager.get('PVE.window.LoginWindow');
    if (login) Ext.override(login, {
        initComponent: function () {
            // Clone the shipped fields/buttons so bindings, realms, languages, OIDC and TFA stay native.
            const items = Ext.clone(this.items);
            const form = Array.isArray(items) && items.find(item => item.reference === 'loginForm');
            if (!form || !Array.isArray(form.buttons)) {
                this.callParent(arguments);
                return;
            }
            this.width = Math.min(448, Ext.Element.getViewportWidth() - 24);
            this.maxHeight = Math.max(240, Ext.Element.getViewportHeight() - 32);
            this.header = false;
            this.title = companyName + ' - Sign in';
            this.ariaLabel = this.title;
            this.draggable = false;
            this.shadow = false;
            this.bodyPadding = 28;
            form.layout = 'anchor';
            form.border = false;
            form.bodyPadding = 0;
            form.fieldDefaults = Object.assign({}, form.fieldDefaults, {
                labelAlign: 'top', labelSeparator: '', anchor: '100%', margin: '0 0 14 0',
            });
            for (const field of form.items) {
                field.labelAlign = 'top';
                field.labelSeparator = '';
                field.anchor = '100%';
            }
            for (const button of form.buttons) {
                if (button.reference === 'saveunField') {
                    button.labelWidth = 158;
                    button.labelAlign = 'left';
                    button.margin = '0 0 16 0';
                } else if (button.reference === 'loginButton') {
                    button.height = 42;
                    button.cls = 'sls-login-button';
                }
            }
            form.dockedItems = [{ xtype: 'toolbar', dock: 'bottom', padding: 0,
                layout: { type: 'vbox', align: 'stretch' }, items: form.buttons }];
            delete form.buttons;
            items.unshift({ xtype: 'component', html:
                '<div class="sls-login-intro">' +
                '<a href="' + encodeAttribute(websiteUrl) + '" target="_blank" rel="noopener noreferrer" aria-label="' +
                encodeAttribute(companyName) + ' website">' +
                '<img class="sls-login-logo" src="' + logoUrl + '" width="384" height="144" alt="' +
                encodeAttribute(productLabel + ' - ' + companyName) + '"></a>' +
                '<div class="sls-eyebrow">' + encode(config.login_eyebrow || 'Infrastructure console') + '</div>' +
                '<h1>' + encode(config.login_heading || 'Welcome back.') + '</h1>' +
                '<p>' + encode(config.login_subtitle || 'Sign in to manage your infrastructure.') + '</p></div>' });
            items.push({ xtype: 'component', html:
                '<div class="sls-login-footer"><span class="fa fa-lock" aria-hidden="true"></span> ' +
                encode(config.footer_text || companyName) + '<span class="sls-powered">Powered by ' +
                encode(productLabel) + '</span></div>' });
            this.items = items;
            this.callParent(arguments);
            this.setScrollable('y');
            this.addCls('sls-login-window');
            this.on('show', showScene);
            this.on('destroy', function () {
                document.body.classList.remove('sls-login-active');
                document.getElementById('sls-login-scene')?.remove();
            });
            this.mon(Ext.GlobalEvents, 'resize', function () {
                this.setWidth(Math.min(448, Ext.Element.getViewportWidth() - 24));
                this.setMaxHeight(Math.max(240, Ext.Element.getViewportHeight() - 32));
                this.center();
            }, this);
        },
    });

    // Read-only node storage overview. Capacities come from the native APIs;
    // the system filesystem remains separate from physical disk capacity.
    Ext.define('SLS.panel.NodeStorage', {
        extend: 'Ext.panel.Panel',
        alias: 'widget.slsNodeStorage',
        title: 'Disks and storage',
        itemId: 'slsNodeStorage',
        cls: 'sls-node-storage',
        height: 360,
        minHeight: 360,
        bodyPadding: 12,
        scrollable: 'y',
        html: '<p>Loading disks and storage…</p>',

        renderStorage: function () {
            if (this.destroyed || this.destroying) return;
            const encode = value => Ext.String.htmlEncode(String(value ?? ''));
            const size = value => encode(Proxmox.Utils.format_size(Number(value) || 0));
            let html = '';
            if (this.diskError) {
                html += '<p role="status">Physical disk inventory unavailable for this account.</p>';
            } else if (this.diskData) {
                const disks = this.diskData.filter(disk => Number(disk.size) > 0 && disk.type !== 'partition');
                const total = disks.reduce((sum, disk) => sum + Number(disk.size), 0);
                html += '<p class="sls-storage-total">' + disks.length + ' physical disks · ' +
                    (total / 1e12).toFixed(2) + ' TB installed (' + size(total) + ')</p>';
                html += '<div class="sls-storage-disks">' + disks.map(disk =>
                    '<div class="sls-storage-disk"><strong>' + encode(disk.model || disk.devpath) + '</strong>' +
                    '<span>' + encode(disk.devpath) + ' · ' + (Number(disk.size) / 1e12).toFixed(2) +
                    ' TB (' + size(disk.size) + ')</span><span>SMART: ' + encode(disk.health || 'Unknown') +
                    '</span></div>').join('') + '</div>';
            } else {
                html += '<p>Loading physical disks…</p>';
            }
            if (this.storageError) {
                html += '<p role="status">Storage usage unavailable. Refresh the Summary to retry.</p>';
            } else if (this.storageData) {
                const labels = { local: 'Host system', 'local-lvm': 'Guest disks', 'nvme-storage': 'Second disk / backups' };
                html += '<table class="sls-storage-table"><thead><tr><th scope="col">Storage</th>' +
                    '<th scope="col">Used / total</th><th scope="col">Available</th></tr></thead><tbody>';
                for (const storage of this.storageData.filter(item => item.enabled)) {
                    const active = Boolean(storage.active) && Number(storage.total) > 0;
                    const percent = active ? Math.min(100, Math.max(0, Number(storage.used) / Number(storage.total) * 100)) : 0;
                    const level = percent >= 90 ? ' critical' : percent >= 80 ? ' warning' : '';
                    html += '<tr><th scope="row">' + encode(storage.storage) +
                        (labels[storage.storage] ? '<small>' + labels[storage.storage] + '</small>' : '') + '</th>';
                    html += active ? '<td>' + size(storage.used) + ' / ' + size(storage.total) +
                        ' <span class="sls-storage-percent">(' + percent.toFixed(1) + '%)</span>' +
                        '<div class="sls-storage-bar' + level + '" role="progressbar" aria-label="' +
                        encode(storage.storage) + ' used" aria-valuemin="0" aria-valuemax="100" aria-valuenow="' +
                        percent.toFixed(1) + '"><span style="width:' + percent.toFixed(2) + '%"></span></div></td><td>' +
                        size(storage.avail) + '</td>' : '<td colspan="2">Unavailable</td>';
                    html += '</tr>';
                }
                html += '</tbody></table>';
            } else {
                html += '<p>Loading storage usage…</p>';
            }
            html += '<p class="sls-storage-note">Host system (/) is one filesystem. Physical disk capacity includes guest storage, system partitions and reserved space.</p>';
            this.update(html);
        },

        refreshStorage: function () {
            if (this.destroyed || this.destroying || !this.isVisible(true)) return;
            const panel = this;
            for (const [key, endpoint] of [['disk', 'disks/list'], ['storage', 'storage']]) {
                if (panel[key + 'Pending']) continue;
                panel[key + 'Pending'] = true;
                Proxmox.Utils.API2Request({
                    url: '/nodes/' + encodeURIComponent(panel.nodename) + '/' + endpoint,
                    method: 'GET',
                    success: function (response) {
                        if (panel.destroyed || panel.destroying) return;
                        panel[key + 'Data'] = response.result.data;
                        panel[key + 'Error'] = false;
                        panel[key + 'Pending'] = false;
                        panel.renderStorage();
                    },
                    failure: function () {
                        if (panel.destroyed || panel.destroying) return;
                        panel[key + 'Error'] = true;
                        panel[key + 'Pending'] = false;
                        panel.renderStorage();
                    },
                });
            }
        },

        initComponent: function () {
            this.callParent(arguments);
            this.on('afterrender', this.refreshStorage, this, { single: true });
            this.mon(this.statusStore, 'load', function () {
                if (!this.isVisible(true)) return;
                const now = Date.now();
                if (now - (this.lastStorageRefresh || 0) >= 30000) {
                    this.lastStorageRefresh = now;
                    this.refreshStorage();
                }
            }, this);
        },
    });

    const nodeStatus = Ext.ClassManager.get('PVE.node.StatusView');
    if (nodeStatus) Ext.override(nodeStatus, {
        initComponent: function () {
            this.items = Ext.clone(this.items);
            const root = this.items.find(item => item.itemId === 'rootfs');
            if (root) root.title = 'Host system (/)';
            this.callParent(arguments);
        },
    });
    const nodeSummary = Ext.ClassManager.get('PVE.node.Summary');
    if (nodeSummary) Ext.override(nodeSummary, {
        initComponent: function () {
            this.callParent(arguments);
            const container = this.down('#itemcontainer');
            if (config.show_storage_panel !== false && container && !container.down('#slsNodeStorage')) {
                container.insert(1, {
                    xtype: 'slsNodeStorage',
                    nodename: this.pveSelNode.data.node,
                    statusStore: this.statusStore,
                    columnWidth: 1,
                    padding: 5,
                });
            }
        },
    });

    Ext.onReady(function () {
        // Workspace construction can reset body classes after first showing its login window.
        if (Ext.ComponentQuery.query('window').some(win => win.hasCls('sls-login-window') && win.isVisible())) showScene();
        const workspace = Ext.ComponentQuery.query('pveStdWorkspace')[0];
        const header = workspace?.down('[region=north]');
        if (header) {
            header.addCls('sls-dashboard-header');
            header.setMargin('0 5 8 5');
        }
    });
})();
