/* Optional primary login passkeys. Native passwords, realms, OIDC and TFA stay native. */
(function () {
    // ExtJS callParent inspects Function.caller; keep this override non-strict.
    if (!window.Ext || !window.Proxmox || window.SLLMakeoverLoginPasskeys) return;
    const base = '/api2/extjs/sll-passkeys';
    const html = value => Ext.String.htmlEncode(String(value ?? ''));
    const currentUser = () => typeof Proxmox.UserName === 'string' && !/[!\x00-\x1f\x7f]/.test(Proxmox.UserName) ? Proxmox.UserName : '';
    const fullSession = user => currentUser() === user && !Proxmox.LoggedOut;
    function error(message, status) { const value = new Error(message); value.status = status; return value; }
    async function api(method, path, payload, token, signal) {
        const headers = { Accept: 'application/json' };
        if (token) headers.CSRFPreventionToken = token;
        const options = { method, headers, credentials: 'same-origin', mode: 'same-origin', cache: 'no-store', signal };
        if (payload !== undefined) { headers['Content-Type'] = 'application/json'; options.body = JSON.stringify(payload); }
        const response = await fetch(base + path, options);
        let result;
        try { result = await response.json(); } catch (_error) { throw error('The passkey service returned an invalid response.', response.status); }
        if (!response.ok || result.success === false) throw error(
            typeof result.message === 'string' ? result.message.slice(0, 512) : 'The passkey request could not be completed.', response.status);
        return result.data;
    }
    function bytes(value) {
        if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw error('The passkey challenge is invalid.');
        const decoded = atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4));
        return Uint8Array.from(decoded, character => character.charCodeAt(0));
    }
    function encoded(value) {
        if (value === null || value === undefined) return null;
        const data = new Uint8Array(value);
        if (data.byteLength > 128 * 1024) throw error('The authenticator response is too large.');
        let binary = '';
        for (let offset = 0; offset < data.length; offset += 8192) binary += String.fromCharCode(...data.subarray(offset, offset + 8192));
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
    function serialized(credential) {
        if (!credential || credential.type !== 'public-key' || !credential.response) throw error('The browser returned an invalid passkey.');
        const response = credential.response;
        const value = { id: credential.id, rawId: encoded(credential.rawId), type: 'public-key',
            response: { clientDataJSON: encoded(response.clientDataJSON) },
            clientExtensionResults: credential.getClientExtensionResults?.() || {} };
        if (response.attestationObject) {
            value.response.attestationObject = encoded(response.attestationObject);
            value.response.transports = response.getTransports?.() || [];
        } else {
            value.response.authenticatorData = encoded(response.authenticatorData);
            value.response.signature = encoded(response.signature);
            value.response.userHandle = encoded(response.userHandle);
        }
        return JSON.stringify(value);
    }
    function availability(status) {
        if (!status?.supported || status.primary_passkeys === false) return status?.reason || 'Login passkeys require the activated passkey backend.';
        if (!window.isSecureContext || !window.PublicKeyCredential || !navigator.credentials?.get || !navigator.credentials?.create) return 'Use a trusted HTTPS address and a browser with passkey support.';
        if (!status.rp || typeof status.rp.id !== 'string' || status.rp.origin !== window.location.origin) return 'Open the configured trusted passkey origin before using login passkeys.';
        return '';
    }
    function publicKey(source, status, creation) {
        if (!source || typeof source !== 'object') throw error('The passkey options are invalid.');
        const value = JSON.parse(JSON.stringify(source));
        value.challenge = bytes(value.challenge);
        if (creation) {
            if (value.rp?.id !== status.rp.id || value.authenticatorSelection?.residentKey !== 'required' ||
                value.authenticatorSelection?.userVerification !== 'required') throw error('The passkey registration policy is not supported.');
            value.user.id = bytes(value.user.id);
            value.authenticatorSelection.requireResidentKey = true;
            value.excludeCredentials = (value.excludeCredentials || []).map(item => ({ ...item, id: bytes(item.id) }));
        } else {
            if (value.rpId !== status.rp.id || value.userVerification !== 'required') throw error('The passkey sign-in policy is not supported.');
            if (value.allowCredentials) value.allowCredentials = value.allowCredentials.map(item => ({ ...item, id: bytes(item.id) }));
        }
        return value;
    }
    function ceremony(value, login) {
        if (!/^[0-9a-f]{32}$/.test(value?.ceremony || '') || (login && !/^[A-Za-z0-9_-]{43}$/.test(value.nonce || ''))) throw error('The passkey ceremony is invalid.');
        return value;
    }
    function clearOwnedPartial(partial) {
        if (partial && Proxmox.LoggedOut === true && (!currentUser() || currentUser() === partial.username) &&
            Ext.util.Cookies.get(Proxmox.Setup.auth_cookie_name) === partial.ticket) {
            Proxmox.LoggedOut = false;
            Proxmox.Utils.authClear();
            Proxmox.UserName = '';
            Proxmox.CSRFPreventionToken = undefined;
        }
    }
    async function continueNativeLogin(view, data) {
        if (view.destroyed) return;
        const controller = view.getController();
        if (typeof controller.success !== 'function' || typeof data?.ticket !== 'string' || typeof data.username !== 'string') throw error('This native login response is not supported.');
        if (data.ticket.startsWith('PVE:!tfa!')) {
            if (typeof controller.performTFAChallenge !== 'function') throw error('This Proxmox build cannot continue the required native second factor.');
            data.LoggedOut = true;
            Proxmox.Utils.setAuthData(data);
            const partial = view.sllLoginPasskeyPartial = { username: data.username, ticket: data.ticket };
            try {
                const result = await controller.performTFAChallenge(data);
                if (view.destroyed || currentUser() !== partial.username || !Proxmox.LoggedOut) return;
                result.CSRFPreventionToken = Proxmox.CSRFPreventionToken;
                result.username = partial.username;
                controller.success(result);
            } catch (failure) { clearOwnedPartial(partial); throw failure; }
            finally { if (view.sllLoginPasskeyPartial === partial) delete view.sllLoginPasskeyPartial; }
        } else if (Ext.isDefined(data.NeedTFA)) {
            const method = Ext.isDefined(data.U2FChallenge) ? 'perform_u2f' : 'perform_otp';
            if (typeof controller[method] !== 'function') throw error('This Proxmox build cannot continue the required native second factor.');
            data.LoggedOut = true;
            Proxmox.Utils.setAuthData(data);
            const partial = view.sllLoginPasskeyPartial = { username: data.username, ticket: data.ticket };
            try { controller[method](data); }
            catch (failure) {
                clearOwnedPartial(partial);
                if (view.sllLoginPasskeyPartial === partial) delete view.sllLoginPasskeyPartial;
                throw failure;
            }
        } else controller.success(data);
    }
    function installLoginButton(view) {
        if (view.destroyed || view.down('#sll-passkey-login')) return;
        const controller = view.getController?.();
        const nativeButton = controller?.lookupReference('loginButton');
        if (!nativeButton?.ownerCt?.add || typeof controller.success !== 'function') return;
        // Keep the native OIDC choice and controller. Only name the ordinary
        // password action so the independent passkey action is unambiguous.
        const model = view.getViewModel?.();
        if (model?.setFormulas && nativeButton.setBind) {
            model.setFormulas({ sllPasswordChoiceText: function (get) {
                return get('openid') ? get('button_text') : 'Sign in with password';
            } });
            nativeButton.setBind({ text: '{sllPasswordChoiceText}' });
        }
        let status, active = null, disposed = false;
        const note = Ext.create('Ext.Component', { itemId: 'sll-passkey-login-status', margin: '5 0 0 0', ariaRole: 'status', hidden: true });
        nativeButton.ownerCt.add({ xtype: 'component', itemId: 'sll-login-choice-or', margin: '6 0 0 0',
            html: '<div style="text-align:center">or</div>' });
        const button = nativeButton.ownerCt.add({ xtype: 'button', itemId: 'sll-passkey-login', ui: 'default',
            text: 'Sign in with passkey', ariaLabel: 'Sign in with passkey', iconCls: 'fa fa-key', disabled: true,
            formBind: false,
            cls: 'sls-login-button', height: 44, minHeight: 44, margin: '6 0 0 0', handler: async () => {
                if (active || disposed || view.destroyed || availability(status)) return;
                const abort = new AbortController(); active = abort; button.setDisabled(true); note.setHidden(true);
                view.el.mask('Waiting for your login passkey…');
                try {
                    const begun = ceremony(await api('POST', '/login-begin', {}, 'SLL-Passkey-Login', abort.signal), true);
                    if (disposed || view.destroyed) return;
                    const assertion = await navigator.credentials.get({ publicKey: publicKey(begun.publicKey, status, false), signal: abort.signal });
                    if (disposed || view.destroyed) return;
                    const data = await api('POST', '/login-finish', { ceremony: begun.ceremony, response: serialized(assertion) }, begun.nonce, abort.signal);
                    if (!disposed && !view.destroyed) await continueNativeLogin(view, data);
                } catch (failure) {
                    // Never clear auth here: a parallel native password/OIDC login may have completed.
                    if (!disposed && !view.destroyed) {
                        const canceled = failure?.name === 'NotAllowedError' || failure?.name === 'AbortError';
                        note.update(html(canceled ? 'Passkey sign-in was canceled. You can still sign in with your password.' :
                            'Passkey sign-in is unavailable. Use password sign-in; accounts using two-factor mode require a password first.'));
                        note.setHidden(false);
                    }
                } finally {
                    if (active === abort) active = null;
                    if (!disposed && !view.destroyed) { view.el.unmask(); button.setDisabled(Boolean(availability(status))); }
                }
            } });
        nativeButton.ownerCt.add(note);
        view.on('destroy', () => {
            disposed = true; active?.abort(); active = null;
            const partial = view.sllLoginPasskeyPartial;
            if (partial) for (const factor of Ext.ComponentQuery.query('window')) {
                if (factor.$className === 'Proxmox.window.TfaLoginWindow' && factor.ticket === partial.ticket && factor.userid === partial.username) factor.close();
            }
            clearOwnedPartial(partial);
            delete view.sllLoginPasskeyPartial;
        }, null, { single: true });
        const load = async () => {
            try { status = await api('GET', '/status'); }
            catch (_failure) { status = null; }
            if (disposed || view.destroyed) return;
            const reason = availability(status);
            const unavailable = 'Passkey sign-in is unavailable. Use your existing login method.';
            button.setDisabled(Boolean(reason)); button.setTooltip(reason ? unavailable : 'Sign in using a registered login passkey.');
            note.update(html(reason ? unavailable : '')); note.setHidden(!reason);
        };
        load();
    }

    function createManagerPanel(options = {}) {
        const embedded = options.embedded === true;
        const user = currentUser();
        let disposed = false, loading = false, status;
        const dialogs = new Set();
        const pendingDeletes = new Set(), rowButtons = new Set();
        const closeOwnedDialogs = () => {
            for (const dialog of dialogs) if (!dialog.destroyed) dialog.close();
            dialogs.clear();
            for (const abort of pendingDeletes) abort.abort();
            pendingDeletes.clear();
        };
        const store = Ext.create('Ext.data.Store', { fields: ['id', 'description', 'created', 'last_used'], data: [], autoDestroy: true });
        const note = Ext.create('Ext.Component', { itemId: 'login-passkeys-status', margin: '0 0 10 0', ariaRole: 'status', html: 'Loading login passkey availability…' });
        let addButton, removeButton, refreshButton, grid;
        const ownReason = () => !user || !fullSession(user) ? 'Sign in to Proxmox again before managing login passkeys.' :
            !/@(?:pam|pve)$/.test(user) ? 'Login passkeys currently support local PAM and PVE accounts only.' : '';
        const reason = () => ownReason() || availability(status);
        const removalBlocked = () => Boolean(ownReason() || !status?.primary_passkeys);
        const notice = text => { if (!disposed) note.update(html(text)); };
        const actions = () => {
            if (disposed) return;
            const blocked = Boolean(reason());
            addButton.setDisabled(blocked || loading);
            removeButton.setDisabled(removalBlocked() || loading || grid.getSelectionModel().getCount() !== 1);
            for (const button of rowButtons) if (!button.destroyed) button.setDisabled(removalBlocked() || loading);
            refreshButton.setDisabled(loading || !fullSession(user));
        };
        async function reload() {
            if (disposed || loading) return;
            loading = true; actions();
            try {
                status = await api('GET', '/status');
                if (disposed) return;
                if (ownReason() || !status?.primary_passkeys) { store.removeAll(); notice(reason()); return; }
                const result = await api('GET', '/credentials', undefined, Proxmox.CSRFPreventionToken);
                if (disposed || !fullSession(user)) return;
                const credentials = Array.isArray(result) ? result : result?.credentials;
                if (!Array.isArray(credentials)) throw error('The login passkey list is invalid.');
                store.loadData(credentials.filter(item => item && /^[0-9a-f]{64}$/.test(item.id || '')).map(item => ({
                    id: item.id, description: String(item.description || 'Login passkey'), created: Number(item.created) || 0, last_used: Number(item.last_used) || 0,
                })));
                if (embedded) grid.setHeight(64 + Math.max(1, Math.min(4, store.getCount())) * 40);
                notice(embedded ? credentials.length + ' registered.' + (reason() ? ' ' + reason() : '') :
                    'Login passkeys for ' + user + '. Choose your passkey or your existing password at sign-in. Adding a login passkey does not enable extra verification.');
                panel.fireEvent('keysloaded', panel);
            } catch (failure) { if (!disposed) { store.removeAll(); notice(failure.message || 'Login passkeys could not be loaded.'); } }
            finally { if (!disposed) { loading = false; actions(); } }
        }
        function add() {
            if (disposed || reason()) return;
            let abort, submitting = false;
            const form = Ext.create('Ext.form.Panel', { bodyPadding: 12, border: false, defaults: { anchor: '100%', labelAlign: 'top' },
                items: [
                    { xtype: 'displayfield', value: html('Account: ' + user) },
                    { xtype: 'textfield', name: 'description', fieldLabel: 'Passkey name', allowBlank: false, maxLength: 64, enforceMaxLength: true },
                    { xtype: 'textfield', name: 'password', fieldLabel: 'Current Proxmox password (setup only)', inputType: 'password', allowBlank: false,
                        maxLength: 1024, enforceMaxLength: true, inputAttrTpl: 'autocomplete=current-password' },
                    { xtype: 'component', margin: '6 0 0 0', html: 'Verify your password once to add this passkey. In login-alternative mode, choose it instead of typing your password. Your device PIN or biometrics confirms it is you. Two-factor mode keeps login passkeys registered but inactive.<br><br>Changing or resetting your password requires adding your login passkeys again. Proxmox password protection upgrades have the same effect.' },
                ] });
            const dialog = Ext.create('Ext.window.Window', { title: 'Add login passkey', modal: true, constrain: true, resizable: false,
                width: Math.min(450, Ext.Element.getViewportWidth() - 20), layout: 'fit', items: [form],
                buttons: [ { text: 'Cancel', handler: () => dialog.close() }, { text: 'Create login passkey', ariaLabel: 'Create login passkey', handler: async () => {
                    if (submitting || disposed || reason() || !form.getForm().isValid()) return;
                    submitting = true; abort = new AbortController(); dialog.setLoading('Verifying your password…');
                    const passwordField = form.getForm().findField('password');
                    try {
                        const pending = api('POST', '/register-begin', { password: passwordField.getValue(), description: form.getForm().findField('description').getValue() }, Proxmox.CSRFPreventionToken, abort.signal);
                        passwordField.setValue('');
                        const begun = ceremony(await pending, false);
                        if (disposed || dialog.destroyed || !fullSession(user)) return;
                        dialog.setLoading('Create your login passkey using your device…');
                        const credential = await navigator.credentials.create({ publicKey: publicKey(begun.publicKey, status, true), signal: abort.signal });
                        if (disposed || dialog.destroyed || !fullSession(user)) return;
                        await api('POST', '/register-finish', { ceremony: begun.ceremony, response: serialized(credential) }, Proxmox.CSRFPreventionToken, abort.signal);
                        if (!disposed && !dialog.destroyed && fullSession(user)) { dialog.close(); reload(); }
                    } catch (failure) {
                        if (!disposed && !dialog.destroyed) Ext.Msg.alert('Login passkey not added', html(
                            failure?.name === 'NotAllowedError' || failure?.name === 'AbortError' ? 'Passkey creation was canceled.' : failure.message || 'The login passkey could not be added.'));
                    } finally {
                        if (!dialog.destroyed) { submitting = false; dialog.setLoading(false); passwordField.setValue(''); }
                    }
                } } ], listeners: { destroy: () => { abort?.abort(); dialogs.delete(dialog); } } });
            dialogs.add(dialog); dialog.show();
        }
        function remove(record) {
            const selected = record?.isModel ? record : grid.getSelectionModel().getSelection()[0];
            if (disposed || loading || removalBlocked() || !selected || store.indexOf(selected) < 0) return;
            const id = selected.get('id'), cookie = Ext.util.Cookies.get(Proxmox.Setup.auth_cookie_name), token = Proxmox.CSRFPreventionToken;
            const current = () => !disposed && !ownReason() && typeof cookie === 'string' && cookie.length > 0 &&
                typeof token === 'string' && token.length > 0 && Ext.util.Cookies.get(Proxmox.Setup.auth_cookie_name) === cookie &&
                Proxmox.CSRFPreventionToken === token;
            const confirmation = Ext.create('Ext.window.MessageBox', { itemId: 'sll-remove-login-passkey', closeAction: 'destroy' });
            dialogs.add(confirmation);
            confirmation.on('destroy', () => dialogs.delete(confirmation), null, { single: true });
            confirmation.show({ title: 'Remove login passkey?',
                message: 'Remove <strong>' + html(selected.get('description')) + '</strong>? This passkey will no longer start a sign-in. Your existing password remains available.',
                buttons: Ext.Msg.YESNO, buttonText: { yes: 'Remove', no: 'Cancel' }, defaultFocus: 'no', icon: Ext.Msg.QUESTION,
                fn: async answer => {
                    confirmation.destroy();
                    if (answer !== 'yes' || !current() || store.indexOf(selected) < 0 || selected.get('id') !== id) return;
                    const abort = new AbortController(); pendingDeletes.add(abort); loading = true; actions();
                    let refresh = false;
                    try {
                        await api('DELETE', '/credentials/' + id, undefined, token, abort.signal);
                        if (current() && !abort.signal.aborted) refresh = true;
                    } catch (failure) { if (current() && !abort.signal.aborted) notice(failure.message || 'The login passkey could not be removed.'); }
                    finally { pendingDeletes.delete(abort); if (!disposed) { loading = false; if (refresh) reload(); else actions(); } }
                },
            });
        }
        addButton = Ext.create('Ext.button.Button', { text: 'Add login passkey', ariaLabel: 'Add login passkey', iconCls: 'fa fa-key', handler: add });
        removeButton = Ext.create('Ext.button.Button', { text: 'Remove selected', ariaLabel: 'Remove selected login passkey', iconCls: 'fa fa-trash', handler: () => remove() });
        refreshButton = Ext.create('Ext.button.Button', { text: 'Refresh', ariaLabel: 'Refresh login passkeys', iconCls: 'fa fa-refresh', handler: reload });
        grid = Ext.create('Ext.grid.Panel', { itemId: 'login-passkeys-grid', store, border: true, minHeight: embedded ? 104 : 180,
            height: embedded ? 104 : undefined, flex: embedded ? undefined : 1,
            emptyText: 'No login passkeys registered.', viewConfig: { deferEmptyText: false },
            tbar: { enableOverflow: true, items: [addButton, removeButton, refreshButton] },
            columns: [
                { text: 'Name', dataIndex: 'description', flex: 1, minWidth: 110, renderer: html },
                { xtype: 'widgetcolumn', text: 'Actions', width: 100,
                    widget: { xtype: 'button', text: 'Remove', ariaLabel: 'Remove login passkey', height: 36,
                        handler: button => remove(button.getWidgetRecord()), listeners: { destroy: button => rowButtons.delete(button) } },
                    onWidgetAttach: (_column, button) => { rowButtons.add(button); button.setDisabled(removalBlocked() || loading); },
                },
                { itemId: 'primary-key-added', text: 'Added', dataIndex: 'created', width: 155, renderer: value => value ? html(new Date(value * 1000).toLocaleString()) : 'Unknown' },
                { itemId: 'primary-key-last-used', text: 'Last used', dataIndex: 'last_used', width: 155, renderer: value => value ? html(new Date(value * 1000).toLocaleString()) : 'Never' },
            ], listeners: { selectionchange: actions, resize: (owner, width) => {
                const compact = width < 520;
                owner.down('#primary-key-added').setHidden(compact); owner.down('#primary-key-last-used').setHidden(compact);
            } } });
        const panel = Ext.create('Ext.panel.Panel', { title: 'Login passkeys', header: embedded, itemId: 'login-passkeys', bodyPadding: embedded ? 8 : 12,
            layout: embedded ? 'anchor' : { type: 'vbox', align: 'stretch' }, defaults: embedded ? { anchor: '100%' } : undefined,
            scrollable: !embedded, items: [
                { xtype: 'component', margin: '0 0 10 0', html: embedded ?
                    'Use these instead of your password. Add them separately from two-factor keys.' :
                    '<h2 style="margin-top:0">Sign in with a passkey or your password</h2>' +
                    '<p>A login passkey replaces your password for that sign-in. Your existing username and password remain available. ' +
                    'The account passkey mode controls whether these login alternatives are active. Other native account or realm verification remains enforced.</p>' },
                note, { xtype: 'component', margin: '0 0 8 0', html: embedded ? 'Remove deletes only that key.' :
                    'Use Remove beside a passkey, or select a row and choose Remove selected. Removal affects that passkey only.' }, grid],
            listeners: { activate: reload, afterrender: reload, hide: closeOwnedDialogs, deactivate: closeOwnedDialogs, destroy: () => {
                disposed = true; closeOwnedDialogs(); rowButtons.clear(); store.destroy();
            } } });
        panel.sllReloadKeys = reload;
        panel.sllCloseKeyDialogs = closeOwnedDialogs;
        panel.sllInvalidateKeys = () => { closeOwnedDialogs(); store.removeAll(); notice('Your Proxmox session changed. Reopen passkey management.'); actions(); };
        actions(); return panel;
    }
    function openManager() {
        const user = currentUser();
        if (!fullSession(user) || !/@(?:pam|pve)$/.test(user)) return;
        const existing = Ext.ComponentQuery.query('window[sllLoginPasskeysWindow=true]')[0];
        if (existing && existing.sllOwnerUser === user) { existing.toFront(); return; }
        if (existing) existing.close();
        Ext.create('Ext.window.Window', { title: 'Passkeys', itemId: 'sll-login-passkeys-window',
            sllLoginPasskeysWindow: true, sllOwnerUser: user, modal: true, constrain: true, layout: 'fit',
            width: Math.min(700, Ext.Element.getViewportWidth() - 20),
            height: Math.min(720, Ext.Element.getViewportHeight() - 20), minWidth: 280, minHeight: 240,
            items: [createSecurityPanel()], buttons: [{ text: 'Close', handler: button => button.up('window').close() }],
            listeners: { afterrender: owner => {
                const resize = () => {
                    if (owner.destroyed) return;
                    const viewWidth = Ext.Element.getViewportWidth(), viewHeight = Ext.Element.getViewportHeight();
                    const width = Math.min(700, viewWidth - 20), height = Math.min(720, viewHeight - 20);
                    if (owner.passkeyResizeAfterLayout) owner.un('afterlayout', owner.passkeyResizeAfterLayout);
                    if (owner.passkeyResizePosition) owner.mun(Ext.GlobalEvents, 'idle', owner.passkeyResizePosition);
                    const position = owner.passkeyResizePosition = () => {
                        if (owner.passkeyResizePosition !== position) return;
                        owner.passkeyResizePosition = null;
                        if (!owner.destroyed) { owner.clearAlignEl(); owner.setPosition(Math.floor((viewWidth - width) / 2), Math.floor((viewHeight - height) / 2)); }
                    };
                    const afterLayout = owner.passkeyResizeAfterLayout = () => {
                        if (owner.passkeyResizePosition === position) owner.mon(Ext.GlobalEvents, 'idle', position, null, { single: true });
                    };
                    owner.on('afterlayout', afterLayout, null, { single: true });
                    owner.setSize(width, height); owner.updateLayout();
                };
                Ext.on('resize', resize); owner.on('destroy', () => Ext.un('resize', resize), null, { single: true });
            } },
        }).show();
    }
    function createSecurityPanel() {
        const user = currentUser(), primary = createManagerPanel({ embedded: true });
        let secondary;
        try { secondary = window.SLLMakeoverNativeSecurity?.createPanel({ embedded: true }); }
        catch (_failure) { /* Primary management remains available. */ }
        let disposed = false, accepting = true, loading = false, queued = false, supported = false, syncing = false;
        let state = null, readAbort, activeDialog = null;
        const session = () => ({ cookie: Ext.util.Cookies.get(Proxmox.Setup.auth_cookie_name), token: Proxmox.CSRFPreventionToken });
        const current = snapshot => !disposed && accepting && fullSession(user) &&
            typeof snapshot.cookie === 'string' && snapshot.cookie.length > 0 && typeof snapshot.token === 'string' && snapshot.token.length > 0 &&
            Ext.util.Cookies.get(Proxmox.Setup.auth_cookie_name) === snapshot.cookie && Proxmox.CSRFPreventionToken === snapshot.token;
        const caption = Ext.create('Ext.Component', { itemId: 'passkey-mode-status', margin: '0 0 8 0', ariaRole: 'status', html: 'Loading your passkey mode…' });
        const requestNote = Ext.create('Ext.Component', { itemId: 'passkey-mode-request-status', ariaRole: 'status', hidden: true, margin: '0 0 8 0' });
        const tell = message => { if (!disposed) { requestNote.update(html(message)); requestNote.setHidden(!message); } };
        const toggle = Ext.create('Ext.form.field.Checkbox', {
            itemId: 'security-mode-toggle', boxLabel: 'Use passkeys for 2FA', ariaLabel: 'Use passkeys for 2FA', ariaRole: 'switch',
            disabled: true, checked: false, anchor: '100%',
            listeners: {
                afterrender: field => { field.inputEl.dom.setAttribute('role', 'switch'); field.inputEl.dom.setAttribute('aria-checked', String(field.getValue())); },
                change: (_field, checked) => { if (!syncing) { sync(); if (state) changeMode(checked ? 'two_factor' : 'alternative'); } },
            },
        });
        const refresh = Ext.create('Ext.button.Button', { text: 'Refresh mode', ariaLabel: 'Refresh passkey mode', iconCls: 'fa fa-refresh',
            handler: () => { primary.sllReloadKeys?.(); secondary?.sllReloadKeys?.(); reloadMode(); } });
        function sync() {
            if (disposed || toggle.destroyed || toggle.destroying || refresh.destroyed || refresh.destroying) return;
            syncing = true; toggle.suspendEvents(); toggle.setValue(state?.mode === 'two_factor'); toggle.resumeEvents(); syncing = false;
            toggle.inputEl?.dom.setAttribute('aria-checked', String(state?.mode === 'two_factor'));
            toggle.setDisabled(!accepting || !fullSession(user) || loading || Boolean(activeDialog) || !supported || !state?.can_change);
            refresh.setDisabled(!accepting || !fullSession(user) || loading || Boolean(activeDialog));
        }
        function validated(value) {
            if (!value || !['alternative', 'two_factor'].includes(value.mode) || !/^[0-9a-f]{64}$/.test(value.revision || '') ||
                typeof value.can_change !== 'boolean' || !Array.isArray(value.native_keys)) throw error('The passkey mode response is invalid.');
            return { ...value, reason: typeof value.reason === 'string' ? value.reason.slice(0, 512) : '',
                native_keys: value.native_keys.filter(key => key && typeof key.id === 'string' && key.id.length > 0 && key.id.length <= 256 &&
                    !/[\x00-\x1f\x7f]/.test(key.id) && ['webauthn', 'u2f'].includes(key.type)).map(key => ({
                    id: key.id, description: String(key.description || 'Two-factor key').slice(0, 512), type: key.type, enable: key.enable === true,
                })) };
        }
        function showState(value) {
            state = validated(value);
            let message = state.mode === 'two_factor' ?
                user + ': two-factor mode. Password first, then extra verification. Login passkeys stay saved but cannot sign you in by themselves.' :
                user + ': login alternative. Use a login passkey OR your password.';
            if (!state.can_change && state.reason) message += ' ' + state.reason;
            if (state.mode === 'alternative' && !state.primary_ready) message += ' Add a login passkey below to set up passwordless sign-in.';
            if (state.other_factors_enabled) message += ' Other verification requirements still apply.';
            caption.update(html(message)); sync();
        }
        async function reloadMode() {
            if (disposed || !accepting || !fullSession(user)) return;
            if (loading) { queued = true; return; }
            loading = true; sync(); const snapshot = session(); readAbort = new AbortController();
            try {
                const capability = await api('GET', '/status', undefined, undefined, readAbort.signal);
                if (!current(snapshot)) return;
                supported = capability?.per_user_mode === true;
                if (!supported) {
                    state = null; caption.update('Per-user passkey mode requires the current Makeover backend. Your existing key-management controls remain available.'); return;
                }
                const value = await api('GET', '/mode', undefined, snapshot.token, readAbort.signal);
                if (current(snapshot)) showState(value);
            } catch (failure) {
                if (current(snapshot) && failure?.name !== 'AbortError') { state = null; caption.update('Your passkey mode could not be loaded. Refresh before changing it.'); }
            } finally {
                loading = false; readAbort = null;
                if (!disposed) { sync(); if (queued) { queued = false; reloadMode(); } }
            }
        }
        function changeMode(mode) {
            if (!state || !supported || !state.can_change || loading || activeDialog || !accepting || !fullSession(user) || mode === state.mode) return;
            tell('');
            if (mode === 'two_factor' && !state.native_keys.length) {
                const guidanceSession = session();
                const guidance = Ext.create('Ext.window.Window', { title: 'Add a two-factor key first', modal: true, constrain: true,
                    width: Math.min(440, Ext.Element.getViewportWidth() - 20), bodyPadding: 12, referenceHolder: true,
                    defaultFocus: '[itemId=cancel-mode-enrollment]', defaultButton: 'cancelModeEnrollment',
                    html: 'Add a two-factor key first. Your login passkeys stay saved. No mode change has been made.',
                    buttons: [{ text: 'Cancel', itemId: 'cancel-mode-enrollment', reference: 'cancelModeEnrollment', handler: () => guidance.close() },
                        { text: 'Add two-factor key', handler: () => { const allowed = current(guidanceSession); guidance.close(); if (allowed) secondary?.sllStartEnrollment?.(); } }],
                    listeners: { destroy: () => { if (activeDialog === guidance) activeDialog = null; sync(); reloadMode(); } },
                });
                activeDialog = guidance; sync(); guidance.show(); return;
            }
            const before = state, snapshot = session(); let abort, submitting = false;
            const valid = () => current(snapshot) && state?.revision === before.revision && !dialog.destroyed && !dialog.destroying;
            const form = Ext.create('Ext.form.Panel', { bodyPadding: 12, border: false, layout: 'anchor',
                defaults: { anchor: '100%', labelAlign: 'top' }, items: [
                    { xtype: 'component', margin: '0 0 10 0', html: mode === 'two_factor' ?
                        'Choose the key to use after your password. Login passkeys stay saved but cannot sign you in by themselves while this mode is on.' :
                        'Stop using your keys as a second factor. Their registrations stay saved. Use a login passkey instead of your password; other verification requirements remain.' },
                    { xtype: 'displayfield', fieldLabel: 'Account', value: html(user) },
                    ...(mode === 'two_factor' ? [{ xtype: 'combobox', name: 'key_id', fieldLabel: 'Two-factor key to enable', allowBlank: false,
                        editable: false, forceSelection: true, queryMode: 'local', valueField: 'id', displayField: 'label',
                        store: { fields: ['id', 'label'], data: before.native_keys.map(key => ({ id: key.id, label: key.description + ' (' + key.type + ')' })) },
                        listConfig: { getInnerTpl: () => '{label:htmlEncode}' }, value: before.native_keys.length === 1 ? before.native_keys[0].id : null }] : []),
                    { xtype: 'textfield', name: 'password', fieldLabel: 'Current Proxmox password', inputType: 'password', allowBlank: false,
                        maxLength: 1024, enforceMaxLength: true, inputAttrTpl: 'autocomplete=current-password' },
                    { xtype: 'component', margin: '8 0 0 0', html: 'Verify your password to change only this account. Your saved keys are kept.' },
                ] });
            const clear = () => { if (!form.destroyed) form.getForm().findField('password')?.setValue(''); };
            const dialog = Ext.create('Ext.window.Window', { itemId: 'sll-passkey-mode-confirm', referenceHolder: true,
                title: mode === 'two_factor' ? 'Use passkeys for two-factor authentication?' : 'Use passkeys as a login alternative?',
                modal: true, constrain: true, width: Math.min(480, Ext.Element.getViewportWidth() - 20), layout: 'fit', items: [form],
                defaultFocus: '[itemId=cancel-passkey-mode]', defaultButton: 'cancelPasskeyMode',
                buttons: [{ text: 'Cancel', itemId: 'cancel-passkey-mode', reference: 'cancelPasskeyMode', handler: () => dialog.close() },
                    { text: 'Confirm mode change', ariaLabel: 'Confirm passkey mode change', handler: async () => {
                        if (submitting) return;
                        if (!valid()) { dialog.close(); tell('Your session or keys changed. Review the current mode before trying again.'); return; }
                        if (!form.getForm().isValid()) return;
                        const key = form.getForm().findField('key_id')?.getValue();
                        if (mode === 'two_factor' && !before.native_keys.some(entry => entry.id === key)) return;
                        submitting = true; abort = new AbortController(); dialog.setLoading('Confirming your passkey mode…');
                        const payload = { mode, expected_revision: before.revision, password: form.getForm().findField('password').getValue() };
                        if (mode === 'two_factor') payload.key_id = key;
                        try {
                            const pending = api('POST', '/mode', payload, snapshot.token, abort.signal); delete payload.password; clear();
                            const result = await pending;
                            if (!valid() || abort.signal.aborted) {
                                if (!dialog.destroyed) dialog.close();
                                tell('Your session or keys changed. Review the current mode before trying again.'); return;
                            }
                            showState(result); dialog.close(); primary.sllReloadKeys?.(); secondary?.sllReloadKeys?.();
                        } catch (failure) {
                            if (!dialog.destroyed && !abort.signal.aborted) {
                                dialog.close(); tell(failure.status === 409 ? 'Your keys changed. Review the refreshed mode and try again.' :
                                    'The requested mode change could not be confirmed. Review the current mode and verify your password before trying again.');
                            }
                        } finally { delete payload.password; clear(); if (!dialog.destroyed) { dialog.setLoading(false); submitting = false; } }
                    } }],
                listeners: { beforeclose: () => { abort?.abort(); clear(); }, beforedestroy: () => { abort?.abort(); clear(); },
                    destroy: () => { if (activeDialog === dialog) activeDialog = null; if (!disposed) { sync(); reloadMode(); } } },
            });
            activeDialog = dialog; sync(); dialog.show();
        }
        function closeOwned() {
            activeDialog?.close(); activeDialog = null; readAbort?.abort();
            primary.sllCloseKeyDialogs?.(); secondary?.sllCloseKeyDialogs?.(); sync();
        }
        const activate = () => { accepting = true; primary.sllReloadKeys?.(); secondary?.sllReloadKeys?.(); reloadMode(); };
        const panel = Ext.create('Ext.panel.Panel', {
            title: 'Security', header: false, itemId: 'security', border: false, bodyPadding: 10, layout: 'anchor',
            defaults: { anchor: '100%' }, scrollable: 'y', items: [
                { xtype: 'fieldset', title: 'Your passkey mode', itemId: 'passkey-mode-policy', cls: 'pm-security-view-switch', layout: 'anchor',
                    defaults: { anchor: '100%' }, items: [toggle, caption, requestNote, { xtype: 'container', layout: 'hbox', items: [refresh] }] },
                primary, ...(secondary ? [secondary] : []),
            ],
            listeners: {
                afterrender: reloadMode,
                activate, show: activate,
                hide: () => { accepting = false; closeOwned(); }, deactivate: () => { accepting = false; closeOwned(); },
                destroy: () => { disposed = true; accepting = false; closeOwned(); },
            },
        });
        panel.mon(primary, 'keysloaded', reloadMode); if (secondary) panel.mon(secondary, 'keysloaded', reloadMode);
        panel.mon(Ext.state.Manager.getProvider(), 'statechange', (_provider, key, value) => {
            if (key !== 'GuiCap' || (value && fullSession(user))) return;
            accepting = false; state = null; closeOwned(); primary.sllInvalidateKeys?.(); secondary?.sllInvalidateKeys?.();
            caption.update('Your Proxmox session changed. Reopen passkey management.');
        });
        panel.sllRefreshMode = reloadMode;
        return panel;
    }
    function installUserMenu(attempt = 0) {
        const menu = Ext.getCmp('userinfo')?.getMenu?.();
        if (!menu) { if (attempt < 20) Ext.defer(() => installUserMenu(attempt + 1), 250); return; }
        const user = currentUser(), allowed = fullSession(user) && /@(?:pam|pve)$/.test(user);
        let item = menu.down('#sll-login-passkeys-menu');
        if (!item && allowed) item = menu.insert(1, { text: 'Login passkeys', ariaLabel: 'Login passkeys', itemId: 'sll-login-passkeys-menu', iconCls: 'fa fa-key', handler: openManager });
        item?.setHidden(!allowed);
    }
    const nativeTfa = Ext.ClassManager.get('Proxmox.window.TfaLoginWindow');
    if (nativeTfa) Ext.override(nativeTfa, { initComponent: function () {
        this.callParent(arguments);
        const field = this.down('textfield[name=totp]');
        if (field) {
            field.setFieldLabel('2FA code (TOTP)');
            field.setEmptyText?.('Code from your authenticator app');
        }
    } });
    const login = Ext.ClassManager.get('PVE.window.LoginWindow');
    if (login) Ext.override(login, { initComponent: function () {
        this.callParent(arguments);
        if (this.rendered) installLoginButton(this);
        else this.on('afterrender', () => installLoginButton(this), null, { single: true });
    } });
    const workspace = Ext.ClassManager.get('PVE.Workspace');
    if (workspace) Ext.override(workspace, {
        updateLoginData: function () { this.callParent(arguments); Ext.defer(() => installUserMenu(), 25); },
        showLogin: function () {
            this.callParent(arguments); installUserMenu();
            for (const dialog of Ext.ComponentQuery.query('window[sllLoginPasskeysWindow=true]')) dialog.close();
        },
    });
    Ext.onReady(() => installUserMenu());
    window.SLLMakeoverLoginPasskeys = Object.freeze({ createManagerPanel, createSecurityPanel, openManager });
})();
