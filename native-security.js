/* Current-account metadata and native WebAuthn enrollment with dialog/session lifetime guards. */
(function () {
    'use strict';
    if (!window.Ext || !window.Proxmox || window.SLLMakeoverNativeSecurity) return;
    const html = value => Ext.String.htmlEncode(String(value ?? ''));
    const account = () => typeof Proxmox.UserName === 'string' && Proxmox.UserName.includes('@') &&
        !/[!\x00-\x1f\x7f]/.test(Proxmox.UserName) ? Proxmox.UserName : null;
    const nativeClass = () => Boolean(Ext.ClassManager?.get('Proxmox.window.AddWebauthn'));

    function createPanel(options = {}) {
        const embedded = options.embedded === true;
        // This panel never accepts an account argument: list/enrollment always
        // belong to the current interactive native Proxmox account.
        const user = account();
        let disposed = false, loaded = false, loading = false;
        let originMismatch = false, removalSupported = false;
        const dialogs = new Set(), pendingRemovals = new Set(), rowButtons = new Set();
        const closeDialogs = () => {
            for (const dialog of dialogs) if (!dialog.destroyed) dialog.close();
            dialogs.clear();
            for (const abort of pendingRemovals) abort.abort();
            pendingRemovals.clear();
        };
        const store = Ext.create('Ext.data.Store', {
            fields: ['id', 'description', 'type', 'created', 'enable'],
            data: [], autoDestroy: true,
        });
        const notice = Ext.create('Ext.Component', {
            itemId: 'security-key-status', margin: '0 0 12 0',
            ariaRole: 'status', html: 'Select Refresh to load your registered keys.',
        });
        const setup = Ext.create('Ext.Component', {
            itemId: 'security-key-setup', margin: '0 0 12 0',
            html: 'WebAuthn uses your trusted HTTPS origin and the native Proxmox relying-party settings.',
        });
        const removalSupport = Ext.create('Ext.Component', { itemId: 'second-factor-removal-support', margin: '0 0 8 0',
            html: 'Checking secure two-factor key removal…' });
        const reason = () => !user || account() !== user || Proxmox.LoggedOut ? 'Sign in to Proxmox again before managing security keys.' :
            !nativeClass() ? 'This Proxmox build does not expose the supported native WebAuthn registration dialog.' :
            window.isSecureContext === false ? 'Open Proxmox through a trusted HTTPS address to register a security key.' :
            !window.PublicKeyCredential ? 'This browser does not support WebAuthn. Use a browser with security-key support.' :
            originMismatch ? 'Open the configured WebAuthn origin shown below before registering a key.' : '';
        const setNotice = (message, error = false) => {
            if (!disposed) notice.update('<div role="' + (error ? 'alert' : 'status') + '">' + html(message) + '</div>');
        };
        const removalBlocked = () => loading || !user || account() !== user || Proxmox.LoggedOut || !removalSupported ||
            !Ext.ClassManager.get('Proxmox.tfa.confirmRemove');
        let addButton, editButton, removeButton, refreshButton, grid;
        const refreshActions = () => {
            if (disposed) return;
            const blocked = reason();
            addButton.setDisabled(Boolean(blocked));
            addButton.setTooltip(blocked || 'Register a key for ' + user + ' using native Proxmox enrollment.');
            editButton.setDisabled(loading || !user || account() !== user || Proxmox.LoggedOut || grid?.getSelectionModel().getCount() !== 1 ||
                !Ext.ClassManager.get('Proxmox.window.TfaEdit'));
            removeButton.setDisabled(removalBlocked() || grid?.getSelectionModel().getCount() !== 1);
            for (const button of rowButtons) if (!button.destroyed) button.setDisabled(removalBlocked());
            refreshButton.setDisabled(loading || !user || account() !== user);
        };
        function reload() {
            if (disposed || loading) return;
            if (!user || account() !== user) {
                store.removeAll(); setNotice('Sign in to Proxmox again before managing security keys.', true);
                refreshActions(); return;
            }
            loading = true; refreshActions(); setNotice('Loading your security keys…');
            // Read public entry metadata for this account only. Never fetch the
            // cluster-wide TFA list or an individual credential's material.
            Proxmox.Utils.API2Request({
                url: '/api2/extjs/access/tfa/' + encodeURIComponent(user), method: 'GET',
                success: response => {
                    if (disposed) return;
                    loading = false;
                    if (account() !== user) {
                        store.removeAll(); setNotice('Your Proxmox account changed. Reopen Makeover.', true);
                        refreshActions(); return;
                    }
                    const entries = response.result?.data;
                    if (!Array.isArray(entries)) {
                        store.removeAll(); setNotice('Proxmox returned an invalid security-key list.', true);
                        refreshActions(); return;
                    }
                    const keys = entries.filter(entry => entry && typeof entry.id === 'string' &&
                        (entry.type === 'webauthn' || entry.type === 'u2f')).map(entry => ({
                        id: entry.id, description: String(entry.description || 'Security key'), type: entry.type,
                        created: Number.isFinite(Number(entry.created)) ? Number(entry.created) : 0,
                        enable: entry.enable !== false && entry.enable !== 0 && entry.enable !== '0',
                    }));
                    store.loadData(keys); loaded = true;
                    if (embedded) grid.setHeight(64 + Math.max(1, Math.min(4, store.getCount())) * 40);
                    setNotice(embedded ? keys.length + ' registered.' : keys.length ? keys.length + ' registered security key' + (keys.length === 1 ? '' : 's') + ' for ' + user + '.' :
                        'No two-factor security keys enrolled for ' + user + '. Select Add two-factor key to register one.');
                    refreshActions();
                    panel.fireEvent('keysloaded', panel);
                },
                failure: () => {
                    if (disposed) return;
                    loading = false; store.removeAll();
                    setNotice('Could not load your security keys. Check your native Proxmox session and permissions, then select Refresh.', true);
                    refreshActions();
                },
            });
        }
        function readSetup() {
            if (disposed || !user || account() !== user) return;
            Proxmox.Utils.API2Request({
                url: '/api2/extjs/cluster/options', method: 'GET',
                success: response => {
                    if (disposed || account() !== user) return;
                    const raw = response.result?.data?.webauthn;
                    let settings;
                    if (raw && typeof raw === 'object' && !Array.isArray(raw)) settings = raw;
                    else if (typeof raw === 'string' && window.PVE?.Parser?.parsePropertyString) {
                        try { settings = PVE.Parser.parsePropertyString(raw); } catch (_error) { return; }
                    } else return;
                    if (!settings || typeof settings !== 'object') return;
                    settings = Object.fromEntries(['id', 'origin', 'rp'].filter(key => typeof settings[key] === 'string').map(key => [key, settings[key].slice(0, 1024)]));
                    let origin;
                    try { origin = settings.origin ? new URL(settings.origin) : null; } catch (_error) { origin = null; }
                    originMismatch = Boolean(origin && origin.origin !== window.location.origin);
                    setup.update('<div><strong>Native WebAuthn settings</strong><br>Relying party: ' + html(settings.rp || settings.id || 'Proxmox') +
                        '<br>RP ID: ' + html(settings.id || 'Not configured') +
                        '<br>Origin: ' + html(origin?.origin || window.location.origin) +
                        (originMismatch ? '<br><strong>Use this configured origin to register and use your key.</strong>' : '') + '</div>');
                    refreshActions();
                },
                // The native endpoint may omit settings for lower-privilege
                // users. Enrollment itself keeps native permission checks.
                failure: () => {},
            });
        }
        function readRemovalSupport() {
            if (disposed || account() !== user || Proxmox.LoggedOut) return;
            Proxmox.Utils.API2Request({ url: '/api2/extjs/sll-passkeys/status', method: 'GET',
                success: response => {
                    if (disposed || account() !== user || Proxmox.LoggedOut) return;
                    removalSupported = response.result?.data?.secondary_removal === true;
                    removalSupport.update(removalSupported ? (embedded ? 'Remove deletes only that key.' : 'Use Remove beside a key, or select a row and choose Remove selected. Removal affects that key only.') :
                        'Secure removal requires the current Makeover backend. Native Two Factor settings remain available.');
                    refreshActions();
                },
                failure: () => {
                    if (disposed) return;
                    removalSupported = false;
                    removalSupport.update('Secure removal is unavailable. Check the Makeover backend before trying again.'); refreshActions();
                },
            });
        }
        const sessionSnapshot = () => ({ cookie: Ext.util.Cookies.get(Proxmox.Setup.auth_cookie_name), token: Proxmox.CSRFPreventionToken });
        const sessionCurrent = session => !disposed && account() === user && !Proxmox.LoggedOut &&
            typeof session.cookie === 'string' && session.cookie.length > 0 && typeof session.token === 'string' && session.token.length > 0 &&
            Ext.util.Cookies.get(Proxmox.Setup.auth_cookie_name) === session.cookie && Proxmox.CSRFPreventionToken === session.token;
        function removeKey(record) {
            const selected = record?.isModel ? record : grid.getSelectionModel().getSelection()[0];
            if (disposed || removalBlocked() || !selected || store.indexOf(selected) < 0) return;
            const id = selected.get('id'), session = sessionSnapshot();
            let abort, submitting = false;
            const current = () => sessionCurrent(session) && store.indexOf(selected) >= 0 && selected.get('id') === id;
            const clearPassword = owner => { if (!owner.destroyed && !owner.destroying) owner.lookup('password')?.setValue(''); };
            const cancel = owner => { abort?.abort(); clearPassword(owner); };
            const dialog = Ext.create('Proxmox.tfa.confirmRemove', {
                itemId: 'sll-remove-second-factor', title: 'Remove two-factor key?',
                userid: html(user), type: selected.get('type'), description: selected.get('description'), created: selected.get('created'),
                width: Math.min(600, Ext.Element.getViewportWidth() - 20), constrain: true,
                // The vendor dialog owns the native fields and root/nonroot
                // password policy. Its stock DELETE puts a password in the
                // query string, so this instance submits to the body-only bridge.
                callback: Ext.emptyFn,
                fieldDefaults: { labelAlign: 'top', anchor: '100%' },
                listeners: { beforeclose: cancel, beforedestroy: cancel,
                    destroy: owner => dialogs.delete(owner) },
            });
            dialogs.add(dialog);
            dialog.formPanel.insert(0, { xtype: 'component', margin: '0 0 10 0',
                html: 'Remove <strong>' + html(selected.get('description')) + '</strong> from ' + html(user) + '? This removes that two-factor key only.' });
            const cancelButton = dialog.getDockedItems('toolbar[dock=bottom]')[0].insert(0, {
                xtype: 'button', text: 'Cancel', itemId: 'sll-cancel-second-factor-removal', reference: 'sllCancelSecondFactorRemoval', handler: () => dialog.close(),
            });
            dialog.defaultFocus = cancelButton; dialog.defaultButton = 'sllCancelSecondFactorRemoval';
            dialog.submit = async function () {
                if (this.destroyed || this.destroying) return;
                if (!current()) { this.close(); setNotice('Your Proxmox session changed. Reopen this key before removing it.', true); return; }
                if (submitting || !this.isValid()) return;
                submitting = true; abort = new AbortController(); pendingRemovals.add(abort);
                const payload = { id };
                const password = this.lookup('password');
                if (!password.disabled) payload.password = password.getValue();
                dialog.setLoading('Removing this key…');
                try {
                    // Explicit CSRF and JSON prevent password query strings;
                    // the bridge calls native own-user deletion and reauth.
                    const request = fetch('/api2/extjs/sll-passkeys/remove-second-factor', {
                        method: 'POST', credentials: 'same-origin', mode: 'same-origin', cache: 'no-store', signal: abort.signal,
                        headers: { Accept: 'application/json', 'Content-Type': 'application/json', CSRFPreventionToken: session.token },
                        body: JSON.stringify(payload),
                    });
                    delete payload.password; clearPassword(dialog);
                    const response = await request, result = await response.json();
                    if (!current() || dialog.destroyed || abort.signal.aborted) return;
                    if (!response.ok || result.success === false || result.data?.removed !== true) throw new Error('Removal failed.');
                    dialog.close(); reload();
                } catch (_failure) {
                    if (current() && !dialog.destroyed && !abort.signal.aborted) setNotice('Proxmox could not remove this key. Check your current password and try again.', true);
                } finally {
                    delete payload.password; pendingRemovals.delete(abort);
                    if (!dialog.destroyed) { clearPassword(dialog); dialog.setLoading(false); submitting = false; }
                }
            };
            dialog.show();
        }
        function confirmAddKey() {
            if (disposed || reason()) return;
            const session = sessionSnapshot();
            const confirmation = Ext.create('Ext.window.MessageBox', { closeAction: 'destroy' });
            dialogs.add(confirmation);
            confirmation.on('destroy', () => dialogs.delete(confirmation), null, { single: true });
            confirmation.show({ title: 'Enable extra verification?',
                message: 'Adding this key turns on two-factor authentication for your account. Sign in with your password, then extra verification. ' +
                    'Login passkeys stay saved but cannot sign you in by themselves while this mode is on. ' +
                    'To add a password alternative, use Add login passkey instead. Continue?',
                buttons: Ext.Msg.YESNO, defaultFocus: 'no', icon: Ext.Msg.QUESTION,
                fn: answer => {
                    confirmation.destroy();
                    if (answer === 'yes' && sessionCurrent(session) && !reason()) addKey();
                },
            });
        }
        function editKey() {
            const selected = grid.getSelectionModel().getSelection()[0];
            if (disposed || !selected || store.indexOf(selected) < 0 || account() !== user || Proxmox.LoggedOut ||
                !Ext.ClassManager.get('Proxmox.window.TfaEdit')) return;
            const id = selected.get('id'), session = sessionSnapshot();
            let entryLoaded = false;
            const current = () => sessionCurrent(session) && store.indexOf(selected) >= 0 && selected.get('id') === id;
            if (!current()) return;
            const clearPassword = dialog => { if (!dialog.destroyed && !dialog.destroying) dialog.down('textfield[name=password]')?.setValue(''); };
            const dialog = Ext.create('Proxmox.window.TfaEdit', {
                'tfa-id': encodeURIComponent(user) + '/' + encodeURIComponent(id),
                title: 'Extra verification · ' + html(user),
                width: Math.min(512, Ext.Element.getViewportWidth() - 20), constrain: true,
                // Preserve native fields, password policy and submit(). Guard
                // only this owned load so a late GET cannot touch a closed form.
                load: function () {
                    const owner = this;
                    if (!current()) return;
                    // Native API2Request unconditionally unmasks waitMsgTarget
                    // even after destruction. Mask this owned dialog with
                    // lifetime checks instead, and reject submit until loaded.
                    owner.on('afterlayout', () => { if (!entryLoaded && current() && !owner.destroyed) owner.setLoading('Loading this key…'); }, null, { single: true });
                    Proxmox.Utils.API2Request({ url: owner.url, method: 'GET',
                        success: response => {
                            if (owner.destroyed || owner.destroying) return;
                            if (!current()) { owner.close(); return; }
                            owner.formPanel.getForm().clearInvalid();
                            owner.digest = response.result?.digest || response.result?.data?.digest;
                            owner.setValues(response.result.data);
                            entryLoaded = true; owner.setLoading(false);
                        },
                        failure: () => {
                            if (owner.destroyed || owner.destroying) return;
                            if (!current()) { owner.close(); return; }
                            setNotice('Could not load this extra-verification key. Select Refresh and try again.', true); owner.close();
                        },
                    });
                },
                submitOptions: {
                    success: () => { if (!dialog.destroyed && !dialog.destroying) dialog.close(); },
                    failure: () => {
                        if (!current() || dialog.destroyed || dialog.destroying) return;
                        dialog.unmask(); setNotice('Proxmox could not update this key. Check your current password and try again.', true);
                    },
                },
                listeners: {
                    beforeclose: owner => clearPassword(owner), beforedestroy: owner => clearPassword(owner),
                    destroy: owner => { dialogs.delete(owner); if (!disposed && sessionCurrent(session)) reload(); },
                },
            });
            dialogs.add(dialog);
            dialog.lookup('userid')?.setValue(user);
            dialog.down('[name=enable]')?.setFieldLabel('Enable this extra factor');
            dialog.formPanel.add({ xtype: 'component', margin: '8 0 0 0',
                html: 'Disabling this entry keeps the key registered. Other enabled Proxmox factors can still require extra verification after either sign-in choice.' });
            const nativeSubmit = dialog.submit;
            dialog.submit = function () {
                if (!current() || this.destroyed || this.destroying) {
                    if (!this.destroyed && !this.destroying) this.close();
                    setNotice('Your Proxmox session changed. Reopen this key before saving.', true); return;
                }
                if (!entryLoaded || !this.isValid()) return;
                // Native submit synchronously copies the field values before
                // dispatch. Clear the password only after that native capture.
                nativeSubmit.call(this); clearPassword(this);
            };
            dialog.show();
        }
        function addKey() {
            const blocked = reason();
            if (blocked) { setNotice(blocked, true); refreshActions(); return; }
            let operation;
            const clearPassword = () => { if (!dialog.destroyed && !dialog.destroying) dialog.down('textfield[name=password]')?.setValue(''); };
            const cancel = () => {
                if (operation) {
                    operation.abort.abort();
                    if (operation.values) delete operation.values.password;
                    if (operation.params) delete operation.params.password;
                    operation.message?.destroy(); operation.message = null;
                }
                clearPassword();
            };
            const dialog = Ext.create('Proxmox.window.AddWebauthn', {
                autoShow: true, fixedUser: true,
                title: 'Add two-factor key · ' + html(user),
                listeners: {
                    beforeclose: cancel,
                    beforedestroy: cancel,
                    destroy: () => { dialogs.delete(dialog); if (!disposed) reload(); },
                },
            });
            dialogs.add(dialog);
            const form = dialog.down('form');
            const nativeUser = dialog.down('pmxDisplayEditField[name=user]');
            const controller = dialog.getController?.();
            const nativeForm = controller?.lookup?.('webauthn_form');
            if (!form?.add || !nativeUser?.displayField || !nativeUser?.editField ||
                typeof controller?.registerWebauthn !== 'function' || typeof nativeForm?.getValues !== 'function' ||
                typeof nativeForm?.isValid !== 'function' || typeof Proxmox.Async?.api2 !== 'function' ||
                typeof Proxmox.Utils.base64url_to_bytes !== 'function' || typeof Proxmox.Utils.bytes_to_base64url !== 'function' ||
                typeof window.AbortController !== 'function') {
                dialog.close(); setNotice('This native registration form is not supported by this Makeover build.', true); return;
            }
            // The shipped fixedUser display field is not submitted. Preserve
            // its fixed account value with a hidden native form field.
            nativeUser.displayField.submitValue = false;
            nativeUser.editField.setDisabled(true);
            form.add({ xtype: 'hiddenfield', name: 'user', value: user });
            // PVE's native controller has no pending-operation cancellation or
            // post-await lifetime checks. Adapt only this owned instance: keep
            // its native form, endpoints, password policy and byte conversions.
            controller.registerWebauthn = async () => {
                if (operation || disposed || dialog.destroyed || reason() || !nativeForm.isValid()) return;
                const session = { cookie: Ext.util.Cookies.get(Proxmox.Setup.auth_cookie_name), token: Proxmox.CSRFPreventionToken };
                const state = { abort: new AbortController(), values: nativeForm.getValues(), params: null, message: null };
                operation = state;
                const current = () => !state.abort.signal.aborted && !disposed && !dialog.destroyed &&
                    account() === user && !Proxmox.LoggedOut && typeof session.cookie === 'string' && session.cookie.length > 0 &&
                    typeof session.token === 'string' && session.token.length > 0 &&
                    Ext.util.Cookies.get(Proxmox.Setup.auth_cookie_name) === session.cookie && Proxmox.CSRFPreventionToken === session.token;
                const requireCurrent = () => { if (!current()) throw new DOMException('Enrollment canceled.', 'AbortError'); };
                try {
                    requireCurrent();
                    if (state.values.user !== user) throw new Error('Unexpected native enrollment account.');
                    delete state.values.user; state.values.type = 'webauthn';
                    dialog.mask('Please wait…', 'x-mask-loading');
                    const endpoint = '/api2/extjs/access/tfa/' + encodeURIComponent(user);
                    const begun = await Proxmox.Async.api2({ url: endpoint, method: 'POST', params: state.values });
                    requireCurrent();
                    const creds = JSON.parse(begun.result.data.challenge);
                    const challenge = creds.publicKey.challenge;
                    creds.publicKey.challenge = Proxmox.Utils.base64url_to_bytes(challenge);
                    creds.publicKey.user.id = Proxmox.Utils.base64url_to_bytes(creds.publicKey.user.id);
                    creds.publicKey.excludeCredentials = (creds.publicKey.excludeCredentials || []).map(item => ({
                        id: Proxmox.Utils.base64url_to_bytes(item.id), type: item.type,
                    }));
                    state.message = Ext.create('Ext.window.MessageBox', { itemId: 'sll-native-enrollment-wait', closeAction: 'destroy' }).show({
                        title: 'WebAuthn setup', message: 'Please confirm the request on your security key or device.', buttons: [],
                    });
                    const credential = await navigator.credentials.create({ ...creds, signal: state.abort.signal });
                    requireCurrent();
                    const response = { id: credential.id, type: credential.type, rawId: Proxmox.Utils.bytes_to_base64url(credential.rawId),
                        response: { attestationObject: Proxmox.Utils.bytes_to_base64url(credential.response.attestationObject),
                            clientDataJSON: Proxmox.Utils.bytes_to_base64url(credential.response.clientDataJSON) } };
                    state.message.destroy(); state.message = null;
                    state.params = { type: 'webauthn', challenge, value: JSON.stringify(response) };
                    if (state.values.password) state.params.password = state.values.password;
                    requireCurrent();
                    await Proxmox.Async.api2({ url: endpoint, method: 'POST', params: state.params });
                    requireCurrent();
                    dialog.close();
                } catch (_failure) {
                    const reportFailure = current() && _failure?.name !== 'NotAllowedError' && _failure?.name !== 'AbortError';
                    if (!dialog.destroyed && !dialog.destroying) dialog.close();
                    if (reportFailure) Ext.Msg.alert('Security key not added', 'Security-key enrollment could not be completed. Please try again.');
                } finally {
                    delete state.values.password;
                    if (state.params) delete state.params.password;
                    state.message?.destroy(); state.message = null;
                    if (!dialog.destroyed) { clearPassword(); dialog.unmask(); }
                    if (operation === state) operation = null;
                }
            };
        }
        addButton = Ext.create('Ext.button.Button', {
            itemId: 'add-security-key', text: 'Add two-factor key', ariaLabel: 'Add two-factor key', iconCls: 'fa fa-key',
            handler: confirmAddKey,
        });
        editButton = Ext.create('Ext.button.Button', {
            itemId: 'edit-security-key', text: 'Enable / disable', ariaLabel: 'Enable or disable extra verification',
            iconCls: 'fa fa-pencil', handler: editKey, hidden: embedded,
        });
        removeButton = Ext.create('Ext.button.Button', { itemId: 'remove-security-key', text: 'Remove selected',
            ariaLabel: 'Remove selected two-factor key', iconCls: 'fa fa-trash', handler: () => removeKey() });
        refreshButton = Ext.create('Ext.button.Button', {
            itemId: 'refresh-security-keys', text: 'Refresh', iconCls: 'fa fa-refresh', handler: reload,
            tooltip: 'Refresh security keys', ariaLabel: 'Refresh security keys',
        });
        grid = Ext.create('Ext.grid.Panel', {
            itemId: 'security-keys-grid', store, border: true, minHeight: embedded ? 104 : 210,
            height: embedded ? 104 : undefined, flex: embedded ? undefined : 1,
            emptyText: 'No WebAuthn security keys are enrolled for this account.',
            viewConfig: { deferEmptyText: false, stripeRows: true },
            tbar: { enableOverflow: true, items: [addButton, editButton, removeButton, refreshButton] },
            columns: [
                { text: 'Description', dataIndex: 'description', flex: 1, minWidth: 110, renderer: (value, _metadata, record) => html(value) +
                    (grid?.getWidth() < 520 ? '<br><small>' + (record.get('enable') ? 'Enabled' : 'Disabled') + '</small>' : '') },
                { xtype: 'widgetcolumn', text: 'Actions', width: 100,
                    widget: { xtype: 'button', text: 'Remove', ariaLabel: 'Remove two-factor key', height: 36,
                        handler: button => removeKey(button.getWidgetRecord()), listeners: { destroy: button => rowButtons.delete(button) } },
                    onWidgetAttach: (_column, button) => { rowButtons.add(button); button.setDisabled(removalBlocked()); },
                },
                { itemId: 'native-key-type', text: 'Type', dataIndex: 'type', width: 110, renderer: value => value === 'u2f' ? 'U2F (legacy)' : 'WebAuthn' },
                { itemId: 'native-key-enabled', text: 'Enabled', dataIndex: 'enable', width: 85, renderer: value => value ? 'Yes' : 'No' },
                { itemId: 'native-key-added', text: 'Added', dataIndex: 'created', width: 160, renderer: value => value > 0 ? html(new Date(value * 1000).toLocaleString()) : 'Unknown' },
            ], listeners: { selectionchange: refreshActions, resize: (owner, width) => {
                const compact = width < 520;
                for (const itemId of ['native-key-type', 'native-key-enabled', 'native-key-added']) owner.down('#' + itemId).setHidden(compact);
                if (owner.rendered && owner.getView().rendered) owner.getView().refresh();
            } },
        });
        const panel = Ext.create('Ext.panel.Panel', {
            title: embedded ? 'Two-factor keys' : 'Extra verification (optional)', header: embedded, itemId: 'second-factor-keys', iconCls: 'fa fa-shield',
            bodyPadding: embedded ? 8 : 12, layout: embedded ? 'anchor' : { type: 'vbox', align: 'stretch' },
            defaults: embedded ? { anchor: '100%' } : undefined, scrollable: !embedded,
            items: [
                { xtype: 'component', margin: '0 0 14 0', html: embedded ?
                    'Keys used after your password. They stay saved when this mode is off.' :
                    '<h2 style="margin-top:0">Extra verification (optional)</h2>' +
                    '<p>For passkey OR password sign-in, use <strong>Login passkeys</strong>. ' +
                    'Keys here add an extra step: password plus key when using your password, or Proxmox\'s configured extra factor after a login passkey.</p>' +
                    '<p>Select a registered key and <strong>Enable / disable</strong> to turn that entry on or off. Disabling keeps it registered.</p>' +
                    '<p>Enrollment is canceled if this panel closes or your Proxmox session changes. ' +
                    'Your appearance changes can remain unsaved while you enroll a key.</p>' },
                notice, ...(!embedded ? [setup] : []), removalSupport, grid,
                ...(embedded ? [{ xtype: 'fieldset', title: 'Native WebAuthn settings', collapsible: true, collapsed: true,
                    margin: '10 0 0 0', itemId: 'native-webAuthn-details', layout: 'anchor', items: [setup] }] : []),
            ],
            listeners: {
                activate: () => { if (!loaded) reload(); readSetup(); readRemovalSupport(); },
                afterrender: () => { if (embedded) { reload(); readSetup(); readRemovalSupport(); } },
                hide: closeDialogs, deactivate: closeDialogs,
                resize: (_panel, width) => {
                    addButton.setText('Add two-factor key');
                    refreshButton.setText(width < 520 ? '' : 'Refresh');
                },
                destroy: () => { disposed = true; closeDialogs(); rowButtons.clear(); store.destroy(); },
            },
        });
        // Native login sets GuiCap after setAuthData; logout clears GuiCap
        // before replacing the workspace. Reject either session transition.
        panel.mon(Ext.state.Manager.getProvider(), 'statechange', (_provider, key, value) => {
            if (key !== 'GuiCap' || (value && account() === user && !Proxmox.LoggedOut)) return;
            closeDialogs(); store.removeAll();
            setNotice('Your Proxmox session changed. Reopen Makeover to manage security keys.', true);
            refreshActions();
        });
        refreshActions();
        panel.sllReloadKeys = reload;
        panel.sllCloseKeyDialogs = closeDialogs;
        panel.sllStartEnrollment = confirmAddKey;
        panel.sllInvalidateKeys = () => { closeDialogs(); store.removeAll(); setNotice('Your Proxmox session changed. Reopen passkey management.', true); refreshActions(); };
        if (reason()) setNotice(reason(), true);
        return panel;
    }
    window.SLLMakeoverNativeSecurity = Object.freeze({ createPanel });
})();
