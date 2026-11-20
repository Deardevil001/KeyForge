/* =========================================================
   KEYFORGE FRONTEND
   File: public/app.js
   Features: authentication, user key vault, admin management,
             user profiles, activity log, two-theme selector.
   ========================================================= */

'use strict';

/* -------------------- State -------------------- */

let currentUser = null;
let keys = [];
let users = [];
let selectedUser = null;

const $ = (id) => document.getElementById(id);

/* -------------------- Helpers -------------------- */

function escapeHTML(value) {
    return String(value ?? '').replace(/[&<>"']/g, (char) => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[char]);
}

function formatDate(value) {
    if (!value) return '—';

    const dateValue = new Date(value);

    if (Number.isNaN(dateValue.getTime())) return '—';

    return dateValue.toLocaleDateString();
}

function getKeyStatus(key) {
    if (key.status === 'revoked') return 'revoked';
    if (new Date(key.expiresAt) <= new Date()) return 'expired';
    if (key.status === 'inactive') return 'inactive';
    return 'active';
}

/* Render controls that match the key's current lifecycle state. */
function keyActionButtons(key) {
    const status = getKeyStatus(key);
    const id = escapeHTML(key.id);

    const deleteButton = `
        <button class="danger" type="button"
            data-action="delete-key" data-key-id="${id}">Delete</button>
    `;

    if (status === 'active') {
        return `
            <button class="secondary" type="button"
                data-action="deactivate-key" data-key-id="${id}">Deactivate</button>
            <button class="danger" type="button"
                data-action="revoke-key" data-key-id="${id}">Revoke</button>
            ${deleteButton}
        `;
    }

    if (status === 'inactive') {
        return `
            <button class="secondary" type="button"
                data-action="activate-key" data-key-id="${id}">Activate</button>
            <button class="danger" type="button"
                data-action="revoke-key" data-key-id="${id}">Revoke</button>
            ${deleteButton}
        `;
    }

    return deleteButton;
}

function statusBadge(key) {
    const state = getKeyStatus(key);

    return `<span class="pill ${state}">${state}</span>`;
}

async function api(url, options = {}) {
    const response = await fetch(`/api${url}`, {
        ...options,
        headers: {
            'Content-Type': 'application/json',
            ...(options.headers || {})
        },
        credentials: 'same-origin'
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
        throw new Error(data.error || 'Request failed.');
    }

    return data;
}

function showToast(text) {
    const toast = $('toast');

    if (!toast) return;

    toast.textContent = text;
    toast.style.display = 'block';

    window.clearTimeout(showToast.timer);

    showToast.timer = window.setTimeout(() => {
        toast.style.display = 'none';
    }, 2800);
}

/* -------------------- Theme: Dark / Light -------------------- */

function applyTheme(theme) {
    const selectedTheme = theme === 'light' ? 'light' : 'dark';

    document.documentElement.setAttribute('data-theme', selectedTheme);

    const selector = $('themeSelect');

    if (selector) {
        selector.value = selectedTheme;
    }

    try {
        localStorage.setItem('keyforge-theme', selectedTheme);
    } catch (error) {
        console.warn('Theme preference could not be saved.', error);
    }
}

function initializeTheme() {
    let savedTheme = 'dark';

    try {
        savedTheme = localStorage.getItem('keyforge-theme') || 'dark';
    } catch (error) {
        console.warn('Theme preference could not be loaded.', error);
    }

    applyTheme(savedTheme);

    $('themeSelect')?.addEventListener('change', (event) => {
        applyTheme(event.target.value);
    });
}

/* -------------------- Authentication UI -------------------- */

function showAuth() {
    $('authView')?.classList.remove('hide');
    $('appView')?.classList.add('hide');
}

function showApp() {
    $('authView')?.classList.add('hide');
    $('appView')?.classList.remove('hide');

    document.querySelectorAll('.adminOnly').forEach((element) => {
        element.classList.toggle('hide', currentUser.role !== 'admin');
    });

    $('accountName').textContent = currentUser.name;
    $('roleLabel').textContent = currentUser.role;
    $('welcome').textContent = `Welcome, ${currentUser.name}`;

    $('profileName').textContent = currentUser.name;
    $('profileEmail').textContent = currentUser.email;
    $('profileRole').textContent = currentUser.role;

    $('profileInitials').textContent = currentUser.name
        .split(/\s+/)
        .map((part) => part[0])
        .join('')
        .slice(0, 2)
        .toUpperCase();

    $('profileLimit').textContent =
    currentUser.role === 'admin' || currentUser.unlimitedKeyAccess === true
        ? 'Unlimited'
        : currentUser.keyLimit;

    // Keep the selected appearance after login.
    applyTheme(document.documentElement.dataset.theme || 'dark');
}

function setAuthTab(tab) {
    document.querySelectorAll('.tab').forEach((button) => {
        button.classList.toggle('active', button.dataset.auth === tab);
    });

    $('loginForm').classList.toggle('hide', tab !== 'login');
    $('registerForm').classList.toggle('hide', tab !== 'register');
    $('authError').textContent = '';
}

/* -------------------- Login / Registration -------------------- */

document.querySelectorAll('.tab').forEach((button) => {
    button.addEventListener('click', () => {
        setAuthTab(button.dataset.auth);
    });
});

$('loginForm').addEventListener('submit', async (event) => {
    event.preventDefault();

    try {
        const formData = new FormData(event.target);

        const result = await api('/auth/login', {
            method: 'POST',
            body: JSON.stringify(Object.fromEntries(formData))
        });

        currentUser = result.user;
        await startApplication();
    } catch (error) {
        $('authError').textContent = error.message;
        if (!currentUser) showAuth();
    }
});

$('registerForm').addEventListener('submit', async (event) => {
    event.preventDefault();

    try {
        const formData = new FormData(event.target);

        const result = await api('/auth/register', {
            method: 'POST',
            body: JSON.stringify(Object.fromEntries(formData))
        });

        currentUser = result.user;
        await startApplication();
    } catch (error) {
        $('authError').textContent = error.message;
        if (!currentUser) showAuth();
    }
});

$('logout').addEventListener('click', async () => {
    try {
        await api('/auth/logout', { method: 'POST' });

        currentUser = null;
        keys = [];
        users = [];

        showAuth();
    } catch (error) {
        showToast(error.message);
    }
});

/* -------------------- Application Startup -------------------- */

async function startApplication() {
    showApp();
    await refreshData();
    await initializeAccountVerification();
    navigateTo('overview');
}

async function refreshData() {
    // Always load keys owned by the currently signed-in account.
    // Admin-wide keys are fetched separately in renderAllKeys().
    const currentUserId = currentUser?.id || currentUser?._id;

    if (!currentUserId) {
        throw new Error('Could not determine the signed-in account ID.');
    }

    const keyResponse = await api(
        `/keys?ownerId=${encodeURIComponent(String(currentUserId))}`
    );

    keys = keyResponse.keys || [];

    renderKeys();
    renderOverview();
    renderProfile();

    if (currentUser.role === 'admin') {
        const [userResponse, activityResponse, statsResponse] = await Promise.all([
            api('/admin/users'),
            api('/admin/activity'),
            api('/admin/stats')
        ]);

        users = userResponse.users || [];

        renderUsers();
        renderActivity(activityResponse.activity || []);

        $('sTotal').textContent = statsResponse.totalKeys;
        $('sActive').textContent = statsResponse.activeKeys;
        $('sDevices').textContent = statsResponse.devices;
        $('sApps').textContent = statsResponse.appRegistrations;

        // Keep admin tables updated after revoke/generate operations.
        if ($('allkeys')?.classList.contains('active')) {
            await renderAllKeys();
        }
    } else {
        $('sTotal').textContent = keys.length;
        $('sActive').textContent = keys.filter(
            (key) => getKeyStatus(key) === 'active'
        ).length;

        $('sDevices').textContent = new Set(
            keys.map((key) => key.deviceId).filter(Boolean)
        ).size;

        $('sApps').textContent = keys.filter(
            (key) => key.appId
        ).length;
    }
}

/* -------------------- Dashboard -------------------- */

function renderOverview() {
    const recentKeys = keys.slice(0, 5);

    $('recentRows').innerHTML = recentKeys.length
        ? recentKeys.map((key) => `
            <tr>
                <td><button type="button" class="key-copy key" data-action="copy-key" data-key-value="${escapeHTML(key.key)}" title="Copy key">${escapeHTML(key.key)}</button></td>
                <td>${escapeHTML(key.type)}</td>
                <td class="id">${escapeHTML(key.deviceId || 'Unbound')}</td>
                <td class="id">${escapeHTML(key.appId || 'Unbound')}</td>
                <td>${formatDate(key.expiresAt)}</td>
                <td>${statusBadge(key)}</td>
            </tr>
        `).join('')
        : `
            <tr>
                <td colspan="6" class="empty">
                    No keys yet. Generate your first key.
                </td>
            </tr>
        `;
}

/* -------------------- User Key List -------------------- */

function renderKeys() {
    const query = ($('keySearch')?.value || '').toLowerCase();
    const selectedStatus = $('statusFilter')?.value || '';

    const filteredKeys = keys.filter((key) => {
        const searchableText = `
            ${key.key}
            ${key.deviceId || ''}
            ${key.appId || ''}
        `.toLowerCase();

        return searchableText.includes(query) &&
            (!selectedStatus || getKeyStatus(key) === selectedStatus);
    });

    $('keysRows').innerHTML = filteredKeys.length
        ? filteredKeys.map((key) => `
            <tr>
                <td><button type="button" class="key-copy key" data-action="copy-key" data-key-value="${escapeHTML(key.key)}" title="Copy key">${escapeHTML(key.key)}</button></td>
                <td>${escapeHTML(key.type)}</td>
                <td class="id">${escapeHTML(key.deviceId || 'Unbound')}</td>
                <td class="id">${escapeHTML(key.appId || 'Unbound')}</td>
                <td>${formatDate(key.createdAt)}</td>
                <td>${formatDate(key.expiresAt)}</td>
                <td>${statusBadge(key)}</td>
                <td>
                    ${keyActionButtons(key)}
                </td>
            </tr>
        `).join('')
        : `
            <tr>
                <td colspan="8" class="empty">No matching keys.</td>
            </tr>
        `;
}

/* -------------------- My Profile -------------------- */

function renderProfile() {
    $('profileKeys').innerHTML = keys.length
        ? keys.map((key) => `
            <tr>
                <td><button type="button" class="key-copy key" data-action="copy-key" data-key-value="${escapeHTML(key.key)}" title="Copy key">${escapeHTML(key.key)}</button></td>
                <td class="id">${escapeHTML(key.deviceId || 'Unbound')}</td>
                <td class="id">${escapeHTML(key.appId || 'Unbound')}</td>
                <td>${statusBadge(key)}</td>
                <td>${formatDate(key.expiresAt)}</td>
                <td>${keyActionButtons(key)}</td>
            </tr>
        `).join('')
        : `
            <tr>
                <td colspan="6" class="empty">
                    No keys associated with this profile.
                </td>
            </tr>
        `;
}

/* -------------------- Key Lifecycle Controls -------------------- */

async function runKeyAction(keyId, action) {
    const labels = {
        activate: 'Activate this key?',
        deactivate: 'Deactivate this key? It can be activated again before expiry.',
        revoke: 'Permanently revoke this key? This cannot be undone.'
    };

    if (!labels[action] || !window.confirm(labels[action])) return;

    try {
        await api(`/keys/${encodeURIComponent(keyId)}/${action}`, {
            method: 'POST'
        });

        const successMessages = {
            activate: 'Key activated successfully.',
            deactivate: 'Key deactivated successfully.',
            revoke: 'Key permanently revoked.'
        };

        showToast(successMessages[action]);
        await refreshData();

        if (selectedUser) {
            await openUserProfile(selectedUser.id);
        }
    } catch (error) {
        showToast(error.message);
    }
}

function activateKey(keyId) {
    return runKeyAction(keyId, 'activate');
}

function deactivateKey(keyId) {
    return runKeyAction(keyId, 'deactivate');
}

function revokeKey(keyId) {
    return runKeyAction(keyId, 'revoke');
}

async function deleteKey(keyId) {
    if (!window.confirm(
        'Permanently delete this key from the database? This action cannot be undone.'
    )) return;

    try {
        await api(`/keys/${encodeURIComponent(keyId)}`, {
            method: 'DELETE'
        });

        showToast('Key permanently deleted.');
        await refreshData();

        if (selectedUser) {
            await openUserProfile(selectedUser.id);
        }
    } catch (error) {
        showToast(error.message);
    }
}

/* -------------------- Navigation -------------------- */

function navigateTo(page) {
    const adminPages = ['users', 'allkeys', 'activity'];

    if (adminPages.includes(page) && currentUser?.role !== 'admin') {
        page = 'overview';
    }

    document.querySelectorAll('.page').forEach((section) => {
        section.classList.toggle('active', section.id === page);
    });

    document.querySelectorAll('#nav button').forEach((button) => {
        button.classList.toggle('active', button.dataset.page === page);
    });

    const pageNames = {
        allkeys: 'All Keys',
        users: 'User Profiles',
        activity: 'Activity Log',
        overview: 'Overview',
        keys: 'My Keys',
        profile: 'My Profile'
    };

    $('pageTitle').textContent = pageNames[page] || page;

    if (page === 'allkeys' && currentUser?.role === 'admin') {
        renderAllKeys();
    }
}

$('nav').addEventListener('click', (event) => {
    const button = event.target.closest('button[data-page]');

    if (button) {
        navigateTo(button.dataset.page);
        closeMobileMenu();
    }
});

/* -------------------- Mobile Hamburger Menu -------------------- */

const menuToggle = $('menuToggle');
const sidebar = document.querySelector('.sidebar');

function closeMobileMenu() {
    if (!menuToggle || !sidebar) return;

    sidebar.classList.remove('menu-open');
    menuToggle.setAttribute('aria-expanded', 'false');
    menuToggle.setAttribute('aria-label', 'Open navigation menu');
}

function toggleMobileMenu() {
    if (!menuToggle || !sidebar) return;

    const isOpen = sidebar.classList.toggle('menu-open');

    menuToggle.setAttribute('aria-expanded', String(isOpen));
    menuToggle.setAttribute(
        'aria-label',
        isOpen ? 'Close navigation menu' : 'Open navigation menu'
    );
}

if (menuToggle && sidebar) {
    menuToggle.addEventListener('click', (event) => {
        event.stopPropagation();
        toggleMobileMenu();
    });

    document.addEventListener('click', (event) => {
        if (
            sidebar.classList.contains('menu-open') &&
            !sidebar.contains(event.target)
        ) {
            closeMobileMenu();
        }
    });

    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') closeMobileMenu();
    });

    window.addEventListener('resize', () => {
        if (window.innerWidth > 900) closeMobileMenu();
    });
}

document.querySelectorAll('[data-goto]').forEach((button) => {
    button.addEventListener('click', () => {
        navigateTo(button.dataset.goto);
    });
});

$('keySearch').addEventListener('input', renderKeys);
$('statusFilter').addEventListener('change', renderKeys);

/* -------------------- Key Generation Modal -------------------- */

function openKeyModal() {
    $('newKeyResult').classList.add('hide');
    $('keyForm').reset();

    // Default expiry is eight days from opening the key generator.
    // datetime-local values are set in the browser's local time zone.
    const expiryInput = $('keyForm').elements.namedItem('expiresAt');
    if (expiryInput) {
        const now = Date.now();
        const defaultExpiry = new Date(now + 8 * 24 * 60 * 60 * 1000);
        const toLocalInput = (date) => new Date(
            date.getTime() - date.getTimezoneOffset() * 60000
        ).toISOString().slice(0, 16);
        expiryInput.min = toLocalInput(new Date(now + 60 * 1000));
        expiryInput.value = toLocalInput(defaultExpiry);
    }

    $('ownerSelect').innerHTML = `
        <option value="">My account</option>
        ${users.map((user) => `
            <option value="${escapeHTML(user.id)}">
                ${escapeHTML(user.name)} (${escapeHTML(user.email)})
            </option>
        `).join('')}
    `;

    document.querySelectorAll('#keyForm .adminOnly').forEach((element) => {
        element.classList.toggle('hide', currentUser.role !== 'admin');
    });

    $('keyModal').classList.remove('hide');
}

$('generateTop').addEventListener('click', openKeyModal);
$('generateMine').addEventListener('click', openKeyModal);
$('adminGenerate').addEventListener('click', openKeyModal);

$('closeModal').addEventListener('click', () => {
    $('keyModal').classList.add('hide');
});

$('keyForm').addEventListener('submit', async (event) => {
    event.preventDefault();

    try {
        const formData = new FormData(event.target);
        const body = {};

        for (const [name, value] of formData.entries()) {
            if (value !== '') {
                body[name] = value;
            }
        }

        body.deviceId = String(body.deviceId || '').trim();
        body.appId = String(body.appId || '').trim();

        if (!body.deviceId || !body.appId) {
            showToast('Device ID and App ID are required.');
            return;
        }

        const expiryValue = String(body.expiresAt || '').trim();
        const expiryDate = new Date(expiryValue);

        if (!expiryValue || Number.isNaN(expiryDate.getTime())) {
            showToast('Choose a valid expiry date and time.');
            return;
        }

        if (expiryDate.getTime() <= Date.now()) {
            showToast('Expiry must be a future date and time.');
            return;
        }

        body.expiresAt = expiryDate.toISOString();

        const result = await api('/keys/generate', {
            method: 'POST',
            body: JSON.stringify(body)
        });

        $('newKeyResult').textContent =
            `Generated key: ${result.key.key} — copy and save it now.`;

        $('newKeyResult').classList.remove('hide');

        await refreshData();
    } catch (error) {
        showToast(error.message);
    }
});

/* -------------------- Admin: User Profiles -------------------- */

function renderUsers() {
    const query = ($('userSearch')?.value || '').toLowerCase();

    const filteredUsers = users.filter((user) => {
        return `${user.name} ${user.email}`.toLowerCase().includes(query);
    });

    $('usersRows').innerHTML = filteredUsers.length
        ? filteredUsers.map((user) => `
            <tr>
                <td>${escapeHTML(user.name)}</td>
                <td>${escapeHTML(user.email)}</td>
                <td>${user.keyCount}</td>
                <td>${user.keyLimit}</td>
                <td>
                    ${user.disabled
                ? '<span class="pill revoked">Disabled</span>'
                : '<span class="pill active">Active</span>'}
                </td>
                <td>
                    <button class="secondary" type="button" data-action="open-user" data-user-id="${escapeHTML(user.id)}">
                        Open profile
                    </button>
                    ${user.role !== 'admin' ? `
                    <button class="secondary" type="button" data-action="toggle-unlimited-key-access" data-user-id="${escapeHTML(user.id)}">
                        ${user.unlimitedKeyAccess ? 'Disable unlimited keys' : 'Enable unlimited keys'}
                    </button>
                    <button class="danger" type="button" data-action="delete-user" data-user-id="${escapeHTML(user.id)}">
                        Delete user
                    </button>` : ''}
                </td>
            </tr>
        `).join('')
        : `
            <tr>
                <td colspan="6" class="empty">No users found.</td>
            </tr>
        `;
}

$('userSearch').addEventListener('input', renderUsers);

async function openUserProfile(userId) {
    selectedUser = users.find((user) => user.id === userId);

    if (!selectedUser) return;

    try {
        // Fetch only the selected user's keys. The backend permits ownerId
        // overrides for admins only; regular users remain scoped to themselves.
        const response = await api(`/keys?ownerId=${encodeURIComponent(userId)}`);

        const ownedKeys = response.keys || [];

        $('detailName').textContent = selectedUser.name;
        $('detailEmail').textContent = selectedUser.email;
        $('detailLimit').value = selectedUser.keyLimit;

        const unlimitedButton = $('toggleUnlimitedKeyAccess');
        if (unlimitedButton) {
            unlimitedButton.textContent = selectedUser.unlimitedKeyAccess
                ? 'Disable unlimited keys'
                : 'Enable unlimited keys';
            unlimitedButton.setAttribute(
                'aria-pressed',
                selectedUser.unlimitedKeyAccess ? 'true' : 'false'
            );
        }

        $('toggleUser').textContent = selectedUser.disabled
            ? 'Enable account'
            : 'Disable account';

        $('detailKeys').innerHTML = ownedKeys.length
            ? ownedKeys.map((key) => `
                <tr>
                    <td><button type="button" class="key-copy key" data-action="copy-key" data-key-value="${escapeHTML(key.key)}" title="Copy key">${escapeHTML(key.key)}</button></td>
                    <td>${escapeHTML(key.type)}</td>
                    <td class="id">${escapeHTML(key.deviceId || 'Unbound')}</td>
                    <td class="id">${escapeHTML(key.appId || 'Unbound')}</td>
                    <td>${formatDate(key.expiresAt)}</td>
                    <td>${statusBadge(key)}</td>
                    <td>
                        ${keyActionButtons(key)}
                    </td>
                </tr>
            `).join('')
            : `
                <tr>
                    <td colspan="7" class="empty">No keys for this user.</td>
                </tr>
            `;

        $('userDetail').classList.remove('hide');
        $('users').querySelector('.panel').classList.add('hide');
    } catch (error) {
        showToast(error.message);
    }
}

$('closeDetail').addEventListener('click', () => {
    $('userDetail').classList.add('hide');
    $('users').querySelector('.panel').classList.remove('hide');
});

$('saveLimit').addEventListener('click', async () => {
    if (!selectedUser) return;

    try {
        const result = await api(`/admin/users/${encodeURIComponent(selectedUser.id)}`, {
            method: 'PATCH',
            body: JSON.stringify({
                keyLimit: Number($('detailLimit').value)
            })
        });

        Object.assign(selectedUser, result.user);

        showToast('Key limit updated.');
        await refreshData();
        await openUserProfile(selectedUser.id);
    } catch (error) {
        showToast(error.message);
    }
});

$('toggleUser').addEventListener('click', async () => {
    if (!selectedUser) return;

    try {
        const result = await api(`/admin/users/${encodeURIComponent(selectedUser.id)}`, {
            method: 'PATCH',
            body: JSON.stringify({
                disabled: !selectedUser.disabled
            })
        });

        Object.assign(selectedUser, result.user);

        showToast('Account status updated.');
        await refreshData();
        await openUserProfile(selectedUser.id);
    } catch (error) {
        showToast(error.message);
    }
});

$('toggleUnlimitedKeyAccess')?.addEventListener('click', async () => {
    if (!selectedUser || selectedUser.role === 'admin') return;

    const enable = !Boolean(selectedUser.unlimitedKeyAccess);

    try {
        const result = await api(
            `/admin/users/${encodeURIComponent(selectedUser.id)}`,
            {
                method: 'PATCH',
                body: JSON.stringify({ unlimitedKeyAccess: enable })
            }
        );

        Object.assign(selectedUser, result.user);
        const cachedUser = users.find(
            (item) => String(item.id) === String(selectedUser.id)
        );
        if (cachedUser) Object.assign(cachedUser, result.user);

        showToast(enable
            ? 'Unlimited key generation enabled.'
            : 'Unlimited key generation disabled.');

        await refreshData();
        await openUserProfile(selectedUser.id);
    } catch (error) {
        showToast(error.message);
    }
});

async function toggleUnlimitedKeyAccess(userId) {
    const user = users.find((item) => String(item.id) === String(userId));
    if (!user || user.role === 'admin') return;

    const enable = !Boolean(user.unlimitedKeyAccess);
    const confirmed = window.confirm(
        `${enable ? 'Enable' : 'Disable'} unlimited key generation for ${user.name}?`
    );
    if (!confirmed) return;

    try {
        const result = await api(`/admin/users/${encodeURIComponent(userId)}`, {
            method: 'PATCH',
            body: JSON.stringify({ unlimitedKeyAccess: enable })
        });

        Object.assign(user, result.user);
        if (selectedUser && String(selectedUser.id) === String(userId)) {
            Object.assign(selectedUser, result.user);
        }

        showToast(enable
            ? 'Unlimited key generation enabled.'
            : 'Unlimited key generation disabled.');
        await refreshData();
    } catch (error) {
        showToast(error.message);
    }
}

async function deleteUser(userId) {
    const user = users.find((item) => String(item.id) === String(userId));
    if (!user || user.role === 'admin') {
        showToast('This account cannot be deleted.');
        return;
    }

    const confirmed = window.confirm(
        `Permanently delete ${user.name} (${user.email}) and all keys owned by this account? This cannot be undone.`
    );
    if (!confirmed) return;

    try {
        await api(`/admin/users/${encodeURIComponent(userId)}`, {
            method: 'DELETE'
        });

        if (selectedUser && String(selectedUser.id) === String(userId)) {
            selectedUser = null;
            $('userDetail')?.classList.add('hide');
            $('users')?.querySelector('.panel')?.classList.remove('hide');
        }

        showToast('User account deleted.');
        await refreshData();
    } catch (error) {
        showToast(error.message);
    }
}

/* -------------------- Admin: All Keys -------------------- */

async function renderAllKeys() {
    if (currentUser?.role !== 'admin') return;

    try {
        const response = await api('/keys');

        const query = ($('allSearch').value || '').toLowerCase();
        const selectedStatus = $('allStatus').value;

        const allKeys = Array.isArray(response.keys) ? response.keys : [];
        const filteredKeys = allKeys.filter((key) => {
            const ownerName = key.owner?.name || '';
            const ownerEmail = key.owner?.email || '';

            const searchableText = `
                ${key.key}
                ${ownerName}
                ${ownerEmail}
                ${key.deviceId || ''}
                ${key.appId || ''}
            `.toLowerCase();

            return searchableText.includes(query) &&
                (!selectedStatus || getKeyStatus(key) === selectedStatus);
        });

        $('allKeysRows').innerHTML = filteredKeys.length
            ? filteredKeys.map((key) => `
                <tr>
                    <td><button type="button" class="key-copy key" data-action="copy-key" data-key-value="${escapeHTML(key.key)}" title="Copy key">${escapeHTML(key.key)}</button></td>
                    <td>
                        ${escapeHTML(key.owner?.name || 'Unassigned')}
                        <br>
                        <span class="muted">${escapeHTML(key.owner?.email || '')}</span>
                    </td>
                    <td>${escapeHTML(key.type)}</td>
                    <td class="id">${escapeHTML(key.deviceId || 'Unbound')}</td>
                    <td class="id">${escapeHTML(key.appId || 'Unbound')}</td>
                    <td>${formatDate(key.expiresAt)}</td>
                    <td>${statusBadge(key)}</td>
                    <td>
                        ${keyActionButtons(key)}
                    </td>
                </tr>
            `).join('')
            : `
                <tr>
                    <td colspan="8" class="empty">No keys found.</td>
                </tr>
            `;
    } catch (error) {
        showToast(error.message);
    }
}

$('allSearch').addEventListener('input', renderAllKeys);
$('allStatus').addEventListener('change', renderAllKeys);

/* -------------------- Admin: Activity Log -------------------- */

function renderActivity(items) {
    $('activityRows').innerHTML = items.length
        ? items.map((item) => `
            <div class="event">
                <b>${escapeHTML(String(item.action || 'event').replace(/_/g, ' '))}</b>
                <div>${escapeHTML(item.details)}</div>
                <small>
                    ${escapeHTML(item.actor?.name || 'System')}
                    · ${formatDate(item.createdAt)}
                </small>
            </div>
        `).join('')
        : '<p class="muted">No activity recorded.</p>';
}

/* -------------------- Dynamic Table Actions -------------------- */

// Buttons rendered inside tables use data attributes instead of inline onclick handlers.
document.addEventListener('click', (event) => {
    const actionButton = event.target.closest('[data-action]');
    if (!actionButton) return;

    const action = actionButton.dataset.action;

    if (action === 'copy-key') {
        const keyValue = actionButton.dataset.keyValue || '';
        copyTextToClipboard(keyValue).then((copied) => {
            showToast(copied ? 'Key copied to clipboard.' : 'Copy failed. Select and copy the key manually.');
        });
    } else if (action === 'activate-key') {
        activateKey(actionButton.dataset.keyId);
    } else if (action === 'deactivate-key') {
        deactivateKey(actionButton.dataset.keyId);
    } else if (action === 'revoke-key') {
        revokeKey(actionButton.dataset.keyId);
    } else if (action === 'delete-key') {
        deleteKey(actionButton.dataset.keyId);
    } else if (action === 'open-user') {
        openUserProfile(actionButton.dataset.userId);
    } else if (action === 'delete-user') {
        deleteUser(actionButton.dataset.userId);
    } else if (action === 'toggle-unlimited-key-access') {
        toggleUnlimitedKeyAccess(actionButton.dataset.userId);
    }
});


/* -------------------- Password Recovery -------------------- */

const forgotPasswordForm = $('forgotPasswordForm');
if (forgotPasswordForm) {
    forgotPasswordForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const message = $('forgotPasswordMessage');
        const submitButton = forgotPasswordForm.querySelector('button[type="submit"]');
        if (submitButton) submitButton.disabled = true;

        try {
            const formData = new FormData(forgotPasswordForm);
            const result = await api('/auth/forgot-password', {
                method: 'POST',
                body: JSON.stringify(Object.fromEntries(formData))
            });
            if (message) {
                message.textContent = result.message ||
                    'If the account exists, password reset instructions have been sent.';
                message.className = 'muted';
            }
            forgotPasswordForm.reset();
        } catch (error) {
            if (message) {
                message.textContent = error.message;
                message.className = 'error';
            }
        } finally {
            if (submitButton) submitButton.disabled = false;
        }
    });
}

const resetPasswordForm = $('resetPasswordForm');
if (resetPasswordForm) {
    resetPasswordForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const message = $('resetPasswordMessage');
        const submitButton = resetPasswordForm.querySelector('button[type="submit"]');
        const formData = new FormData(resetPasswordForm);
        const password = String(formData.get('password') || '');
        const confirmPassword = String(formData.get('confirmPassword') || '');

        if (password !== confirmPassword) {
            if (message) {
                message.textContent = 'Passwords do not match.';
                message.className = 'error';
            }
            return;
        }

        if (submitButton) submitButton.disabled = true;
        try {
            const token = new URLSearchParams(window.location.search).get('token') || '';
            const result = await api('/auth/reset-password', {
                method: 'POST',
                body: JSON.stringify({ token, password })
            });
            if (message) {
                message.textContent = result.message ||
                    'Password reset successfully. You can now sign in.';
                message.className = 'muted';
            }
            resetPasswordForm.reset();
        } catch (error) {
            if (message) {
                message.textContent = error.message;
                message.className = 'error';
            }
        } finally {
            if (submitButton) submitButton.disabled = false;
        }
    });
}

/* -------------------- Initial Load -------------------- */

async function initializeApplication() {
    initializeTheme();

    try {
        const response = await api('/auth/me');

        currentUser = response.user;

        await startApplication();
    } catch {
        showAuth();
    }
}

initializeApplication();
/* -------------------- Account Verification -------------------- */

const accountVerificationResult = $('accountVerificationResult');
const accountVerificationString = $('accountVerificationString');
const accountVerificationStatus = $('accountVerificationStatus');
const generateAccountVerificationButton = $('generateAccountVerification');

/*
 * This is account-level verification, so there is no App ID field.
 * The backend stores the verification hash; the browser keeps the returned
 * plain string in localStorage so it remains visible after page refresh.
 */
function accountVerificationStorageKey() {
    const accountId = currentUser?.id || currentUser?._id || currentUser?.email;
    return accountId
        ? `keyforge-account-verification:${String(accountId)}`
        : null;
}

function saveAccountVerificationString(value) {
    const storageKey = accountVerificationStorageKey();
    if (!storageKey) return;

    try {
        if (value) {
            localStorage.setItem(storageKey, value);
        } else {
            localStorage.removeItem(storageKey);
        }
    } catch (error) {
        console.warn('Account verification string could not be saved locally.', error);
    }
}

function showAccountVerificationString(value) {
    if (!accountVerificationResult || !accountVerificationString) return;

    accountVerificationString.value = value || '';
    accountVerificationResult.classList.toggle('hide', !value);
}

async function generateAccountVerificationString({ automatic = false } = {}) {
    if (generateAccountVerificationButton) {
        generateAccountVerificationButton.disabled = true;
        generateAccountVerificationButton.textContent = 'Generate';
    }

    try {
        const result = await api('/account-verification/rotate', {
            method: 'POST',
            body: JSON.stringify({})
        });

        const value = String(result.verificationString || '');
        if (!value) {
            throw new Error('The server did not return a verification string.');
        }

        saveAccountVerificationString(value);
        showAccountVerificationString(value);

        if (accountVerificationStatus) {
            accountVerificationStatus.textContent =
                automatic
                    ? 'Verification string generated automatically.'
                    : 'Verification string generated.';
        }

        if (!automatic) showToast('Account verification string generated.');
    } catch (error) {
        if (accountVerificationStatus) {
            accountVerificationStatus.textContent = error.message;
        }
        showToast(error.message);
    } finally {
        if (generateAccountVerificationButton) {
            generateAccountVerificationButton.disabled = false;
            generateAccountVerificationButton.textContent = 'Generate';
        }
    }
}

async function initializeAccountVerification() {
    if (!accountVerificationResult || !accountVerificationString) return;

    if (generateAccountVerificationButton) {
        generateAccountVerificationButton.textContent = 'Generate';
    }

    const storageKey = accountVerificationStorageKey();
    let savedValue = '';

    try {
        savedValue = storageKey ? localStorage.getItem(storageKey) || '' : '';
    } catch (error) {
        console.warn('Could not load saved verification string.', error);
    }

    if (savedValue) {
        showAccountVerificationString(savedValue);

        if (accountVerificationStatus) {
            accountVerificationStatus.textContent =
                'Your account verification string is saved.';
        }
        return;
    }

    try {
        const result = await api('/account-verification/current');

        if (result.status !== 'active') {
            showAccountVerificationString('');

            if (accountVerificationStatus) {
                accountVerificationStatus.textContent =
                    'Verification string is revoked. Click Generate to create a new one.';
            }
            return;
        }

        const value = String(result.verificationString || '');

        if (!value) {
            throw new Error('Server returned an empty verification string.');
        }

        saveAccountVerificationString(value);
        showAccountVerificationString(value);

        if (accountVerificationStatus) {
            accountVerificationStatus.textContent =
                'Your account verification string is loaded.';
        }
    } catch (error) {
        if (accountVerificationStatus) {
            accountVerificationStatus.textContent = error.message;
        }
    }
}

generateAccountVerificationButton?.addEventListener('click', async () => {
    await generateAccountVerificationString();
});

$('revokeAccountVerification')?.addEventListener('click', async () => {
    if (!window.confirm(
        'Revoke this account verification string? It will stop working immediately.'
    )) return;

    try {
        await api('/account-verification/revoke', {
            method: 'POST',
            body: JSON.stringify({})
        });

        saveAccountVerificationString('');
        showAccountVerificationString('');

        if (accountVerificationStatus) {
            accountVerificationStatus.textContent =
                'Account verification string revoked.';
        }

        showToast('Verification string revoked.');
    } catch (error) {
        showToast(error.message);
    }
});

async function copyTextToClipboard(value) {
    const text = String(value ?? '').trim();
    if (!text) return false;

    try {
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(text);
            return true;
        }
    } catch (_) {
        // Use the compatibility fallback.
    }

    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute('readonly', '');
    textarea.style.position = 'fixed';
    textarea.style.left = '-9999px';
    textarea.style.top = '0';
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    textarea.setSelectionRange(0, textarea.value.length);

    let copied = false;
    try {
        copied = document.execCommand('copy');
    } catch (_) {
        copied = false;
    } finally {
        textarea.remove();
    }
    return copied;
}

$('copyAccountVerification')?.addEventListener('click', async () => {
    const value = accountVerificationString?.value || '';

    if (!value) {
        showToast('No verification string to copy.');
        return;
    }

    const copied = await copyTextToClipboard(value);
    showToast(copied
        ? 'Verification string copied.'
        : 'Copy failed. Select and copy the string manually.');
});