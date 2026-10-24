const state = {
  sites: [],
  changes: [],
  siteChanges: [],
  notificationSettings: null,
  notificationDirty: false,
  appVersion: null,
  selectedSiteId: null,
  activeView: 'overview',
  activeViewEl: null,
  activeNavEl: null,
  refreshInFlight: false,
  dialogAvailableGroups: [],
  dialogNotifyAllGroups: true,
  dialogAccounts: [],
  dialogStoredPlatform: null,
  reportGroups: [],
  reportLayout: null,
  reportLayoutDirty: false,
  botSettings: null,
  botSettingsDirty: false,
};

const els = {
  navItems: Array.from(document.querySelectorAll('[data-view-target]')),
  views: Array.from(document.querySelectorAll('[data-view]')),
  toastContainer: document.getElementById('toastContainer'),
  logoutBtn: document.getElementById('logoutBtn'),
  statsSites: document.getElementById('stat-sites'),
  statsEnabled: document.getElementById('stat-enabled'),
  statsOk: document.getElementById('stat-ok'),
  statsFailed: document.getElementById('stat-failed'),
  statsChanges: document.getElementById('stat-changes'),
  sidebarCount: document.getElementById('sidebar-count'),
  appVersion: document.getElementById('appVersion'),
  overviewSitesBody: document.getElementById('overviewSitesBody'),
  overviewChangesBody: document.getElementById('overviewChangesBody'),
  sitesBody: document.getElementById('sitesBody'),
  changesBody: document.getElementById('changesBody'),
  detailPane: document.getElementById('detailPane'),
  detailSubtitle: document.getElementById('detailSubtitle'),
  refreshBtn: document.getElementById('refreshBtn'),
  addSiteBtn: document.getElementById('addSiteBtn'),
  searchInput: document.getElementById('searchInput'),
  statusFilter: document.getElementById('statusFilter'),
  dialog: document.getElementById('siteDialog'),
  form: document.getElementById('siteForm'),
  dialogTitle: document.getElementById('dialogTitle'),
  siteId: document.getElementById('siteId'),
  siteName: document.getElementById('siteName'),
  sitePlatform: document.getElementById('sitePlatform'),
  siteBaseUrl: document.getElementById('siteBaseUrl'),
  siteInterval: document.getElementById('siteInterval'),
  siteUsageDivisor: document.getElementById('siteUsageDivisor'),
  sub2apiUsageEndpointField: document.getElementById('sub2apiUsageEndpointField'),
  siteSub2apiUsageEndpoint: document.getElementById('siteSub2apiUsageEndpoint'),
  siteLoginEnabled: document.getElementById('siteLoginEnabled'),
  siteAccountsSection: document.getElementById('siteAccountsSection'),
  siteAccountsList: document.getElementById('siteAccountsList'),
  addAccountBtn: document.getElementById('addAccountBtn'),
  sub2apiAuthHelp: document.getElementById('sub2apiAuthHelp'),
  siteBalanceAlertEnabled: document.getElementById('siteBalanceAlertEnabled'),
  siteBalanceAlertThreshold: document.getElementById('siteBalanceAlertThreshold'),
  siteNotifyGroupsSection: document.getElementById('siteNotifyGroupsSection'),
  siteNotifyGroupsList: document.getElementById('siteNotifyGroupsList'),
  selectAllNotifyGroupsBtn: document.getElementById('selectAllNotifyGroupsBtn'),
  clearNotifyGroupsBtn: document.getElementById('clearNotifyGroupsBtn'),
  newapiAuthSection: document.getElementById('newapiAuthSection'),
  siteEnabled: document.getElementById('siteEnabled'),
  dialogMsg: document.getElementById('dialogMsg'),
  saveSiteBtn: document.getElementById('saveSiteBtn'),
  siteDialogTabs: Array.from(document.querySelectorAll('[data-site-tab]')),
  siteDialogPanels: Array.from(document.querySelectorAll('[data-site-tab-panel]')),
  testConnBtn: document.getElementById('testConnBtn'),
  closeDialogBtn: document.getElementById('closeDialogBtn'),
  notifyForm: document.getElementById('notifyForm'),
  wecomEnabled: document.getElementById('wecomEnabled'),
  wecomWebhook: document.getElementById('wecomWebhook'),
  wecomStatus: document.getElementById('wecomStatus'),
  testWecomBtn: document.getElementById('testWecomBtn'),
  feishuEnabled: document.getElementById('feishuEnabled'),
  feishuWebhook: document.getElementById('feishuWebhook'),
  feishuSecret: document.getElementById('feishuSecret'),
  feishuStatus: document.getElementById('feishuStatus'),
  testFeishuBtn: document.getElementById('testFeishuBtn'),
  qqEnabled: document.getElementById('qqEnabled'),
  qqApiUrl: document.getElementById('qqApiUrl'),
  qqApiToken: document.getElementById('qqApiToken'),
  qqGroupId: document.getElementById('qqGroupId'),
  qqStatus: document.getElementById('qqStatus'),
  testQqBtn: document.getElementById('testQqBtn'),
  emailEnabled: document.getElementById('emailEnabled'),
  emailStatus: document.getElementById('emailStatus'),
  smtpHost: document.getElementById('smtpHost'),
  smtpPort: document.getElementById('smtpPort'),
  smtpUsername: document.getElementById('smtpUsername'),
  smtpPassword: document.getElementById('smtpPassword'),
  smtpUseSsl: document.getElementById('smtpUseSsl'),
  smtpFrom: document.getElementById('smtpFrom'),
  smtpTo: document.getElementById('smtpTo'),
  notifyStatus: document.getElementById('notifyStatus'),
  testEmailBtn: document.getElementById('testEmailBtn'),
  siteReportGroup: document.getElementById('siteReportGroup'),
  reportGroupForm: document.getElementById('reportGroupForm'),
  reportGroupName: document.getElementById('reportGroupName'),
  reportGroupsBoard: document.getElementById('reportGroupsBoard'),
  reportLayoutStatus: document.getElementById('reportLayoutStatus'),
  saveReportLayoutBtn: document.getElementById('saveReportLayoutBtn'),
  botAliasList: document.getElementById('botAliasList'),
  botTemplateList: document.getElementById('botTemplateList'),
  botNegativeQuotaThreshold: document.getElementById('botNegativeQuotaThreshold'),
  addBotAliasBtn: document.getElementById('addBotAliasBtn'),
  saveBotSettingsBtn: document.getElementById('saveBotSettingsBtn'),
  botSettingsStatus: document.getElementById('botSettingsStatus'),
};

function fmtTime(value) {
  if (!value) return '-';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString('zh-CN', { hour12: false });
}

function escapeHtml(str) {
  return String(str ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

function badgeClass(status) {
  if (status === 'ok') return 'ok';
  if (status === 'failed') return 'bad';
  if (status === 'warning') return 'warn';
  return 'neutral';
}

function changeClass(change) {
  if (change.change_type === 'group_removed') return 'bad';
  if (change.change_type === 'balance_low') return 'warn';
  if (change.change_type === 'balance_recovered') return 'ok';
  if (change.change_type === 'ratio_changed' && Number(change.change_percent) > 0) return 'warn';
  if (change.change_type === 'ratio_changed') return 'ok';
  return 'neutral';
}

function changeTypeLabel(type) {
  const labels = {
    ratio_changed: '倍率变化',
    group_added: '新增分组',
    group_removed: '删除分组',
    group_renamed: '分组更名',
    desc_changed: '描述变化',
    status_changed: '状态变化',
    is_exclusive_changed: '专属变化',
    subscription_type_changed: '订阅变化',
    rpm_limit_changed: 'RPM 变化',
    platform_changed: '平台变化',
    balance_low: '低余额',
    balance_recovered: '余额恢复',
  };
  return labels[type] || type || '-';
}

function ratioLabel(item) {
  if (!item) return '-';
  const ratio = item.ratio;
  if (item.ratio_type === 'text') return `${ratio}`;
  const n = Number(ratio);
  if (Number.isFinite(n)) {
    const text = n.toFixed(8).replace(/0+$/, '').replace(/\.$/, '');
    return `${text || '0'}x`;
  }
  return `${ratio}`;
}

function usageDivisorLabel(value) {
  const divisor = Number(value);
  if (!Number.isFinite(divisor) || divisor <= 0) return '1 : 1';
  const text = divisor.toFixed(8).replace(/0+$/, '').replace(/\.$/, '');
  return `1 : ${text || '1'}`;
}

function balanceLabel(site) {
  if (site.current_balance === null || site.current_balance === undefined) return '-';
  const value = Number(site.current_balance);
  if (!Number.isFinite(value)) return '-';
  const currency = String(site.balance_currency || '').toUpperCase();
  const symbol = currency === 'USD' ? '$' : ['CNY', 'RMB'].includes(currency) ? '¥' : `${currency} `;
  return `${symbol}${value.toFixed(2)}`;
}

function safeHttpUrl(value) {
  try {
    const url = new URL(String(value || ''));
    return ['http:', 'https:'].includes(url.protocol) ? url.href : '';
  } catch {
    return '';
  }
}

function upstreamLink(baseUrl) {
  const href = safeHttpUrl(baseUrl);
  if (!href) return escapeHtml(baseUrl || '-');
  return `<a class="upstream-link" href="${escapeHtml(href)}" target="_blank" rel="noopener noreferrer" title="在新标签页打开上游站点">${escapeHtml(baseUrl)} ↗</a>`;
}

function showToast(message, type = 'success') {
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  els.toastContainer.appendChild(toast);
  window.setTimeout(() => toast.classList.add('visible'), 10);
  window.setTimeout(() => {
    toast.classList.remove('visible');
    window.setTimeout(() => toast.remove(), 180);
  }, 2800);
}

function setSiteDialogTab(tabName) {
  state.siteDialogTab = tabName;
  els.siteDialogTabs.forEach((button) => {
    const active = button.dataset.siteTab === tabName;
    button.classList.toggle('active', active);
    button.setAttribute('aria-selected', active ? 'true' : 'false');
  });
  els.siteDialogPanels.forEach((panel) => {
    panel.classList.toggle('active', panel.dataset.siteTabPanel === tabName);
  });
  els.testConnBtn.classList.toggle('hidden', tabName !== 'basic');
}

function availableGroupsForSite(site) {
  if (!site) return [];
  const publicGroups = Object.keys(site.current_groups || {});
  const loginGroups = Object.keys(site.current_login_groups || {});
  const activeGroups = site.login_enabled && loginGroups.length ? loginGroups : publicGroups;
  return [...new Set(activeGroups)].sort((a, b) => a.localeCompare(b, 'zh-CN'));
}

function selectedNotifyGroups() {
  return Array.from(els.siteNotifyGroupsList.querySelectorAll('input[type="checkbox"]:checked'))
    .map((input) => input.value);
}

function renderNotifyGroupPicker(groups, selectedGroups = [], selectAllByDefault = false) {
  state.dialogAvailableGroups = [...new Set([...groups, ...selectedGroups])]
    .sort((a, b) => a.localeCompare(b, 'zh-CN'));
  const selected = new Set(selectAllByDefault ? state.dialogAvailableGroups : selectedGroups);
  els.siteNotifyGroupsList.innerHTML = state.dialogAvailableGroups.length
    ? state.dialogAvailableGroups.map((name) => `
        <label class="group-picker-item">
          <input type="checkbox" value="${escapeHtml(name)}" ${selected.has(name) ? 'checked' : ''} />
          <span>${escapeHtml(name)}</span>
        </label>
      `).join('')
    : '<div class="empty-inline">暂无已采集分组</div>';
}

function platformLabel(siteOrValue) {
  const value = typeof siteOrValue === 'string' ? siteOrValue : (siteOrValue?.platform || 'newapi');
  return value === 'sub2api' ? 'sub2api' : 'NewAPI';
}

function accountCards() {
  return Array.from(els.siteAccountsList.querySelectorAll('.account-card'));
}

function accountField(card, name) {
  return card.querySelector(`[data-field="${name}"]`);
}

function accountCardSummary(card) {
  const id = Number(card.dataset.accountId);
  return id ? state.dialogAccounts.find((account) => account.id === id) || null : null;
}

function accountsVisible() {
  return els.sitePlatform.value === 'sub2api' || els.siteLoginEnabled.checked;
}

function accountStatusHtml(account) {
  if (!account) return '<span class="muted">新账号，保存后开始检测</span>';
  const parts = [];
  const balance = balanceLabel(account);
  parts.push(`余额 <b class="${account.balance_alert_active ? 'balance-low' : ''}">${escapeHtml(balance)}</b>`);
  parts.push(account.login_last_error
    ? `<span class="account-error">登录异常：${escapeHtml(account.login_last_error)}</span>`
    : account.login_last_check_at ? '登录正常' : '尚未检测');
  if (account.balance_last_error) parts.push(`<span class="account-error">余额采集：${escapeHtml(account.balance_last_error)}</span>`);
  return parts.join(' · ');
}

function accountCardHtml(account) {
  return `
    <div class="account-card" data-account-id="${account?.id || ''}" data-stored-mode="${escapeHtml(account?.auth_mode || 'password')}">
      <div class="account-card-head">
        <input class="input account-name-input" data-field="name" maxlength="40" placeholder="账号名称，例如：主号" value="${escapeHtml(account?.name || '')}" />
        <span class="tag strong account-primary-tag">主账号</span>
        <div class="action-row">
          <button type="button" class="btn btn-secondary btn-small" data-account-act="primary">设为主账号</button>
          <button type="button" class="btn btn-secondary btn-small" data-account-act="test">测试</button>
          <button type="button" class="btn btn-secondary btn-small" data-account-act="usage">今日消耗</button>
          <button type="button" class="btn btn-secondary btn-small" data-account-act="remove">删除</button>
        </div>
      </div>
      <div class="dialog-grid account-newapi-fields">
        <label class="field">
          <span>系统访问令牌</span>
          <input class="input" data-field="access_token" type="password" autocomplete="off" />
        </label>
        <label class="field">
          <span>NewAPI 用户 ID</span>
          <input class="input" data-field="access_user_id" inputmode="numeric" placeholder="例如：4" value="${escapeHtml(account?.access_user_id || '')}" />
        </label>
      </div>
      <div class="dialog-grid account-sub2api-fields">
        <label class="field span-2">
          <span>认证方式</span>
          <select class="input" data-field="auth_mode">
            <option value="password" ${account?.auth_mode === 'token' ? '' : 'selected'}>账号密码登录</option>
            <option value="token" ${account?.auth_mode === 'token' ? 'selected' : ''}>导入登录态</option>
          </select>
        </label>
        <label class="field account-password-field">
          <span>用户邮箱</span>
          <input class="input" data-field="login_username" autocomplete="off" placeholder="user@example.com" value="${escapeHtml(account?.login_username || '')}" />
        </label>
        <label class="field account-password-field">
          <span>用户密码</span>
          <input class="input" data-field="login_password" type="password" autocomplete="new-password" />
        </label>
        <label class="field span-2 account-token-field">
          <span>auth_token</span>
          <input class="input" data-field="sub2api_access_token" type="password" autocomplete="off" />
        </label>
        <label class="field account-token-field">
          <span>refresh_token</span>
          <input class="input" data-field="refresh_token" type="password" autocomplete="off" />
        </label>
        <label class="field account-token-field">
          <span>token_expires_at</span>
          <input class="input" data-field="token_expires_at" autocomplete="off" placeholder="可选" value="${escapeHtml(account?.token_expires_at || '')}" />
        </label>
      </div>
      <div class="account-status">${accountStatusHtml(account)}</div>
      <div class="account-msg" data-account-msg></div>
    </div>
  `;
}

function addAccountCard(account = null) {
  els.siteAccountsList.insertAdjacentHTML('beforeend', accountCardHtml(account));
  updateAccountCards();
}

function renderAccountCards(accounts) {
  els.siteAccountsList.innerHTML = '';
  (accounts || []).forEach((account) => els.siteAccountsList.insertAdjacentHTML('beforeend', accountCardHtml(account)));
}

function cardUsesSavedAuth(card) {
  return !!card.dataset.accountId && els.sitePlatform.value === state.dialogStoredPlatform;
}

function updateAccountCards() {
  const platform = els.sitePlatform.value || 'newapi';
  const isSub2api = platform === 'sub2api';
  const siteSaved = !!els.siteId.value;
  accountCards().forEach((card, index) => {
    const account = accountCardSummary(card);
    const saved = cardUsesSavedAuth(card);
    const mode = accountField(card, 'auth_mode').value || 'password';
    const sameMode = saved && card.dataset.storedMode === mode;
    card.classList.toggle('primary', index === 0);
    card.querySelector('.account-primary-tag').classList.toggle('hidden', index !== 0);
    card.querySelector('[data-account-act="primary"]').classList.toggle('hidden', index === 0);
    card.querySelector('[data-account-act="usage"]').classList.toggle('hidden', !siteSaved || !card.dataset.accountId);
    card.querySelector('.account-newapi-fields').classList.toggle('hidden', isSub2api);
    card.querySelector('.account-sub2api-fields').classList.toggle('hidden', !isSub2api);
    card.querySelectorAll('.account-password-field').forEach((field) => field.classList.toggle('hidden', mode === 'token'));
    card.querySelectorAll('.account-token-field').forEach((field) => field.classList.toggle('hidden', mode !== 'token'));
    accountField(card, 'access_token').placeholder = saved && account?.has_access_token ? '留空保留已保存令牌' : '必填';
    accountField(card, 'login_password').placeholder = sameMode && account?.has_login_password ? '留空保留已保存密码' : '必填';
    accountField(card, 'sub2api_access_token').placeholder = sameMode && account?.has_access_token ? '留空保留已保存令牌' : '必填';
    accountField(card, 'refresh_token').placeholder = sameMode && account?.has_refresh_token ? '留空保留；可选' : '可选';
  });
}

function updatePlatformFields() {
  const platform = els.sitePlatform.value || 'newapi';
  const isSub2api = platform === 'sub2api';
  els.newapiAuthSection.classList.toggle('hidden', isSub2api);
  els.sub2apiAuthHelp.classList.toggle('hidden', !isSub2api);
  els.sub2apiUsageEndpointField.classList.toggle('hidden', !isSub2api);
  const visible = accountsVisible();
  els.siteAccountsSection.classList.toggle('hidden', !visible);
  if (visible && !accountCards().length) addAccountCard();
  updateAccountCards();
}

function accountPayload(card) {
  const platform = els.sitePlatform.value;
  const id = Number(card.dataset.accountId) || null;
  const name = accountField(card, 'name').value.trim();
  if (platform !== 'sub2api') {
    return {
      id,
      name,
      access_token: accountField(card, 'access_token').value.trim(),
      access_user_id: accountField(card, 'access_user_id').value.trim(),
    };
  }
  const authMode = accountField(card, 'auth_mode').value || 'password';
  if (authMode === 'password') {
    return {
      id,
      name,
      auth_mode: authMode,
      login_username: accountField(card, 'login_username').value.trim(),
      login_password: accountField(card, 'login_password').value,
    };
  }
  return {
    id,
    name,
    auth_mode: authMode,
    access_token: accountField(card, 'sub2api_access_token').value.trim(),
    refresh_token: accountField(card, 'refresh_token').value.trim(),
    token_expires_at: accountField(card, 'token_expires_at').value.trim(),
  };
}

function setActiveView(view) {
  state.activeView = view;
  const nextView = els.views.find((item) => item.dataset.view === view);
  const nextNav = els.navItems.find((item) => item.dataset.viewTarget === view);
  els.views.forEach((item) => item.classList.toggle('active', item === nextView));
  els.navItems.forEach((item) => item.classList.toggle('active', item === nextNav));
  state.activeViewEl = nextView || null;
  state.activeNavEl = nextNav || null;
  requestAnimationFrame(() => {
    renderActiveView();
    pruneInactiveViews();
  });
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  });
  const text = await res.text();
  let body = null;
  try { body = text ? JSON.parse(text) : null; } catch { body = { raw: text }; }
  if (res.status === 401) {
    const next = encodeURIComponent(`${window.location.pathname}${window.location.search}`);
    window.location.href = `/login?next=${next}`;
    throw new Error('登录已过期，请重新登录');
  }
  if (!res.ok) {
    throw new Error(body?.message || body?.error || `HTTP ${res.status}`);
  }
  return body;
}

function renderStats() {
  const sites = state.sites;
  els.statsSites.textContent = sites.length;
  els.statsEnabled.textContent = sites.filter((s) => s.enabled).length;
  els.statsOk.textContent = sites.filter((s) => s.status === 'ok').length;
  els.statsFailed.textContent = sites.filter((s) => ['warning', 'failed'].includes(s.status)).length;
  els.statsChanges.textContent = state.changes.length;
  els.sidebarCount.textContent = sites.length;
}

function renderActiveView() {
  if (state.activeView === 'overview') {
    renderStats();
    els.overviewSitesBody.innerHTML = siteRows(state.sites);
    els.overviewChangesBody.innerHTML = changeRows(state.changes.slice(0, 8));
    return;
  }
  if (state.activeView === 'sites') {
    els.sitesBody.innerHTML = siteRows(filteredSites());
    return;
  }
  if (state.activeView === 'changes') {
    els.changesBody.innerHTML = changeRows(state.changes);
    return;
  }
  if (state.activeView === 'notifications') {
    renderNotificationSettings();
    return;
  }
  if (state.activeView === 'botSettings') {
    renderBotSettings();
    return;
  }
  if (state.activeView === 'reportGroups') {
    const editingSelect = document.activeElement?.matches?.('[data-report-site-group]');
    if (!editingSelect || !state.reportLayout) renderReportBoard();
    return;
  }
  if (state.activeView === 'detail') {
    renderDetail(state.sites.find((s) => s.id === state.selectedSiteId));
  }
}

function buildReportLayout() {
  const groups = state.reportGroups.map((group) => ({ id: group.id, name: group.name, siteIds: [] }));
  const ungrouped = { id: null, name: '未分组', siteIds: [] };
  const byId = new Map(groups.map((group) => [group.id, group]));
  state.sites.forEach((site) => {
    (byId.get(site.report_group_id) || ungrouped).siteIds.push(site.id);
  });
  return [...groups, ungrouped];
}

function setReportLayoutDirty(dirty) {
  state.reportLayoutDirty = dirty;
  els.reportLayoutStatus.textContent = dirty ? '排序已修改，尚未保存' : '调整后点击“保存排序”生效。';
  els.reportLayoutStatus.classList.toggle('error', dirty);
}

// Keeps an unsaved draft consistent with the latest server data: groups added, renamed or
// deleted elsewhere are reflected, and a site whose group changed on the server (site dialog,
// new site) follows the server instead of being reverted by the draft on save.
function reconcileReportLayout(draft) {
  const fresh = buildReportLayout();
  const freshById = new Map(fresh.map((group) => [group.id, group]));
  const serverGroupOf = new Map(state.sites.map((site) => [site.id, site.report_group_id ?? null]));
  const baseline = state.reportLayoutBaseline || new Map();

  const kept = draft.filter((group) => freshById.has(group.id));
  const keptIds = new Set(kept.map((group) => group.id));
  const merged = kept.filter((group) => group.id !== null).map((group) => ({ ...group, name: freshById.get(group.id).name, siteIds: [...group.siteIds] }));
  fresh.forEach((group) => { if (group.id !== null && !keptIds.has(group.id)) merged.push({ ...group, siteIds: [] }); });
  merged.push({ ...(kept.find((group) => group.id === null) || fresh[fresh.length - 1]), siteIds: [...(kept.find((group) => group.id === null)?.siteIds || [])] });
  const byId = new Map(merged.map((group) => [group.id, group]));

  const placed = new Set();
  merged.forEach((group) => {
    group.siteIds = group.siteIds.filter((siteId) => {
      if (!serverGroupOf.has(siteId) || placed.has(siteId)) return false;
      const serverGroup = serverGroupOf.get(siteId);
      if (baseline.has(siteId) && baseline.get(siteId) !== serverGroup && group.id !== serverGroup) return false;
      placed.add(siteId);
      return true;
    });
  });
  state.sites.forEach((site) => {
    if (placed.has(site.id)) return;
    (byId.get(site.report_group_id ?? null) || merged[merged.length - 1]).siteIds.push(site.id);
  });
  return merged;
}

function renderReportBoard() {
  if (!state.reportLayout || !state.reportLayoutDirty) {
    state.reportLayout = buildReportLayout();
  } else {
    state.reportLayout = reconcileReportLayout(state.reportLayout);
  }
  state.reportLayoutBaseline = new Map(state.sites.map((site) => [site.id, site.report_group_id ?? null]));
  const layout = state.reportLayout;
  const siteById = new Map(state.sites.map((site) => [site.id, site]));
  const groupOptions = layout.map((group, index) => `<option value="${index}">${escapeHtml(group.name)}</option>`).join('');
  const realGroupCount = layout.length - 1;
  els.reportGroupsBoard.innerHTML = layout.map((group, groupIndex) => {
    const isUngrouped = group.id === null;
    const rows = group.siteIds.length
      ? group.siteIds.map((siteId, siteIndex) => {
          const site = siteById.get(siteId);
          if (!site) return '';
          return `
            <div class="report-site-row">
              <span class="report-site-order">${siteIndex + 1}</span>
              <div class="report-site-name">
                <strong>${escapeHtml(site.name)}</strong>
                <span>${escapeHtml(platformLabel(site))}${site.enabled ? '' : ' · 已停用'}</span>
              </div>
              <div class="action-row">
                <button class="btn btn-secondary btn-small" type="button" data-report-site-move="-1" data-group-index="${groupIndex}" data-site-index="${siteIndex}" ${siteIndex === 0 ? 'disabled' : ''} aria-label="上移 ${escapeHtml(site.name)}">↑</button>
                <button class="btn btn-secondary btn-small" type="button" data-report-site-move="1" data-group-index="${groupIndex}" data-site-index="${siteIndex}" ${siteIndex === group.siteIds.length - 1 ? 'disabled' : ''} aria-label="下移 ${escapeHtml(site.name)}">↓</button>
                <select class="input input-small" data-report-site-group data-group-index="${groupIndex}" data-site-index="${siteIndex}" aria-label="${escapeHtml(site.name)} 所属分组">
                  ${groupOptions.replace(`value="${groupIndex}"`, `value="${groupIndex}" selected`)}
                </select>
              </div>
            </div>
          `;
        }).join('')
      : '<div class="empty-inline">暂无站点</div>';
    return `
      <section class="report-group-card${isUngrouped ? ' ungrouped' : ''}">
        <div class="report-group-head">
          <div>
            <div class="section-title">${isUngrouped ? '' : `${groupIndex + 1}. `}${escapeHtml(group.name)}</div>
            <span class="muted">${group.siteIds.length} 个站点</span>
          </div>
          ${isUngrouped ? '' : `
            <div class="action-row">
              <button class="btn btn-secondary btn-small" type="button" data-report-group-move="-1" data-group-index="${groupIndex}" ${groupIndex === 0 ? 'disabled' : ''} aria-label="上移分组 ${escapeHtml(group.name)}">↑</button>
              <button class="btn btn-secondary btn-small" type="button" data-report-group-move="1" data-group-index="${groupIndex}" ${groupIndex === realGroupCount - 1 ? 'disabled' : ''} aria-label="下移分组 ${escapeHtml(group.name)}">↓</button>
              <button class="btn btn-secondary btn-small" type="button" data-report-group-rename="${group.id}">改名</button>
              <button class="btn btn-secondary btn-small" type="button" data-report-group-delete="${group.id}">删除</button>
            </div>
          `}
        </div>
        <div class="report-site-list">${rows}</div>
      </section>
    `;
  }).join('');
}

const BOT_TEMPLATE_LABELS = {
  profit_title: '查利润 · 标题',
  profit_group_header: '查利润 · 分组标题',
  profit_site_line: '查利润 · 站点行',
  profit_site_failed: '查利润 · 查询失败的站点行',
  profit_group_subtotal: '查利润 · 分组小计',
  profit_separator: '查利润 · 汇总前分隔线',
  profit_footer: '查利润 · 汇总',
  profit_filter_title: '查利润 分组名 · 标题',
  profit_filter_footer: '查利润 分组名 · 合计',
  balance_title: '查余额 · 标题',
  balance_filter_title: '查余额 分组名 · 标题',
  balance_group_header: '查余额 · 分组标题',
  balance_site_line: '查余额 · 站点行',
  balance_site_missing: '查余额 · 无数据的站点行',
  balance_group_subtotal: '查余额 · 分组小计',
};

function botAliasRow(alias = { alias: '', target: '' }) {
  return `
    <div class="bot-alias-row">
      <input class="input" data-bot-alias-field="alias" maxlength="30" placeholder="别名，如：利润" value="${escapeHtml(alias.alias)}" aria-label="别名" />
      <span class="muted">→</span>
      <input class="input" data-bot-alias-field="target" maxlength="80" placeholder="实际执行，如：查利润 画图" value="${escapeHtml(alias.target)}" aria-label="实际执行" />
      <button class="btn btn-secondary btn-small" type="button" data-bot-alias-remove>删除</button>
    </div>
  `;
}

function renderBotSettings(options = {}) {
  const settings = state.botSettings;
  if (!settings || (state.botSettingsDirty && !options.force)) return;
  els.botAliasList.innerHTML = settings.aliases.length
    ? settings.aliases.map(botAliasRow).join('')
    : '<div class="empty-inline" data-bot-alias-empty>暂无别名</div>';
  els.botNegativeQuotaThreshold.value = String(settings.negative_quota_threshold ?? settings.default_negative_quota_threshold ?? 5);
  els.botTemplateList.innerHTML = Object.keys(settings.default_templates).map((key) => {
    const variables = settings.template_variables[key] || [];
    const value = settings.templates[key] ?? '';
    const customized = key in (settings.template_overrides || {});
    return `
      <div class="field bot-template-item">
        <div class="bot-template-label">
          <label for="botTemplate-${escapeHtml(key)}">${escapeHtml(BOT_TEMPLATE_LABELS[key] || key)}${customized ? ' <span class="tag strong">已自定义</span>' : ''}</label>
          <button class="btn btn-secondary btn-small" type="button" data-bot-template-reset="${escapeHtml(key)}">恢复默认</button>
        </div>
        <textarea id="botTemplate-${escapeHtml(key)}" class="input bot-template-input" rows="${Math.max(1, value.split('\n').length)}" data-bot-template="${escapeHtml(key)}" aria-describedby="botTemplateHelp-${escapeHtml(key)}">${escapeHtml(value)}</textarea>
        <small id="botTemplateHelp-${escapeHtml(key)}" class="field-help">可用变量：${variables.length ? variables.map((name) => `{${escapeHtml(name)}}`).join(' ') : '无'} · 默认：${escapeHtml(settings.default_templates[key]).replaceAll('\n', ' ⏎ ')}</small>
      </div>
    `;
  }).join('');
}

function setBotSettingsDirty(dirty) {
  state.botSettingsDirty = dirty;
  els.botSettingsStatus.textContent = dirty ? '有未保存的修改' : '';
  els.botSettingsStatus.classList.toggle('error', dirty);
}

function collectBotSettings() {
  const aliases = Array.from(els.botAliasList.querySelectorAll('.bot-alias-row'))
    .map((row) => ({
      alias: row.querySelector('[data-bot-alias-field="alias"]').value.trim(),
      target: row.querySelector('[data-bot-alias-field="target"]').value.trim(),
    }))
    .filter((item) => item.alias || item.target);
  const templates = {};
  els.botTemplateList.querySelectorAll('[data-bot-template]').forEach((input) => {
    templates[input.dataset.botTemplate] = input.value;
  });
  const thresholdText = els.botNegativeQuotaThreshold.value.trim();
  const negative_quota_threshold = thresholdText === '' ? state.botSettings.default_negative_quota_threshold : Number(thresholdText);
  return { aliases, templates, negative_quota_threshold };
}

function renderReportGroupSelect(selectedId = null) {
  els.siteReportGroup.innerHTML = [
    '<option value="">未分组</option>',
    ...state.reportGroups.map((group) => `<option value="${group.id}">${escapeHtml(group.name)}</option>`),
  ].join('');
  els.siteReportGroup.value = selectedId ? String(selectedId) : '';
}

function pruneInactiveViews() {
  if (state.activeView !== 'overview') {
    els.overviewSitesBody.innerHTML = '';
    els.overviewChangesBody.innerHTML = '';
  }
  if (state.activeView !== 'sites') {
    els.sitesBody.innerHTML = '';
  }
  if (state.activeView !== 'changes') {
    els.changesBody.innerHTML = '';
  }
}

function balanceCell(site) {
  const accounts = site.accounts || [];
  if (accounts.length <= 1) {
    return `<span class="${site.balance_alert_active ? 'balance-low' : ''}">${escapeHtml(balanceLabel(site))}</span>`;
  }
  return `<div class="account-balances">${accounts.map((account) => `
    <span class="${account.balance_alert_active ? 'balance-low' : ''}${account.login_last_error ? ' account-error' : ''}"
      title="${escapeHtml(account.login_last_error || account.balance_last_error || '')}">${escapeHtml(account.label)}：${escapeHtml(balanceLabel(account))}</span>
  `).join('')}</div>`;
}

function siteRows(sites) {
  return sites.map((site) => {
    const selected = site.id === state.selectedSiteId ? ' selected' : '';
    const authCount = Number(site.current_login_groups_count || 0);
    const publicCount = Number(site.current_groups_count || 0);
    const hiddenCount = Math.max(0, authCount - publicCount);
    return `
      <tr class="${selected}">
        <td>
          <button class="link-cell" data-act="view" data-id="${site.id}">
            <strong>${escapeHtml(site.name)}</strong>
            <span>${escapeHtml(platformLabel(site))} · ${escapeHtml(site.base_url)}</span>
          </button>
        </td>
        <td><span class="badge ${badgeClass(site.status)}">${escapeHtml(site.status)}</span></td>
        <td>
          ${hiddenCount ? `<span class="tag strong">${hiddenCount} 个隐藏</span>` : '<span class="muted">无</span>'}
          ${site.platform === 'sub2api' ? '<span class="tag login">用户登录</span>' : site.login_enabled ? '<span class="tag login">认证增强</span>' : ''}
          ${Number(site.account_count || 0) > 1 ? `<span class="tag">${site.account_count} 个账号</span>` : ''}
        </td>
        <td>${site.current_groups_count || 0}</td>
        <td>${balanceCell(site)}</td>
        <td>${fmtTime(site.last_check_at)}</td>
        <td>
          <div class="action-row">
            <button class="btn btn-secondary" data-act="check" data-id="${site.id}">检测</button>
            <button class="btn btn-secondary" data-act="edit" data-id="${site.id}">编辑</button>
            <button class="btn btn-secondary" data-act="delete" data-id="${site.id}">删除</button>
          </div>
        </td>
      </tr>
    `;
  }).join('');
}

function filteredSites() {
  const keyword = els.searchInput.value.trim().toLowerCase();
  const filter = els.statusFilter.value;
  return state.sites.filter((site) => {
    if (keyword && !(`${site.name} ${site.base_url}`.toLowerCase().includes(keyword))) return false;
    if (filter && site.status !== filter) return false;
    return true;
  });
}

function renderSites() {
  if (state.activeView === 'sites') {
    els.sitesBody.innerHTML = siteRows(filteredSites());
  }
  if (state.activeView === 'overview') {
    els.overviewSitesBody.innerHTML = siteRows(state.sites);
  }
}

function changeRows(changes) {
  return changes.map((change) => `
    <tr>
      <td>${fmtTime(change.created_at)}</td>
      <td>${escapeHtml((state.sites.find((s) => s.id === change.site_id) || {}).name || `#${change.site_id}`)}</td>
      <td><span class="badge ${changeClass(change)}">${escapeHtml(changeTypeLabel(change.change_type))}</span></td>
      <td>${escapeHtml(change.group_name || '-')}</td>
      <td>${escapeHtml(change.message || '-')}</td>
    </tr>
  `).join('');
}

function renderGlobalChanges() {
  if (state.activeView === 'changes') {
    els.changesBody.innerHTML = changeRows(state.changes);
  }
  if (state.activeView === 'overview') {
    els.overviewChangesBody.innerHTML = changeRows(state.changes.slice(0, 8));
  }
}

function renderNotificationSettings(options = {}) {
  if (state.notificationDirty && !options.force) return;
  const settings = state.notificationSettings || {};
  els.wecomEnabled.checked = !!settings.wecom_enabled;
  els.wecomWebhook.value = settings.wecom_webhook || '';
  const wecomParts = [];
  wecomParts.push(settings.wecom_enabled ? '企业微信已启用' : '企业微信未启用');
  if (settings.wecom_has_webhook) wecomParts.push('Webhook 已保存');
  if (settings.wecom_last_sent_at) wecomParts.push(`上次发送：${fmtTime(settings.wecom_last_sent_at)}`);
  if (settings.wecom_last_error) wecomParts.push(`错误：${settings.wecom_last_error}`);
  els.wecomStatus.textContent = wecomParts.join(' · ');
  els.wecomStatus.classList.toggle('error', !!settings.wecom_last_error);

  els.feishuEnabled.checked = !!settings.feishu_enabled;
  els.feishuWebhook.value = settings.feishu_webhook || '';
  els.feishuSecret.value = '';
  const feishuParts = [];
  feishuParts.push(settings.feishu_enabled ? '飞书推送已启用' : '飞书推送未启用');
  if (settings.feishu_has_webhook) feishuParts.push('Webhook 已保存');
  if (settings.feishu_has_secret) feishuParts.push('签名密钥已保存');
  if (settings.feishu_last_sent_at) feishuParts.push(`上次发送：${fmtTime(settings.feishu_last_sent_at)}`);
  if (settings.feishu_last_error) feishuParts.push(`错误：${settings.feishu_last_error}`);
  els.feishuStatus.textContent = feishuParts.join(' · ');
  els.feishuStatus.classList.toggle('error', !!settings.feishu_last_error);

  els.qqEnabled.checked = !!settings.qq_enabled;
  els.qqApiUrl.value = settings.qq_api_url || '';
  els.qqApiToken.value = '';
  els.qqGroupId.value = settings.qq_group_id || '';
  const qqParts = [];
  qqParts.push(settings.qq_enabled ? 'QQ 群推送已启用' : 'QQ 群推送未启用');
  if (settings.qq_has_api_token) qqParts.push('接口 Token 已保存');
  if (settings.qq_group_id) qqParts.push(`通知群：${settings.qq_group_id}`);
  if (settings.qq_last_sent_at) qqParts.push(`上次发送：${fmtTime(settings.qq_last_sent_at)}`);
  if (settings.qq_last_error) qqParts.push(`错误：${settings.qq_last_error}`);
  els.qqStatus.textContent = qqParts.join(' · ');
  els.qqStatus.classList.toggle('error', !!settings.qq_last_error);

  els.emailEnabled.checked = !!settings.email_enabled;
  els.smtpHost.value = settings.smtp_host || '';
  els.smtpPort.value = settings.smtp_port || 465;
  els.smtpUsername.value = settings.smtp_username || '';
  els.smtpPassword.value = '';
  els.smtpUseSsl.checked = settings.smtp_use_ssl !== false;
  els.smtpFrom.value = settings.smtp_from || '';
  els.smtpTo.value = settings.smtp_to || '';
  const parts = [];
  parts.push(settings.email_enabled ? '邮箱推送已启用' : '邮箱推送未启用');
  if (settings.has_smtp_password) parts.push('密码已保存');
  if (settings.email_last_sent_at) parts.push(`上次发送：${fmtTime(settings.email_last_sent_at)}`);
  if (settings.email_last_error) parts.push(`错误：${settings.email_last_error}`);
  els.emailStatus.textContent = parts.join(' · ');
  els.emailStatus.classList.toggle('error', !!settings.email_last_error);
}

function renderDetail(site) {
  if (!site) {
    els.detailSubtitle.textContent = '选择一个站点查看当前倍率、隐藏分组和历史变化。';
    els.detailPane.className = 'detail-empty';
    els.detailPane.innerHTML = '还没有选中站点';
    return;
  }

  els.detailSubtitle.innerHTML = upstreamLink(site.base_url);
  const publicGroupsObj = site.current_groups || {};
  const loginGroupsObj = site.current_login_groups || {};
  const activeGroupsObj = site.login_enabled && Object.keys(loginGroupsObj).length ? loginGroupsObj : publicGroupsObj;
  const groups = Object.entries(activeGroupsObj);
  const notifyGroupNames = [...new Set([...Object.keys(activeGroupsObj), ...(site.notify_groups || [])])]
    .sort((a, b) => a.localeCompare(b, 'zh-CN'));
  const selectedNotifyGroupSet = new Set(site.notify_all_groups ? notifyGroupNames : (site.notify_groups || []));
  const notifyGroupRows = notifyGroupNames.length
    ? notifyGroupNames.map((name) => `
        <label class="group-picker-item">
          <input type="checkbox" data-detail-notify-group value="${escapeHtml(name)}"
            ${selectedNotifyGroupSet.has(name) ? 'checked' : ''} />
          <span>${escapeHtml(name)}</span>
        </label>
      `).join('')
    : '<div class="empty-inline">暂无已采集分组</div>';
  const hiddenGroups = Object.entries(loginGroupsObj).filter(([name]) => !(name in publicGroupsObj));
  const accounts = site.accounts || [];
  const accountRows = accounts.map((account) => {
    const authText = site.platform === 'sub2api'
      ? (account.auth_mode === 'token' ? `导入登录态（refresh ${account.has_refresh_token ? '已配置' : '未配置'}）` : `账号登录 ${account.login_username || '-'}`)
      : `用户 ID ${account.access_user_id || '-'}`;
    const errors = [
      account.login_last_error ? `登录异常：${account.login_last_error}` : '',
      account.balance_last_error ? `余额采集：${account.balance_last_error}` : '',
    ].filter(Boolean);
    return `
      <div class="info-row account-info-row">
        <div>
          <strong>${escapeHtml(account.label)}${account.is_primary ? ' <span class="tag strong">主账号</span>' : ''}</strong>
          <span>${escapeHtml(authText)} · 余额检测 ${fmtTime(account.balance_last_check_at)}</span>
          ${errors.length ? `<span class="account-error">${escapeHtml(errors.join('；'))}</span>` : ''}
        </div>
        <b class="${account.balance_alert_active ? 'balance-low' : ''}">${escapeHtml(balanceLabel(account))}</b>
      </div>
    `;
  }).join('');
  const groupRows = groups.length
    ? groups.map(([name, item]) => `
        <div class="group-row">
          <div>
            <strong>${escapeHtml(name)}</strong>
            <span>${escapeHtml([item.platform, item.status, item.is_exclusive ? '专属' : '', item.desc || '-'].filter(Boolean).join(' · '))}</span>
          </div>
          <div class="group-ratio">${escapeHtml(ratioLabel(item))}</div>
        </div>
      `).join('')
    : '<div class="empty-inline">暂无倍率数据</div>';

  const historyRows = state.siteChanges.length
    ? state.siteChanges.slice(0, 10).map((change) => `
        <div class="history-row">
          <div>
            <span class="badge ${changeClass(change)}">${escapeHtml(changeTypeLabel(change.change_type))}</span>
            <strong>${escapeHtml(change.group_name || '-')}</strong>
            <p>${escapeHtml(change.message || '-')}</p>
          </div>
          <time>${fmtTime(change.created_at)}</time>
        </div>
      `).join('')
    : '<div class="empty-inline">暂无历史变化</div>';

  els.detailPane.className = 'detail-box';
  els.detailPane.innerHTML = `
    <div class="detail-title-row">
      <div>
        <div class="detail-title">${escapeHtml(site.name)}</div>
        <div class="muted">${escapeHtml(platformLabel(site))} · ${upstreamLink(site.base_url)}${site.report_group_name ? ` · 汇报分组：${escapeHtml(site.report_group_name)}` : ''}</div>
      </div>
      <span class="badge ${badgeClass(site.status)}">${escapeHtml(site.status)}</span>
    </div>
    ${site.last_error ? `<div class="error-box">${escapeHtml(site.last_error)}</div>` : ''}
    <div class="detail-meta">
      <div class="meta-card"><div class="k">监控间隔</div><div class="v">${site.interval_minutes} 分钟</div></div>
      <div class="meta-card"><div class="k">金额换算</div><div class="v">${usageDivisorLabel(site.usage_divisor)}</div></div>
      <div class="meta-card"><div class="k">公开分组</div><div class="v">${site.current_groups_count || 0}</div></div>
      <div class="meta-card"><div class="k">认证分组</div><div class="v">${site.current_login_groups_count || 0}</div></div>
      <div class="meta-card"><div class="k">${accounts.length > 1 ? '余额合计' : '账户余额'}</div><div class="v ${site.balance_alert_active ? 'balance-low' : ''}">${escapeHtml(balanceLabel(site))}</div></div>
      <div class="meta-card"><div class="k">余额预警</div><div class="v">${site.balance_alert_enabled ? `低于 ¥${Number(site.balance_alert_threshold || 0).toFixed(2)}` : '未启用'}</div></div>
      <div class="meta-card"><div class="k">余额检测</div><div class="v">${fmtTime(site.balance_last_check_at)}</div></div>
      <div class="meta-card"><div class="k">上次检测</div><div class="v">${fmtTime(site.last_check_at)}</div></div>
      <div class="meta-card"><div class="k">下次检测</div><div class="v">${fmtTime(site.next_check_at)}</div></div>
      <div class="meta-card"><div class="k">连续失败</div><div class="v">${site.consecutive_failures || 0}</div></div>
      <div class="meta-card"><div class="k">启用状态</div><div class="v">${site.enabled ? '启用中' : '已停用'}</div></div>
      <div class="meta-card wide"><div class="k">变化通知范围</div><div class="v">${site.notify_all_groups ? '全部分组' : escapeHtml((site.notify_groups || []).join('、') || '-')}</div></div>
      <div class="meta-card wide"><div class="k">监控模式</div><div class="v">${site.platform === 'sub2api' ? `sub2api 用户登录（${accounts.length} 个账号）` : site.login_enabled ? `认证增强监控（${accounts.length} 个账号）` : '公开分组监控'}</div></div>
    </div>
    ${accounts.length ? `
      <section class="detail-section">
        <div class="section-title">账号</div>
        <div class="info-list">${accountRows}</div>
      </section>
    ` : ''}
    <section class="detail-section notify-scope-editor">
      <div class="group-picker-head notify-scope-head">
        <div>
          <div class="section-title">分组变化通知</div>
          <div id="detailNotifyStatus" class="muted">${site.notify_all_groups ? '当前通知全部分组' : `已选择 ${(site.notify_groups || []).length} 个分组`}</div>
        </div>
        <button class="btn btn-primary" type="button" data-detail-notify-action="save">保存通知范围</button>
      </div>
      <div class="group-picker-head">
        <span>通知分组</span>
        <div class="action-row">
          <button class="btn btn-secondary btn-small" type="button" data-detail-notify-action="select-all">全选</button>
          <button class="btn btn-secondary btn-small" type="button" data-detail-notify-action="clear">清空</button>
        </div>
      </div>
      <div class="group-picker" data-detail-notify-list>${notifyGroupRows}</div>
    </section>
    <section class="mode-note ${site.login_enabled ? 'enabled' : ''}">
      ${site.platform === 'sub2api'
        ? '当前站点使用 sub2api 普通用户账号登录，主账号检测实际可见的分组倍率和用户专属倍率；其他账号只检测余额和登录状态。'
        : site.login_enabled
        ? '当前站点已开启认证增强监控，主账号的系统访问令牌用于采集隐藏或专属分组；其他账号只检测余额和登录状态。'
        : '当前站点只监控公开 /api/user/groups。若该站存在特殊分组，可在编辑站点中开启认证增强监控。'}
    </section>
    ${site.login_enabled && hiddenGroups.length ? `
      <section class="detail-section">
        <div class="section-title">认证后新增分组</div>
        <div class="info-list">
          ${hiddenGroups.map(([name, item]) => `
            <div class="info-row">
              <div><strong>${escapeHtml(name)}</strong><span>${escapeHtml(item.desc || '-')}</span></div>
              <b>${escapeHtml(ratioLabel(item))}</b>
            </div>
          `).join('')}
        </div>
      </section>
    ` : ''}
    <section class="detail-section">
      <div class="section-title">${site.platform === 'sub2api' ? '用户可见分组倍率' : site.login_enabled && Object.keys(loginGroupsObj).length ? '认证分组倍率' : '当前公开分组倍率'}</div>
      <div class="group-list">${groupRows}</div>
    </section>
    <section class="detail-section">
      <div class="section-title">该站历史变化</div>
      <div class="history-list">${historyRows}</div>
    </section>
  `;
}

function openDialog(site = null) {
  els.dialogMsg.textContent = '';
  els.dialogMsg.classList.remove('error');
  els.saveSiteBtn.disabled = false;
  els.saveSiteBtn.textContent = '保存配置';
  setSiteDialogTab('basic');
  if (site) {
    els.dialogTitle.textContent = '编辑站点';
    els.siteId.value = site.id;
    els.siteName.value = site.name;
    els.sitePlatform.value = site.platform || 'newapi';
    els.siteBaseUrl.value = site.base_url;
    els.siteInterval.value = site.interval_minutes;
    els.siteUsageDivisor.value = site.usage_divisor ?? 1;
    els.siteSub2apiUsageEndpoint.value = site.sub2api_usage_endpoint || 'dashboard';
    els.siteLoginEnabled.checked = !!site.login_enabled;
    els.siteBalanceAlertEnabled.checked = !!site.balance_alert_enabled;
    els.siteBalanceAlertThreshold.value = site.balance_alert_threshold ?? 10;
    state.dialogNotifyAllGroups = site.notify_all_groups !== false;
    renderNotifyGroupPicker(availableGroupsForSite(site), site.notify_groups || [], state.dialogNotifyAllGroups);
    els.siteEnabled.checked = !!site.enabled;
    renderReportGroupSelect(site.report_group_id);
    state.dialogAccounts = site.accounts || [];
    state.dialogStoredPlatform = site.platform || 'newapi';
  } else {
    els.dialogTitle.textContent = '添加站点';
    els.siteId.value = '';
    els.siteName.value = '';
    els.sitePlatform.value = 'newapi';
    els.siteBaseUrl.value = '';
    els.siteInterval.value = 3;
    els.siteUsageDivisor.value = 1;
    els.siteSub2apiUsageEndpoint.value = 'dashboard';
    els.siteLoginEnabled.checked = false;
    els.siteBalanceAlertEnabled.checked = false;
    els.siteBalanceAlertThreshold.value = 10;
    state.dialogNotifyAllGroups = true;
    renderNotifyGroupPicker([], [], true);
    els.siteEnabled.checked = true;
    renderReportGroupSelect(null);
    state.dialogAccounts = [];
    state.dialogStoredPlatform = null;
  }
  renderAccountCards(state.dialogAccounts);
  updatePlatformFields();
  if (!els.dialog.open) els.dialog.showModal();
}

async function loadSelectedSiteChanges() {
  if (!state.selectedSiteId) {
    state.siteChanges = [];
    return;
  }
  const resp = await api(`/api/sites/${state.selectedSiteId}/changes?limit=50`);
  state.siteChanges = resp.data || [];
}

function renderAll() {
  renderActiveView();
}

// A refresh requested while one is running waits for it, then refetches, so data
// written just before the call (save/rename/delete) is never hidden by an older response.
async function refreshAll(options = {}) {
  if (state.refreshPromise) {
    if (options.background) return state.refreshPromise;
    await state.refreshPromise.catch(() => {});
    if (state.refreshPromise) return refreshAll(options);
  }
  state.refreshPromise = doRefreshAll(options);
  try {
    return await state.refreshPromise;
  } finally {
    state.refreshPromise = null;
  }
}

async function doRefreshAll(options = {}) {
  {
  const [overview, sitesResp, changesResp, notifyResp, groupsResp, botResp] = await Promise.all([
    api('/api/overview'),
    api('/api/sites'),
    api('/api/changes?limit=50'),
    api('/api/notifications/settings'),
    api('/api/report-groups'),
    api('/api/bot-settings'),
  ]);
  state.sites = sitesResp.data || [];
  state.reportGroups = groupsResp.data || [];
  if (!state.botSettingsDirty) state.botSettings = botResp.data || null;
  state.changes = changesResp.data || [];
  state.notificationSettings = notifyResp.data || {};
  state.appVersion = overview.version || null;
  els.appVersion.textContent = state.appVersion ? `v${state.appVersion}` : 'v-';
  if (!state.selectedSiteId && state.sites.length) {
    state.selectedSiteId = state.sites[0].id;
  }
  const shouldLoadDetail = options.loadDetail ?? state.activeView === 'detail';
  if (shouldLoadDetail) {
    await loadSelectedSiteChanges();
  }
  renderAll();
  return overview;
  }
}

function notificationPayload() {
  return {
    wecom_enabled: els.wecomEnabled.checked,
    wecom_webhook: els.wecomWebhook.value.trim(),
    feishu_enabled: els.feishuEnabled.checked,
    feishu_webhook: els.feishuWebhook.value.trim(),
    feishu_secret: els.feishuSecret.value.trim(),
    qq_enabled: els.qqEnabled.checked,
    qq_api_url: els.qqApiUrl.value.trim(),
    qq_api_token: els.qqApiToken.value.trim(),
    qq_group_id: els.qqGroupId.value.trim(),
    email_enabled: els.emailEnabled.checked,
    smtp_host: els.smtpHost.value.trim(),
    smtp_port: Math.max(1, Number(els.smtpPort.value || 465)),
    smtp_username: els.smtpUsername.value.trim(),
    smtp_password: els.smtpPassword.value,
    smtp_use_ssl: els.smtpUseSsl.checked,
    smtp_from: els.smtpFrom.value.trim(),
    smtp_to: els.smtpTo.value.trim(),
  };
}

async function checkSite(id) {
  await api(`/api/sites/${id}/check`, { method: 'POST', body: '{}' });
  await refreshAll();
}

async function deleteSite(id) {
  if (!confirm('确认删除这个站点？')) return;
  await api(`/api/sites/${id}`, { method: 'DELETE' });
  state.selectedSiteId = null;
  await refreshAll();
}

els.addSiteBtn.addEventListener('click', () => openDialog());
els.closeDialogBtn.addEventListener('click', () => els.dialog.close());
els.addAccountBtn.addEventListener('click', () => {
  addAccountCard();
  const cards = accountCards();
  accountField(cards[cards.length - 1], 'name').focus();
});
els.siteAccountsList.addEventListener('change', (event) => {
  if (event.target.matches('[data-field="auth_mode"]')) updateAccountCards();
});
els.siteAccountsList.addEventListener('click', (event) => {
  const button = event.target.closest('[data-account-act]');
  if (!button) return;
  const card = button.closest('.account-card');
  const act = button.dataset.accountAct;
  if (act === 'primary') {
    els.siteAccountsList.prepend(card);
    updateAccountCards();
    setAccountMessage(card, '已设为主账号，保存后生效');
  } else if (act === 'remove') {
    const label = accountField(card, 'name').value.trim() || '这个账号';
    if (card.dataset.accountId && !confirm(`确认删除「${label}」？保存后生效，该账号的余额和登录状态不再检测。`)) return;
    card.remove();
    updatePlatformFields();
  } else if (act === 'test') {
    testAccount(card, button).catch((err) => setAccountMessage(card, err.message, true));
  } else if (act === 'usage') {
    queryAccountUsage(card, button).catch((err) => setAccountMessage(card, err.message, true));
  }
});
els.logoutBtn.addEventListener('click', async () => {
  try {
    await api('/api/auth/logout', { method: 'POST', body: '{}' });
  } finally {
    window.location.href = '/login';
  }
});
els.siteDialogTabs.forEach((button) => {
  button.addEventListener('click', () => setSiteDialogTab(button.dataset.siteTab));
});
els.siteLoginEnabled.addEventListener('change', updatePlatformFields);
els.sitePlatform.addEventListener('change', updatePlatformFields);
els.siteNotifyGroupsList.addEventListener('change', () => {
  state.dialogNotifyAllGroups = state.dialogAvailableGroups.length > 0
    && selectedNotifyGroups().length === state.dialogAvailableGroups.length;
});
els.selectAllNotifyGroupsBtn.addEventListener('click', () => {
  els.siteNotifyGroupsList.querySelectorAll('input[type="checkbox"]').forEach((input) => { input.checked = true; });
  state.dialogNotifyAllGroups = true;
});
els.clearNotifyGroupsBtn.addEventListener('click', () => {
  els.siteNotifyGroupsList.querySelectorAll('input[type="checkbox"]').forEach((input) => { input.checked = false; });
  state.dialogNotifyAllGroups = false;
});
els.refreshBtn.addEventListener('click', () => refreshAll().catch((err) => alert(err.message)));
els.searchInput.addEventListener('input', renderSites);
els.statusFilter.addEventListener('change', renderSites);
els.notifyForm.addEventListener('input', () => { state.notificationDirty = true; });
els.notifyForm.addEventListener('focusin', () => { state.notificationDirty = true; });
els.navItems.forEach((item) => {
  item.addEventListener('click', () => setActiveView(item.dataset.viewTarget));
});

els.detailPane.addEventListener('click', async (event) => {
  const button = event.target.closest('[data-detail-notify-action]');
  if (!button || button.disabled) return;
  const action = button.dataset.detailNotifyAction;
  const groupInputs = Array.from(els.detailPane.querySelectorAll('[data-detail-notify-group]'));
  if (action === 'select-all') {
    groupInputs.forEach((input) => { input.checked = true; });
    return;
  }
  if (action === 'clear') {
    groupInputs.forEach((input) => { input.checked = false; });
    return;
  }
  if (action !== 'save') return;

  const notifyGroups = groupInputs.filter((input) => input.checked).map((input) => input.value);
  const notifyAll = groupInputs.length === 0 || notifyGroups.length === groupInputs.length;
  const status = els.detailPane.querySelector('#detailNotifyStatus');
  if (!notifyGroups.length && groupInputs.length) {
    if (status) {
      status.textContent = '请至少选择一个通知分组';
      status.classList.add('error');
    }
    showToast('请至少选择一个通知分组', 'error');
    return;
  }

  button.disabled = true;
  button.textContent = '保存中...';
  if (status) {
    status.textContent = '保存中...';
    status.classList.remove('error');
  }
  try {
    await api(`/api/sites/${state.selectedSiteId}`, {
      method: 'PUT',
      body: JSON.stringify({ notify_all_groups: notifyAll, notify_groups: notifyGroups }),
    });
    await refreshAll({ loadDetail: true });
    const refreshedStatus = els.detailPane.querySelector('#detailNotifyStatus');
    if (refreshedStatus) refreshedStatus.textContent = notifyAll ? '已保存：通知全部分组' : `已保存：通知 ${notifyGroups.length} 个分组`;
    showToast('通知范围保存成功');
  } catch (err) {
    button.disabled = false;
    button.textContent = '保存通知范围';
    if (status) {
      status.textContent = `保存失败：${err.message}`;
      status.classList.add('error');
    }
    showToast(`通知范围保存失败：${err.message}`, 'error');
  }
});

els.addBotAliasBtn.addEventListener('click', () => {
  els.botAliasList.querySelector('[data-bot-alias-empty]')?.remove();
  els.botAliasList.insertAdjacentHTML('beforeend', botAliasRow());
  els.botAliasList.lastElementChild.querySelector('input').focus();
  setBotSettingsDirty(true);
});

els.botAliasList.addEventListener('click', (event) => {
  const button = event.target.closest('[data-bot-alias-remove]');
  if (!button) return;
  button.closest('.bot-alias-row').remove();
  setBotSettingsDirty(true);
});

els.botTemplateList.addEventListener('click', (event) => {
  const button = event.target.closest('[data-bot-template-reset]');
  if (!button) return;
  const key = button.dataset.botTemplateReset;
  const input = els.botTemplateList.querySelector(`[data-bot-template="${CSS.escape(key)}"]`);
  input.value = state.botSettings.default_templates[key];
  setBotSettingsDirty(true);
});

['input', 'change'].forEach((type) => {
  els.botAliasList.addEventListener(type, () => setBotSettingsDirty(true));
  els.botTemplateList.addEventListener(type, () => setBotSettingsDirty(true));
  els.botNegativeQuotaThreshold.addEventListener(type, () => setBotSettingsDirty(true));
});

els.saveBotSettingsBtn.addEventListener('click', async () => {
  els.saveBotSettingsBtn.disabled = true;
  els.botSettingsStatus.textContent = '保存中...';
  els.botSettingsStatus.classList.remove('error');
  try {
    const res = await api('/api/bot-settings', { method: 'PUT', body: JSON.stringify(collectBotSettings()) });
    state.botSettings = res.data;
    setBotSettingsDirty(false);
    renderBotSettings({ force: true });
    els.botSettingsStatus.textContent = '已保存，机器人最多 30 秒内生效';
    showToast('机器人配置已保存');
  } catch (err) {
    els.botSettingsStatus.textContent = `保存失败：${err.message}`;
    els.botSettingsStatus.classList.add('error');
    showToast(`保存失败：${err.message}`, 'error');
  } finally {
    els.saveBotSettingsBtn.disabled = false;
  }
});

function moveItem(list, from, to) {
  if (to < 0 || to >= list.length) return;
  const [item] = list.splice(from, 1);
  list.splice(to, 0, item);
}

els.reportGroupsBoard.addEventListener('change', (event) => {
  const select = event.target.closest('[data-report-site-group]');
  if (!select) return;
  const layout = state.reportLayout;
  const fromGroup = layout[Number(select.dataset.groupIndex)];
  const toGroup = layout[Number(select.value)];
  if (!fromGroup || !toGroup || fromGroup === toGroup) return;
  const [siteId] = fromGroup.siteIds.splice(Number(select.dataset.siteIndex), 1);
  toGroup.siteIds.push(siteId);
  setReportLayoutDirty(true);
  renderReportBoard();
});

els.reportGroupsBoard.addEventListener('click', async (event) => {
  const layout = state.reportLayout;
  const siteMove = event.target.closest('[data-report-site-move]');
  if (siteMove) {
    const group = layout[Number(siteMove.dataset.groupIndex)];
    const index = Number(siteMove.dataset.siteIndex);
    moveItem(group.siteIds, index, index + Number(siteMove.dataset.reportSiteMove));
    setReportLayoutDirty(true);
    renderReportBoard();
    return;
  }
  const groupMove = event.target.closest('[data-report-group-move]');
  if (groupMove) {
    const index = Number(groupMove.dataset.groupIndex);
    const target = index + Number(groupMove.dataset.reportGroupMove);
    if (target < 0 || target >= layout.length - 1) return;
    moveItem(layout, index, target);
    setReportLayoutDirty(true);
    renderReportBoard();
    return;
  }
  const renameBtn = event.target.closest('[data-report-group-rename]');
  if (renameBtn) {
    const groupId = Number(renameBtn.dataset.reportGroupRename);
    const group = state.reportGroups.find((item) => item.id === groupId);
    const name = window.prompt('新的分组名称', group?.name || '');
    if (name === null || !name.trim()) return;
    try {
      await api(`/api/report-groups/${groupId}`, { method: 'PUT', body: JSON.stringify({ name: name.trim() }) });
      await refreshAll();
      showToast('分组已改名');
    } catch (err) {
      showToast(`改名失败：${err.message}`, 'error');
    }
    return;
  }
  const deleteBtn = event.target.closest('[data-report-group-delete]');
  if (deleteBtn) {
    const groupId = Number(deleteBtn.dataset.reportGroupDelete);
    const group = state.reportGroups.find((item) => item.id === groupId);
    if (!confirm(`确认删除分组「${group?.name || ''}」？组内站点会移到“未分组”。`)) return;
    try {
      await api(`/api/report-groups/${groupId}`, { method: 'DELETE' });
      const removed = layout.find((item) => item.id === groupId);
      if (removed) {
        layout[layout.length - 1].siteIds.push(...removed.siteIds);
        removed.siteIds = [];
      }
      await refreshAll();
      showToast('分组已删除');
    } catch (err) {
      showToast(`删除失败：${err.message}`, 'error');
    }
  }
});

els.reportGroupForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const name = els.reportGroupName.value.trim();
  if (!name) return;
  try {
    await api('/api/report-groups', { method: 'POST', body: JSON.stringify({ name }) });
    els.reportGroupName.value = '';
    await refreshAll();
    showToast('分组已添加');
  } catch (err) {
    showToast(`添加失败：${err.message}`, 'error');
  }
});

els.saveReportLayoutBtn.addEventListener('click', async () => {
  const layout = state.reportLayout || buildReportLayout();
  els.saveReportLayoutBtn.disabled = true;
  try {
    await api('/api/sites/order', {
      method: 'PUT',
      body: JSON.stringify({
        group_ids: layout.filter((group) => group.id !== null).map((group) => group.id),
        layout: layout.map((group) => ({ group_id: group.id, site_ids: group.siteIds })),
      }),
    });
    state.reportLayout = null;
    setReportLayoutDirty(false);
    await refreshAll();
    showToast('排序已保存');
  } catch (err) {
    showToast(`保存失败：${err.message}`, 'error');
  } finally {
    els.saveReportLayoutBtn.disabled = false;
  }
});

async function handleSiteTableClick(e) {
  const btn = e.target.closest('[data-act]');
  if (!btn) return;
  const id = Number(btn.dataset.id);
  const act = btn.dataset.act;
  const site = state.sites.find((s) => s.id === id);
  state.selectedSiteId = id;
  renderSites();
  if (act === 'view') {
    setActiveView('detail');
    renderDetail(site);
    loadSelectedSiteChanges()
      .then(() => renderDetail(state.sites.find((s) => s.id === state.selectedSiteId)))
      .catch((err) => console.error(err));
    return;
  }
  await loadSelectedSiteChanges();
  renderDetail(site);
  if (act === 'check') return checkSite(id).catch((err) => alert(err.message));
  if (act === 'edit') return openDialog(site);
  if (act === 'delete') return deleteSite(id).catch((err) => alert(err.message));
}

els.sitesBody.addEventListener('click', handleSiteTableClick);
els.overviewSitesBody.addEventListener('click', handleSiteTableClick);

els.form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const platform = els.sitePlatform.value;
  const loginEnabled = platform === 'sub2api' ? true : els.siteLoginEnabled.checked;
  const payload = {
    name: els.siteName.value.trim(),
    platform,
    base_url: els.siteBaseUrl.value.trim(),
    interval_minutes: Math.max(1, Number(els.siteInterval.value || 3)),
    usage_divisor: Number(els.siteUsageDivisor.value),
    sub2api_usage_endpoint: platform === 'sub2api' ? els.siteSub2apiUsageEndpoint.value : 'dashboard',
    login_enabled: loginEnabled,
    enabled: els.siteEnabled.checked,
    report_group_id: els.siteReportGroup.value ? Number(els.siteReportGroup.value) : null,
    balance_alert_enabled: els.siteBalanceAlertEnabled.checked,
    balance_alert_threshold: Math.max(0, Number(els.siteBalanceAlertThreshold.value || 0)),
    notify_all_groups: state.dialogAvailableGroups.length === 0
      || selectedNotifyGroups().length === state.dialogAvailableGroups.length,
    notify_groups: selectedNotifyGroups(),
  };
  if (loginEnabled) payload.accounts = accountCards().map(accountPayload);
  const id = els.siteId.value;
  if (id && !loginEnabled && state.dialogAccounts.length
    && !confirm(`关闭认证增强后会删除已保存的 ${state.dialogAccounts.length} 个账号，余额和登录状态不再检测。确认保存？`)) return;
  if (!payload.name || !payload.base_url) {
    setSiteDialogTab('basic');
    els.dialogMsg.textContent = '请填写站点名称和 Base URL';
    els.dialogMsg.classList.add('error');
    showToast('站点名称和 Base URL 不能为空', 'error');
    return;
  }
  if (!Number.isFinite(payload.usage_divisor) || payload.usage_divisor <= 0) {
    setSiteDialogTab('basic');
    els.dialogMsg.textContent = '金额换算倍率必须是大于 0 的数字';
    els.dialogMsg.classList.add('error');
    showToast('金额换算倍率必须是大于 0 的数字', 'error');
    return;
  }
  if (!payload.notify_all_groups && !payload.notify_groups.length) {
    setSiteDialogTab('notify');
    els.dialogMsg.textContent = '请至少选择一个通知分组';
    els.dialogMsg.classList.add('error');
    showToast('请至少选择一个通知分组', 'error');
    return;
  }
  els.saveSiteBtn.disabled = true;
  els.saveSiteBtn.textContent = '保存中...';
  els.dialogMsg.textContent = '正在保存配置...';
  els.dialogMsg.classList.remove('error');
  try {
    if (id) {
      await api(`/api/sites/${id}`, { method: 'PUT', body: JSON.stringify(payload) });
    } else {
      await api('/api/sites', { method: 'POST', body: JSON.stringify(payload) });
    }
    els.dialog.close();
    await refreshAll();
    showToast(id ? '站点配置保存成功' : '站点添加成功');
  } catch (err) {
    els.saveSiteBtn.disabled = false;
    els.saveSiteBtn.textContent = '保存配置';
    els.dialogMsg.textContent = err.message;
    els.dialogMsg.classList.add('error');
    if (/账号|登录|令牌|用户 ID|auth_token|邮箱|密码|重复添加|认证配置/.test(err.message)) setSiteDialogTab('auth');
    showToast(`保存失败：${err.message}`, 'error');
  }
});

function setAccountMessage(card, message, isError = false) {
  const box = card.querySelector('[data-account-msg]');
  box.textContent = message || '';
  box.classList.toggle('error', !!isError);
}

function updateGroupsFromAuthTest(result) {
  if (result.success && result.groups) {
    renderNotifyGroupPicker(Object.keys(result.groups), selectedNotifyGroups(), state.dialogNotifyAllGroups);
  }
}

async function runAccountTest(card) {
  const platform = els.sitePlatform.value;
  const baseUrl = els.siteBaseUrl.value.trim().replace(/\/+$/, '');
  if (!baseUrl) throw new Error('请先在基础配置中填写 Base URL');
  const account = accountPayload(card);
  const siteId = Number(els.siteId.value);
  if (siteId) {
    return api(`/api/sites/${siteId}/auth/test`, {
      method: 'POST',
      body: JSON.stringify({ ...account, account_id: account.id, platform, base_url: baseUrl }),
    });
  }
  if (platform === 'sub2api') {
    if (account.auth_mode === 'password' && (!account.login_username || !account.login_password)) {
      throw new Error('请填写用户邮箱和密码');
    }
    if (account.auth_mode === 'token' && !account.access_token) throw new Error('请填写 auth_token');
    const res = await api('/api/check-connection', {
      method: 'POST',
      body: JSON.stringify({ ...account, platform, base_url: baseUrl }),
    });
    if (res.refreshed_auth) {
      accountField(card, 'sub2api_access_token').value = res.refreshed_auth.access_token || account.access_token || '';
      accountField(card, 'refresh_token').value = res.refreshed_auth.refresh_token || account.refresh_token || '';
      accountField(card, 'token_expires_at').value = res.refreshed_auth.token_expires_at || account.token_expires_at || '';
    }
    return res;
  }
  if (!account.access_token || !account.access_user_id) throw new Error('请填写系统访问令牌和 NewAPI 用户 ID');
  return api('/api/check-login', {
    method: 'POST',
    body: JSON.stringify({ base_url: baseUrl, access_token: account.access_token, access_user_id: account.access_user_id }),
  });
}

async function testAccount(card, button) {
  const originalText = button.textContent;
  button.disabled = true;
  button.textContent = '测试中...';
  setAccountMessage(card, '正在测试认证...');
  try {
    const res = await runAccountTest(card);
    const source = res.used_saved_credentials ? '（已保存认证）' : '';
    setAccountMessage(
      card,
      res.success ? `认证成功${source}：可见 ${res.groups_count} 个分组` : `认证失败：${res.message}`,
      !res.success,
    );
    if (accountCards()[0] === card) updateGroupsFromAuthTest(res);
  } finally {
    button.disabled = false;
    button.textContent = originalText;
  }
}

async function queryAccountUsage(card, button) {
  const siteId = Number(els.siteId.value);
  const accountId = Number(card.dataset.accountId);
  if (!siteId || !accountId) throw new Error('请先保存账号');
  const originalText = button.textContent;
  button.disabled = true;
  button.textContent = '查询中...';
  setAccountMessage(card, '正在实时查询今日消耗...');
  try {
    const result = await api(`/api/sites/${siteId}/usage/today`, {
      method: 'POST',
      body: JSON.stringify({ account_id: accountId }),
    });
    if (result.sub2api_usage_endpoint) {
      els.siteSub2apiUsageEndpoint.value = result.sub2api_usage_endpoint;
      const site = state.sites.find((item) => item.id === siteId);
      if (site) site.sub2api_usage_endpoint = result.sub2api_usage_endpoint;
    }
    const switchedText = result.endpoint_switched ? '；默认接口不可用，已自动切换并固定使用兼容接口' : '';
    if (result.live_success) {
      setAccountMessage(card, `今日消耗：¥${Number(result.amount || 0).toFixed(2)}（上游原始 ${Number(result.raw_amount || 0).toFixed(4)} ${result.raw_currency || 'USD'}）${switchedText}`);
    } else if (result.cached) {
      setAccountMessage(card, `实时查询失败：${result.error || '未知错误'}；当天缓存：¥${Number(result.amount || 0).toFixed(2)}`, true);
    } else {
      setAccountMessage(card, `今日消耗查询失败：${result.error || '未知错误'}`, true);
    }
  } finally {
    button.disabled = false;
    button.textContent = originalText;
  }
}

els.testConnBtn.addEventListener('click', async () => {
  const baseUrl = els.siteBaseUrl.value.trim().replace(/\/+$/, '');
  const platform = els.sitePlatform.value;
  els.dialogMsg.classList.remove('error');
  if (!baseUrl) {
    els.dialogMsg.textContent = '请先填写 Base URL';
    return;
  }
  els.dialogMsg.textContent = '检测中...';
  try {
    let res;
    if (platform === 'sub2api') {
      const card = accountCards()[0];
      if (!card) {
        els.dialogMsg.textContent = 'sub2api 需要先在认证配置中添加账号';
        return;
      }
      res = await runAccountTest(card);
    } else {
      res = await api('/api/check-connection', {
        method: 'POST',
        body: JSON.stringify({ platform, base_url: baseUrl }),
      });
    }
    els.dialogMsg.textContent = res.success
      ? `连接成功${platform === 'sub2api' ? '（主账号）' : ''}：${res.groups_count} 个分组`
      : `连接失败：${res.message}`;
    els.dialogMsg.classList.toggle('error', !res.success);
    updateGroupsFromAuthTest(res);
  } catch (err) {
    els.dialogMsg.textContent = `连接失败：${err.message}`;
    els.dialogMsg.classList.add('error');
  }
});

els.notifyForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  els.emailStatus.textContent = '保存中...';
  els.emailStatus.classList.remove('error');
  try {
    const res = await api('/api/notifications/settings', {
      method: 'PUT',
      body: JSON.stringify(notificationPayload()),
    });
    state.notificationSettings = res.data || {};
    state.notificationDirty = false;
    renderNotificationSettings({ force: true });
  } catch (err) {
    els.emailStatus.textContent = `保存失败：${err.message}`;
    els.emailStatus.classList.add('error');
  }
});

els.testEmailBtn.addEventListener('click', async () => {
  els.emailStatus.textContent = '测试邮件发送中...';
  els.emailStatus.classList.remove('error');
  try {
    const res = await api('/api/notifications/test-email', {
      method: 'POST',
      body: JSON.stringify(notificationPayload()),
    });
    els.emailStatus.textContent = res.message || '测试完成';
    state.notificationDirty = false;
    await refreshAll();
  } catch (err) {
    els.emailStatus.textContent = `测试失败：${err.message}`;
    els.emailStatus.classList.add('error');
  }
});

els.testWecomBtn.addEventListener('click', async () => {
  els.wecomStatus.textContent = '测试企业微信发送中...';
  els.wecomStatus.classList.remove('error');
  try {
    const res = await api('/api/notifications/test-wecom', {
      method: 'POST',
      body: JSON.stringify(notificationPayload()),
    });
    els.wecomStatus.textContent = res.message || '测试完成';
    state.notificationDirty = false;
    await refreshAll();
  } catch (err) {
    els.wecomStatus.textContent = `测试失败：${err.message}`;
    els.wecomStatus.classList.add('error');
  }
});

els.testFeishuBtn.addEventListener('click', async () => {
  els.feishuStatus.textContent = '测试飞书发送中...';
  els.feishuStatus.classList.remove('error');
  try {
    const res = await api('/api/notifications/test-feishu', {
      method: 'POST',
      body: JSON.stringify(notificationPayload()),
    });
    els.feishuStatus.textContent = res.message || '测试完成';
    state.notificationDirty = false;
    await refreshAll();
  } catch (err) {
    els.feishuStatus.textContent = `测试失败：${err.message}`;
    els.feishuStatus.classList.add('error');
  }
});

els.testQqBtn.addEventListener('click', async () => {
  els.qqStatus.textContent = '测试 QQ 群发送中...';
  els.qqStatus.classList.remove('error');
  try {
    const res = await api('/api/notifications/test-qq', {
      method: 'POST',
      body: JSON.stringify(notificationPayload()),
    });
    els.qqStatus.textContent = res.message || '测试完成';
    state.notificationDirty = false;
    await refreshAll();
  } catch (err) {
    els.qqStatus.textContent = `测试失败：${err.message}`;
    els.qqStatus.classList.add('error');
  }
});

refreshAll().catch((err) => {
  console.error(err);
  els.detailPane.textContent = err.message;
});

setInterval(() => {
  refreshAll({ background: true }).catch(() => {});
}, 15000);
