(function () {
  // @ts-ignore
  const vscode = acquireVsCodeApi();

  const $loading = document.getElementById('dashboard-loading');
  const $cards = document.getElementById('dashboard-cards');

  let rawXml = '';

  window.addEventListener('message', (event) => {
    const msg = event.data;
    switch (msg.type) {
      case 'setInfo':
        renderDashboard(msg.info);
        break;
      case 'setLoading':
        $loading.style.display = msg.loading ? '' : 'none';
        $cards.style.display = msg.loading ? 'none' : '';
        break;
      case 'error':
        showError(msg.message);
        break;
    }
  });

  function renderDashboard(info) {
    const cards = [];

    // Device card
    const dev = info.device || {};
    cards.push(renderCard(window.I18N.device, [
      { label: window.I18N.name, value: dev.name || '-' },
      { label: window.I18N.id, value: dev.id || '-' },
      { label: window.I18N.type, value: dev.type || '-' },
    ]));

    // OS card
    const os = info.os || {};
    cards.push(renderCard(window.I18N.os, [
      { label: window.I18N.name, value: os.name || os.id || '-' },
      { label: window.I18N.version, value: os.version || '-' },
      { label: window.I18N.arch, value: info.arch || '-' },
      { label: window.I18N.platform, value: info.platform || '-' },
    ]));

    // Frida card
    cards.push(renderCard(window.I18N.frida, [
      { label: window.I18N.version, value: info.frida || '-' },
    ]));

    // Security card
    const access = info.access || 'unknown';
    let accessLabel;
    if (access === 'full') {
      accessLabel = window.I18N.full;
    } else if (access === 'jailed') {
      accessLabel = window.I18N.jailed;
    } else {
      accessLabel = window.I18N.unknown;
    }
    cards.push(renderCard(window.I18N.security, [
      { label: window.I18N.access, value: accessLabel, badge: access },
    ]));

    $cards.innerHTML = '';
    cards.forEach(c => $cards.appendChild(c));
  }

  function renderCard(title, rows) {
    const card = document.createElement('div');
    card.className = 'dashboard-card';

    const header = document.createElement('div');
    header.className = 'dashboard-card-header';
    header.textContent = title;
    card.appendChild(header);

    const body = document.createElement('div');
    body.className = 'dashboard-card-body';

    rows.forEach(r => {
      const row = document.createElement('div');
      row.className = 'info-row';

      const label = document.createElement('span');
      label.className = 'label';
      label.textContent = r.label;

      const value = document.createElement('span');
      value.className = 'value';
      value.textContent = r.value;

      if (r.badge) {
        const badge = document.createElement('span');
        badge.className = 'dashboard-badge dashboard-badge-' + r.badge;
        badge.textContent = r.value;
        row.appendChild(label);
        row.appendChild(badge);
      } else {
        row.appendChild(label);
        row.appendChild(value);
      }

      body.appendChild(row);
    });

    card.appendChild(body);
    return card;
  }

  function showError(message) {
    const toast = document.createElement('div');
    toast.className = 'error-toast';
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 5000);
  }

  vscode.postMessage({ type: 'ready' });
})();
