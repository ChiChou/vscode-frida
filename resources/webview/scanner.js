(function () {
  // @ts-ignore
  const vscode = acquireVsCodeApi();

  let scanMode = 'string';
  let scanning = false;
  let matchCount = 0;

  const $scanTabs = document.getElementById('scan-tabs');
  const $scanInput = document.getElementById('scan-input');
  const $btnScan = document.getElementById('btn-scan');
  const $btnStop = document.getElementById('btn-stop');
  const $scanResults = document.getElementById('scan-results');
  const $scanProgress = document.getElementById('scan-progress');
  const $progressFill = document.getElementById('progress-fill');
  const $progressText = document.getElementById('progress-text');
  const $statusText = document.getElementById('status-text');
  const $hexDump = document.getElementById('hex-dump');

  window.addEventListener('message', (event) => {
    const msg = event.data;
    switch (msg.type) {
      case 'setRanges':
        // Ranges loaded, ready to scan
        break;
      case 'setStatus':
        handleStatus(msg.status);
        break;
      case 'scanMatch':
        appendMatch(msg.address, msg.size);
        break;
      case 'scanProgress':
        updateProgress(msg.current, msg.total);
        break;
      case 'scanComplete':
        onScanComplete(msg);
        break;
      case 'setReadResult':
        renderHexDump(msg.address, msg.hex);
        break;
      case 'error':
        showError(msg.message);
        break;
    }
  });

  function handleStatus(status) {
    switch (status) {
      case 'connecting':
        $statusText.textContent = window.I18N.connecting;
        $statusText.className = 'loading';
        $scanInput.disabled = true;
        $btnScan.disabled = true;
        break;
      case 'ready':
        $statusText.style.display = 'none';
        $scanInput.disabled = false;
        $btnScan.disabled = false;
        $scanResults.innerHTML = '';
        break;
      case 'disconnected':
        $statusText.style.display = '';
        $statusText.textContent = 'Disconnected';
        $statusText.className = 'placeholder';
        $scanInput.disabled = true;
        $btnScan.disabled = true;
        setScanning(false);
        break;
      case 'error':
        $statusText.style.display = '';
        $statusText.textContent = 'Error';
        $statusText.className = 'placeholder';
        $scanInput.disabled = true;
        $btnScan.disabled = true;
        break;
    }
  }

  $scanTabs.addEventListener('click', (e) => {
    const tab = e.target.closest('.scan-tab');
    if (!tab) return;
    const newMode = tab.dataset.mode;
    if (newMode === scanMode) return;

    const oldMode = scanMode;
    const input = $scanInput.value;
    scanMode = newMode;
    $scanTabs.querySelectorAll('.scan-tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    updatePlaceholder();

    // Auto-convert input between modes
    if (newMode === 'pointer') {
      $scanInput.value = '';
    } else if (oldMode === 'string' && newMode === 'hex') {
      // string -> hex
      if (input) {
        const bytes = [];
        for (let i = 0; i < input.length; i++) {
          bytes.push(input.charCodeAt(i).toString(16).padStart(2, '0'));
        }
        $scanInput.value = bytes.join(' ');
      }
    } else if (oldMode === 'hex' && newMode === 'string') {
      // hex -> string
      if (input) {
        const parts = input.trim().split(/\s+/);
        let str = '';
        for (const p of parts) {
          if (p === '??') continue;
          const code = parseInt(p, 16);
          if (!isNaN(code) && code >= 0x20 && code <= 0x7e) {
            str += String.fromCharCode(code);
          }
        }
        $scanInput.value = str;
      }
    } else if (oldMode === 'pointer') {
      $scanInput.value = '';
    }
  });

  $btnScan.addEventListener('click', startScan);

  $btnStop.addEventListener('click', () => {
    vscode.postMessage({ type: 'cancel' });
  });

  $scanInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !scanning) $btnScan.click();
  });

  function startScan() {
    const input = $scanInput.value.trim();
    if (!input) return;

    const pattern = convertPattern(input, scanMode);
    if (!pattern) {
      showError('Invalid pattern');
      return;
    }

    matchCount = 0;
    $scanResults.innerHTML = '';
    $hexDump.style.display = 'none';
    setScanning(true);

    vscode.postMessage({ type: 'scan', pattern });
  }

  function setScanning(active) {
    scanning = active;
    $btnScan.style.display = active ? 'none' : '';
    $btnStop.style.display = active ? '' : 'none';
    $scanInput.disabled = active;
    $scanProgress.style.display = active ? '' : 'none';
    if (!active) {
      $progressFill.style.width = '0%';
      $progressText.textContent = '';
    }
  }

  function updateProgress(current, total) {
    const pct = Math.round((current / total) * 100);
    $progressFill.style.width = pct + '%';
    $progressText.textContent = current + ' / ' + total;
  }

  function appendMatch(address, size) {
    matchCount++;

    // Add header on first match
    if (matchCount === 1) {
      const header = document.createElement('div');
      header.className = 'pane-header scan-results-header';
      header.id = 'results-header';
      header.innerHTML = '<h2>' + window.I18N.results + ' (1)</h2>';
      $scanResults.appendChild(header);
    } else {
      const header = document.getElementById('results-header');
      if (header) {
        header.innerHTML = '<h2>' + window.I18N.results + ' (' + matchCount + ')</h2>';
      }
    }

    const row = document.createElement('div');
    row.className = 'list-row';

    const addr = document.createElement('span');
    addr.className = 'name mono';
    addr.textContent = address;
    row.appendChild(addr);

    row.addEventListener('click', () => {
      selectResult(row);
      vscode.postMessage({ type: 'read', address: address, size: 256 });
    });

    $scanResults.appendChild(row);
  }

  $scanResults.setAttribute('tabindex', '0');

  $scanResults.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const rows = $scanResults.querySelectorAll('.list-row');
      if (!rows.length) return;
      const current = $scanResults.querySelector('.list-row.selected');
      let idx = current ? Array.from(rows).indexOf(current) : -1;
      idx = e.key === 'ArrowDown' ? Math.min(idx + 1, rows.length - 1) : Math.max(idx - 1, 0);
      selectResult(rows[idx]);
      rows[idx].click();
    }
  });

  function selectResult(row) {
    const prev = $scanResults.querySelector('.list-row.selected');
    if (prev) prev.classList.remove('selected');
    row.classList.add('selected');
    row.scrollIntoView({ block: 'nearest' });
  }

  function onScanComplete(msg) {
    setScanning(false);
    if (matchCount === 0) {
      $scanResults.innerHTML = '<div class="placeholder">' + window.I18N.noResults + '</div>';
    }
  }

  function updatePlaceholder() {
    switch (scanMode) {
      case 'string':
        $scanInput.placeholder = 'Search string...';
        break;
      case 'hex':
        $scanInput.placeholder = 'AA BB CC ?? DD...';
        break;
      case 'pointer':
        $scanInput.placeholder = '0x7fff12340000';
        break;
    }
  }

  function convertPattern(input, mode) {
    switch (mode) {
      case 'string': {
        const bytes = [];
        for (let i = 0; i < input.length; i++) {
          const code = input.charCodeAt(i);
          if (code > 0xff) {
            bytes.push((code & 0xff).toString(16).padStart(2, '0'));
            bytes.push(((code >> 8) & 0xff).toString(16).padStart(2, '0'));
          } else {
            bytes.push(code.toString(16).padStart(2, '0'));
          }
        }
        return bytes.join(' ');
      }
      case 'hex':
        return input;
      case 'pointer': {
        let addr = input;
        if (addr.startsWith('0x') || addr.startsWith('0X')) {
          addr = addr.substring(2);
        }
        addr = addr.padStart(16, '0');
        const bytes = [];
        for (let i = addr.length - 2; i >= 0; i -= 2) {
          bytes.push(addr.substring(i, i + 2));
        }
        return bytes.join(' ');
      }
    }
    return null;
  }

  function renderHexDump(address, hexStr) {
    $hexDump.style.display = '';
    $hexDump.innerHTML = '';

    const pre = document.createElement('pre');
    pre.className = 'hex-dump-content';

    const bytes = [];
    for (let i = 0; i < hexStr.length; i += 2) {
      bytes.push(parseInt(hexStr.substring(i, i + 2), 16));
    }

    const lines = [];
    const baseAddr = BigInt(address);
    for (let i = 0; i < bytes.length; i += 16) {
      const chunk = bytes.slice(i, i + 16);
      const addr = '0x' + (baseAddr + BigInt(i)).toString(16).padStart(12, '0');
      const hexPart = chunk.map(b => b.toString(16).padStart(2, '0')).join(' ');
      const asciiPart = chunk.map(b => (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '.').join('');
      lines.push(addr + '  ' + hexPart.padEnd(48, ' ') + '  ' + asciiPart);
    }

    pre.textContent = lines.join('\n');
    $hexDump.appendChild(pre);
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
