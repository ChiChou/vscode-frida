(function () {
  // @ts-ignore
  const vscode = acquireVsCodeApi();

  let allRanges = [];
  let permFilter = { r: false, w: false, x: false };

  const $rangeList = document.getElementById('range-list');
  const $filterR = document.getElementById('filter-r');
  const $filterW = document.getElementById('filter-w');
  const $filterX = document.getElementById('filter-x');

  window.addEventListener('message', (event) => {
    const msg = event.data;
    switch (msg.type) {
      case 'setRanges':
        allRanges = msg.ranges;
        renderRanges();
        break;
      case 'setLoading':
        if (msg.loading) {
          $rangeList.innerHTML = '<div class="loading">Loading...</div>';
        }
        break;
      case 'error':
        showError(msg.message);
        break;
    }
  });

  $filterR.addEventListener('change', () => { permFilter.r = $filterR.checked; renderRanges(); });
  $filterW.addEventListener('change', () => { permFilter.w = $filterW.checked; renderRanges(); });
  $filterX.addEventListener('change', () => { permFilter.x = $filterX.checked; renderRanges(); });

  $rangeList.setAttribute('tabindex', '0');

  $rangeList.addEventListener('click', (e) => {
    const btn = e.target.closest('.dump-btn');
    if (btn) {
      vscode.postMessage({ type: 'dump', address: btn.dataset.address, size: Number(btn.dataset.size) });
      return;
    }
    const row = e.target.closest('.range-row');
    if (row) selectRow(row);
  });

  $rangeList.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const rows = $rangeList.querySelectorAll('.range-row');
      if (!rows.length) return;
      const current = $rangeList.querySelector('.range-row.selected');
      let idx = current ? Array.from(rows).indexOf(current) : -1;
      idx = e.key === 'ArrowDown' ? Math.min(idx + 1, rows.length - 1) : Math.max(idx - 1, 0);
      selectRow(rows[idx]);
    }
  });

  function selectRow(row) {
    const prev = $rangeList.querySelector('.range-row.selected');
    if (prev) prev.classList.remove('selected');
    row.classList.add('selected');
    row.scrollIntoView({ block: 'nearest' });
  }


  function filterRanges() {
    const anyPerm = permFilter.r || permFilter.w || permFilter.x;
    if (!anyPerm) return allRanges;
    return allRanges.filter(r => {
      if (permFilter.r && !r.protection.includes('r')) return false;
      if (permFilter.w && !r.protection.includes('w')) return false;
      if (permFilter.x && !r.protection.includes('x')) return false;
      return true;
    });
  }

  function renderRanges() {
    const filtered = filterRanges();

    $rangeList.innerHTML = '';
    const fragment = document.createDocumentFragment();

    filtered.forEach(r => {
      const row = document.createElement('div');
      row.className = 'range-row';

      const topLine = document.createElement('div');
      topLine.className = 'range-row-top';

      const addrSpan = document.createElement('span');
      addrSpan.className = 'name mono';
      addrSpan.textContent = r.base;

      const sizeSpan = document.createElement('span');
      sizeSpan.className = 'address';
      sizeSpan.textContent = formatSize(r.size);

      const protSpan = document.createElement('span');
      protSpan.className = 'badge';
      protSpan.textContent = r.protection;

      const dumpBtn = document.createElement('button');
      dumpBtn.className = 'dump-btn';
      dumpBtn.title = 'Dump';
      dumpBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v8"/><path d="m16 6-4 4-4-4"/><rect width="20" height="8" x="2" y="14" rx="2"/><path d="M6 18h.01"/><path d="M10 18h.01"/></svg>';
      dumpBtn.dataset.address = r.base;
      dumpBtn.dataset.size = r.size;

      topLine.appendChild(addrSpan);
      topLine.appendChild(sizeSpan);
      topLine.appendChild(protSpan);
      topLine.appendChild(dumpBtn);

      const bottomLine = document.createElement('div');
      bottomLine.className = 'range-row-path';
      bottomLine.textContent = r.file ? r.file.path : '';

      row.appendChild(topLine);
      row.appendChild(bottomLine);

      fragment.appendChild(row);
    });

    $rangeList.appendChild(fragment);
  }

  function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
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
