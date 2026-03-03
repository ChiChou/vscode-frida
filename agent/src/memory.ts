interface MemoryRange {
  base: string;
  size: number;
  protection: string;
  file?: { path: string; offset: number; size: number };
}

interface ScanMatch {
  address: string;
  size: number;
}

export function ranges(): MemoryRange[] {
  return Process.enumerateRanges('---').map(r => {
    const result: MemoryRange = {
      base: r.base.toString(),
      size: r.size,
      protection: r.protection,
    };
    if (r.file) {
      result.file = {
        path: r.file.path,
        offset: r.file.offset,
        size: r.file.size,
      };
    }
    return result;
  });
}

export function read(address: string, size: number): string {
  const buf = ptr(address).readByteArray(size);
  if (!buf) return '';
  const arr = new Uint8Array(buf);
  const hex: string[] = [];
  for (let i = 0; i < arr.length; i++) {
    hex.push(arr[i].toString(16).padStart(2, '0'));
  }
  return hex.join('');
}

export function scan(rangeBase: string, rangeSize: number, pattern: string): Promise<ScanMatch[]> {
  return new Promise((resolve) => {
    const matches: ScanMatch[] = [];
    const MAX_MATCHES = 1000;

    Memory.scan(ptr(rangeBase), rangeSize, pattern, {
      onMatch(address, size) {
        matches.push({ address: address.toString(), size });
        if (matches.length >= MAX_MATCHES) return 'stop';
      },
      onError(reason) {
        // skip unreadable pages
      },
      onComplete() {
        resolve(matches);
      },
    });
  });
}

let scanCancelled = false;

export function cancelScan(): void {
  scanCancelled = true;
}

export function dump(address: string, size: number): void {
  const CHUNK = 4096;
  const base = ptr(address);
  let offset = 0;

  function next(): void {
    if (offset >= size) {
      send({ subject: 'dump', event: 'end' });
      return;
    }
    const len = Math.min(CHUNK, size - offset);
    const buf = base.add(offset).readByteArray(len);
    send({ subject: 'dump', event: 'data' }, buf);
    offset += len;
    setTimeout(next, 0);
  }
  next();
}

export function scanAll(pattern: string): Promise<{ totalRanges: number; totalMatches: number }> {
  scanCancelled = false;
  const allRanges = Process.enumerateRanges('r--');
  let totalMatches = 0;
  const MAX = 10000;

  return new Promise((resolve) => {
    let i = 0;
    function next(): void {
      if (scanCancelled || i >= allRanges.length || totalMatches >= MAX) {
        send({ subject: 'scanAll', event: 'complete', cancelled: scanCancelled,
               totalRanges: allRanges.length, scannedRanges: i, totalMatches });
        resolve({ totalRanges: allRanges.length, totalMatches });
        return;
      }
      const r = allRanges[i++];
      send({ subject: 'scanAll', event: 'progress', current: i, total: allRanges.length });
      Memory.scan(r.base, r.size, pattern, {
        onMatch(address, size) {
          totalMatches++;
          send({ subject: 'scanAll', event: 'match', address: address.toString(), size });
          if (totalMatches >= MAX || scanCancelled) return 'stop';
        },
        onError() {},
        onComplete() { setTimeout(next, 0); },
      });
    }
    next();
  });
}

