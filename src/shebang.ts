import { promises as fs } from 'node:fs';

const SHEBANG_UNIX = '#!';
const BUF_SHEBANG_UNIX = Buffer.from(SHEBANG_UNIX);
const PE_MAGIC = Buffer.from('MZ');

// const ZIP_SIGNATURE = Buffer.from([0x50, 0x4B, 0x05, 0x06]);

// typedef struct {
//   DWORD sig;
//   DWORD unused_disk_nos;
//   DWORD unused_numrecs;
//   DWORD cdsize;
//   DWORD cdoffset;
// } ENDCDR;

// https://github.com/pypa/distlib/blob/32301789a7815de0e74f57fe013ae52af717a3da/PC/launcher.c#L177
//
// the implementation is so cursed that we might as well simply search for #!

function parseWindowsLauncher(buffer: Buffer) {
  let subarray = buffer;

  while (true) {
    let p = subarray.lastIndexOf(BUF_SHEBANG_UNIX);
    if (p === -1) { throw new Error('Invalid shebang'); }

    const end = subarray.indexOf('\n', p);
    if (end === -1) { throw new Error('Invalid shebang'); }

    const line = subarray.subarray(p, end).toString().trim();
    if (line.endsWith('.exe')) {
      return interpreter(line);
    }

    subarray = subarray.subarray(end + 1);
  }
}

function interpreter(line: string) {
  if (!line.startsWith(SHEBANG_UNIX)) { throw new Error('Invalid shebang'); }
  return line.substring(SHEBANG_UNIX.length);
}

export default async function shebang(path: string) {
  const buffer = await fs.readFile(path);
  const magic = buffer.subarray(0, SHEBANG_UNIX.length);

  if (magic.compare(BUF_SHEBANG_UNIX) === 0) {
    const lineEnd = buffer.indexOf('\n');
    return interpreter(buffer.subarray(0, lineEnd).toString());
  } else if (magic.compare(PE_MAGIC) === 0) {
    return parseWindowsLauncher(buffer);
  }

  throw new Error('Invalid file format');
}

