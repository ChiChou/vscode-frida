import { promises as fs } from 'node:fs';

const SHEBANG_UNIX = '#!';
const BUF_SHEBANG_UNIX = Buffer.from(SHEBANG_UNIX);
const PE_MAGIC = Buffer.from('MZ');

const ZIP_SIGNATURE = Buffer.from([0x50, 0x4B, 0x05, 0x06]);

// https://bitbucket.org/vinay.sajip/simple_launcher/src/2e1c7592574c4f42062fd3a5b1051ec02da4b543/launcher.c#lines-177

// typedef struct {
//   DWORD sig;
//   DWORD unused_disk_nos;
//   DWORD unused_numrecs;
//   DWORD cdsize;
//   DWORD cdoffset;
// } ENDCDR;

function parseWindowsLauncher(buffer: Buffer) {
  const end = buffer.lastIndexOf(ZIP_SIGNATURE);
  if (end === -1) { throw new Error('Invalid archive'); }

  const cdsize = buffer.readUInt16LE(end + 12);
  const cdoffset = buffer.readUInt32LE(end + 16);
  const endOfShebang = end - cdsize - cdoffset;

  const shebang = buffer.lastIndexOf(BUF_SHEBANG_UNIX, endOfShebang);
  const line = buffer.subarray(shebang, endOfShebang).toString().trim();
  return interpreter(line);
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

