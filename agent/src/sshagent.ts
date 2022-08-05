import { unlinkSync, readFileSync, createWriteStream } from 'fs';

const system = new NativeFunction(
  Module.findExportByName(null, 'system')!, 'int', ['pointer']);

function sh(cmd: string): number {
  return system(Memory.allocUtf8String(cmd)) as number;
}

export async function signDebugserver(ent: string) {
  const dest = '/usr/bin/debugserver';
  const tmp = '/tmp/ent.xml';

  if (sh(`cp /Developer${dest} ${dest}`) !== 0) {
    throw new Error('Failed to copy original debugserver. Did you mount Developer Disk Image?');
  }
  await write(tmp, ent);
  if (sh(`ldid -S${tmp} ${dest}`) !== 0) {
    throw new Error('Failed to sign debugserver with new signature. Is ldid avaliable on your device?');
  }
  unlinkSync(tmp);
}

function write(file: string, content: string) {
  return new Promise((resolve, reject) => {
    const stream = createWriteStream(file);
    stream.on('finish', resolve).on('error', reject);
    stream.write(content);
    stream.end();
  });
}

export async function copyid(id: string) {
  for (const user of ['root', 'mobile']) {
    // look at me I am so injected
    const parent = `/var/${user}/.ssh/`;
    const file = `${parent}authorized_keys`;

    sh(`mkdir -p ${parent}`);
    sh(`touch ${file}`);
    sh(`chown ${user}:${user} ${file}`);
    sh(`chmod 0600 ${file}`);

    let content: string[] = [];
    try {
      content = readFileSync(file).toString().split('\n');
    } catch (_) { }

    if (content.indexOf(id) > -1) { continue; }

    content.push(id);
    const joint = content.join('\n') + '\n';
    return write(file, joint);
  }
}