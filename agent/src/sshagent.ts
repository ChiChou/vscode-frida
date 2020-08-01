import { readFileSync, createWriteStream } from 'fs';


export async function copyid(id: string) {
  const system = new NativeFunction(Module.findExportByName(null, 'system')!, 'int', ['pointer']);
  function sh(cmd: string): number {
    return system(Memory.allocUtf8String(cmd)) as number;
  }

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

    await new Promise((resolve, reject) => {
      content.push(id);
      const joint = content.join('\n') + '\n';
      const stream = createWriteStream(file);
      stream.on('finish', resolve).on('error', reject);
      stream.write(joint);
      stream.end();
    });
  }
}