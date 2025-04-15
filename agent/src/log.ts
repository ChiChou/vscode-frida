// sys/fcntl.h
const F_SETFL = 4;
const O_NONBLOCK = 0x0004;

const stderr = 2;
const SIZEOF_INT = 4; // for mac & iOS

const subject = 'syslog';
const fildes: NativePointer = Memory.alloc(SIZEOF_INT * 2);

let stream: UnixInputStream;

export function start() {
  stop();

  const resolve = (name: string): NativePointer => {
    const p = Module.findExportByName(null, name);
    if (!p) {
      throw new Error(`Platform not supported. Is your target on ${name}?`);
    }
    return p;
  }

  const pipe = new NativeFunction(resolve('pipe'), 'int', ['pointer']);
  const dup2 = new NativeFunction(resolve('dup2'), 'int', ['int', 'int']);
  const close = new NativeFunction(resolve('close'), 'int', ['int']);
  const fcntl = new NativeFunction(resolve('fcntl'), 'int', ['int', 'int', 'int']);

  pipe(fildes);

  const input = fildes.readInt();
  const output = fildes.add(SIZEOF_INT).readInt();

  dup2(output, stderr);
  close(output);
  fcntl(input, F_SETFL, O_NONBLOCK);

  stream = new UnixInputStream(input);

  function read() {
    stream.read(4096).then((buf) => {
      if (buf.byteLength) {
        send({ subject }, buf);
      }

      setImmediate(read);
    });
  }

  setImmediate(read);
}

export function stop() {
  if (stream) {
    stream.close();
  }
}
