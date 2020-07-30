import * as net from 'net';


function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    net.createServer((socket) => {
      const { port } = socket.address() as net.AddressInfo;
      resolve(port);
    }).on('error', reject);
  });
}

export async function decrypt(): Promise<void> {
  const port = await freePort();
  
}
