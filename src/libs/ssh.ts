import { homedir } from "os";
import { join } from "path";

export function keyPath(pub = false): string {
  let filename = 'id_rsa'
  if (pub) filename += '.pub'
  return join(homedir(), '.ssh', filename);
}