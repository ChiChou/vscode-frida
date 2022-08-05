import * as fs from './fs.js';
import { start, stop } from './log.js';
import { copyid, signDebugserver } from './sshagent.js';

const ping = () => Process.id;

rpc.exports = {
    fs: fs.invoke,
    start,
    stop,
    ping,
    copyid,
    signDebugserver
};
