import { start, stop } from './log.js';
import { copyid, signDebugserver } from './sshagent.js';

const ping = () => Process.id;

rpc.exports = {
    start,
    stop,
    ping,
    copyid,
    signDebugserver
};
