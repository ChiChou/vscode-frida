import { start, stop } from './log.js';

const ping = () => Process.id;

rpc.exports = {
    start,
    stop,
    ping
};
