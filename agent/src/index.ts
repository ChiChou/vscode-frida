import * as fs from './fs';
import { start, stop } from './log';

const ping = () => Process.id;

rpc.exports = {
    fs: fs.invoke,
    start,
    stop,
    ping,
};
