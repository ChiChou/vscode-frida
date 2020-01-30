import * as fs from './fs';
import { start, stop } from './log';

rpc.exports = {
    fs: fs.invoke,
    start,
    stop,
};
