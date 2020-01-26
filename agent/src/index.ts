import { get as getFileSystem } from './fs';

const fs = getFileSystem();

rpc.exports = {
    copy: fs.copy.bind(fs),
    mkdir: fs.mkdir.bind(fs),
    rm: fs.rm.bind(fs),
    ls: fs.ls.bind(fs),
    read: fs.read.bind(fs),
    mv: fs.rename.bind(fs),
    stat: fs.stat.bind(fs),
    write: fs.write.bind(fs),
};
