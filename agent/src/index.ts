import { get as getFileSystem } from './fs';

const fs = getFileSystem();

rpc.exports = {
    copy: fs.copy.bind(fs),
    mkdir: fs.createDirectory.bind(fs),
    rm: fs.delete.bind(fs),
    ls: fs.readDirectory.bind(fs),
    read: fs.readFile.bind(fs),
    mv: fs.rename.bind(fs),
    stat: fs.stat.bind(fs),
    write: fs.writeFile.bind(fs),
};
