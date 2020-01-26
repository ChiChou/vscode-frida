import { FileStat, FileType } from "../vscode";
import * as fs from "fs";

type Uri = String;

export abstract class FileSystem {
  public abstract copy(source: Uri, target: Uri, options?: { overwrite: boolean }): Thenable<void>;
  public abstract mkdir(uri: Uri): Thenable<void>;
  public abstract rm(uri: Uri, options?: { recursive: boolean, useTrash: boolean }): Thenable<void>;
  public abstract ls(uri: Uri): Thenable<[string, FileType][]>;
  public abstract read(uri: Uri): Thenable<Uint8Array>;
  public abstract rename(source: Uri, target: Uri, options?: { overwrite: boolean }): Thenable<void>;
  public abstract stat(uri: Uri): Thenable<FileStat>;
  public abstract write(uri: Uri, content: Uint8Array): Thenable<void>;
}

export class ObjCFileSystem implements FileSystem {
  manager: ObjC.Object;
  constructor() {
    this.manager = ObjC.classes.NSFileManager.defaultManager();
  }

  public copy(source: String, target: String, options?: { overwrite: boolean; } | undefined): Thenable<void> {
    if (options!.overwrite && this.manager.fileExistsAtPath_(target)) {
      this.rm(target);
    }
    this.manager.copyItemAtPath_toPath_error_(source, target, NULL);
    return Promise.resolve();
  }

  public mkdir(uri: String): Thenable<void> {
    const YES = 1;
    this.manager.createDirectoryAtPath_withIntermediateDirectories_attributes_error_(uri, YES, NULL, NULL);
    return Promise.resolve();
  }

  public rm(uri: String, options?: { recursive: boolean; useTrash: boolean; } | undefined): Thenable<void> {
    this.manager.removeItemAtPath_error_(uri, NULL);
    return Promise.resolve();
  }

  public ls(uri: String): Thenable<[string, FileType][]> {
    const arr = this.manager.contentsOfDirectoryAtPath_error_(uri, NULL);
    const length = arr.count();
    const parent = ObjC.classes.NSString.stringWithString_(uri);
    const pError = Memory.alloc(Process.pointerSize);
    const result: [string, FileType][] = [];

    const mapping: {[type: string]: FileType } = {
      NSFileTypeRegular: FileType.File,
      NSFileTypeDirectory: FileType.Directory,
      NSFileTypeSymbolicLink: FileType.SymbolicLink,
    };

    for (let i = 0; i < length; i++) {
      const entry = arr.objectAtIndex_(i);
      const filename = parent.stringByAppendingPathComponent_(entry);
      pError.writePointer(NULL);
      const attr = this.manager.attributesOfItemAtPath_error_(filename, pError);
      const err = pError.readPointer();
      if (!err.isNull()) {
        console.error(new ObjC.Object(err).localizedDescription());
      } 
      const type = mapping[attr.objectForKey_('NSFileType').toString()] || FileType.Unknown;
      result.push([entry.toString(), type]);
    }
    return Promise.resolve(result);
  }

  public read(uri: String): Thenable<Uint8Array> {
    // todo: check file size
    throw new Error("Method not implemented.");
  }

  public rename(source: String, target: String, options?: { overwrite: boolean; } | undefined): Thenable<void> {
    if (options!.overwrite && this.manager.fileExistsAtPath_(target)) {
      this.rm(target);
    }
    this.manager.moveItemAtPath_toPath_error_(source, target, NULL);
    return Promise.resolve();
  }

  public stat(uri: String): Thenable<FileStat> {
    // TODO: use attributesOfItemAtPath_error_
    const stat = fs.statSync(uri as fs.PathLike);
    const { size, mode } = stat;
    const ctime = stat.ctimeMs;
    const mtime = stat.mtimeMs;

    const { constants } = fs;
    const { S_IFREG, S_IFLNK, S_IFDIR } = constants;

    let type = FileType.Unknown;
    if (mode & S_IFLNK) {
      type = FileType.SymbolicLink;
    } else if (mode & S_IFREG) {
      type = FileType.File;
    } else if (mode & S_IFDIR) {
      type = FileType.Directory;
    }

    return Promise.resolve({
      type,
      ctime,
      mtime,
      size,
    });
  }

  public write(uri: String, content: Uint8Array): Thenable<void> {
    throw new Error("Method not implemented.");
  }

}

export function get(): FileSystem {
  if (ObjC.available) {
    return new ObjCFileSystem();
  } /* else if (Java.available) {
    
  } */

  throw new Error('Not implemented');
}