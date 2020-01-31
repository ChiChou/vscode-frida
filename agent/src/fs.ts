import { FileStat, FileType } from "../vscode";
import * as fs from "fs";

export abstract class FileSystem {
  public abstract copy(source: string, target: string, options?: { overwrite: boolean }): Thenable<void>;
  public abstract mkdir(uri: string): Thenable<void>;
  public abstract rm(uri: string, options?: { recursive: boolean, useTrash: boolean }): Thenable<void>;
  public abstract ls(uri: string): Thenable<[string, FileType][]>;
  public abstract read(uri: string): Thenable<Uint8Array>;
  public abstract rename(source: string, target: String, options?: { overwrite: boolean }): Thenable<void>;
  public abstract stat(uri: string): Thenable<FileStat>;
  public abstract write(uri: string, content: Uint8Array): Thenable<void>;
}

// export class JavaFileSystem implements FileSystem

export class ObjCFileSystem implements FileSystem {
  manager: ObjC.Object;
  constructor() {
    this.manager = ObjC.classes.NSFileManager.defaultManager();
  }

  private normalize(uri: string): ObjC.Object {
    return ObjC.classes.NSString.stringWithString_(uri).stringByExpandingTildeInPath();
  }

  public copy(source: string, target: string, options?: { overwrite: boolean; } | undefined): Thenable<void> {
    const src = this.normalize(source);
    const dst = this.normalize(target);
    if (options!.overwrite && this.manager.fileExistsAtPath_(dst)) {
      this.rm(target);
    }
    this.manager.copyItemAtPath_toPath_error_(src, dst, NULL);
    return Promise.resolve();
  }

  public mkdir(path: string): Thenable<void> {
    const abs = this.normalize(path);
    const YES = 1;
    this.manager.createDirectoryAtPath_withIntermediateDirectories_attributes_error_(abs, YES, NULL, NULL);
    return Promise.resolve();
  }

  public rm(path: string, options?: { recursive: boolean; useTrash: boolean; } | undefined): Thenable<void> {
    const abs = this.normalize(path);
    console.log(options);
    if (options?.recursive) {
      this.manager.removeItemAtPath_error_(abs, NULL);
    } else {
      fs.unlinkSync(abs.toString());
    }
    return Promise.resolve();
  }

  public ls(uri: string): Thenable<[string, FileType][]> {
    const abs = this.normalize(uri);

    const pError = Memory.alloc(Process.pointerSize).writePointer(NULL);
    const arr = this.manager.contentsOfDirectoryAtPath_error_(abs, pError);
    {
      const err = pError.readPointer();
      if (!err.isNull()) {
        const reason = new ObjC.Object(err).localizedDescription().toString();
        return Promise.reject(new Error(reason));
      }
    }

    const length = arr.count();
    const result: [string, FileType][] = [];

    const mapping: { [type: string]: FileType } = {
      NSFileTypeRegular: FileType.File,
      NSFileTypeDirectory: FileType.Directory,
      NSFileTypeSymbolicLink: FileType.SymbolicLink,
    };

    for (let i = 0; i < length; i++) {
      const entry = arr.objectAtIndex_(i);
      const filename = abs.stringByAppendingPathComponent_(entry);
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

  public read(path: string): Thenable<Uint8Array> {
    // todo: check file size
    throw new Error("Method not implemented.");
  }

  public rename(source: string, target: string, options?: { overwrite: boolean; } | undefined): Thenable<void> {
    const src = this.normalize(source);
    const dst = this.normalize(target);
    if (options!.overwrite && this.manager.fileExistsAtPath_(dst)) {
      this.rm(target);
    }
    this.manager.moveItemAtPath_toPath_error_(src, dst, NULL);
    return Promise.resolve();
  }

  public stat(path: string): Thenable<FileStat> {
    const uri = this.normalize(path);
    // TODO: use attributesOfItemAtPath_error_
    const stat = fs.statSync(uri.toString());
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

export function getApi(): FileSystem {
  if (ObjC.available) {
    return new ObjCFileSystem();
  } /* else if (Java.available) {
    
  } */

  throw new Error('Not implemented');
}

export async function invoke(method: string, ...args: string[]) {
  const api = getApi();
  if (Reflect.has(api, method)) {
    return Reflect.get(api, method).apply(api, args);
  }
}