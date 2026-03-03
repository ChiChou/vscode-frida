import ObjC from 'frida-objc-bridge';

import type { ArgInfo, MethodInfo } from '../types.js';
import { api as objcApi } from './runtime.js';
import { parse as parseTypeEncoding } from './signature.js';

interface Methods {
  classes: () => Promise<string[]>;
  protocols: () => Promise<string[]>;
  methodsOf: (name: string) => Promise<MethodInfo[]>;
  ownMethodsOf: (name: string) => Promise<MethodInfo[]>;
  superClasses: (name: string) => Promise<string[]>;
  classesHierarchy: () => Record<string, string>;
  infoPlist: () => Promise<string>;
}

function getClass(name: string): ObjC.Object {
  if (ObjC.classes.hasOwnProperty(name)) return ObjC.classes[name];
  throw new Error(`Class ${name} not found`);
}

function inspectObjCMethod(cls: ObjC.Object, sel: string): MethodInfo {
  const isInstance = sel.startsWith('- ');
  const cleanSel = sel.substring(2);

  const args: ArgInfo[] = [];
  let retType = 'v';

  try {
    const selPtr = objcApi.sel_registerName(Memory.allocUtf8String(cleanSel));
    const target = isInstance ? cls.handle : objcApi.object_getClass(cls.handle);
    const methodHandle = objcApi.class_getInstanceMethod(target, selPtr);
    if (!methodHandle.isNull()) {
      const typesPtr = objcApi.method_getTypeEncoding(methodHandle);
      if (!typesPtr.isNull()) {
        const enc = typesPtr.readUtf8String() as string;
        // parseTypeEncoding returns [retType, selfType, cmdType, arg0Type, …]
        const types = parseTypeEncoding(enc);
        if (types.length > 0)
          retType = types[0];
        // skip types[1] (self) and types[2] (_cmd), actual args start at index 3
        for (let i = 3; i < types.length; i++)
          args.push({ type: types[i] });
      }
    }
  } catch (_) { /* type encoding unavailable */ }

  return {
    name: sel,
    display: sel,
    args,
    returnType: retType,
    isStatic: !isInstance,
  };
}

export function applyOverrides(methods: Methods): void {
  methods.classes = async () => Object.keys(ObjC.classes);
  methods.protocols = async () => Object.keys(ObjC.protocols);

  methods.ownMethodsOf = async (name: string) => {
    const cls = getClass(name);
    return cls.$ownMethods.map(sel => inspectObjCMethod(cls, sel));
  };
  methods.methodsOf = async (name: string) => {
    const cls = getClass(name);
    return cls.$methods.map(sel => inspectObjCMethod(cls, sel));
  };
  methods.superClasses = async (name: string) => {
    const chain: string[] = [];
    let cls = getClass(name).$superClass;
    while (cls) {
      chain.push(cls.name);
      cls = cls.$superClass;
    }
    return chain;
  };

  methods.classesHierarchy = () => {
    const result: Record<string, string> = {};
    for (const name of Object.keys(ObjC.classes)) {
      try {
        const sup = ObjC.classes[name].$superClass;
        result[name] = sup ? sup.$className : '';
      } catch (_) {
        result[name] = '';
      }
    }
    return result;
  };

  methods.infoPlist = async () => {
    const bundle = ObjC.classes.NSBundle.mainBundle();
    const dict = bundle.infoDictionary();

    const format = 100; // NSPropertyListXMLFormat_v1_0
    const errorPtr = Memory.alloc(Process.pointerSize);
    errorPtr.writePointer(NULL);

    const data = ObjC.classes.NSPropertyListSerialization
      .dataWithPropertyList_format_options_error_(dict, format, 0, errorPtr);

    const err = errorPtr.readPointer();
    if (!err.isNull()) {
      const nsErr = new ObjC.Object(err);
      throw new Error(nsErr.localizedDescription().toString());
    }

    const nsString = ObjC.classes.NSString.alloc()
      .initWithData_encoding_(data, 4); // NSUTF8StringEncoding
    return nsString.toString() as string;
  };
}
