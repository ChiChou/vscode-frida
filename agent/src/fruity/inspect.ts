import ObjC from 'frida-objc-bridge';

import type { ArgInfo, MethodInfo, ObjCClassInfo, JavaClassInfo } from '../types.js';
import { api as objcApi, getClass, copyIvars, copyProperties, copyClassProperties, copyProtocols, copyOwnMethods } from './runtime.js';
import { parse as parseTypeEncoding } from './signature.js';

interface Methods {
  classes: () => Promise<string[]>;
  protocols: () => Promise<string[]>;
  methodsOf: (name: string) => Promise<MethodInfo[]>;
  ownMethodsOf: (name: string) => Promise<MethodInfo[]>;
  superClasses: (name: string) => Promise<string[]>;
  classInfo: (name: string) => Promise<ObjCClassInfo | JavaClassInfo>;
  infoPlist: () => Promise<string>;
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
        const types = parseTypeEncoding(enc);
        if (types.length > 0)
          retType = types[0];
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
      chain.push(cls.$className);
      cls = cls.$superClass;
    }
    return chain;
  };

  methods.classInfo = async (name: string): Promise<ObjCClassInfo> => {
    const cls = getClass(name);

    // superclass
    const sup = cls.$superClass;
    const superClass = sup ? sup.$className : null;

    // protocols
    const protocols = copyProtocols(cls);

    // methods: instance + class
    const instanceMethods = copyOwnMethods(cls, false);
    const classMethods = copyOwnMethods(cls, true);
    const allMethods = [...instanceMethods, ...classMethods];

    // properties: instance + class
    const instanceProps = copyProperties(cls).map(p => ({ ...p, isClass: false }));
    const classProps = copyClassProperties(cls).map(p => ({ ...p, isClass: true }));
    const properties = [...instanceProps, ...classProps];

    // ivars
    const ivars = copyIvars(cls);

    return {
      name,
      superClass,
      protocols,
      methods: allMethods,
      properties,
      ivars,
    };
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
