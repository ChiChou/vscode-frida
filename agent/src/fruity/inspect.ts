import ObjC from 'frida-objc-bridge';

import type { ArgInfo, MethodInfo, ObjCClassInfo, ObjCMethodInfo, ObjCPropertyInfo, ObjCProtocolInfo, JavaClassInfo } from '../types.js';
import { api as objcApi, getClass, copyIvars, copyProperties, copyClassProperties, copyProtocols, copyOwnMethods, getProtocolMethodExtendedTypes } from './runtime.js';
import { parse as parseTypeEncoding } from './signature.js';

interface Methods {
  classes: () => Promise<string[]>;
  protocols: () => Promise<string[]>;
  methodsOf: (name: string) => Promise<MethodInfo[]>;
  ownMethodsOf: (name: string) => Promise<MethodInfo[]>;
  superClasses: (name: string) => Promise<string[]>;
  classInfo: (name: string) => Promise<ObjCClassInfo | JavaClassInfo>;
  protocolMethodsOf: (name: string) => Promise<MethodInfo[]>;
  ownProtocolMethodsOf: (name: string) => Promise<MethodInfo[]>;
  parentProtocols: (name: string) => Promise<string[]>;
  protocolInfo: (name: string) => Promise<ObjCProtocolInfo>;
  infoPlist: () => Promise<string>;
}

function inspectObjCMethod(cls: ObjC.Object, sel: string): MethodInfo {
  const isInstance = sel.startsWith('- ');
  const cleanSel = sel.substring(2);

  const args: ArgInfo[] = [];
  let retType = 'v';

  try {
    const selPtr = ObjC.selector(cleanSel);
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

function getProtocolBridge(name: string): ObjC.Protocol {
  const proto = ObjC.protocols[name];
  if (!proto) throw new Error(`Protocol ${name} not found`);
  return proto;
}

function bridgeMethodToMethodInfo(selector: string, info: { types: string }): MethodInfo {
  const isInstance = selector.startsWith('- ');
  const args: ArgInfo[] = [];
  let retType = 'v';

  if (info.types) {
    try {
      const types = parseTypeEncoding(info.types);
      if (types.length > 0) retType = types[0];
      for (let i = 3; i < types.length; i++) args.push({ type: types[i] });
    } catch (_) { /* type encoding unavailable */ }
  }

  return {
    name: selector,
    display: selector,
    args,
    returnType: retType,
    isStatic: !isInstance,
  };
}

function collectProtocolMethods(proto: ObjC.Protocol, ownOnly: boolean): MethodInfo[] {
  const result: MethodInfo[] = [];
  const seen = new Set<string>();

  for (const [selector, info] of Object.entries(proto.methods)) {
    if (!seen.has(selector)) {
      seen.add(selector);
      result.push(bridgeMethodToMethodInfo(selector, info));
    }
  }

  if (!ownOnly) {
    for (const parent of Object.values(proto.protocols)) {
      for (const [selector, info] of Object.entries(parent.methods)) {
        if (!seen.has(selector)) {
          seen.add(selector);
          result.push(bridgeMethodToMethodInfo(selector, info));
        }
      }
    }
  }

  return result;
}

/** Convert bridge property dict { T: '@"NSString"', R: '', C: '' } to attribute string 'T@"NSString",R,C' */
function propertyDictToAttrString(attrs: Record<string, string>): string {
  return Object.entries(attrs)
    .map(([key, value]) => value ? `${key}${value}` : key)
    .join(',');
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

    // enrich method type encodings from adopted protocols
    // protocol extended types preserve class names (e.g. @"NSString") while
    // class method_getTypeEncoding only has generic id (@)
    if (protocols.length > 0) {
      const protoHandles = protocols
        .map(p => ObjC.protocols[p])
        .filter(p => p != null);

      for (const method of allMethods) {
        const isInstance = method.selector.startsWith('- ');
        const bareSel = method.selector.substring(2);
        for (const proto of protoHandles) {
          const extTypes = getProtocolMethodExtendedTypes(proto.handle, bareSel, true, isInstance)
            ?? getProtocolMethodExtendedTypes(proto.handle, bareSel, false, isInstance);
          if (extTypes) {
            method.types = extTypes;
            break;
          }
        }
      }
    }

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

  methods.ownProtocolMethodsOf = async (name: string) => {
    return collectProtocolMethods(getProtocolBridge(name), true);
  };
  methods.protocolMethodsOf = async (name: string) => {
    return collectProtocolMethods(getProtocolBridge(name), false);
  };
  methods.parentProtocols = async (name: string) => {
    return Object.keys(getProtocolBridge(name).protocols);
  };
  methods.protocolInfo = async (name: string): Promise<ObjCProtocolInfo> => {
    const proto = getProtocolBridge(name);
    const handle = proto.handle;

    const required: ObjCMethodInfo[] = [];
    const optional: ObjCMethodInfo[] = [];
    for (const [selector, info] of Object.entries(proto.methods)) {
      const isInstance = selector.startsWith('- ');
      const bareSel = selector.substring(2);
      const extTypes = getProtocolMethodExtendedTypes(handle, bareSel, info.required, isInstance);
      const entry = { selector, types: extTypes ?? info.types };
      if (info.required) {
        required.push(entry);
      } else {
        optional.push(entry);
      }
    }

    const parentProtocols = Object.keys(proto.protocols);

    const properties: ObjCPropertyInfo[] = Object.entries(proto.properties)
      .map(([propName, attrs]) => ({
        name: propName,
        attributes: propertyDictToAttrString(attrs),
        isClass: false,
      }));

    return {
      name,
      parentProtocols,
      methods: required,
      optionalMethods: optional,
      properties,
    };
  };

  methods.infoPlist = async () => {
    const NSPropertyListXMLFormat_v1_0 = 100;
    const bundle = ObjC.classes.NSBundle.mainBundle();
    const dict = bundle.infoDictionary();

    const errorPtr = Memory.alloc(Process.pointerSize);
    errorPtr.writePointer(NULL);

    const data = ObjC.classes.NSPropertyListSerialization
      .dataWithPropertyList_format_options_error_(dict, NSPropertyListXMLFormat_v1_0, 0, errorPtr);

    const err = errorPtr.readPointer();
    if (!err.isNull()) {
      const nsErr = new ObjC.Object(err);
      throw new Error(nsErr.localizedDescription().toString());
    }

    const NSUTF8StringEncoding = 4;
    const nsString = ObjC.classes.NSString.alloc()
      .initWithData_encoding_(data, NSUTF8StringEncoding);
    return nsString.toString() as string;
  };
}
