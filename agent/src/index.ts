import Java from 'frida-java-bridge';
import ObjC from 'frida-objc-bridge';

/* eslint-disable curly */
/* eslint-disable @typescript-eslint/naming-convention */

import { start, stop } from './log.js';

import { api as objcApi } from './fruity/runtime.js';
import { parse as parseTypeEncoding } from './fruity/signature.js';

enum Runtime {
  Java = 'Java',
  ObjectiveC = 'ObjectiveC',
  Generic = 'Generic',
};

interface ArgInfo {
  type: string;
}

interface MethodInfo {
  name: string;
  display: string;
  args: ArgInfo[];
  returnType: string;
  isStatic: boolean;
}

interface FieldInfo {
  name: string;
  display: string;
  type: string;
  isStatic: boolean;
}

interface ClassMemberInfo {
  methods: MethodInfo[];
  fields: FieldInfo[];
}

const methods = {
  start,
  stop,

  runtime() {
    if (Java.available) return Runtime.Java;
    if (ObjC.available) return Runtime.ObjectiveC;
    return Runtime.Generic;
  },

  ping: () => Process.id,

  classes: async () => [] as string[],
  protocols: async () => [] as string[],

  methodsOf: async (_name: string): Promise<MethodInfo[]> => [],
  ownMethodsOf: async (_name: string): Promise<MethodInfo[]> => [],
  fieldsOf: async (_name: string): Promise<FieldInfo[]> => [],
  ownFieldsOf: async (_name: string): Promise<FieldInfo[]> => [],
  classMembers: async (_name: string): Promise<ClassMemberInfo> => ({ methods: [], fields: [] }),
  superClasses: async (_name: string): Promise<string[]> => [],

  // Returns [names, parents] where parents[i] is the index of the
  // superclass of names[i], or -1 for roots. Compact: each class name
  // appears once, parent relationships are integers instead of strings.
  objcClassHierarchy: (): [string[], number[]] => {
    if (!ObjC.available) throw new Error("Objective-C not available");

    const names = Object.keys(ObjC.classes);
    const indexMap: Record<string, number> = {};
    for (let i = 0; i < names.length; i++)
      indexMap[names[i]] = i;

    const parents = new Array<number>(names.length);
    for (let i = 0; i < names.length; i++) {
      try {
        const sup = ObjC.classes[names[i]].$superClass;
        if (sup) {
          const pn = sup.$className;
          parents[i] = pn in indexMap ? indexMap[pn] : -1;
        } else {
          parents[i] = -1;
        }
      } catch (_) {
        parents[i] = -1;
      }
    }

    return [names, parents];
  },

  modules: () => Process.enumerateModules(),
  exports: (name: string) => Process.findModuleByName(name)?.enumerateExports(),
  imports: (name: string) => Process.findModuleByName(name)?.enumerateImports(),
  symbols: (name: string) => Process.findModuleByName(name)?.enumerateSymbols(),
};

if (Java.available) {
  function perform<T>(fn: () => T): Promise<T> {
    return new Promise<T>((resolve) => {
      Java.perform(() => {
        resolve(fn());
      });
    });
  };

  function shortenType(t: string): string {
    const last = t.lastIndexOf('.');
    return last >= 0 ? t.substring(last + 1) : t;
  }

  function inspectJavaMethod(m: any, Modifier: any): MethodInfo {
    const mods = m.getModifiers();
    const isStatic = Modifier.isStatic(mods);
    const retTypeName = m.getReturnType().getName() as string;
    const mName = m.getName() as string;
    const paramTypes = m.getParameterTypes();
    const args: ArgInfo[] = [];
    const shortArgs: string[] = [];
    for (let j = 0; j < paramTypes.length; j++) {
      const typeName = paramTypes[j].getName() as string;
      args.push({ type: typeName });
      shortArgs.push(shortenType(typeName));
    }
    const prefix = isStatic ? 'static ' : '';
    return {
      name: mName,
      display: `${prefix}${shortenType(retTypeName)} ${mName}(${shortArgs.join(', ')})`,
      args,
      returnType: retTypeName,
      isStatic,
    };
  }

  methods.classes = async () => perform(() => Java.enumerateLoadedClassesSync());

  methods.methodsOf = async (name: string) => perform(() => {
    const Modifier = Java.use('java.lang.reflect.Modifier');
    const jClass = Java.use(name).class;
    const allMethods = jClass.getMethods();
    const result: MethodInfo[] = [];
    for (let i = 0; i < allMethods.length; i++) {
      result.push(inspectJavaMethod(allMethods[i], Modifier));
    }
    return result;
  });

  methods.ownMethodsOf = async (name: string) => perform(() => {
    const Modifier = Java.use('java.lang.reflect.Modifier');
    const jClass = Java.use(name).class;
    const declared = jClass.getDeclaredMethods();
    const result: MethodInfo[] = [];
    for (let i = 0; i < declared.length; i++) {
      result.push(inspectJavaMethod(declared[i], Modifier));
    }
    return result;
  });

  function inspectJavaField(f: any, Modifier: any): FieldInfo {
    const mods = f.getModifiers();
    const isStatic = Modifier.isStatic(mods);
    const typeName = f.getType().getName() as string;
    const fName = f.getName() as string;
    const prefix = isStatic ? 'static ' : '';
    return {
      name: fName,
      display: `${prefix}${shortenType(typeName)} ${fName}`,
      type: typeName,
      isStatic,
    };
  }

  methods.fieldsOf = async (name: string) => perform(() => {
    const Modifier = Java.use('java.lang.reflect.Modifier');
    const jClass = Java.use(name).class;
    const allFields = jClass.getFields();
    const result: FieldInfo[] = [];
    for (let i = 0; i < allFields.length; i++) {
      result.push(inspectJavaField(allFields[i], Modifier));
    }
    return result;
  });

  methods.ownFieldsOf = async (name: string) => perform(() => {
    const Modifier = Java.use('java.lang.reflect.Modifier');
    const jClass = Java.use(name).class;
    const declared = jClass.getDeclaredFields();
    const result: FieldInfo[] = [];
    for (let i = 0; i < declared.length; i++) {
      result.push(inspectJavaField(declared[i], Modifier));
    }
    return result;
  });

  methods.classMembers = async (name: string) => perform(() => {
    const Modifier = Java.use('java.lang.reflect.Modifier');
    const jClass = Java.use(name).class;
    
    const declaredMethods = jClass.getDeclaredMethods();
    const methods: MethodInfo[] = [];
    for (let i = 0; i < declaredMethods.length; i++) {
      methods.push(inspectJavaMethod(declaredMethods[i], Modifier));
    }
    
    const declaredFields = jClass.getDeclaredFields();
    const fields: FieldInfo[] = [];
    for (let i = 0; i < declaredFields.length; i++) {
      fields.push(inspectJavaField(declaredFields[i], Modifier));
    }
    
    return { methods, fields };
  });

  methods.superClasses = async (name: string) => perform(() => {
    const sup = Java.use(name).class.getSuperclass()?.getName();
    return sup ? [sup] : [];
  });

} else if (ObjC.available) {
  methods.classes = async () => Object.keys(ObjC.classes);
  methods.protocols = async () => Object.keys(ObjC.protocols);

  function getClass(name: string) {
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
}

rpc.exports = methods;
