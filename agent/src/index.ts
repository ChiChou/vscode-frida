import Java from 'frida-java-bridge';
import ObjC from 'frida-objc-bridge';

/* eslint-disable curly */
/* eslint-disable @typescript-eslint/naming-convention */

import { start, stop } from './log.js';

enum Runtime {
  Java = 'Java',
  ObjectiveC = 'ObjectiveC',
  Generic = 'Generic',
};

interface ArgInfo {
  type: string;
  isObject: boolean;
}

interface MethodInfo {
  name: string;
  display: string;
  args: ArgInfo[];
  returnType: string;
  isReturnObject: boolean;
  isStatic: boolean;
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
  superClasses: async (_name: string): Promise<string[]> => [],

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

  const javaPrimitives = new Set([
    'int', 'long', 'boolean', 'byte', 'short', 'char', 'float', 'double', 'void',
  ]);

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
      args.push({ type: typeName, isObject: !javaPrimitives.has(typeName) });
      shortArgs.push(shortenType(typeName));
    }
    const prefix = isStatic ? 'static ' : '';
    return {
      name: mName,
      display: `${prefix}${shortenType(retTypeName)} ${mName}(${shortArgs.join(', ')})`,
      args,
      returnType: retTypeName,
      isReturnObject: !javaPrimitives.has(retTypeName),
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

  interface NSMethodSignature {
    numberOfArguments(): number;
    getArgumentTypeAtIndex_(index: number): string;
    methodReturnType(): string;
  }

  function inspectObjCMethod(cls: any, sel: string): MethodInfo {
    const isInstance = sel.startsWith('- ');
    const cleanSel = sel.substring(2);
    let sig: NSMethodSignature | null = null;
    try {
      if (isInstance) {
        sig = cls.instanceMethodSignatureForSelector_(ObjC.selector(cleanSel)) as NSMethodSignature | null;
      } else {
        // class method: instance method of the metaclass
        sig = cls.$metaClass?.instanceMethodSignatureForSelector_(ObjC.selector(cleanSel)) as NSMethodSignature | null;
      }
    } catch (_) { /* signature unavailable */ }

    const args: ArgInfo[] = [];
    let retType = 'v';
    let isReturnObject = false;

    if (sig) {
      const argCount = sig.numberOfArguments();
      // skip index 0 (self) and 1 (_cmd)
      for (let i = 2; i < argCount; i++) {
        const t = sig.getArgumentTypeAtIndex_(i);
        args.push({ type: t, isObject: t[0] === '@' });
      }
      retType = sig.methodReturnType();
      isReturnObject = retType[0] === '@';
    }

    return {
      name: sel,
      display: sel,
      args,
      returnType: retType,
      isReturnObject,
      isStatic: !isInstance,
    };
  }

  methods.ownMethodsOf = async (name: string) => {
    const cls = getClass(name);
    return (cls.$ownMethods as string[]).map(sel => inspectObjCMethod(cls, sel));
  };
  methods.methodsOf = async (name: string) => {
    const cls = getClass(name);
    return (cls.$methods as string[]).map(sel => inspectObjCMethod(cls, sel));
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
