import Java from 'frida-java-bridge';

import type { ArgInfo, MethodInfo, FieldInfo, ClassMemberInfo, ObjCClassInfo, JavaClassInfo } from '../types.js';
import { manifest } from './manifest.js';
import { perform } from './util.js';

// Java reflection types for Java.use<T>()
interface JModifier {
  isStatic: Java.MethodDispatcher;
  toString: Java.MethodDispatcher;
}

interface JClass {
  getName: Java.MethodDispatcher;
  getModifiers: Java.MethodDispatcher;
  getMethods: Java.MethodDispatcher;
  getDeclaredMethods: Java.MethodDispatcher;
  getFields: Java.MethodDispatcher;
  getDeclaredFields: Java.MethodDispatcher;
  getSuperclass: Java.MethodDispatcher;
  getInterfaces: Java.MethodDispatcher;
}

interface JMethod {
  getName: Java.MethodDispatcher;
  getModifiers: Java.MethodDispatcher;
  getReturnType: Java.MethodDispatcher;
  getParameterTypes: Java.MethodDispatcher;
}

interface JField {
  getName: Java.MethodDispatcher;
  getModifiers: Java.MethodDispatcher;
  getType: Java.MethodDispatcher;
}

interface Methods {
  classes: () => Promise<string[]>;
  methodsOf: (name: string) => Promise<MethodInfo[]>;
  ownMethodsOf: (name: string) => Promise<MethodInfo[]>;
  fieldsOf: (name: string) => Promise<FieldInfo[]>;
  ownFieldsOf: (name: string) => Promise<FieldInfo[]>;
  classMembers: (name: string) => Promise<ClassMemberInfo>;
  superClasses: (name: string) => Promise<string[]>;
  classInfo: (name: string) => Promise<ObjCClassInfo | JavaClassInfo>;
  manifest: () => Promise<string>;
}

function shortenType(t: string): string {
  const last = t.lastIndexOf('.');
  return last >= 0 ? t.substring(last + 1) : t;
}

function useModifier(): Java.Wrapper<JModifier> {
  return Java.use<JModifier>('java.lang.reflect.Modifier');
}

function inspectJavaMethod(m: Java.Wrapper<JMethod>, Modifier: Java.Wrapper<JModifier>): MethodInfo {
  const mods = m.getModifiers() as number;
  const isStatic = Modifier.isStatic(mods) as boolean;
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

function inspectJavaField(f: Java.Wrapper<JField>, Modifier: Java.Wrapper<JModifier>): FieldInfo {
  const mods = f.getModifiers() as number;
  const isStatic = Modifier.isStatic(mods) as boolean;
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

export function applyOverrides(methods: Methods): void {
  methods.classes = async () => perform(() => Java.enumerateLoadedClassesSync());

  methods.methodsOf = async (name: string) => perform(() => {
    const Modifier = useModifier();
    const jClass = Java.use(name).class as Java.Wrapper<JClass>;
    const allMethods = jClass.getMethods() as Java.Wrapper<JMethod>[];
    const result: MethodInfo[] = [];
    for (let i = 0; i < allMethods.length; i++) {
      result.push(inspectJavaMethod(allMethods[i], Modifier));
    }
    return result;
  });

  methods.ownMethodsOf = async (name: string) => perform(() => {
    const Modifier = useModifier();
    const jClass = Java.use(name).class as Java.Wrapper<JClass>;
    const declared = jClass.getDeclaredMethods() as Java.Wrapper<JMethod>[];
    const result: MethodInfo[] = [];
    for (let i = 0; i < declared.length; i++) {
      result.push(inspectJavaMethod(declared[i], Modifier));
    }
    return result;
  });

  methods.fieldsOf = async (name: string) => perform(() => {
    const Modifier = useModifier();
    const jClass = Java.use(name).class as Java.Wrapper<JClass>;
    const allFields = jClass.getFields() as Java.Wrapper<JField>[];
    const result: FieldInfo[] = [];
    for (let i = 0; i < allFields.length; i++) {
      result.push(inspectJavaField(allFields[i], Modifier));
    }
    return result;
  });

  methods.ownFieldsOf = async (name: string) => perform(() => {
    const Modifier = useModifier();
    const jClass = Java.use(name).class as Java.Wrapper<JClass>;
    const declared = jClass.getDeclaredFields() as Java.Wrapper<JField>[];
    const result: FieldInfo[] = [];
    for (let i = 0; i < declared.length; i++) {
      result.push(inspectJavaField(declared[i], Modifier));
    }
    return result;
  });

  methods.classMembers = async (name: string) => perform(() => {
    const Modifier = useModifier();
    const jClass = Java.use(name).class as Java.Wrapper<JClass>;

    const declaredMethods = jClass.getDeclaredMethods() as Java.Wrapper<JMethod>[];
    const methodInfos: MethodInfo[] = [];
    for (let i = 0; i < declaredMethods.length; i++) {
      methodInfos.push(inspectJavaMethod(declaredMethods[i], Modifier));
    }

    const declaredFields = jClass.getDeclaredFields() as Java.Wrapper<JField>[];
    const fieldInfos: FieldInfo[] = [];
    for (let i = 0; i < declaredFields.length; i++) {
      fieldInfos.push(inspectJavaField(declaredFields[i], Modifier));
    }

    return { methods: methodInfos, fields: fieldInfos };
  });

  methods.superClasses = async (name: string) => perform(() => {
    const jClass = Java.use(name).class as Java.Wrapper<JClass>;
    const sup = jClass.getSuperclass();
    const supName = sup ? (sup as Java.Wrapper<JClass>).getName() as string : null;
    return supName ? [supName] : [];
  });

  methods.classInfo = async (name: string): Promise<JavaClassInfo> => perform(() => {
    const Modifier = useModifier();
    const modToString = Modifier.toString.overload('int');
    const jClass = Java.use(name).class as Java.Wrapper<JClass>;

    // class modifiers
    const classModifiers = modToString.call(Modifier, jClass.getModifiers()) as string;

    // superclass
    const supClass = jClass.getSuperclass();
    const superClass = supClass ? (supClass as Java.Wrapper<JClass>).getName() as string : null;

    // interfaces
    const ifaceList = jClass.getInterfaces() as Java.Wrapper<JClass>[];
    const interfaces: string[] = [];
    for (let i = 0; i < ifaceList.length; i++) {
      interfaces.push(ifaceList[i].getName() as string);
    }

    // declared methods
    const declaredMethods = jClass.getDeclaredMethods() as Java.Wrapper<JMethod>[];
    const jMethods: JavaClassInfo['methods'] = [];
    for (let i = 0; i < declaredMethods.length; i++) {
      const m = declaredMethods[i];
      const mods = m.getModifiers() as number;
      const modStr = modToString.call(Modifier, mods) as string;
      const isStatic = Modifier.isStatic(mods) as boolean;
      const retTypeName = m.getReturnType().getName() as string;
      const mName = m.getName() as string;
      const paramTypes = m.getParameterTypes();
      const args: string[] = [];
      const shortArgs: string[] = [];
      for (let j = 0; j < paramTypes.length; j++) {
        const typeName = paramTypes[j].getName() as string;
        args.push(typeName);
        shortArgs.push(shortenType(typeName));
      }
      const prefix = isStatic ? 'static ' : '';
      jMethods.push({
        name: mName,
        display: `${prefix}${shortenType(retTypeName)} ${mName}(${shortArgs.join(', ')})`,
        args,
        returnType: retTypeName,
        modifiers: modStr,
        isStatic,
      });
    }

    // declared fields
    const declaredFields = jClass.getDeclaredFields() as Java.Wrapper<JField>[];
    const jFields: JavaClassInfo['fields'] = [];
    for (let i = 0; i < declaredFields.length; i++) {
      const f = declaredFields[i];
      const mods = f.getModifiers() as number;
      const modStr = modToString.call(Modifier, mods) as string;
      const isStatic = Modifier.isStatic(mods) as boolean;
      const typeName = f.getType().getName() as string;
      const fName = f.getName() as string;
      const prefix = isStatic ? 'static ' : '';
      jFields.push({
        name: fName,
        display: `${prefix}${shortenType(typeName)} ${fName}`,
        type: typeName,
        modifiers: modStr,
        isStatic,
      });
    }

    return {
      modifiers: classModifiers,
      name,
      superClass,
      interfaces,
      methods: jMethods,
      fields: jFields,
    };
  });

  methods.manifest = manifest;
}
