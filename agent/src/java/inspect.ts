import Java from 'frida-java-bridge';

import type { ArgInfo, MethodInfo, FieldInfo, ClassMemberInfo } from '../types.js';
import { manifest } from './manifest.js';
import { perform } from './util.js';

interface Methods {
  classes: () => Promise<string[]>;
  methodsOf: (name: string) => Promise<MethodInfo[]>;
  ownMethodsOf: (name: string) => Promise<MethodInfo[]>;
  fieldsOf: (name: string) => Promise<FieldInfo[]>;
  ownFieldsOf: (name: string) => Promise<FieldInfo[]>;
  classMembers: (name: string) => Promise<ClassMemberInfo>;
  superClasses: (name: string) => Promise<string[]>;
  manifest: () => Promise<string>;
}

function shortenType(t: string): string {
  const last = t.lastIndexOf('.');
  return last >= 0 ? t.substring(last + 1) : t;
}

function inspectJavaMethod(m: Java.Wrapper, Modifier: Java.Wrapper): MethodInfo {
  const mods = m.getModifiers();
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

function inspectJavaField(f: Java.Wrapper, Modifier: Java.Wrapper): FieldInfo {
  const mods = f.getModifiers();
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
    const methodInfos: MethodInfo[] = [];
    for (let i = 0; i < declaredMethods.length; i++) {
      methodInfos.push(inspectJavaMethod(declaredMethods[i], Modifier));
    }

    const declaredFields = jClass.getDeclaredFields();
    const fieldInfos: FieldInfo[] = [];
    for (let i = 0; i < declaredFields.length; i++) {
      fieldInfos.push(inspectJavaField(declaredFields[i], Modifier));
    }

    return { methods: methodInfos, fields: fieldInfos };
  });

  methods.superClasses = async (name: string) => perform(() => {
    const sup = Java.use(name).class.getSuperclass()?.getName();
    return sup ? [sup] : [];
  });

  methods.manifest = manifest;
}
