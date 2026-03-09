import ObjC from "frida-objc-bridge";

type Ptr = NativePointerValue;
type Fn<R extends NativeFunctionReturnValue, A extends Ptr[]> = NativeFunction<
  R,
  A
>;

interface ObjCApi {
  // libsystem_malloc
  free: Fn<void, [Ptr]>;

  // libobjc - message sending
  objc_msgSend: NativePointer;
  objc_msgSend_stret?: NativePointer;
  objc_msgSend_fpret?: NativePointer;
  objc_msgSendSuper: NativePointer;
  objc_msgSendSuper_stret?: NativePointer;
  objc_msgSendSuper_fpret?: NativePointer;

  // libobjc - class management
  objc_getClassList: Fn<number, [Ptr, Ptr]>;
  objc_lookUpClass: Fn<NativePointer, [Ptr]>;
  objc_allocateClassPair: Fn<NativePointer, [Ptr, Ptr, Ptr]>;
  objc_disposeClassPair: Fn<void, [Ptr]>;
  objc_registerClassPair: Fn<void, [Ptr]>;

  // libobjc - class introspection
  class_isMetaClass: Fn<number, [Ptr]>;
  class_getName: Fn<NativePointer, [Ptr]>;
  class_getImageName: Fn<NativePointer, [Ptr]>;
  class_getSuperclass: Fn<NativePointer, [Ptr]>;
  class_getInstanceSize: Fn<NativePointer, [Ptr]>;
  class_copyProtocolList: Fn<NativePointer, [Ptr, Ptr]>;
  class_copyMethodList: Fn<NativePointer, [Ptr, Ptr]>;
  class_copyIvarList: Fn<NativePointer, [Ptr, Ptr]>;
  class_getClassMethod: Fn<NativePointer, [Ptr, Ptr]>;
  class_getInstanceMethod: Fn<NativePointer, [Ptr, Ptr]>;
  class_addProtocol: Fn<number, [Ptr, Ptr]>;
  class_addMethod: Fn<number, [Ptr, Ptr, Ptr, Ptr]>;

  // libobjc - protocol
  objc_getProtocol: Fn<NativePointer, [Ptr]>;
  objc_copyProtocolList: Fn<NativePointer, [Ptr]>;
  objc_allocateProtocol: Fn<NativePointer, [Ptr]>;
  objc_registerProtocol: Fn<void, [Ptr]>;
  protocol_getName: Fn<NativePointer, [Ptr]>;
  protocol_copyMethodDescriptionList: Fn<NativePointer, [Ptr, Ptr, Ptr, Ptr]>;
  protocol_copyPropertyList: Fn<NativePointer, [Ptr, Ptr]>;
  protocol_copyProtocolList: Fn<NativePointer, [Ptr, Ptr]>;
  protocol_addProtocol: Fn<void, [Ptr, Ptr]>;
  protocol_addMethodDescription: Fn<void, [Ptr, Ptr, Ptr, Ptr, Ptr]>;

  // libobjc - ivar
  ivar_getName: Fn<NativePointer, [Ptr]>;
  ivar_getTypeEncoding: Fn<NativePointer, [Ptr]>;
  ivar_getOffset: Fn<NativePointer, [Ptr]>;

  // libobjc - object
  object_isClass?: Fn<number, [Ptr]>;
  object_getClass: Fn<NativePointer, [Ptr]>;
  object_getClassName: Fn<NativePointer, [Ptr]>;

  // libobjc - method
  method_getName: Fn<NativePointer, [Ptr]>;
  method_getTypeEncoding: Fn<NativePointer, [Ptr]>;
  method_getImplementation: Fn<NativePointer, [Ptr]>;
  method_setImplementation: Fn<NativePointer, [Ptr, Ptr]>;

  // libobjc - property
  property_getName: Fn<NativePointer, [Ptr]>;
  property_copyAttributeList: Fn<NativePointer, [Ptr, Ptr]>;

  // libobjc - selector
  sel_getName: Fn<NativePointer, [Ptr]>;
  sel_registerName: Fn<NativePointer, [Ptr]>;

  // libdispatch
  dispatch_async_f: Fn<void, [Ptr, Ptr, Ptr]>;
  _dispatch_main_q: NativePointer;
}

export const api = ObjC.api as unknown as ObjCApi;

function libobjcFn<R extends NativeFunctionReturnValue, A extends Ptr[]>(
  name: string,
  ret: NativeFunctionReturnType,
  args: NativeFunctionArgumentType[],
) {
  return new NativeFunction(
    Process.getModuleByName("libobjc.A.dylib").getExportByName(name)!,
    ret,
    args,
  ) as unknown as Fn<R, A>;
}

export function getClass(name: string): ObjC.Object {
  const cls = ObjC.classes[name];
  if (!cls)
    throw new Error(`Class ${name} not found`);

  return cls;
}

let extras: {
  class_copyPropertyList: Fn<NativePointer, [Ptr, Ptr]>;
  property_getAttributes: Fn<NativePointer, [Ptr]>;
};

function extraApi() {
  if (extras) return extras;
  return (extras = {
    class_copyPropertyList: libobjcFn("class_copyPropertyList", "pointer", [
      "pointer",
      "pointer",
    ]),
    property_getAttributes: libobjcFn(
      "property_getAttributes",
      "pointer",
      ["pointer"],
    ),
  });
}

export interface ObjCMethod {
  name: string;
  imp: string;
  types: string;
}

export function resolveMethod(clazz: ObjC.Object, sel: string): ObjCMethod {
  const isClassMethod = sel.startsWith("+ ");
  const selName = sel.substring(2);
  const selPtr = api.sel_registerName(Memory.allocUtf8String(selName));
  const target = isClassMethod
    ? api.object_getClass(clazz.handle)
    : clazz.handle;
  const methodHandle = api.class_getInstanceMethod(target, selPtr);
  const impl = api.method_getImplementation(methodHandle).toString();
  const types = api
    .method_getTypeEncoding(methodHandle)
    .readUtf8String() as string;
  return { name: sel, imp: impl, types };
}

export interface Ivar {
  name: string;
  offset: number;
  type: string;
}

export function copySuperClasses(clazz: ObjC.Object): string[] {
  const proto = [];
  {
    let cur = clazz;
    while ((cur = cur.$superClass)) proto.unshift(cur.$className);
  }
  return proto;
}

export function copyIvars(clazz: ObjC.Object): Ivar[] {
  const { pointerSize } = Process;
  const numIvarsBuf = Memory.alloc(pointerSize);
  const ivarHandles = api.class_copyIvarList(clazz.handle, numIvarsBuf);
  const result: Ivar[] = [];

  if (ivarHandles.isNull()) return result;

  try {
    const numIvars = numIvarsBuf.readUInt();
    for (let i = 0; i < numIvars; i++) {
      const handle = ivarHandles.add(i * pointerSize).readPointer();
      const name = api.ivar_getName(handle).readUtf8String() as string;
      const offset = api.ivar_getOffset(handle).toInt32();
      const type = api.ivar_getTypeEncoding(handle).readUtf8String() as string;

      result.push({
        name,
        offset,
        type,
      });
    }
  } finally {
    api.free(ivarHandles);
  }

  return result;
}

export interface PropertyInfo {
  name: string;
  attributes: string;
}

function copyPropertyList(classHandle: NativePointerValue): PropertyInfo[] {
  const { class_copyPropertyList, property_getAttributes } = extraApi();
  const result: PropertyInfo[] = [];

  const nPropsBuf = Memory.alloc(Process.pointerSize);
  const props = class_copyPropertyList(classHandle, nPropsBuf);
  const nProps = nPropsBuf.readUInt();

  if (props.isNull()) return result;

  try {
    for (let i = 0; i < nProps; i++) {
      const handle = props.add(i * Process.pointerSize).readPointer();
      const namePtr = api.property_getName(handle);
      if (namePtr.isNull()) continue;
      const name = namePtr.readUtf8String() as string;
      const attrPtr = property_getAttributes(handle);
      if (attrPtr.isNull()) continue;
      const attributes = attrPtr.readUtf8String() as string;
      result.push({ name, attributes });
    }
  } finally {
    api.free(props);
  }

  return result;
}

export function copyProperties(clazz: ObjC.Object): PropertyInfo[] {
  return copyPropertyList(clazz.handle);
}

export function copyClassProperties(clazz: ObjC.Object): PropertyInfo[] {
  return copyPropertyList(api.object_getClass(clazz.handle));
}

export function copyProtocols(clazz: ObjC.Object): string[] {
  const { pointerSize } = Process;
  const countBuf = Memory.alloc(pointerSize);
  const list = api.class_copyProtocolList(clazz.handle, countBuf);
  const result: string[] = [];

  if (list.isNull()) return result;

  try {
    const count = countBuf.readUInt();
    for (let i = 0; i < count; i++) {
      const handle = list.add(i * pointerSize).readPointer();
      const name = api.protocol_getName(handle).readUtf8String() as string;
      result.push(name);
    }
  } finally {
    api.free(list);
  }

  return result;
}

export function copyOwnMethods(clazz: ObjC.Object, isMetaClass: boolean): { selector: string; types: string }[] {
  const { pointerSize } = Process;
  const target = isMetaClass ? api.object_getClass(clazz.handle) : clazz.handle;
  const countBuf = Memory.alloc(pointerSize);
  const list = api.class_copyMethodList(target, countBuf);
  const result: { selector: string; types: string }[] = [];

  if (list.isNull()) return result;

  try {
    const count = countBuf.readUInt();
    const prefix = isMetaClass ? '+ ' : '- ';
    for (let i = 0; i < count; i++) {
      const handle = list.add(i * pointerSize).readPointer();
      const selPtr = api.method_getName(handle);
      const selector = prefix + (api.sel_getName(selPtr).readUtf8String() as string);
      const typesPtr = api.method_getTypeEncoding(handle);
      const types = typesPtr.isNull() ? '' : typesPtr.readUtf8String() as string;
      result.push({ selector, types });
    }
  } finally {
    api.free(list);
  }

  return result;
}
