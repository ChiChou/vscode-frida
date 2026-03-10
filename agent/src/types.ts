export enum Runtime {
  Java = 'Java',
  ObjectiveC = 'ObjectiveC',
  Generic = 'Generic',
}

export interface ArgInfo {
  type: string;
}

export interface MethodInfo {
  name: string;
  display: string;
  args: ArgInfo[];
  returnType: string;
  isStatic: boolean;
}

export interface FieldInfo {
  name: string;
  display: string;
  type: string;
  isStatic: boolean;
}

export interface ClassMemberInfo {
  methods: MethodInfo[];
  fields: FieldInfo[];
}

export interface ObjCMethodInfo {
  selector: string;    // "- initWithFrame:" or "+ alloc"
  types: string;       // raw encoding "@48@0:8{CGRect=...}16"
}

export interface ObjCIvarInfo {
  name: string;        // "_delegate"
  type: string;        // type encoding "@\"NSString\""
  offset: number;
}

export interface ObjCPropertyInfo {
  name: string;        // "delegate"
  attributes: string;  // full attr string "T@\"NSString\",W,N,V_delegate"
  isClass: boolean;
}

export interface ObjCClassInfo {
  name: string;
  superClass: string | null;
  protocols: string[];
  methods: ObjCMethodInfo[];
  properties: ObjCPropertyInfo[];
  ivars: ObjCIvarInfo[];
}

export interface ObjCProtocolInfo {
  name: string;
  parentProtocols: string[];
  methods: ObjCMethodInfo[];
  optionalMethods: ObjCMethodInfo[];
  properties: ObjCPropertyInfo[];
}

export interface JavaMethodInfo {
  name: string;
  display: string;
  args: string[];
  returnType: string;
  modifiers: string;
  isStatic: boolean;
}

export interface JavaFieldInfo {
  name: string;
  display: string;
  type: string;
  modifiers: string;
  isStatic: boolean;
}

export interface JavaClassInfo {
  modifiers: string;
  name: string;
  superClass: string | null;
  interfaces: string[];
  methods: JavaMethodInfo[];
  fields: JavaFieldInfo[];
}
