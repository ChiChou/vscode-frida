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
