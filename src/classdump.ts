// Objective-C type encoding parser
// Ported from ClassDumpRuntime's CDTypeParser

type TypeModifier =
  | "const"
  | "in"
  | "inout"
  | "out"
  | "bycopy"
  | "byref"
  | "oneway"
  | "_Atomic"
  | "_Complex";

interface PrimitiveType {
  kind: "primitive";
  modifiers: TypeModifier[];
  name: string;
}
interface ObjectType {
  kind: "object";
  modifiers: TypeModifier[];
  className: string | null;
  protocols: string[];
}
interface PointerType {
  kind: "pointer";
  modifiers: TypeModifier[];
  pointee: ParseType;
}
interface ArrayType {
  kind: "array";
  modifiers: TypeModifier[];
  size: number;
  elementType: ParseType;
}
interface RecordType {
  kind: "record";
  modifiers: TypeModifier[];
  isUnion: boolean;
  name: string | null;
  fields: { name: string | null; type: ParseType }[] | null;
}
interface BlockType {
  kind: "block";
  modifiers: TypeModifier[];
  returnType: ParseType | null;
  parameterTypes: ParseType[] | null;
}
interface BitFieldType {
  kind: "bitfield";
  modifiers: TypeModifier[];
  width: number;
}

type ParseType =
  | PrimitiveType
  | ObjectType
  | PointerType
  | ArrayType
  | RecordType
  | BlockType
  | BitFieldType;

const primitiveMap: Record<string, string> = {
  c: "char",
  i: "int",
  s: "short",
  l: "long",
  q: "long long",
  t: "__int128",
  C: "unsigned char",
  I: "unsigned int",
  S: "unsigned short",
  L: "unsigned long",
  Q: "unsigned long long",
  T: "unsigned __int128",
  f: "float",
  d: "double",
  D: "long double",
  B: "BOOL",
  v: "void",
  "#": "Class",
  ":": "SEL",
  "?": "void /* function */",
  " ": "void /* unknown type, blank encoding */",
};

const modifierMap: Record<string, TypeModifier> = {
  r: "const",
  n: "in",
  N: "inout",
  o: "out",
  O: "bycopy",
  R: "byref",
  V: "oneway",
  A: "_Atomic",
  j: "_Complex",
};

const primitiveChars = new Set(Object.keys(primitiveMap));
// '^' is a modifier in endOfTypeEncoding but a pointer constructor in typeForEncoding
const modifierCharsForSkip = new Set([
  "^",
  "r",
  "n",
  "N",
  "o",
  "O",
  "R",
  "V",
  "A",
  "j",
]);

/** Find the index past the end of one type encoding starting at `pos`. */
function endOfTypeEncoding(enc: string, pos: number): number {
  while (pos < enc.length) {
    const ch = enc[pos];

    if (primitiveChars.has(ch) || ch === "*") {
      return pos + 1;
    }
    if (modifierCharsForSkip.has(ch)) {
      pos++;
      continue;
    }
    if (ch === "@") {
      pos++;
      if (pos < enc.length && enc[pos] === '"') {
        pos++;
        while (enc[pos] !== '"') pos++;
        pos++;
      } else if (pos < enc.length && enc[pos] === "?") {
        pos++;
        if (pos < enc.length && enc[pos] === "<") {
          let open = 1;
          while (open) {
            pos++;
            if (enc[pos] === "<") open++;
            else if (enc[pos] === ">") open--;
          }
          pos++;
        }
      }
      return pos;
    }
    if (ch === "b") {
      pos++;
      while (pos < enc.length && enc[pos] >= "0" && enc[pos] <= "9") pos++;
      return pos;
    }
    if (ch === "[" || ch === "{" || ch === "(") {
      const close = ch === "[" ? "]" : ch === "{" ? "}" : ")";
      let open = 1;
      while (open) {
        pos++;
        if (enc[pos] === ch) open++;
        else if (enc[pos] === close) open--;
      }
      pos++;
      return pos;
    }
    // unknown character — stop
    return pos;
  }
  return pos;
}

/** Parse a single type encoding from enc[start..end). */
function parseType(enc: string, start: number, end: number): ParseType {
  const modifiers: TypeModifier[] = [];
  let i = start;

  for (; i < end; i++) {
    const ch = enc[i];
    if (ch in modifierMap) {
      modifiers.push(modifierMap[ch]);
      continue;
    }

    if (ch === "^") {
      i++;
      let pointee: ParseType;
      if (i >= end) {
        pointee = { kind: "primitive", modifiers: [], name: "void" };
      } else {
        pointee = parseType(enc, i, end);
      }
      return { kind: "pointer", modifiers, pointee };
    }
    if (ch === "*") {
      return {
        kind: "pointer",
        modifiers,
        pointee: { kind: "primitive", modifiers: [], name: "char" },
      };
    }
    if (ch in primitiveMap) {
      return { kind: "primitive", modifiers, name: primitiveMap[ch] };
    }
    if (ch === "@") {
      if (i + 1 < end && enc[i + 1] === '"') {
        // @"ClassName" or @"ClassName<Proto1><Proto2>" or @"<Proto>"
        i += 2;
        const qStart = i;
        let protocolHead = -1;
        while (enc[i] !== '"') {
          if (enc[i] === "<" && protocolHead < 0) protocolHead = i;
          i++;
        }
        let className: string | null = null;
        const protocols: string[] = [];
        if (protocolHead < 0) {
          className = enc.slice(qStart, i);
        } else {
          const baseLen = protocolHead - qStart;
          if (baseLen > 0) className = enc.slice(qStart, protocolHead);
          // parse protocol list: <Proto1><Proto2>...
          let ps = protocolHead;
          while (ps < i) {
            const pStart = ps + 1; // skip '<'
            let pEnd = pStart;
            while (enc[pEnd] !== ">") pEnd++;
            protocols.push(enc.slice(pStart, pEnd));
            ps = pEnd + 1; // skip '>'
          }
        }
        return { kind: "object", modifiers, className, protocols };
      }
      if (i + 1 < end && enc[i + 1] === "?") {
        // Block type
        i += 2; // skip '@?'
        if (i < end && enc[i] === "<") {
          i++; // skip '<'
          // return type
          const retEnd = endOfTypeEncoding(enc, i);
          const returnType = parseType(enc, i, retEnd);
          i = retEnd;
          // skip first block parameter (itself: @?)
          i += 2;
          // find matching '>'
          let paramEnd = i - 1;
          let openTokens = 1;
          while (openTokens) {
            paramEnd++;
            if (enc[paramEnd] === "<") openTokens++;
            else if (enc[paramEnd] === ">") openTokens--;
          }
          const parameterTypes: ParseType[] = [];
          while (i < paramEnd) {
            const tokenEnd = endOfTypeEncoding(enc, i);
            parameterTypes.push(parseType(enc, i, tokenEnd));
            i = tokenEnd;
          }
          return { kind: "block", modifiers, returnType, parameterTypes };
        }
        return {
          kind: "block",
          modifiers,
          returnType: null,
          parameterTypes: null,
        };
      }
      // plain id
      return { kind: "object", modifiers, className: null, protocols: [] };
    }
    if (ch === "b") {
      i++;
      let numStr = "";
      while (i < end && enc[i] >= "0" && enc[i] <= "9") {
        numStr += enc[i];
        i++;
      }
      const width = parseInt(numStr, 10);
      return { kind: "bitfield", modifiers, width };
    }
    if (ch === "[") {
      // find matching ']'
      let open = 1;
      let j = i;
      while (open) {
        j++;
        if (enc[j] === "[") open++;
        else if (enc[j] === "]") open--;
      }
      // parse size
      let si = i + 1;
      let sizeStr = "";
      while (enc[si] >= "0" && enc[si] <= "9") {
        sizeStr += enc[si];
        si++;
      }
      const size = parseInt(sizeStr, 10);
      const elementType = parseType(enc, si, j);
      return { kind: "array", modifiers, size, elementType };
    }
    if (ch === "{" || ch === "(") {
      const isUnion = ch === "(";
      const close = isUnion ? ")" : "}";
      let open = 1;
      let j = i;
      while (open) {
        j++;
        if (enc[j] === ch) open++;
        else if (enc[j] === close) open--;
      }
      // j points to the closing bracket
      return parseRecord(enc, i, j + 1, isUnion, modifiers);
    }
    // unknown
    return {
      kind: "primitive",
      modifiers,
      name: `void /* unknown encoding '${ch}' */`,
    };
  }
  return {
    kind: "primitive",
    modifiers,
    name: "void /* unknown type, empty encoding */",
  };
}

function parseRecord(
  enc: string,
  start: number,
  end: number,
  isUnion: boolean,
  modifiers: TypeModifier[],
): RecordType {
  const openCh = isUnion ? "(" : "{";
  const closeCh = isUnion ? ")" : "}";

  // find '=' at depth 1, or the closing bracket
  let i = start + 1;
  let openTokens = 1;
  while (true) {
    const ch = enc[i];
    if (ch === openCh) openTokens++;
    else if (ch === closeCh) openTokens--;
    if (openTokens === 0) break;
    if (openTokens === 1 && ch === "=") break;
    i++;
  }

  // name is between start+1 and i (exclusive)
  const nameStr = enc.slice(start + 1, i);
  let name: string | null = null;
  // anonymous structs have name "?" — treat as unnamed
  if (nameStr.length > 0 && nameStr !== "?") {
    name = nameStr;
  }

  // move past '=' or if we hit the end, there are no fields
  i++;
  if (i >= end) {
    return { kind: "record", modifiers, isUnion, name, fields: null };
  }

  const endToken = end - 1; // points to closing bracket
  const fields: { name: string | null; type: ParseType }[] = [];

  while (i < endToken) {
    let fieldName: string | null = null;
    if (enc[i] === '"') {
      i++;
      const nameStart = i;
      while (enc[i] !== '"') i++;
      fieldName = enc.slice(nameStart, i);
      i++;
    }
    const tokenEnd = endOfTypeEncoding(enc, i);
    const fieldType = parseType(enc, i, tokenEnd);
    fields.push({ name: fieldName, type: fieldType });
    i = tokenEnd;
  }

  return { kind: "record", modifiers, isUnion, name, fields };
}

/** Format a ParseType as an Objective-C type string (without variable name). */
function formatType(type: ParseType): string {
  const mods = type.modifiers.length > 0 ? type.modifiers.join(" ") + " " : "";

  switch (type.kind) {
    case "primitive":
      return mods + type.name;

    case "object": {
      if (type.className) {
        const protos =
          type.protocols.length > 0 ? `<${type.protocols.join(", ")}>` : "";
        return `${mods}${type.className}${protos} *`;
      }
      const protos =
        type.protocols.length > 0 ? `<${type.protocols.join(", ")}>` : "";
      return `${mods}id${protos}`;
    }

    case "pointer": {
      const pointeeStr = formatType(type.pointee);
      // if pointee already ends with '*' or '* ', don't add space
      if (pointeeStr.endsWith("*")) {
        return mods + pointeeStr + "*";
      }
      return mods + pointeeStr + " *";
    }

    case "array": {
      // collect nested array dimensions
      const dims: number[] = [];
      let head: ParseType = type;
      while (head.kind === "array") {
        dims.push(head.size);
        head = head.elementType;
      }
      return `${mods}${formatType(head)}[${dims.join("][")}]`;
    }

    case "record": {
      const keyword = type.isUnion ? "union" : "struct";
      const namePart = type.name ? ` ${type.name}` : "";
      if (type.fields === null) {
        return `${mods}${keyword}${namePart}`;
      }
      let fieldNum = 0;
      const fieldStrs = type.fields.map((f) => {
        const fname = f.name ?? `x${fieldNum++}`;
        return formatTypeWithVarName(f.type, fname);
      });
      return `${mods}${keyword}${namePart} { ${fieldStrs.join("; ")}; }`;
    }

    case "block": {
      if (type.returnType && type.parameterTypes) {
        const ret = formatType(type.returnType);
        const params =
          type.parameterTypes.length === 0
            ? "void"
            : type.parameterTypes.map((p) => formatType(p)).join(", ");
        const modsPart =
          type.modifiers.length > 0 ? type.modifiers.join(" ") + " " : "";
        return `${ret} (^${modsPart})(${params})`;
      }
      return `${mods}id /* block */`;
    }

    case "bitfield": {
      // bitfield base type by width (assuming 8-bit byte, LP64)
      let base: string;
      if (type.width <= 8) base = "unsigned char";
      else if (type.width <= 16) base = "unsigned short";
      else if (type.width <= 32) base = "unsigned int";
      else if (type.width <= 64) base = "unsigned long long";
      else base = "unsigned __int128";
      return `${mods}${base} : ${type.width}`;
    }
  }
}

/** Format a type with a variable name (for struct fields, etc). */
function formatTypeWithVarName(type: ParseType, varName: string): string {
  // For arrays, the var name goes before the brackets
  if (type.kind === "array") {
    const mods =
      type.modifiers.length > 0 ? type.modifiers.join(" ") + " " : "";
    const dims: number[] = [];
    let head: ParseType = type;
    while (head.kind === "array") {
      dims.push(head.size);
      head = head.elementType;
    }
    return `${mods}${formatType(head)} ${varName}[${dims.join("][")}]`;
  }
  // For blocks with signature, var name goes inside (^name)
  if (type.kind === "block" && type.returnType && type.parameterTypes) {
    const ret = formatType(type.returnType);
    const params =
      type.parameterTypes.length === 0
        ? "void"
        : type.parameterTypes.map((p) => formatType(p)).join(", ");
    const mods =
      type.modifiers.length > 0 ? type.modifiers.join(" ") + " " : "";
    return `${ret} (^${mods}${varName})(${params})`;
  }
  // For bitfields: "type varName : width"
  if (type.kind === "bitfield") {
    const mods =
      type.modifiers.length > 0 ? type.modifiers.join(" ") + " " : "";
    let base: string;
    if (type.width <= 8) base = "unsigned char";
    else if (type.width <= 16) base = "unsigned short";
    else if (type.width <= 32) base = "unsigned int";
    else if (type.width <= 64) base = "unsigned long long";
    else base = "unsigned __int128";
    return `${mods}${base} ${varName} : ${type.width}`;
  }
  const typeStr = formatType(type);
  // For pointer types ending with '*', no space before varName
  if (typeStr.endsWith("*")) return `${typeStr}${varName}`;
  return `${typeStr} ${varName}`;
}

/**
 * Parse a method type encoding string and return an array of formatted type strings
 * for each positional parameter (excluding self and _cmd).
 * Index 0 is the return type.
 *
 * Example:
 *   parseMethodTypes('@48@0:8@16Q24Q32^@40')
 *   => ['id', 'id', 'unsigned long long', 'unsigned long long', 'id *']
 *   // [return, param1, param2, param3, param4]
 */
function parseMethodTypes(encoding: string): string[] {
  let pos = 0;

  // 1. Parse return type
  const retEnd = endOfTypeEncoding(encoding, pos);
  const returnType = parseType(encoding, pos, retEnd);
  pos = retEnd;

  // 2. Skip stack size
  while (pos < encoding.length && encoding[pos] >= "0" && encoding[pos] <= "9")
    pos++;

  // 3. Parse all argument types
  const allArgs: ParseType[] = [];
  while (pos < encoding.length) {
    const typeEnd = endOfTypeEncoding(encoding, pos);
    allArgs.push(parseType(encoding, pos, typeEnd));
    pos = typeEnd;

    // Skip GNU runtime register hint '+'
    if (pos < encoding.length && encoding[pos] === "+") pos++;
    // Skip negative sign in offset
    if (pos < encoding.length && encoding[pos] === "-") pos++;
    // Skip offset digits
    while (
      pos < encoding.length &&
      encoding[pos] >= "0" &&
      encoding[pos] <= "9"
    )
      pos++;
  }

  // 4. Return [returnType, ...userArgs] (trimming self and _cmd from front)
  const types = [formatType(returnType)];
  // Usually first 2 args are self (id) and _cmd (SEL) — skip them
  const userArgs =
    allArgs.length > 2
      ? allArgs.slice(allArgs.length - (allArgs.length - 2))
      : [];
  for (const arg of userArgs) {
    types.push(formatType(arg));
  }
  return types;
}

/**
 * Generate an Objective-C method prototype from a selector and type encoding.
 *
 * Example:
 *   dump('- initWithContentsOfFile:options:maxLength:error:', '@48@0:8@16Q24Q32^@40')
 *   => '- (id)initWithContentsOfFile:(id)arg1 options:(unsigned long long)arg2 maxLength:(unsigned long long)arg3 error:(id *)arg4;'
 */
export function dump(selector: string, encoding: string): string {
  // Extract instance/class indicator
  let prefix: string;
  let sel: string;
  if (selector.startsWith("+ ") || selector.startsWith("- ")) {
    prefix = selector[0];
    sel = selector.slice(2);
  } else if (selector.startsWith("+") || selector.startsWith("-")) {
    prefix = selector[0];
    sel = selector.slice(1);
  } else {
    prefix = "-";
    sel = selector;
  }

  const types = parseMethodTypes(encoding);
  const returnTypeStr = types[0];
  const paramTypes = types.slice(1);

  const colonCount = (sel.match(/:/g) || []).length;

  if (colonCount === 0) {
    // no-argument method
    return `${prefix} (${returnTypeStr})${sel};`;
  }

  const parts = sel.split(":");
  // last element after final ':' is empty string
  const selectorParts = parts.slice(0, colonCount);

  // Fill in missing param types if encoding had fewer than expected
  while (paramTypes.length < colonCount) {
    paramTypes.push("void /* unknown type, empty encoding */");
  }

  const params = selectorParts.map((part, idx) => {
    return `${part}:(${paramTypes[idx]})arg${idx + 1}`;
  });

  return `${prefix} (${returnTypeStr})${params.join(" ")};`;
}

/**
 * Generate an Objective-C ivar declaration from a name and type encoding.
 *
 * Example:
 *   dumpIvar('_name', '@"NSString"')
 *   => 'NSString *_name'
 */
export function dumpIvar(name: string, typeEncoding: string): string {
  const type = parseType(typeEncoding, 0, typeEncoding.length);
  return formatTypeWithVarName(type, name);
}

interface PropertyInfo {
  type: ParseType;
  attributes: { name: string; value: string | null }[];
  ivar: string | null;
  getter: string | null;
  setter: string | null;
}

/**
 * Parse a property attributes string as returned by property_getAttributes().
 *
 * Format: "T<type encoding>,<attribute codes>"
 * Attribute codes:
 *   R = readonly, C = copy, & = retain, W = weak, N = nonatomic,
 *   G<name> = getter, S<name> = setter, V<name> = ivar, D = dynamic,
 *   P = GC-eligible, ? = @optional
 */
function parsePropertyAttributes(attrString: string): PropertyInfo {
  const attributes: { name: string; value: string | null }[] = [];
  let type: ParseType = { kind: "primitive", modifiers: [], name: "void" };
  let ivar: string | null = null;
  let getter: string | null = null;
  let setter: string | null = null;

  let pos = 0;
  while (pos < attrString.length) {
    const code = attrString[pos];
    pos++;

    // Find the end of this attribute value (delimited by ',' or end of string)
    // Must handle nested type encodings with quotes, braces, parens
    const valueStart = pos;
    while (pos < attrString.length && attrString[pos] !== ",") {
      if (attrString[pos] === '"') {
        pos++;
        while (pos < attrString.length && attrString[pos] !== '"') pos++;
        pos++; // skip closing quote
      } else if (attrString[pos] === "{") {
        let open = 1;
        while (open) {
          pos++;
          if (attrString[pos] === "{") open++;
          else if (attrString[pos] === "}") open--;
        }
        pos++;
      } else if (attrString[pos] === "(") {
        let open = 1;
        while (open) {
          pos++;
          if (attrString[pos] === "(") open++;
          else if (attrString[pos] === ")") open--;
        }
        pos++;
      } else {
        pos++;
      }
    }

    const value = pos > valueStart ? attrString.slice(valueStart, pos) : null;

    switch (code) {
      case "T":
        if (value) {
          type = parseType(value, 0, value.length);
        }
        break;
      case "R":
        attributes.push({ name: "readonly", value: null });
        break;
      case "C":
        attributes.push({ name: "copy", value: null });
        break;
      case "&":
        attributes.push({ name: "retain", value: null });
        break;
      case "W":
        attributes.push({ name: "weak", value: null });
        break;
      case "N":
        attributes.push({ name: "nonatomic", value: null });
        break;
      case "G":
        getter = value;
        attributes.push({ name: "getter", value });
        break;
      case "S":
        setter = value;
        attributes.push({ name: "setter", value });
        break;
      case "V":
        ivar = value;
        break;
      case "D":
        // @dynamic — don't synthesize getter/setter
        break;
      case "P":
        // GC-eligible, no notation
        break;
      case "?":
        // @optional in protocol
        break;
    }

    // skip comma separator
    if (pos < attrString.length && attrString[pos] === ",") pos++;
  }

  return { type, attributes, ivar, getter, setter };
}

/**
 * Generate an Objective-C @property declaration from a name and property attributes string.
 *
 * Example:
 *   dumpProperty('name', 'T@"NSString",C,N,V_name')
 *   => '@property (copy, nonatomic) NSString *name'
 *
 *   dumpProperty('count', 'TQ,R,N,V_count')
 *   => '@property (readonly, nonatomic) unsigned long long count'
 */
export function dumpProperty(
  name: string,
  attrString: string,
  isClass: boolean = false,
): string {
  const info = parsePropertyAttributes(attrString);

  const allAttrs = isClass
    ? [{ name: "class", value: null }, ...info.attributes]
    : info.attributes;

  let result = "@property";
  if (allAttrs.length > 0) {
    const attrStrs = allAttrs.map((a) =>
      a.value !== null ? `${a.name}=${a.value}` : a.name,
    );
    result += ` (${attrStrs.join(", ")})`;
  }
  result += " " + formatTypeWithVarName(info.type, name);
  return result;
}

export interface ObjCClassInfo {
  name: string;
  superClass: string | null;
  protocols: string[];
  methods: { selector: string; types: string }[];
  properties: { name: string; attributes: string; isClass: boolean }[];
  ivars: { name: string; type: string; offset: number }[];
}

export function generateHeader(info: ObjCClassInfo): string {
  function* generate(): Generator<string, void, undefined> {
    // @interface line
    const superPart = info.superClass ? ` : ${info.superClass}` : '';
    const protoPart = info.protocols.length > 0 ? ` <${info.protocols.join(', ')}>` : '';
    yield `@interface ${info.name}${superPart}${protoPart}`;

    // ivars
    if (info.ivars.length > 0) {
      yield '{';
      for (const ivar of info.ivars) {
        try {
          yield `  ${dumpIvar(ivar.name, ivar.type)};`;
        } catch (_) {
          yield `  /* unknown */ ${ivar.name};`;
        }
      }
      yield '}';
    }

    yield '';

    // properties
    for (const prop of info.properties) {
      try {
        yield `${dumpProperty(prop.name, prop.attributes, prop.isClass)};`;
      } catch (_) {
        yield `@property ${prop.name}; /* failed to parse attributes */`;
      }
    }

    if (info.properties.length > 0) {
      yield '';
    }

    // methods
    for (const method of info.methods) {
      if (!method.types) {
        yield dump(method.selector, 'v@0:8');
        continue;
      }
      try {
        yield dump(method.selector, method.types);
      } catch (_) {
        yield dump(method.selector, 'v@0:8');
      }
    }

    yield '';
    yield '@end';
  }

  return [...generate()].join('\n');
}

export interface ObjCProtocolInfo {
  name: string;
  parentProtocols: string[];
  methods: { selector: string; types: string }[];
  optionalMethods: { selector: string; types: string }[];
  properties: { name: string; attributes: string; isClass: boolean }[];
}

export function generateProtocolHeader(info: ObjCProtocolInfo): string {
  function* generate(): Generator<string, void, undefined> {
    const protoPart = info.parentProtocols.length > 0 ? ` <${info.parentProtocols.join(', ')}>` : '';
    yield `@protocol ${info.name}${protoPart}`;
    yield '';

    // properties
    for (const prop of info.properties) {
      if (prop.attributes) {
        try {
          yield `${dumpProperty(prop.name, prop.attributes, prop.isClass)};`;
        } catch (_) {
          yield `@property ${prop.name}; /* failed to parse attributes */`;
        }
      } else {
        yield `@property ${prop.name};`;
      }
    }

    if (info.properties.length > 0) {
      yield '';
    }

    // required methods
    for (const method of info.methods) {
      if (!method.types) {
        yield dump(method.selector, 'v@0:8');
        continue;
      }
      try {
        yield dump(method.selector, method.types);
      } catch (_) {
        yield dump(method.selector, 'v@0:8');
      }
    }

    // optional methods
    if (info.optionalMethods.length > 0) {
      yield '';
      yield '@optional';
      for (const method of info.optionalMethods) {
        if (!method.types) {
          yield dump(method.selector, 'v@0:8');
          continue;
        }
        try {
          yield dump(method.selector, method.types);
        } catch (_) {
          yield dump(method.selector, 'v@0:8');
        }
      }
    }

    yield '';
    yield '@end';
  }

  return [...generate()].join('\n');
}

export interface JavaClassInfo {
  modifiers: string;
  name: string;
  superClass: string | null;
  interfaces: string[];
  methods: { name: string; args: string[]; returnType: string; modifiers: string }[];
  fields: { name: string; type: string; modifiers: string }[];
}

const javaPrimitives = new Set(['void', 'boolean', 'byte', 'char', 'short', 'int', 'long', 'float', 'double']);

/** Strip array prefix and JNI encoding, return the base qualified class name or null for primitives. */
function resolveJavaType(t: string): string | null {
  let s = t;
  while (s.startsWith('[')) s = s.substring(1);
  if (s.startsWith('L') && s.endsWith(';')) s = s.substring(1, s.length - 1);
  if (javaPrimitives.has(s) || !s.includes('.')) return null;
  return s;
}

function shortenJavaType(t: string): string {
  // "[Lcom.example.Foo;" -> "Foo[]", "com.example.Foo" -> "Foo"
  let arrayDepth = 0;
  let s = t;
  while (s.startsWith('[')) {
    arrayDepth++;
    s = s.substring(1);
  }
  if (s.startsWith('L') && s.endsWith(';')) {
    s = s.substring(1, s.length - 1);
  }
  const last = s.lastIndexOf('.');
  const short = last >= 0 ? s.substring(last + 1) : s;
  return short + '[]'.repeat(arrayDepth);
}

function collectJavaImports(info: JavaClassInfo): string[] {
  const types = new Set<string>();
  const ownPackage = info.name.lastIndexOf('.') >= 0
    ? info.name.substring(0, info.name.lastIndexOf('.'))
    : '';

  function add(t: string) {
    const resolved = resolveJavaType(t);
    if (resolved) types.add(resolved);
  }

  if (info.superClass) add(info.superClass);
  for (const iface of info.interfaces) add(iface);
  for (const f of info.fields) add(f.type);
  for (const m of info.methods) {
    add(m.returnType);
    for (const a of m.args) add(a);
  }

  return [...types]
    .filter(t => {
      // exclude java.lang.* (auto-imported) and same-package classes
      if (t.startsWith('java.lang.') && !t.substring('java.lang.'.length).includes('.')) return false;
      if (t === info.name) return false;
      const pkg = t.lastIndexOf('.') >= 0 ? t.substring(0, t.lastIndexOf('.')) : '';
      if (pkg === ownPackage) return false;
      return true;
    })
    .sort();
}

export function generateJavaHeader(info: JavaClassInfo): string {
  function* generate(): Generator<string, void, undefined> {
    // package
    const lastDot = info.name.lastIndexOf('.');
    if (lastDot >= 0) {
      yield `package ${info.name.substring(0, lastDot)};`;
      yield '';
    }

    // imports
    const imports = collectJavaImports(info);
    if (imports.length > 0) {
      for (const imp of imports) {
        yield `import ${imp};`;
      }
      yield '';
    }

    // class declaration
    const keyword = info.modifiers.includes('interface') ? '' : 'class ';
    const mods = info.modifiers ? info.modifiers + ' ' : '';
    const shortName = shortenJavaType(info.name);
    let decl = `${mods}${keyword}${shortName}`;
    if (info.superClass && info.superClass !== 'java.lang.Object') {
      decl += ` extends ${shortenJavaType(info.superClass)}`;
    }
    if (info.interfaces.length > 0) {
      const implKeyword = info.modifiers.includes('interface') ? ' extends ' : ' implements ';
      decl += implKeyword + info.interfaces.map(shortenJavaType).join(', ');
    }
    yield decl + ' {';

    // fields
    if (info.fields.length > 0) {
      for (const f of info.fields) {
        const mods = f.modifiers ? f.modifiers + ' ' : '';
        yield `    ${mods}${shortenJavaType(f.type)} ${f.name};`;
      }
      yield '';
    }

    // methods
    for (const m of info.methods) {
      const mods = m.modifiers ? m.modifiers + ' ' : '';
      const params = m.args.map((a, i) => `${shortenJavaType(a)} arg${i}`).join(', ');
      const ret = shortenJavaType(m.returnType);
      yield `    ${mods}${ret} ${m.name}(${params});`;
    }

    yield '}';
  }

  return [...generate()].join('\n');
}
