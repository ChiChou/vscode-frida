import * as vscode from 'vscode';

export interface NativeHookRequest {
  module: string;
  functions: string[];
}

export interface ArgInfo {
  type: string;
  isObject: boolean;
}

export interface MethodSelection {
  className: string;
  name: string;
  display: string;
  args: ArgInfo[];
  returnType: string;
  isReturnObject: boolean;
  isStatic: boolean;
}

export interface FunctionPrototype {
  args: string[];
  returns: string;
  error?: string;
}

const SYSTEM_PROMPT = `Give me the argument types and return type for each function name. 
Return a JSON object where keys are function names and values are objects with "args" (array of types) and "returns" (type).

Example input: malloc, free, strcpy
Example output:
{"malloc": {"args": ["uint"], "returns": "void *"}, "free": {"args": ["void *"], "returns": "void"}, "strcpy": {"args": ["char *", "char *"], "returns": "char *"}}

Do not include qualifiers. My program can only handle these native types:
"void *", "int", "uint", "long", "float", "double", "bool", "char *", "id", "void"

Please normalize types to those. If a type is an Objective-C class or instance, use "id".

If a function is not in your knowledge, set its value to {"error": "unknown function"}.

Only output the JSON object, no explanations.`;

async function queryFunctionPrototypes(functionNames: string[]): Promise<Map<string, FunctionPrototype>> {
  const result = new Map<string, FunctionPrototype>();

  if (functionNames.length === 0) {
    return result;
  }

  try {
    const models = await vscode.lm.selectChatModels({ vendor: 'copilot' });
    if (models.length === 0) {
      return result;
    }

    const model = models[0];
    const messages = [
      vscode.LanguageModelChatMessage.User(SYSTEM_PROMPT),
      vscode.LanguageModelChatMessage.User(functionNames.join(', '))
    ];

    const response = await model.sendRequest(messages, {}, new vscode.CancellationTokenSource().token);

    let jsonStr = '';
    for await (const chunk of response.text) {
      jsonStr += chunk;
    }

    jsonStr = jsonStr.trim();
    const jsonMatch = jsonStr.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]);
      for (const fn of functionNames) {
        if (parsed[fn]) {
          result.set(fn, parsed[fn] as FunctionPrototype);
        }
      }
    }
  } catch {
    // ignore errors
  }

  return result;
}

function getArgExpression(type: string, index: number): string {
  switch (type) {
    case 'char *':
      return `args[${index}].readUtf8String()`;
    case 'id':
      return `new ObjC.Object(args[${index}]).toString()`;
    default:
      return `args[${index}]`;
  }
}

function* generateNativeHookBasic(fn: string): Generator<string> {
  yield `// ${fn}`;
  yield `Interceptor.attach(mod.getExportByName(${JSON.stringify(fn)}), {`;
  yield `  onEnter(args) {`;
  yield `    console.log('[${fn}] called');`;
  yield `  },`;
  yield `  onLeave(retval) {`;
  yield `    console.log('[${fn}] returned:', retval);`;
  yield `  }`;
  yield `});`;
  yield ``;
}

function* generateNativeHook(fn: string, proto: FunctionPrototype | undefined): Generator<string> {
  yield `// ${fn}`;
  yield `Interceptor.attach(mod.getExportByName(${JSON.stringify(fn)}), {`;
  yield `  onEnter(args) {`;

  if (proto && !proto.error && proto.args.length > 0) {
    const argExprs = proto.args.map((type, i) => getArgExpression(type, i));
    yield `    console.log('[${fn}] called', ${argExprs.join(', ')});`;
  } else {
    yield `    console.log('[${fn}] called');`;
  }

  yield `  },`;
  yield `  onLeave(retval) {`;

  if (proto && !proto.error) {
    switch (proto.returns) {
      case 'void':
        yield `    console.log('[${fn}] returned');`;
        break;
      case 'char *':
        yield `    console.log('[${fn}] returned:', retval.readUtf8String());`;
        break;
      case 'id':
        yield `    if (!retval.isNull()) {`;
        yield `      console.log('[${fn}] returned:', new ObjC.Object(retval).toString());`;
        yield `    } else {`;
        yield `      console.log('[${fn}] returned: null');`;
        yield `    }`;
        break;
      default:
        yield `    console.log('[${fn}] returned:', retval);`;
    }
  } else {
    yield `    console.log('[${fn}] returned:', retval);`;
  }

  yield `  }`;
  yield `});`;
  yield ``;
}

export function generateNativeHooksBasic(req: NativeHookRequest): string {
  function* generate(): Generator<string> {
    yield `const mod = Process.findModuleByName(${JSON.stringify(req.module)});`;
    yield '';
    for (const fn of req.functions) {
      yield* generateNativeHookBasic(fn);
    }
  }
  return [...generate()].join('\n');
}

export async function generateNativeHooks(req: NativeHookRequest): Promise<string> {
  const prototypes = await queryFunctionPrototypes(req.functions);

  function* generate(): Generator<string> {
    yield `const mod = Process.findModuleByName(${JSON.stringify(req.module)});`;
    yield '';
    for (const fn of req.functions) {
      yield* generateNativeHook(fn, prototypes.get(fn));
    }
  }
  return [...generate()].join('\n');
}

export function generateObjCHooks(selections: MethodSelection[]): string {
  const grouped = groupBy(selections, s => s.className);

  function* generate(): Generator<string> {
    for (const [className, methods] of grouped) {
      yield `// Class: ${className}`;
      yield `if (ObjC.available) {`;
      yield `  const cls = ObjC.classes[${JSON.stringify(className)}];`;
      yield '';

      for (const m of methods) {
        const varName = sanitize(m.name);
        const cleanSel = m.name.substring(2);

        const argExprs = m.args.map((arg, i) => {
          const argIdx = i + 2;
          return arg.isObject ? `new ObjC.Object(args[${argIdx}]).toString()` : `args[${argIdx}]`;
        });

        yield `  // ${m.name}`;
        yield `  const ${varName} = cls[${JSON.stringify(m.name)}];`;
        yield `  Interceptor.attach(${varName}.implementation, {`;
        yield `    onEnter(args) {`;
        if (argExprs.length > 0) {
          yield `      console.log('[${className} ${cleanSel}] called', ${argExprs.join(', ')});`;
        } else {
          yield `      console.log('[${className} ${cleanSel}] called');`;
        }
        yield `    },`;
        yield `    onLeave(retval) {`;
        if (m.isReturnObject) {
          yield `      if (!retval.isNull()) {`;
          yield `        console.log('[${className} ${cleanSel}] returned:', new ObjC.Object(retval).toString());`;
          yield `      } else {`;
          yield `        console.log('[${className} ${cleanSel}] returned: null');`;
          yield `      }`;
        } else {
          yield `      console.log('[${className} ${cleanSel}] returned:', retval);`;
        }
        yield `    }`;
        yield `  });`;
        yield '';
      }

      yield `}`;
    }
  }

  const blocks: string[] = [];
  let currentBlock: string[] = [];

  for (const line of generate()) {
    if (line.startsWith('// Class:')) {
      if (currentBlock.length > 0) {
        blocks.push(currentBlock.join('\n'));
        currentBlock = [];
      }
    }
    currentBlock.push(line);
  }
  if (currentBlock.length > 0) {
    blocks.push(currentBlock.join('\n'));
  }

  return blocks.join('\n\n');
}

export function generateJavaHooks(selections: MethodSelection[]): string {
  const grouped = groupBy(selections, s => s.className);

  function* generate(): Generator<string> {
    for (const [className, methods] of grouped) {
      yield `// Class: ${className}`;
      yield `Java.perform(() => {`;
      yield `  const cls = Java.use(${JSON.stringify(className)});`;
      yield '';

      for (const m of methods) {
        const argTypes = m.args.map(a => JSON.stringify(a.type)).join(', ');
        const argNames = m.args.map((_, i) => `arg${i}`).join(', ');

        yield `  // ${m.display}`;
        yield `  cls[${JSON.stringify(m.name)}].overload(${argTypes}).implementation = function(${argNames}) {`;
        yield `    console.log('[${className}.${m.name}] called');`;

        if (m.returnType === 'void') {
          yield `    this[${JSON.stringify(m.name)}](${argNames});`;
        } else {
          yield `    const ret = this[${JSON.stringify(m.name)}](${argNames});`;
          yield `    console.log('[${className}.${m.name}] returned:', ret);`;
          yield `    return ret;`;
        }

        yield `  };`;
        yield '';
      }

      yield `});`;
    }
  }

  const blocks: string[] = [];
  let currentBlock: string[] = [];

  for (const line of generate()) {
    if (line.startsWith('// Class:')) {
      if (currentBlock.length > 0) {
        blocks.push(currentBlock.join('\n'));
        currentBlock = [];
      }
    }
    currentBlock.push(line);
  }
  if (currentBlock.length > 0) {
    blocks.push(currentBlock.join('\n'));
  }

  return blocks.join('\n\n');
}

function sanitize(name: string): string {
  return 'p_' + name.replace(/[^a-zA-Z0-9_]/g, '_');
}

function groupBy<T>(items: T[], keyFn: (item: T) => string): Map<string, T[]> {
  const map = new Map<string, T[]>();
  for (const item of items) {
    const key = keyFn(item);
    if (!map.has(key)) { map.set(key, []); }
    map.get(key)!.push(item);
  }
  return map;
}
