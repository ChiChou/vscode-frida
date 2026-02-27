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

const SYSTEM_PROMPT = `Give me the argument types and return type for each function name. Return a JSON object where keys are function names and values are objects with "args" (array of types) and "returns" (type).

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

function generateArgPrintCode(args: string[], fn: string): { onEnter: string[]; argCount: number } {
  const onEnter: string[] = [];
  const argCount = args.length;

  if (argCount === 0) {
    onEnter.push(`      console.log('[${fn}] called');`);
  } else {
    const argExprs: string[] = [];
    for (let i = 0; i < args.length; i++) {
      const type = args[i];
      switch (type) {
        case 'char *':
          argExprs.push(`args[${i}].readUtf8String()`);
          break;
        case 'void *':
        case 'int':
        case 'uint':
        case 'long':
        case 'float':
        case 'double':
        case 'bool':
          argExprs.push(`args[${i}]`);
          break;
        case 'id':
          argExprs.push(`new ObjC.Object(args[${i}]).toString()`);
          break;
        default:
          argExprs.push(`args[${i}]`);
      }
    }
    onEnter.push(`      console.log(\`[${fn}](\${[${argExprs.join(', ')}].join(', ')})\`);`);
  }

  return { onEnter, argCount };
}

function generateReturnPrintCode(returnType: string, fn: string): string[] {
  const onLeave: string[] = [];
  
  switch (returnType) {
    case 'void':
      onLeave.push(`      console.log('[${fn}] returned');`);
      break;
    case 'char *':
      onLeave.push(`      console.log('[${fn}] returned:', retval.readUtf8String());`);
      break;
    case 'id':
      onLeave.push(`      if (!retval.isNull()) {`);
      onLeave.push(`        console.log('[${fn}] returned:', new ObjC.Object(retval).toString());`);
      onLeave.push(`      } else {`);
      onLeave.push(`        console.log('[${fn}] returned: null');`);
      onLeave.push(`      }`);
      break;
    case 'void *':
    case 'int':
    case 'uint':
    case 'long':
    case 'float':
    case 'double':
    case 'bool':
    default:
      onLeave.push(`      console.log('[${fn}] returned:', retval);`);
  }

  return onLeave;
}

export function generateNativeHooksBasic(req: NativeHookRequest): string {
  const lines: string[] = [];
  lines.push(`const mod = Process.findModuleByName(${JSON.stringify(req.module)});`);
  lines.push('');

  for (const fn of req.functions) {
    const varName = sanitize(fn);
    lines.push(`// ${fn}`);
    lines.push(`const ${varName} = mod.findExportByName(${JSON.stringify(fn)});`);
    lines.push(`if (${varName}) {`);
    lines.push(`  Interceptor.attach(${varName}, {`);
    lines.push(`    onEnter(args) {`);
    lines.push(`      console.log('[${fn}] called');`);
    lines.push(`    },`);
    lines.push(`    onLeave(retval) {`);
    lines.push(`      console.log('[${fn}] returned:', retval);`);
    lines.push(`    }`);
    lines.push(`  });`);
    lines.push(`}`);
    lines.push('');
  }

  return lines.join('\n');
}

export async function generateNativeHooks(req: NativeHookRequest): Promise<string> {
  const lines: string[] = [];
  lines.push(`const mod = Process.findModuleByName(${JSON.stringify(req.module)});`);
  lines.push('');

  const prototypes = await queryFunctionPrototypes(req.functions);

  for (const fn of req.functions) {
    const varName = sanitize(fn);
    lines.push(`// ${fn}`);
    lines.push(`const ${varName} = mod.findExportByName(${JSON.stringify(fn)});`);
    lines.push(`if (${varName}) {`);
    lines.push(`  Interceptor.attach(${varName}, {`);
    lines.push(`    onEnter(args) {`);

    const proto = prototypes.get(fn);
    if (proto && !proto.error) {
      const { onEnter } = generateArgPrintCode(proto.args, fn);
      lines.push(...onEnter.map(l => '  ' + l));
    } else {
      lines.push(`      console.log('[${fn}] called');`);
    }

    lines.push(`    },`);
    lines.push(`    onLeave(retval) {`);

    if (proto && !proto.error) {
      const onLeave = generateReturnPrintCode(proto.returns, fn);
      lines.push(...onLeave.map(l => '  ' + l));
    } else {
      lines.push(`      console.log('[${fn}] returned:', retval);`);
    }

    lines.push(`    }`);
    lines.push(`  });`);
    lines.push(`}`);
    lines.push('');
  }

  return lines.join('\n');
}

export function generateObjCHooks(selections: MethodSelection[]): string {
  const grouped = groupBy(selections, s => s.className);
  const blocks: string[] = [];

  for (const [className, methods] of grouped) {
    const lines: string[] = [];
    lines.push(`// Class: ${className}`);
    lines.push(`if (ObjC.available) {`);
    lines.push(`  const cls = ObjC.classes[${JSON.stringify(className)}];`);
    lines.push('');

    for (const m of methods) {
      const varName = sanitize(m.name);
      const cleanSel = m.name.substring(2); // remove "- " or "+ "

      lines.push(`  // ${m.name}`);

      // argument formatting
      const argParts: string[] = [];
      for (let i = 0; i < m.args.length; i++) {
        const argIdx = i + 2; // skip self and _cmd
        if (m.args[i].isObject) {
          argParts.push(`new ObjC.Object(args[${argIdx}]).toString()`);
        } else {
          argParts.push(`args[${argIdx}]`);
        }
      }

      // return value formatting
      const retExpr = m.isReturnObject
        ? 'new ObjC.Object(retval).toString()'
        : 'retval';

      lines.push(`  const ${varName} = cls[${JSON.stringify(m.name)}];`);
      lines.push(`  Interceptor.attach(${varName}.implementation, {`);
      lines.push(`    onEnter(args) {`);
      if (argParts.length > 0) {
        lines.push(`      const formatted = [${argParts.join(', ')}];`);
        lines.push(`      console.log(\`[${className} ${cleanSel}](\${formatted.join(', ')})\`);`);
      } else {
        lines.push(`      console.log('[${className} ${cleanSel}] called');`);
      }
      lines.push(`    },`);
      lines.push(`    onLeave(retval) {`);
      lines.push(`      console.log(\`[${className} ${cleanSel}] returned: \${${retExpr}}\`);`);
      lines.push(`    }`);
      lines.push(`  });`);
      lines.push('');
    }

    lines.push(`}`);
    blocks.push(lines.join('\n'));
  }

  return blocks.join('\n\n');
}

export function generateJavaHooks(selections: MethodSelection[]): string {
  const grouped = groupBy(selections, s => s.className);
  const blocks: string[] = [];

  for (const [className, methods] of grouped) {
    const lines: string[] = [];
    lines.push(`// Class: ${className}`);
    lines.push(`Java.perform(() => {`);
    lines.push(`  const cls = Java.use(${JSON.stringify(className)});`);
    lines.push('');

    for (const m of methods) {
      const argTypes = m.args.map(a => JSON.stringify(a.type)).join(', ');
      const argNames = m.args.map((_, i) => `arg${i}`).join(', ');
      const callArgs = argNames;

      lines.push(`  // ${m.display}`);
      lines.push(`  cls[${JSON.stringify(m.name)}].overload(${argTypes}).implementation = function(${argNames}) {`);
      lines.push(`    console.log('[${className}.${m.name}] called');`);

      if (m.returnType === 'void') {
        lines.push(`    this[${JSON.stringify(m.name)}](${callArgs});`);
      } else {
        lines.push(`    const ret = this[${JSON.stringify(m.name)}](${callArgs});`);
        lines.push(`    console.log('[${className}.${m.name}] returned:', ret);`);
        lines.push(`    return ret;`);
      }

      lines.push(`  };`);
      lines.push('');
    }

    lines.push(`});`);
    blocks.push(lines.join('\n'));
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
