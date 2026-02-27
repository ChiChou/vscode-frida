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

export function generateNativeHooks(req: NativeHookRequest): string {
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
