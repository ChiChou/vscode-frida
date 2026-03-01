/**
 * Yields each type encoding substring from an ObjC method type encoding,
 * skipping type qualifiers (rnNoORV), digits (frame offsets/sizes), and
 * balanced brace/bracket groups (structs, unions, arrays) so that compound
 * types count as a single slot.
 */
function* slots(enc: string): Generator<string> {
  let i = 0;

  function skipType(): void {
    if (i >= enc.length) return;
    const ch = enc[i];

    // type qualifiers — skip and recurse
    if ("rnNoORV".includes(ch)) {
      i++;
      skipType();
      return;
    }

    if (ch === "{" || ch === "(") {
      // struct {name=...} or union (name=...)
      const close = ch === "{" ? "}" : ")";
      let depth = 1;
      i++;
      while (i < enc.length && depth > 0) {
        if (enc[i] === ch) depth++;
        else if (enc[i] === close) depth--;
        i++;
      }
    } else if (ch === "[") {
      // array [countType]
      let depth = 1;
      i++;
      while (i < enc.length && depth > 0) {
        if (enc[i] === "[") depth++;
        else if (enc[i] === "]") depth--;
        i++;
      }
    } else if (ch === "^") {
      // pointer to type — skip "^" then skip the pointee type
      i++;
      skipType();
    } else if (ch === "@") {
      i++;
      // "@?" = block, "@\"ClassName\"" = typed id — skip the trailer
      if (i < enc.length && enc[i] === "?") i++;
      else if (i < enc.length && enc[i] === '"') {
        i++;
        while (i < enc.length && enc[i] !== '"') i++;
        if (i < enc.length) i++; // closing quote
      }
    } else {
      // simple type (v, i, I, c, C, d, f, B, q, Q, s, S, l, L, :, #, *, ?, b (bitfield), etc.)
      i++;
    }
  }

  while (i < enc.length) {
    // skip frame-offset digits
    if (enc[i] >= "0" && enc[i] <= "9") {
      i++;
      continue;
    }
    const start = i;
    skipType();
    yield enc.substring(start, i);
  }
}

/**
 * Parse an ObjC method type encoding into per-slot type encoding substrings.
 * Returns [retType, selfType, cmdType, arg0Type, arg1Type, …].
 */
export function parse(enc: string): string[] {
  return Array.from(slots(enc));
}
