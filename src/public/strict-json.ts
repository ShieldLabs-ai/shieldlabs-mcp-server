/** Parse JSON without silently overwriting duplicate object members. */
export function parseStrictJson(text: string): unknown {
  const value: unknown = JSON.parse(text);
  // JSON.parse establishes valid syntax. String tokens consume escaped quotes
  // and delimiters, so braces inside strings cannot affect the object stack.
  const containers: (Set<string> | undefined)[] = [];
  for (const match of text.matchAll(/"(?:[^"\\]|\\[\s\S])*"|[{}[\]]/g)) {
    const token = match[0];
    if (token === '{') containers.push(new Set());
    else if (token === '[') containers.push(undefined);
    else if (token === '}' || token === ']') containers.pop();
    else {
      let next = match.index + token.length;
      while (/\s/.test(text[next] ?? '') && next < text.length) next++;
      if (text[next] !== ':') continue;
      const keys = containers[containers.length - 1]!;
      const key = JSON.parse(token) as string;
      if (keys.has(key)) throw new SyntaxError('Duplicate JSON member.');
      keys.add(key);
    }
  }
  return value;
}
