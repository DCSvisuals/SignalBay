/** Turn a hunt box into an FTS5 prefix query. Returns null when nothing is searchable. */
export function toFtsQuery(input: string): string | null {
  const tokens = input
    .toLowerCase()
    .split(/[^a-z0-9_.:@/-]+/i)
    .map((token) => token.replace(/"/g, ""))
    .filter((token) => token.length >= 2)
    .slice(0, 8);
  if (tokens.length === 0) return null;
  return tokens.map((token) => `"${token}"*`).join(" AND ");
}
