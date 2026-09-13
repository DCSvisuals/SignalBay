export function cleanHtmlText(value: string | null | undefined, max = 0): string {
  if (!value) return "";
  let text = String(value);
  text = text.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1");
  text = text.replace(/<script[\s\S]*?<\/script>/gi, " ");
  text = text.replace(/<style[\s\S]*?<\/style>/gi, " ");
  text = decodeEntities(text);
  text = text.replace(/<[^>]+>/g, " ");
  text = decodeEntities(text);
  text = text
    .replace(/&nbsp;/gi, " ")
    .replace(/&[a-z]+;/gi, " ")
    .replace(/\u00a0/g, " ")
    .replace(/View CSAF Summary/gi, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (max > 0 && text.length > max) {
    text = `${text.slice(0, max).replace(/\s+\S*$/, "")}…`;
  }
  return text;
}

function decodeEntities(value: string): string {
  return value
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => safeChar(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, num) => safeChar(Number(num)))
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;|&#39;/g, "'");
}

function safeChar(code: number): string {
  if (!Number.isFinite(code) || code < 32) return " ";
  try {
    return String.fromCodePoint(code);
  } catch {
    return " ";
  }
}
