// Small shared tools: clipboard + file download. Every table/list in the app
// offers copy/export via these so behavior (and toasts) stay uniform.
import { store } from "./store";

export async function copyText(text: string, what = "Copied") {
  try {
    await navigator.clipboard.writeText(text);
    store.toast(what, text.length > 60 ? text.slice(0, 57) + "…" : text);
  } catch {
    store.toast("Copy failed", "clipboard unavailable", true);
  }
}

export function download(filename: string, text: string, mime = "text/plain") {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: mime }));
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

/** rows → CSV with proper quoting */
export function toCsv(rows: Record<string, unknown>[]): string {
  if (!rows.length) return "";
  const cols = Object.keys(rows[0]);
  const esc = (v: unknown) => {
    const s = v == null ? "" : String(v);
    return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  return [cols.join(","), ...rows.map((r) => cols.map((c) => esc(r[c])).join(","))].join("\n");
}
