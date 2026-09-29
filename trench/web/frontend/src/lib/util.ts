// Small shared tools: clipboard + file download. Every table/list in the app
// offers copy/export via these so behavior (and toasts) stay uniform.
import { store } from "./store";

/** Copy and say so — once. `detail` describes what was copied when the text
 *  itself is too long to be a useful confirmation. */
export async function copyText(text: string, what = "Copied", detail?: string) {
  try {
    await navigator.clipboard.writeText(text);
    store.toast(what, detail ?? (text.length > 60 ? text.slice(0, 57) + "…" : text));
  } catch {
    store.toast("Copy failed", "clipboard unavailable", true);
  }
}

export function download(filename: string, text: string, mime = "text/plain") {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: mime }));
  a.download = filename;
  a.click();
  // revoking in the same tick can cancel the download in some browsers
  setTimeout(() => URL.revokeObjectURL(a.href), 30_000);
}

/** rows → CSV with proper quoting.
 *
 *  Every value here was chosen by whoever sent the query — a name, a client id,
 *  a rule — so a cell starting with = + - @ is neutralised with a leading quote
 *  mark. Otherwise opening the export in a spreadsheet would run it as a
 *  formula (CSV injection). Numbers are left alone, so -1 stays a number. */
export function toCsv(rows: Record<string, unknown>[]): string {
  if (!rows.length) return "";
  const cols = Object.keys(rows[0]);
  const esc = (v: unknown) => {
    let s = v == null ? "" : String(v);
    if (typeof v !== "number" && /^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  return [cols.join(","), ...rows.map((r) => cols.map((c) => esc(r[c])).join(","))].join("\n");
}
