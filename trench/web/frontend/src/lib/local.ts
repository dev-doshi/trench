// localStorage that cannot take the app down. Storage throws outright when site
// data is blocked (and in some private windows), and a preference is never worth
// a blank screen — so a failed read is "not set" and a failed write is dropped.
export const local = {
  get(k: string): string | null {
    try { return localStorage.getItem(k); } catch { return null; }
  },
  set(k: string, v: string) {
    try { localStorage.setItem(k, v); } catch { /* not persisted; still applied */ }
  },
  del(k: string) {
    try { localStorage.removeItem(k); } catch { /* nothing to remove */ }
  },
};
