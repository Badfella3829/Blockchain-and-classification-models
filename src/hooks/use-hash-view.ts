import { useEffect, useState } from "react";

export const VIEWS = ["overview", "detections", "audit", "model-health"] as const;
export type View = (typeof VIEWS)[number];

export const VIEW_TITLES: Record<View, string> = {
  overview: "Overview",
  detections: "Detections",
  audit: "Audit ledger",
  "model-health": "Model health",
};

/** Maps a location hash to a view; anything unknown (or with a query) falls back to the overview. */
export function viewFromHash(hash: string): View {
  const name = hash.replace(/^#/, "");
  return (VIEWS as readonly string[]).includes(name) ? (name as View) : "overview";
}

export function useHashView() {
  const [view, setView] = useState<View>("overview");
  useEffect(() => {
    const sync = () => setView(viewFromHash(window.location.hash));
    sync();
    window.addEventListener("hashchange", sync);
    return () => window.removeEventListener("hashchange", sync);
  }, []);
  useEffect(() => {
    document.title = `${VIEW_TITLES[view]} · Sentinel Threat Intelligence`;
  }, [view]);
  const navigate = (next: View) => {
    if (window.location.hash !== `#${next}`) window.location.hash = next;
    else setView(next);
  };
  return { view, navigate };
}
