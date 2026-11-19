import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

export type Theme = "dark" | "light";
export type RefreshSetting = 5 | 15 | 30 | 0;

const KEYS = { theme: "sentinel.theme", refresh: "sentinel.refresh", lastRead: "sentinel.alerts.lastRead" } as const;

export function readStorage(key: string): string | null {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

export function writeStorage(key: string, value: string) {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    // Storage can be unavailable (private mode, blocked cookies); settings then last for this visit only.
  }
}

export function parseRefresh(value: string | null): RefreshSetting {
  const n = Number(value);
  return n === 5 || n === 15 || n === 30 || n === 0 ? n : 5;
}

type Preferences = {
  theme: Theme;
  setTheme: (theme: Theme) => void;
  refreshSeconds: RefreshSetting;
  setRefreshSeconds: (value: RefreshSetting) => void;
  /** Milliseconds for TanStack Query's refetchInterval, or false when auto-refresh is off. */
  refetchInterval: number | false;
  lastReadAlerts: string | null;
  markAlertsRead: () => void;
  settingsOpen: boolean;
  setSettingsOpen: (open: boolean) => void;
  helpOpen: boolean;
  setHelpOpen: (open: boolean) => void;
};

const PreferencesContext = createContext<Preferences | null>(null);

export function PreferencesProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>("dark");
  const [refreshSeconds, setRefreshState] = useState<RefreshSetting>(5);
  const [lastReadAlerts, setLastRead] = useState<string | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);

  // Browser storage is read after hydration so server and client render the same first frame.
  useEffect(() => {
    setThemeState(readStorage(KEYS.theme) === "light" ? "light" : "dark");
    setRefreshState(parseRefresh(readStorage(KEYS.refresh)));
    setLastRead(readStorage(KEYS.lastRead));
  }, []);

  useEffect(() => {
    document.documentElement.dataset["theme"] = theme;
    document.documentElement.classList.toggle("dark", theme === "dark");
  }, [theme]);

  const setTheme = useCallback((next: Theme) => {
    setThemeState(next);
    writeStorage(KEYS.theme, next);
  }, []);
  const setRefreshSeconds = useCallback((next: RefreshSetting) => {
    setRefreshState(next);
    writeStorage(KEYS.refresh, String(next));
  }, []);
  const markAlertsRead = useCallback(() => {
    const now = new Date().toISOString();
    setLastRead(now);
    writeStorage(KEYS.lastRead, now);
  }, []);

  const value = useMemo<Preferences>(
    () => ({
      theme,
      setTheme,
      refreshSeconds,
      setRefreshSeconds,
      refetchInterval: refreshSeconds === 0 ? false : refreshSeconds * 1000,
      lastReadAlerts,
      markAlertsRead,
      settingsOpen,
      setSettingsOpen,
      helpOpen,
      setHelpOpen,
    }),
    [theme, setTheme, refreshSeconds, setRefreshSeconds, lastReadAlerts, markAlertsRead, settingsOpen, helpOpen],
  );
  return <PreferencesContext.Provider value={value}>{children}</PreferencesContext.Provider>;
}

export function usePreferences() {
  const value = useContext(PreferencesContext);
  if (!value) throw new Error("usePreferences must be used inside PreferencesProvider");
  return value;
}
