import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Bell, CheckCheck, Search, ShieldAlert, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { usePreferences } from "@/hooks/use-preferences";
import { alertsQuery, cleanSearch, DEFAULT_FILTERS, incidentsQuery } from "@/lib/api";
import { filterIncidents, incidentData as demoIncidents } from "./demo-data";
import type { IncidentRow } from "./incident-rows";
import { relativeTime, toIncidentRow } from "./incident-rows";

type TopBarWidgetsProps = {
  offline: boolean;
  onSelectIncident: (incident: IncidentRow) => void;
};

export function TopBarWidgets({ offline, onSelectIncident }: TopBarWidgetsProps) {
  const { refetchInterval, lastReadAlerts, markAlertsRead } = usePreferences();
  const [queryText, setQueryText] = useState("");
  const [debouncedQuery, setDebouncedQuery] = useState("");
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [alertsOpen, setAlertsOpen] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const id = setTimeout(() => setDebouncedQuery(cleanSearch(queryText)), 180);
    return () => clearTimeout(id);
  }, [queryText]);

  // Ctrl/Cmd+K focuses the global incident search input.
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        searchRef.current?.focus();
        searchRef.current?.select();
        setDropdownOpen(true);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  // Close search dropdown on outside click.
  useEffect(() => {
    const onPointerDown = (event: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setDropdownOpen(false);
      }
    };
    document.addEventListener("mousedown", onPointerDown);
    return () => document.removeEventListener("mousedown", onPointerDown);
  }, []);

  const searchQuery = useQuery({
    ...incidentsQuery(
      { ...DEFAULT_FILTERS, search: debouncedQuery, page: 1, pageSize: 6 },
      false,
    ),
    enabled: !offline && debouncedQuery.length > 0,
  });

  const searchResults: IncidentRow[] = useMemo(() => {
    if (!queryText.trim()) return [];
    if (offline) return filterIncidents(demoIncidents, queryText, "All").slice(0, 6);
    return (searchQuery.data?.items ?? []).map(toIncidentRow);
  }, [offline, queryText, searchQuery.data]);

  const alerts = useQuery({
    ...alertsQuery(lastReadAlerts, refetchInterval),
    enabled: !offline,
  });

  const alertItems: IncidentRow[] = useMemo(() => {
    if (offline) {
      if (lastReadAlerts) return [];
      return demoIncidents.filter((i) => i.severity === "Critical" || i.severity === "High").slice(0, 6);
    }
    return (alerts.data?.items ?? []).map(toIncidentRow);
  }, [offline, alerts.data, lastReadAlerts]);

  const unreadCount = offline ? alertItems.length : (alerts.data?.unread ?? 0);

  return (
    <div className="topbar-widgets">
      <div className="global-search-wrap" ref={containerRef}>
        <label className="search-box">
          <Search size={15} aria-hidden="true" />
          <span className="sr-only">Search incidents by ID, source, or category</span>
          <Input
            ref={searchRef}
            type="search"
            role="combobox"
            aria-expanded={dropdownOpen && queryText.trim().length > 0}
            aria-controls="global-search-results"
            aria-autocomplete="list"
            aria-keyshortcuts="Control+K Meta+K"
            value={queryText}
            onFocus={() => setDropdownOpen(true)}
            onChange={(event) => {
              setQueryText(event.target.value);
              setDropdownOpen(true);
            }}
            onKeyDown={(event) => {
              if (event.key === "Escape") {
                setDropdownOpen(false);
                searchRef.current?.blur();
              } else if (event.key === "Enter" && searchResults[0]) {
                event.preventDefault();
                onSelectIncident(searchResults[0]);
                setDropdownOpen(false);
              }
            }}
            placeholder="Search ID, source, category…"
          />
          {queryText ? (
            <button
              type="button"
              className="search-clear-btn"
              onClick={() => {
                setQueryText("");
                setDebouncedQuery("");
                searchRef.current?.focus();
              }}
              aria-label="Clear search"
            >
              <X size={13} aria-hidden="true" />
            </button>
          ) : (
            <kbd aria-hidden="true">⌘K</kbd>
          )}
        </label>

        {dropdownOpen && queryText.trim().length > 0 ? (
          <div
            id="global-search-results"
            className="search-dropdown"
            role="listbox"
            aria-label="Matching incidents"
          >
            {!offline && searchQuery.isFetching ? (
              <div className="search-dropdown-state">Searching incidents…</div>
            ) : searchResults.length === 0 ? (
              <div className="search-dropdown-state">
                No incidents matching &ldquo;{queryText.trim()}&rdquo;.
              </div>
            ) : (
              searchResults.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  role="option"
                  aria-selected={false}
                  className="search-result-item"
                  onClick={() => {
                    onSelectIncident(item);
                    setDropdownOpen(false);
                  }}
                >
                  <div className="search-result-top">
                    <span className="font-mono tabular-nums font-medium">{item.id}</span>
                    <span className={`severity-text severity-text-${item.severity.toLowerCase()}`}>
                      {item.severity}
                    </span>
                  </div>
                  <div className="search-result-meta">
                    <span>{item.category}</span>
                    <span aria-hidden="true">·</span>
                    <span className="font-mono tabular-nums">{item.source}</span>
                    <span aria-hidden="true">·</span>
                    <span>{item.status}</span>
                  </div>
                </button>
              ))
            )}
          </div>
        ) : null}
      </div>

      <Popover open={alertsOpen} onOpenChange={setAlertsOpen}>
        <PopoverTrigger asChild>
          <button
            type="button"
            className="icon-button notification-button"
            aria-label={
              unreadCount > 0
                ? `Alerts: ${unreadCount} unread critical or high incidents`
                : "Alerts: no unread critical or high incidents"
            }
          >
            <Bell size={16} aria-hidden="true" />
            {unreadCount > 0 ? (
              <span className="unread-count-badge tabular-nums" aria-hidden="true">
                {unreadCount > 99 ? "99+" : unreadCount}
              </span>
            ) : null}
          </button>
        </PopoverTrigger>
        <PopoverContent align="end" className="alerts-popover w-80 p-0">
          <div className="alerts-popover-header">
            <div>
              <strong>Critical &amp; High alerts</strong>
              <small>
                {unreadCount > 0
                  ? `${unreadCount} unread since ${lastReadAlerts ? relativeTime(lastReadAlerts) : "session start"}`
                  : "All caught up"}
              </small>
            </div>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="mark-read-btn"
              disabled={unreadCount === 0}
              onClick={() => markAlertsRead()}
            >
              <CheckCheck size={14} aria-hidden="true" />
              <span>Mark all read</span>
            </Button>
          </div>
          <div className="alerts-popover-list">
            {alertItems.length === 0 ? (
              <div className="alerts-empty">
                <ShieldAlert size={18} aria-hidden="true" />
                <p>No unread Critical or High incidents.</p>
              </div>
            ) : (
              alertItems.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  className="alert-item-btn"
                  onClick={() => {
                    setAlertsOpen(false);
                    onSelectIncident(item);
                  }}
                >
                  <div className="alert-item-top">
                    <span className={`severity-text severity-text-${item.severity.toLowerCase()}`}>
                      {item.severity}
                    </span>
                    <span className="font-mono tabular-nums">{item.id}</span>
                    <span className="alert-item-time tabular-nums">{item.firstSeen}</span>
                  </div>
                  <div className="alert-item-sub">
                    <span>{item.category}</span>
                    <span aria-hidden="true">·</span>
                    <span className="font-mono tabular-nums">{item.source}</span>
                  </div>
                </button>
              ))
            )}
          </div>
        </PopoverContent>
      </Popover>
    </div>
  );
}
