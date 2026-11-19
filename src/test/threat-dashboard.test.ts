import { describe, expect, it } from "vitest";

import {
  filterIncidents,
  incidentData,
  sortIncidentRows,
} from "@/components/threat-dashboard/demo-data";
import { viewFromHash } from "@/hooks/use-hash-view";
import { parseRefresh } from "@/hooks/use-preferences";

describe("threat dashboard incident filtering & sorting", () => {
  it("shows only high-severity incidents when that severity is selected", () => {
    expect(filterIncidents(incidentData, "", "High").map((incident) => incident.id)).toEqual([
      "SIG-1039",
      "SIG-1035",
    ]);
  });

  it("finds incidents by matching detection text without case sensitivity", () => {
    expect(filterIncidents(incidentData, "dns", "All").map((incident) => incident.id)).toEqual([
      "SIG-1039",
    ]);
  });

  it("filters incidents by status", () => {
    const contained = filterIncidents(incidentData, "", "All", "Contained");
    expect(contained.length).toBeGreaterThan(0);
    expect(contained.every((item) => item.status === "Contained")).toBe(true);
  });

  it("sorts incidents by confidence descending and ascending", () => {
    const desc = sortIncidentRows(incidentData, "confidence", "desc");
    const asc = sortIncidentRows(incidentData, "confidence", "asc");
    expect(desc[0]!.confidence).toBeGreaterThanOrEqual(desc[desc.length - 1]!.confidence);
    expect(asc[0]!.confidence).toBeLessThanOrEqual(asc[asc.length - 1]!.confidence);
  });
});

describe("hash view routing & preferences helpers", () => {
  it("maps valid plain hash names to views and rejects query strings or unknown hashes", () => {
    expect(viewFromHash("#overview")).toBe("overview");
    expect(viewFromHash("#detections")).toBe("detections");
    expect(viewFromHash("#audit")).toBe("audit");
    expect(viewFromHash("#model-health")).toBe("model-health");
    expect(viewFromHash("#detections?foo=1")).toBe("overview");
    expect(viewFromHash("#unknown")).toBe("overview");
    expect(viewFromHash("")).toBe("overview");
  });

  it("parses valid auto-refresh intervals and defaults safely", () => {
    expect(parseRefresh("5")).toBe(5);
    expect(parseRefresh("15")).toBe(15);
    expect(parseRefresh("30")).toBe(30);
    expect(parseRefresh("0")).toBe(0);
    expect(parseRefresh("999")).toBe(5);
    expect(parseRefresh(null)).toBe(5);
  });
});
