import { describe, expect, it } from "vitest";

import { filterIncidents, incidentData } from "@/components/threat-dashboard/demo-data";

describe("threat dashboard incident filtering", () => {
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
});