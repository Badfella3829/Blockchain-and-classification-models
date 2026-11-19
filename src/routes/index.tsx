import { createFileRoute } from "@tanstack/react-router";
import { DashboardShell } from "@/components/threat-dashboard/dashboard-shell";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Overview · Sentinel Threat Intelligence" },
      {
        name: "description",
        content:
          "Monitor live network threat detections, tamper-evident audit blocks, and model health in Sentinel.",
      },
      { property: "og:title", content: "Sentinel Threat Intelligence" },
      {
        property: "og:description",
        content:
          "Monitor live network threat detections, tamper-evident audit blocks, and model health in Sentinel.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: DashboardShell,
});
