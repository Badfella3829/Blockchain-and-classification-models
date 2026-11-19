import { createFileRoute } from "@tanstack/react-router";
import { DashboardShell } from "@/components/threat-dashboard/dashboard-shell";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Sentinel | Threat Intelligence Dashboard" },
      {
        name: "description",
        content: "Review sample security detections, traffic signals, and audit activity in the Sentinel dashboard.",
      },
      { property: "og:title", content: "Sentinel | Threat Intelligence Dashboard" },
      {
        property: "og:description",
        content: "Review sample security detections, traffic signals, and audit activity in the Sentinel dashboard.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: DashboardShell,
});
