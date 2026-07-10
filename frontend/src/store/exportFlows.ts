// Flow export (GROWTH G4.1) — turn the live world into a file a security person
// can take somewhere else: JSON for tooling, CSV for a spreadsheet. Pure
// functions over the mirrored store (tested); the download trigger lives in the
// HUD. This is the client-side half of the pro layer — it exports what you can
// already see, nothing the agent didn't stream.

import type { Flow } from "../protocol";

export function flowsToJson(flows: Flow[]): string {
  return JSON.stringify(flows, null, 2);
}

export const CSV_COLUMNS = [
  "name",
  "ip",
  "port",
  "protocol",
  "category",
  "encrypted",
  "process",
  "pid",
  "org",
  "asn",
  "city",
  "country",
  "activity",
  "alive",
  "flags",
] as const;

/** RFC-4180-style quoting: only when the value needs it, quotes doubled. */
function csvField(value: string): string {
  if (/[",\n\r]/.test(value)) return `"${value.replaceAll('"', '""')}"`;
  return value;
}

export function flowsToCsv(flows: Flow[]): string {
  const rows = flows.map((f) =>
    [
      f.name,
      f.ip,
      String(f.port),
      f.protocol,
      f.category,
      String(f.encrypted),
      f.process?.name ?? "",
      f.process ? String(f.process.pid) : "",
      f.asn?.org ?? "",
      f.asn ? String(f.asn.number) : "",
      f.location?.city ?? "",
      f.location?.country ?? "",
      f.activity.toFixed(2),
      String(f.alive),
      f.flags.join("|"),
    ]
      .map(csvField)
      .join(","),
  );
  return [CSV_COLUMNS.join(","), ...rows].join("\n") + "\n";
}

/** Timestamped filename so repeated exports never collide. */
export function exportFilename(ext: "json" | "csv", now = new Date()): string {
  const stamp = now.toISOString().replace(/[:T]/g, "-").slice(0, 19);
  return `netscope-flows-${stamp}.${ext}`;
}
