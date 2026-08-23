import { describe, expect, it } from "vitest";

import {
  criticalityRank,
  formatConfidence,
  formatRelative,
  formatTime,
  formatTimestamp,
  humanize,
  severityRank,
  shortId,
} from "@/lib/format";

describe("formatTimestamp", () => {
  it("always renders UTC", () => {
    // GRIEFER stores UTC. A console that silently converts to the viewer's zone
    // makes two analysts describing one incident disagree about when it happened.
    expect(formatTimestamp("2026-08-23T09:14:22Z")).toBe("2026-08-23 09:14:22 UTC");
    expect(formatTimestamp("2026-08-23T11:14:22+02:00")).toBe("2026-08-23 09:14:22 UTC");
  });

  it("does not crash on a malformed value", () => {
    expect(formatTimestamp("not a date")).toBe("unknown");
    expect(formatTime("not a date")).toBe("--:--:--");
  });
});

describe("formatRelative", () => {
  const now = new Date("2026-08-23T12:00:00Z");

  it("scales the unit to the age", () => {
    expect(formatRelative("2026-08-23T11:59:30Z", now)).toBe("30s ago");
    expect(formatRelative("2026-08-23T11:45:00Z", now)).toBe("15m ago");
    expect(formatRelative("2026-08-23T09:00:00Z", now)).toBe("3h ago");
    expect(formatRelative("2026-08-20T12:00:00Z", now)).toBe("3d ago");
  });

  it("names a future timestamp rather than rendering a negative age", () => {
    expect(formatRelative("2026-08-23T13:00:00Z", now)).toBe("in the future");
  });
});

describe("ranking", () => {
  it("orders severity and criticality", () => {
    expect(severityRank("critical")).toBeGreaterThan(severityRank("high"));
    expect(severityRank("informational")).toBe(0);
    expect(criticalityRank("critical")).toBeGreaterThan(criticalityRank("low"));
  });
});

describe("humanize", () => {
  it("turns identifiers into readable text", () => {
    expect(humanize("privilege_escalation")).toBe("Privilege escalation");
    expect(humanize("policy.evaluated")).toBe("Policy evaluated");
    expect(humanize("")).toBe("");
  });
});

describe("formatConfidence", () => {
  it("renders a percentage", () => {
    expect(formatConfidence(0.95)).toBe("95%");
    expect(formatConfidence(0)).toBe("0%");
  });
});

describe("shortId", () => {
  it("keeps the type prefix, which is the part an analyst reads", () => {
    expect(shortId("inc-01a02e7e-a36d-7ce4-bd04-368597500ebe")).toBe("inc-01a02e7e");
  });

  it("leaves a short identifier alone", () => {
    expect(shortId("evt-1")).toBe("evt-1");
    expect(shortId("nodashes")).toBe("nodashes");
  });
});
