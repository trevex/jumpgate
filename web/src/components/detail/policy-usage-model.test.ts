import { describe, it, expect } from "vitest";
import { formatDuration, usageLabel } from "./policy-usage-model";

describe("formatDuration", () => {
  it("renders whole hours", () => expect(formatDuration(28800)).toBe("8h"));
  it("renders minutes", () => expect(formatDuration(900)).toBe("15m"));
  it("renders seconds", () => expect(formatDuration(45)).toBe("45s"));
});

describe("usageLabel", () => {
  it("maps known usages", () => {
    expect(usageLabel("requester_source")).toBe("Requester source");
    expect(usageLabel("requestable")).toBe("Requestable");
  });
});
