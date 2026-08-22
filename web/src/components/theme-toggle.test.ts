import { describe, expect, it } from "vitest";
import { nextTheme } from "./theme-toggle";

// The toggle's click handler calls setTheme(nextTheme(resolvedTheme)); this
// locks its two-state behavior: a click always flips to the opposite of the
// currently-resolved theme (so from the system default it lands on light/dark).
describe("nextTheme", () => {
  it("flips dark -> light", () => {
    expect(nextTheme("dark")).toBe("light");
  });

  it("flips light -> dark", () => {
    expect(nextTheme("light")).toBe("dark");
  });

  it("defaults to dark when the resolved theme is unknown", () => {
    expect(nextTheme(undefined)).toBe("dark");
  });

  it("clicking twice returns to the starting theme", () => {
    const start = "light";
    expect(nextTheme(nextTheme(start))).toBe(start);
  });
});
