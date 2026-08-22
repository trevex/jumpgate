import { useEffect, useState } from "react";
import { Moon, Sun } from "lucide-react";
import { useTheme } from "next-themes";
import { Button } from "./ui/button";

/**
 * Given the currently-resolved theme, returns the theme to switch to.
 * Two-state UX: the toggle always flips to the opposite of what's on screen,
 * starting from the system-resolved default. Pure + exported for testing.
 */
export function nextTheme(resolved: string | undefined): "light" | "dark" {
  return resolved === "dark" ? "light" : "dark";
}

/**
 * Ghost icon button that toggles light/dark. System is the default (via the
 * provider) until the user picks; from then on it flips based on the resolved
 * theme. Token-styled to match the sign-out ghost button in the shell.
 */
export function ThemeToggle() {
  const { resolvedTheme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);

  // Avoid a hydration/first-paint icon flip: the resolved theme isn't known
  // until after mount, so render a stable placeholder until then.
  useEffect(() => setMounted(true), []);

  const isDark = resolvedTheme === "dark";
  const label = mounted
    ? `Switch to ${isDark ? "light" : "dark"} theme`
    : "Toggle theme";

  return (
    <Button
      variant="ghost"
      size="icon"
      className="h-8 w-8 shrink-0 text-muted-foreground hover:text-foreground"
      onClick={() => setTheme(nextTheme(resolvedTheme))}
      aria-label={label}
    >
      {mounted && isDark ? (
        <Sun className="h-4 w-4" aria-hidden="true" />
      ) : (
        <Moon className="h-4 w-4" aria-hidden="true" />
      )}
    </Button>
  );
}
