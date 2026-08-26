import { useSyncExternalStore } from "react";

const DESKTOP_MQ = "(min-width: 1024px)"; // Tailwind `lg`

/**
 * `true` at the `lg` breakpoint and up. SSR-safe (the server snapshot is always
 * desktop, matching the rendered HTML) and updates on viewport change. Used to
 * gate desktop-only affordances (the icon-only sidebar collapse and the Guide
 * resizable split) so they never apply to the stacked mobile layout.
 */
export function useIsDesktop() {
  return useSyncExternalStore(
    (onChange) => {
      const mq = window.matchMedia(DESKTOP_MQ);
      mq.addEventListener("change", onChange);
      return () => mq.removeEventListener("change", onChange);
    },
    () => window.matchMedia(DESKTOP_MQ).matches,
    () => true,
  );
}
