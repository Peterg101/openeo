import { afterEach, vi } from "vitest";
import { cleanup } from "@testing-library/react";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

/** Replace window.location with a spy-able stub (jsdom cannot navigate). */
export function stubLocation() {
  const assign = vi.fn();
  Object.defineProperty(window, "location", {
    configurable: true,
    value: { assign, href: "http://localhost/", pathname: "/" },
  });
  return assign;
}

export function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}
