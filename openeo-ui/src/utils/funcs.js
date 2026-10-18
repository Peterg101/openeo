export function buildUrl(path) {
  // In production the UI and the API share an origin, so paths are used as-is.
  // In `vite dev` the dev server proxies the API paths to the charger (see
  // vite.config.js), so the browser still only ever talks to one origin and the
  // session cookie / same-origin checks behave exactly as on the Pi.
  return path;
}

export const LOGIN_URL = "/login";

let redirecting = false;

/**
 * fetch() wrapper for every call to the charger:
 *  - sends the session cookie (same-origin),
 *  - on HTTP 401 (not logged in / session expired) sends the browser to the login page.
 */
export async function apiFetch(url, options = {}) {
  const response = await fetch(url, { credentials: "same-origin", ...options });
  if (response.status === 401 && !redirecting) {
    redirecting = true;
    window.location.assign(LOGIN_URL);
  }
  return response;
}

/** POST a JSON body (the server rejects every other content type). */
export function postJson(url, body = {}, options = {}) {
  return apiFetch(url, {
    ...options,
    method: "POST",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    body: JSON.stringify(body),
  });
}

/** Log out the current browser session and go to the login page. */
export async function logout() {
  try {
    await postJson(buildUrl("logout"));
  } finally {
    window.location.assign(LOGIN_URL);
  }
}

/** Test hook: allow another redirect after a test has triggered one. */
export function _resetRedirectGuard() {
  redirecting = false;
}

export function getCurrencyConfig() {
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone ?? "";

  if (tz.startsWith("Pacific/Auckland") || tz.startsWith("NZ"))
    return { locale: "en-NZ", currency: "NZD", symbol: "NZ$" };

  if (tz.startsWith("Australia/"))
    return { locale: "en-AU", currency: "AUD", symbol: "A$" };

  const ukZones = [
    "Europe/London", "Europe/Belfast", "Europe/Jersey",
    "Europe/Guernsey", "Europe/Isle_of_Man",
  ];

  if (ukZones.includes(tz))
    return { locale: "en-GB", currency: "GBP", symbol: "£" };

  if (tz.startsWith("Europe/"))
    return { locale: "de-DE", currency: "EUR", symbol: "€" };

  if (
    tz.startsWith("America/") ||
    tz.startsWith("US/") ||
    ["EST", "PST", "CST", "MST"].includes(tz)
  )
    return { locale: "en-US", currency: "USD", symbol: "$" };

  // Fallback → GBP
  return { locale: "en-GB", currency: "GBP", symbol: "£" };
}


export function formatCurrency(amount,CURRENCY = getCurrencyConfig()) {
  return new Intl.NumberFormat(CURRENCY.locale, {
    style: "currency",
    currency: CURRENCY.currency,
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(amount ?? 0);
}
