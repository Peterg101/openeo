import { describe, it, expect, vi, beforeEach } from "vitest";
import { apiFetch, postJson, _resetRedirectGuard, LOGIN_URL } from "../utils/funcs";
import { stubLocation, jsonResponse } from "./setup";

describe("apiFetch", () => {
  let assign;
  beforeEach(() => {
    assign = stubLocation();
    _resetRedirectGuard();
  });

  it("sends the session cookie and passes good responses through", async () => {
    const f = vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse({ a: 1 }));
    const res = await apiFetch("getstatus");
    expect(await res.json()).toEqual({ a: 1 });
    expect(f).toHaveBeenCalledWith("getstatus", { credentials: "same-origin" });
    expect(assign).not.toHaveBeenCalled();
  });

  it("redirects to the login page on 401 (once, even for parallel polls)", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(() => Promise.resolve(jsonResponse({ detail: "no" }, 401)));
    await Promise.all([apiFetch("getstatus"), apiFetch("getconfig"), apiFetch("getsessiondata")]);
    expect(assign).toHaveBeenCalledTimes(1);
    expect(assign).toHaveBeenCalledWith(LOGIN_URL);
  });

  it("does not redirect on other errors", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse({}, 500));
    const res = await apiFetch("getstatus");
    expect(res.status).toBe(500);
    expect(assign).not.toHaveBeenCalled();
  });
});

describe("postJson", () => {
  beforeEach(() => {
    stubLocation();
    _resetRedirectGuard();
  });

  it("always sends application/json with a JSON body", async () => {
    const f = vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse({}));
    await postJson("setsettings", { "switch:on": true });
    const [url, opts] = f.mock.calls[0];
    expect(url).toBe("setsettings");
    expect(opts.method).toBe("POST");
    expect(opts.headers["Content-Type"]).toBe("application/json");
    expect(JSON.parse(opts.body)).toEqual({ "switch:on": true });
    expect(opts.credentials).toBe("same-origin");
  });

  it("defaults to an empty JSON object (restart has no payload)", async () => {
    const f = vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse({}));
    await postJson("restart");
    expect(f.mock.calls[0][1].body).toBe("{}");
  });
});
