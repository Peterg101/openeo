import { describe, it, expect, vi, beforeEach } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { stubLocation, jsonResponse } from "./setup";

// The login page is server-rendered (lib/webapp/loginpage.py) so it needs no public assets.
// Load the REAL page template and run its inline script against a mocked fetch.
const src = readFileSync(resolve(process.cwd(), "../lib/webapp/loginpage.py"), "utf8");
const template = src.split('_PAGE = """')[1].split('"""')[0];

function mount(hasPassword = true) {
  const html = template
    .replace("@@BANNER@@", hasPassword ? "" : '<div class="warn">No admin password set - edit openeo-setup.txt on the SD card, then reboot.</div>')
    .replace(/@@DISABLED@@/g, hasPassword ? "" : "disabled");
  const body = html.split("<body>")[1].split("</body>")[0];
  const script = body.match(/<script>([\s\S]*)<\/script>/)[1];
  document.body.innerHTML = body.replace(/<script>[\s\S]*<\/script>/, "");
  // eslint-disable-next-line no-new-func
  new Function(script)();
}

const submit = () => document.getElementById("f").dispatchEvent(new Event("submit", { cancelable: true }));
const flush = () => new Promise((r) => setTimeout(r, 0));

describe("login page", () => {
  let assign;
  beforeEach(() => {
    assign = stubLocation();
  });

  it("posts the password as JSON and goes to the dashboard on success", async () => {
    const f = vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse({ status: "ok" }));
    mount();
    document.getElementById("p").value = "correct horse";
    submit();
    await flush();
    const [url, opts] = f.mock.calls[0];
    expect(url).toBe("/login");
    expect(opts.method).toBe("POST");
    expect(opts.headers["Content-Type"]).toBe("application/json");
    expect(JSON.parse(opts.body)).toEqual({ username: "admin", password: "correct horse" });
    expect(assign).toHaveBeenCalledWith("/");
  });

  it("shows the server's message and re-enables the button on failure", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse({ detail: "Incorrect password" }, 401));
    mount();
    submit();
    await flush();
    expect(document.getElementById("msg").textContent).toBe("Incorrect password");
    expect(document.getElementById("b").disabled).toBe(false);
    expect(assign).not.toHaveBeenCalled();
  });

  it("explains rate limiting and network errors", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(jsonResponse({ detail: "Too many attempts, retry later" }, 429));
    mount();
    submit();
    await flush();
    expect(document.getElementById("msg").textContent).toContain("Too many attempts");
    vi.spyOn(globalThis, "fetch").mockRejectedValueOnce(new Error("down"));
    submit();
    await flush();
    expect(document.getElementById("msg").textContent).toBe("Could not reach the charger");
  });

  it("tells the owner what to do when no admin password exists, and cannot be submitted", () => {
    mount(false);
    expect(document.body.textContent).toContain("edit openeo-setup.txt on the SD card");
    expect(document.getElementById("b").disabled).toBe(true);
    expect(document.getElementById("p").disabled).toBe(true);
  });
});
