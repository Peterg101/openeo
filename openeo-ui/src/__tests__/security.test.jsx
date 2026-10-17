import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import Security from "../openeo-Security";
import { _resetRedirectGuard, logout } from "../utils/funcs";
import { stubLocation, jsonResponse } from "./setup";

function route(handlers) {
  return vi.spyOn(globalThis, "fetch").mockImplementation((url, opts = {}) => {
    const key = (opts.method || "GET") + " " + url;
    if (!(key in handlers)) throw new Error("unexpected request " + key);
    return Promise.resolve(handlers[key](opts));
  });
}

describe("Security settings", () => {
  let assign;
  beforeEach(() => {
    assign = stubLocation();
    _resetRedirectGuard();
  });

  it("change-password form posts JSON and sends you back to log in", async () => {
    const f = route({
      "GET auth/status": () => jsonResponse({ authenticated: true, api_token_enabled: false }),
      "POST change_password": () => jsonResponse({ status: "ok", relogin: true }),
    });
    render(<Security />);
    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Current password"), "old password");
    await user.type(screen.getByLabelText(/^New password/), "brand new pass");
    await user.type(screen.getByLabelText("Confirm new password"), "brand new pass");
    await user.click(screen.getByRole("button", { name: "Change password" }));
    await waitFor(() => expect(assign).toHaveBeenCalledWith("/login"));
    const call = f.mock.calls.find(([u]) => u === "change_password");
    expect(call[1].headers["Content-Type"]).toBe("application/json");
    expect(JSON.parse(call[1].body)).toEqual({ current_password: "old password", new_password: "brand new pass" });
  });

  it("refuses mismatched confirmation without calling the server", async () => {
    const f = route({ "GET auth/status": () => jsonResponse({ api_token_enabled: false }) });
    render(<Security />);
    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Current password"), "old password");
    await user.type(screen.getByLabelText(/^New password/), "brand new pass");
    await user.type(screen.getByLabelText("Confirm new password"), "different pass");
    await user.click(screen.getByRole("button", { name: "Change password" }));
    expect(await screen.findByText("The new passwords do not match")).toBeTruthy();
    expect(f.mock.calls.some(([u]) => u === "change_password")).toBe(false);
    expect(assign).not.toHaveBeenCalled();
  });

  it("shows the server's reason when the change is rejected", async () => {
    route({
      "GET auth/status": () => jsonResponse({ api_token_enabled: false }),
      "POST change_password": () => jsonResponse({ detail: "Current password is incorrect" }, 403),
    });
    render(<Security />);
    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Current password"), "nope nope");
    await user.type(screen.getByLabelText(/^New password/), "brand new pass");
    await user.type(screen.getByLabelText("Confirm new password"), "brand new pass");
    await user.click(screen.getByRole("button", { name: "Change password" }));
    expect(await screen.findByText("Current password is incorrect")).toBeTruthy();
    expect(assign).not.toHaveBeenCalled();
  });

  it("an expired session during the change redirects to login (401)", async () => {
    route({
      "GET auth/status": () => jsonResponse({}, 401),
      "POST change_password": () => jsonResponse({ detail: "Not authenticated" }, 401),
    });
    render(<Security />);
    await waitFor(() => expect(assign).toHaveBeenCalledWith("/login"));
  });

  it("log out button posts /logout then goes to the login page", async () => {
    const f = route({
      "GET auth/status": () => jsonResponse({ api_token_enabled: false }),
      "POST logout": () => jsonResponse({ status: "ok" }),
    });
    render(<Security />);
    await userEvent.setup().click(screen.getByRole("button", { name: "Log out" }));
    await waitFor(() => expect(assign).toHaveBeenCalledWith("/login"));
    expect(f.mock.calls.some(([u, o]) => u === "logout" && o.method === "POST")).toBe(true);
  });

  it("logout() still leaves the page when the request fails", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("offline"));
    await logout().catch(() => {});
    expect(assign).toHaveBeenCalledWith("/login");
  });

  it("API token is shown once after the password is confirmed", async () => {
    route({
      "GET auth/status": () => jsonResponse({ api_token_enabled: false }),
      "POST api_token": (o) => {
        expect(JSON.parse(o.body)).toEqual({ password: "my password" });
        return jsonResponse({ token: "oeo_abc123" });
      },
    });
    render(<Security />);
    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Your password"), "my password");
    await user.click(screen.getByRole("button", { name: "Generate token" }));
    expect((await screen.findByTestId("new-token")).textContent).toBe("oeo_abc123");
    expect(screen.getByRole("button", { name: "Revoke token" })).toBeTruthy();
  });
});
