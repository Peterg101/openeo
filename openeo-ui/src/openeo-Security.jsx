import { useState, useEffect } from "react";
import { buildUrl, apiFetch, postJson, logout, LOGIN_URL } from "./utils/funcs";
import { styles } from "./utils/styles";

async function detail(res, fallback) {
  try {
    const body = await res.json();
    return body.detail || fallback;
  } catch {
    return fallback;
  }
}

/** Settings -> Security: change password, API token, log out. */
export default function Security() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [message, setMessage] = useState(null); // {ok, text}
  const [tokenEnabled, setTokenEnabled] = useState(false);
  const [tokenPassword, setTokenPassword] = useState("");
  const [newToken, setNewToken] = useState("");

  useEffect(() => {
    apiFetch(buildUrl("auth/status"))
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => d && setTokenEnabled(!!d.api_token_enabled))
      .catch(() => {});
  }, []);

  async function changePassword(e) {
    e.preventDefault();
    setMessage(null);
    if (next !== confirm) {
      setMessage({ ok: false, text: "The new passwords do not match" });
      return;
    }
    const res = await postJson(buildUrl("change_password"), {
      current_password: current,
      new_password: next,
    });
    if (res.ok) {
      setMessage({ ok: true, text: "Password changed. Please log in again." });
      window.location.assign(LOGIN_URL); // every session was invalidated
    } else if (res.status !== 401) {
      setMessage({ ok: false, text: await detail(res, "Could not change the password") });
    }
  }

  async function generateToken(e) {
    e.preventDefault();
    setMessage(null);
    const res = await postJson(buildUrl("api_token"), { password: tokenPassword });
    if (res.ok) {
      const body = await res.json();
      setNewToken(body.token);
      setTokenEnabled(true);
      setTokenPassword("");
    } else if (res.status !== 401) {
      setMessage({ ok: false, text: await detail(res, "Could not create a token") });
    }
  }

  async function revokeToken() {
    const res = await postJson(buildUrl("api_token/revoke"));
    if (res.ok) {
      setTokenEnabled(false);
      setNewToken("");
    }
  }

  const field = (label, value, setter, name, autoComplete) => (
    <div style={styles.fieldRow}>
      <label style={styles.fieldLabel} htmlFor={name}>{label}</label>
      <div style={styles.fieldControl}>
        <input id={name} name={name} type="password" value={value} autoComplete={autoComplete}
          onChange={(e) => setter(e.target.value)} style={styles.textInput} />
      </div>
    </div>
  );

  return (
    <div style={styles.section}>
      <div style={styles.sectionHeader}>Security</div>

      <form onSubmit={changePassword} aria-label="Change password">
        {field("Current password", current, setCurrent, "current_password", "current-password")}
        {field("New password (8+ characters)", next, setNext, "new_password", "new-password")}
        {field("Confirm new password", confirm, setConfirm, "confirm_password", "new-password")}
        <div style={styles.buttonRow}>
          <button type="submit" style={styles.Btn}>Change password</button>
        </div>
      </form>
      {message && (
        <div role="status" style={{ padding: "8px 16px", color: message.ok ? "#a8e6a3" : "#f4a9a8" }}>
          {message.text}
        </div>
      )}

      <div style={styles.sectionHeader}>API token (/metrics and /api only)</div>
      <form onSubmit={generateToken} aria-label="API token">
        <div style={styles.fieldNote}>
          {tokenEnabled ? "A token is active." : "No token: bearer access is off."} A new token replaces any
          previous one and is shown only once.
        </div>
        {field("Your password", tokenPassword, setTokenPassword, "token_password", "current-password")}
        <div style={styles.buttonRow}>
          <button type="submit" style={styles.Btn}>Generate token</button>
          {tokenEnabled && (
            <button type="button" style={styles.Btn} onClick={revokeToken}>Revoke token</button>
          )}
        </div>
      </form>
      {newToken && (
        <div style={{ padding: "8px 16px", wordBreak: "break-all" }}>
          Copy it now: <code data-testid="new-token">{newToken}</code>
        </div>
      )}

      <div style={styles.buttonRow}>
        <button type="button" style={styles.Btn} onClick={logout}>Log out</button>
      </div>
    </div>
  );
}
