"""The login page: self-contained HTML (inline CSS/JS, no external assets)."""

from __future__ import annotations

NO_PASSWORD_MESSAGE: str = "No admin password set - edit openeo-setup.txt on the SD card, then reboot."

_PAGE: str = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpenEO - Log in</title>
<style>
body{font-family:system-ui,sans-serif;background:#1b1f27;color:#e6e6e6;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
form{background:#262b36;padding:2rem;border-radius:8px;width:min(92vw,22rem)}
h1{margin:0 0 1rem;font-size:1.3rem}
label{display:block;margin:.8rem 0 .2rem;font-size:.9rem}
input{width:100%;box-sizing:border-box;padding:.6rem;border-radius:4px;border:1px solid #4a5160;background:#1b1f27;color:inherit}
button{margin-top:1.2rem;width:100%;padding:.7rem;border:0;border-radius:4px;background:#2f6fbd;color:#fff;font-size:1rem;cursor:pointer}
button:disabled{opacity:.5;cursor:not-allowed}
#msg{margin-top:1rem;min-height:1.2rem;color:#ff8a80;font-size:.9rem}
.warn{background:#5a3b00;padding:.7rem;border-radius:4px;margin-bottom:1rem;font-size:.9rem}
</style></head><body>
<form id="f" autocomplete="on">
<h1>OpenEO</h1>
@@BANNER@@
<label for="u">User</label>
<input id="u" name="username" value="admin" autocomplete="username" readonly>
<label for="p">Password</label>
<input id="p" name="password" type="password" autocomplete="current-password" required @@DISABLED@@>
<button id="b" type="submit" @@DISABLED@@>Log in</button>
<div id="msg" role="alert"></div>
</form>
<script>
document.getElementById("f").addEventListener("submit", async function (e) {
  e.preventDefault();
  var msg = document.getElementById("msg"), b = document.getElementById("b");
  msg.textContent = ""; b.disabled = true;
  try {
    var r = await fetch("/login", {method: "POST", credentials: "same-origin",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({username: "admin", password: document.getElementById("p").value})});
    if (r.ok) { window.location.assign("/"); return; }
    var d = {}; try { d = await r.json(); } catch (x) {}
    msg.textContent = d.detail || "Login failed";
  } catch (x) { msg.textContent = "Could not reach the charger"; }
  b.disabled = false;
});
</script></body></html>
"""


def render_login_page(has_password: bool) -> str:
    if has_password:
        banner, disabled = "", ""
    else:
        banner, disabled = '<div class="warn">%s</div>' % NO_PASSWORD_MESSAGE, "disabled"
    return _PAGE.replace("@@BANNER@@", banner).replace("@@DISABLED@@", disabled)
