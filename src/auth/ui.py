"""
Streamlit sign-in flow: password -> MFA code, with first-sign-in password
change and authenticator enrolment, account lockout and idle timeout.

require_login() returns the signed-in user (dict) or stops the page after
showing the sign-in screens.
"""

import io
import json
import time
from pathlib import Path

import qrcode
import streamlit as st

from src.auth import store
from src.auth.rbac import DEVELOPER_ROLE, role_name
from src.auth.security import (
    hash_password, new_totp_secret, password_problems, provisioning_uri, verify_password,
    verify_totp,
)

IDLE_TIMEOUT_SECONDS = 30 * 60
GENERIC_ERROR = "Invalid username or password."
AUTH_CONFIG = Path(__file__).resolve().parents[2] / "config" / "auth.json"
DEV_USER = {"username": "developer", "display_name": "Developer", "email": "",
            "role": DEVELOPER_ROLE, "team": ""}


def auth_enabled():
    """Sign-in is on unless config/auth.json explicitly says "enabled": false (fail-safe)."""
    try:
        return json.loads(AUTH_CONFIG.read_text(encoding="utf-8")).get("enabled", True) is not False
    except (OSError, ValueError, AttributeError):
        return True


AUTH_CSS = """
<style>
.block-container { padding-top: 3.5rem !important; max-width: 1180px; }
.auth-brand {
  position: relative; overflow: hidden; border-radius: 28px; padding: 44px 40px; min-height: 540px;
  color: #ffffff;
  border: 1px solid rgba(56,189,248,0.25);
  background:
    radial-gradient(circle at 110% -10%, rgba(56,189,248,0.35) 0, rgba(56,189,248,0) 42%),
    radial-gradient(circle at -15% 115%, rgba(99,102,241,0.45) 0, rgba(99,102,241,0) 48%),
    linear-gradient(140deg, #1e1b4b 0%, #172554 55%, #0c4a6e 100%);
  box-shadow: 0 30px 60px rgba(0,0,0,0.55);
}
.auth-brand::after {
  content: ''; position: absolute; inset: 0; pointer-events: none; opacity: 0.18;
  background-image: linear-gradient(rgba(255,255,255,0.5) 1px, transparent 1px),
                    linear-gradient(90deg, rgba(255,255,255,0.5) 1px, transparent 1px);
  background-size: 34px 34px;
  mask-image: linear-gradient(160deg, #000 0%, transparent 65%);
  -webkit-mask-image: linear-gradient(160deg, #000 0%, transparent 65%);
}
.auth-chip { display: inline-block; padding: 6px 14px; border-radius: 999px; font-size: 0.78rem;
  font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase;
  background: rgba(255,255,255,0.16); border: 1px solid rgba(255,255,255,0.30); }
.auth-brand h1 { color: #ffffff; font-size: 2.3rem; line-height: 1.15; font-weight: 800;
  letter-spacing: -0.02em; margin: 26px 0 12px; padding: 0; }
.auth-brand .lead { color: rgba(255,255,255,0.88); font-size: 1.02rem; line-height: 1.6;
  margin: 0 0 30px; max-width: 30rem; }
.auth-point { display: flex; gap: 14px; align-items: flex-start; margin: 0 0 18px; }
.auth-point b { display: block; color: #ffffff; font-size: 0.98rem; }
.auth-point span { color: rgba(255,255,255,0.80); font-size: 0.9rem; }
.auth-dot { flex: 0 0 auto; width: 10px; height: 10px; margin-top: 7px; border-radius: 50%;
  background: #5eead4; box-shadow: 0 0 0 5px rgba(94,234,212,0.22); }
.auth-foot { position: absolute; left: 40px; right: 40px; bottom: 28px;
  color: rgba(255,255,255,0.70); font-size: 0.8rem; }
.auth-card { padding: 40px 4px 10px; }
.auth-steps { display: flex; gap: 8px; margin: 0 0 22px; }
.auth-steps i { flex: 1; height: 5px; border-radius: 999px; background: rgba(128,128,128,0.22); }
.auth-steps i.on { background: linear-gradient(90deg, #6366f1, #38bdf8); }
.auth-card h2 { font-size: 1.75rem; font-weight: 800; letter-spacing: -0.01em; margin: 0 0 6px; padding: 0; }
.auth-card p { opacity: 0.72; margin: 0 0 6px; }
[data-testid="stForm"] { border-radius: 20px !important; padding: 26px 24px 20px !important;
  border: 1px solid rgba(148,163,184,0.18) !important;
  background: linear-gradient(160deg, #172033 0%, #0f172a 100%);
  box-shadow: 0 18px 40px rgba(0,0,0,0.45); }
[data-testid="stForm"] input { border-radius: 12px !important; padding: 12px 14px !important; }
[data-testid="stForm"] button[kind="primaryFormSubmit"], [data-testid="stForm"] [data-testid="stBaseButton-primaryFormSubmit"] {
  border: none !important; border-radius: 12px !important; padding: 12px 0 !important; font-weight: 700 !important;
  background: linear-gradient(100deg, #6366f1, #0ea5e9) !important; color: #ffffff !important;
  box-shadow: 0 10px 22px rgba(56,189,248,0.25); transition: transform .15s ease, box-shadow .15s ease; }
[data-testid="stForm"] button[kind="primaryFormSubmit"]:hover, [data-testid="stForm"] [data-testid="stBaseButton-primaryFormSubmit"]:hover {
  transform: translateY(-2px); box-shadow: 0 14px 28px rgba(56,189,248,0.40); }
.auth-note { margin-top: 14px; font-size: 0.82rem; opacity: 0.65; text-align: center; }
@media (max-width: 900px) { .auth-brand { min-height: 0; padding: 30px 24px 70px; }
  .auth-brand h1 { font-size: 1.8rem; } .auth-foot { left: 24px; } }
@media (prefers-reduced-motion: reduce) { [data-testid="stForm"] button { transition: none !important; } }
</style>
"""

BRAND_PANEL = """
<div class='auth-brand'>
  <span class='auth-chip'>Threat-aware security</span>
  <h1>Know which assets will be attacked next.</h1>
  <p class='lead'>Machine-learning predictions of which vulnerabilities will become actively
  exploited, matched to your devices, with a clear plan of what to fix first.</p>
  <div class='auth-point'><div class='auth-dot'></div><div><b>Predict exploitation</b>
    <span>Calibrated risk scores for every CVE on every device</span></div></div>
  <div class='auth-point'><div class='auth-dot'></div><div><b>See the blast radius</b>
    <span>Attack paths show how far one compromise can spread</span></div></div>
  <div class='auth-point'><div class='auth-dot'></div><div><b>Fix what matters</b>
    <span>Prioritised patch plans and owner notifications</span></div></div>
  <div class='auth-foot'>🔒 Protected by password + two-factor authentication. All access is audited.</div>
</div>
"""

STAGES = ["password", "change_password", "enrol", "mfa"]


def _card(title, subtitle):
    stage = st.session_state.get("auth_stage", "password")
    step = STAGES.index(stage) if stage in STAGES else 0
    bars = "".join(f"<i class='{'on' if i <= step else ''}'></i>" for i in range(len(STAGES)))
    st.markdown(f"<div class='auth-card'><div class='auth-steps'>{bars}</div>"
                f"<h2>{title}</h2><p>{subtitle}</p></div>", unsafe_allow_html=True)


def _qr_png(uri):
    image = qrcode.make(uri, box_size=6, border=2)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def _sign_out(reason):
    user = st.session_state.get("auth_user")
    if user:
        store.audit(reason, user["username"], user["role"])
    for key in ["auth_user", "auth_stage", "auth_pending", "auth_enrol_secret", "auth_last_active"]:
        st.session_state.pop(key, None)


def sign_out():
    _sign_out("logout")


def _password_stage():
    _card("Welcome back", "Sign in to the threat-aware exposure dashboard.")
    with st.form("login", clear_on_submit=False):
        username = st.text_input("Username", key="login_username").strip().lower()
        password = st.text_input("Password", type="password", key="login_password")
        submitted = st.form_submit_button("Continue", type="primary", use_container_width=True)
    if not submitted:
        return

    user = store.get_user(username) if username else None
    if user is None or not user["active"]:
        store.audit("login_failed", username or None, None, "unknown or disabled account", "failure")
        st.error(GENERIC_ERROR)
        return
    if store.is_locked(user):
        store.audit("login_blocked", username, user["role"], "account locked", "failure")
        st.error(f"Account temporarily locked after repeated failed attempts. "
                 f"Try again later or ask an administrator.")
        return
    if not verify_password(password, user["password_hash"]):
        locked = store.record_failure(user)
        store.audit("login_failed", username, user["role"], "wrong password", "failure")
        if locked:
            store.audit("account_locked", username, user["role"],
                        f"{store.MAX_FAILED_LOGINS} failed attempts", "failure")
        st.error(GENERIC_ERROR)
        return

    st.session_state["auth_pending"] = username
    st.session_state["auth_stage"] = "change_password" if user["must_change_password"] else \
        ("mfa" if user["mfa_enabled"] else "enrol")
    st.rerun()


def _change_password_stage(user):
    _card("Choose a new password", "Your password is temporary and must be changed.")
    with st.form("change_password"):
        new = st.text_input("New password", type="password")
        again = st.text_input("Repeat new password", type="password")
        submitted = st.form_submit_button("Save password", type="primary", use_container_width=True)
    st.caption("At least 12 characters, using three of: lowercase, uppercase, digits, symbols.")
    if not submitted:
        return
    problems = password_problems(new, user["username"])
    if new != again:
        st.error("The passwords do not match.")
    elif verify_password(new, user["password_hash"]):
        st.error("Choose a password different from the temporary one.")
    elif problems:
        st.error("Password not accepted: " + "; ".join(problems) + ".")
    else:
        store.update_user(user["username"], password_hash=hash_password(new), must_change_password=0)
        store.audit("password_changed", user["username"], user["role"])
        st.session_state["auth_stage"] = "mfa" if user["mfa_enabled"] else "enrol"
        st.rerun()


def _enrol_stage(user):
    _card("Set up two-factor authentication",
          "Scan the code with an authenticator app (Microsoft Authenticator, Google Authenticator, Authy).")
    secret = st.session_state.setdefault("auth_enrol_secret", new_totp_secret())
    left, right = st.columns([1, 2])
    left.image(_qr_png(provisioning_uri(secret, user["username"])), width=220)
    right.markdown("**Can't scan?** Add an account manually with this key (time-based):")
    right.code(" ".join(secret[i:i + 4] for i in range(0, len(secret), 4)))
    with right.form("enrol"):
        code = st.text_input("Enter the 6-digit code shown in the app", max_chars=6)
        submitted = st.form_submit_button("Verify and finish", type="primary")
    if not submitted:
        return
    counter = verify_totp(secret, code)
    if counter is None:
        store.audit("mfa_enrol_failed", user["username"], user["role"], outcome="failure")
        st.error("That code is not valid. Check the time on your phone and try the current code.")
        return
    store.update_user(user["username"], totp_secret=secret, mfa_enabled=1, last_totp_counter=counter)
    store.audit("mfa_enrolled", user["username"], user["role"])
    _complete(user)


def _mfa_stage(user):
    _card("Two-factor authentication", f"Enter the 6-digit code from your authenticator app.")
    with st.form("mfa"):
        code = st.text_input("Authentication code", max_chars=6)
        submitted = st.form_submit_button("Sign in", type="primary", use_container_width=True)
    if st.button("Back to sign in"):
        _sign_out("login_cancelled")
        st.rerun()
    if not submitted:
        return
    if store.is_locked(user):
        st.error("Account temporarily locked after repeated failed attempts.")
        return
    counter = verify_totp(user["totp_secret"], code, user["last_totp_counter"])
    if counter is None:
        locked = store.record_failure(user)
        store.audit("mfa_failed", user["username"], user["role"], outcome="failure")
        if locked:
            store.audit("account_locked", user["username"], user["role"],
                        f"{store.MAX_FAILED_LOGINS} failed attempts", "failure")
        st.error("Invalid or already used code.")
        return
    store.update_user(user["username"], last_totp_counter=counter)
    _complete(user)


def _complete(user):
    store.record_success(user["username"])
    store.audit("login", user["username"], user["role"], "password + MFA")
    st.session_state["auth_user"] = {k: user[k] for k in
                                     ["username", "display_name", "email", "role", "team"]}
    st.session_state["auth_last_active"] = time.time()
    for key in ["auth_stage", "auth_pending", "auth_enrol_secret"]:
        st.session_state.pop(key, None)
    st.rerun()


def require_login():
    """The signed-in user, or show the sign-in screens and stop."""
    if not auth_enabled():
        return dict(DEV_USER)
    user = st.session_state.get("auth_user")
    if user:
        idle = time.time() - st.session_state.get("auth_last_active", 0)
        if idle > IDLE_TIMEOUT_SECONDS:
            _sign_out("session_timeout")
            st.warning("You were signed out after 30 minutes of inactivity.")
        else:
            st.session_state["auth_last_active"] = time.time()
            return user

    stage = st.session_state.get("auth_stage", "password")
    pending = store.get_user(st.session_state.get("auth_pending", "")) if stage != "password" else None

    st.markdown(AUTH_CSS, unsafe_allow_html=True)
    # The enrolment screen needs more room for the QR code and the key
    brand, form = st.columns([1, 1.25] if stage == "enrol" else [1.1, 1], gap="large")
    brand.markdown(BRAND_PANEL, unsafe_allow_html=True)
    with form:
        if stage == "password" or pending is None:
            _password_stage()
        elif stage == "change_password":
            _change_password_stage(pending)
        elif stage == "enrol":
            _enrol_stage(pending)
        else:
            _mfa_stage(pending)
        st.markdown("<div class='auth-note'>Authorised users only · Sessions end after 30 minutes "
                    "of inactivity</div>", unsafe_allow_html=True)
    st.stop()


def user_badge(user):
    team = f" · {user['team']}" if user.get("team") else ""
    return f"**{user['display_name']}**  \n{role_name(user['role'])}{team}"
