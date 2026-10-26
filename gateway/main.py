from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response, Form
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse

from audit import log_event

from database import (
    init_db,
    get_user,
    list_users,
    create_user,
    delete_user,
    verify_password,
    get_notes,
    add_note,
)
from auth import create_access_token, decode_access_token, ACCESS_TOKEN_EXPIRE_MINUTES
from policies import PolicyDecisionPoint


AUDIT_LOG_FILE = Path(__file__).resolve().parent / "access_audit.log"


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()

    # Seed demo users
    if not get_user("admin"):
        create_user("admin", "admin123", 4)
        print("Created User: admin (level 4)")
    if not get_user("viewer"):
        create_user("viewer", "viewer123", 1)
        print("Created User: viewer (level 1)")
    if not get_user("manager"):
        create_user("manager", "manager123", 2)
        print("Created User: manager (level 2)")
    if not get_user("exec"):
        create_user("exec", "exec123", 3)
        print("Created User: exec (level 3)")

    if not get_notes():
        add_note("Confidential: System maintenance tonight.")
        add_note("Q3 Financials: Strong growth expected.")
        print("Added initial notes")

    yield


app = FastAPI(lifespan=lifespan)
pdp = PolicyDecisionPoint()


# -----------------------------
# LOGIN PAGE
# -----------------------------
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return """
    <html>
    <body style="font-family: sans-serif; background: #111827; height: 100vh; display: flex; align-items: center; justify-content: center; color: white;">
        <div style="background: #1f2937; padding: 2rem; border-radius: 12px; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25); width: 380px;">
            <h2 style="margin-top: 0; color: #10b981; text-align: center;">Zero Trust Gateway</h2>
            <p style="text-align: center; color: #9ca3af; margin-bottom: 1.5rem;">Identity Broker Login</p>

            <div style="background:#0b1220; border:1px solid #374151; padding:0.75rem; border-radius:10px; margin-bottom:1rem; color:#cbd5e1; font-size:0.9rem;">
              Demo users:<br/>
              admin/admin123 (level 4)<br/>
              exec/exec123 (level 3)<br/>
              manager/manager123 (level 2)<br/>
              viewer/viewer123 (level 1)
            </div>

            <form action="/token" method="post">
                <div style="margin-bottom: 1rem;">
                    <label style="display: block; font-size: 0.875rem; margin-bottom: 0.5rem;">Username</label>
                    <input type="text" name="username" required style="width: 100%; padding: 0.75rem; border-radius: 6px; border: none; background: #374151; color: white; box-sizing: border-box;">
                </div>
                <div style="margin-bottom: 1.25rem;">
                    <label style="display: block; font-size: 0.875rem; margin-bottom: 0.5rem;">Password</label>
                    <input type="password" name="password" required style="width: 100%; padding: 0.75rem; border-radius: 6px; border: none; background: #374151; color: white; box-sizing: border-box;">
                </div>
                <button type="submit" style="width: 100%; padding: 0.75rem; border-radius: 6px; border: none; background: #10b981; color: white; font-weight: bold; cursor: pointer;">
                    Authenticate
                </button>
            </form>
        </div>
    </body>
    </html>
    """


# -----------------------------
# LOGIN HANDLER -> COOKIE + AUDIT
# -----------------------------
@app.post("/token")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    user = get_user(username)

    if not user or not verify_password(password, user["hashed_password"]):
        log_event("LOGIN_FAILED", username, 0, request, extra="reason=bad_credentials")
        return HTMLResponse("Invalid credentials. <a href='/login'>Try again</a>", status_code=401)

    access_token = create_access_token(
        data={"sub": user["username"], "role_level": int(user["role_level"])},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    log_event("LOGIN_SUCCESS", user["username"], int(user["role_level"]), request)

    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        secure=True,
        samesite="lax",
    )
    return response


# -----------------------------
# VERIFY REQUEST (COOKIE + PDP)
# -----------------------------
async def verify_request(request: Request) -> dict:
    token = None
    cookie_auth = request.cookies.get("access_token")

    if cookie_auth and cookie_auth.startswith("Bearer "):
        token = cookie_auth.split(" ", 1)[1]

    if token is None:
        raise HTTPException(status_code=307, headers={"Location": "/login"})

    payload = decode_access_token(token)
    if payload is None:
        raise HTTPException(status_code=307, headers={"Location": "/login"})

    pdp.evaluate(user_claims=payload, request=request)
    return payload


# -----------------------------
# LOGOUT + AUDIT
# -----------------------------
@app.get("/logout")
async def logout(request: Request):
    try:
        cookie_auth = request.cookies.get("access_token")
        if cookie_auth and cookie_auth.startswith("Bearer "):
            token = cookie_auth.split(" ", 1)[1]
            payload = decode_access_token(token)
            if payload:
                log_event(
                    "LOGOUT",
                    payload.get("sub", "unknown"),
                    int(payload.get("role_level", 0)),
                    request,
                )
    except Exception:
        pass

    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("access_token")
    return response


# -----------------------------
# ADMIN UI: CREATE + DELETE USER (LEVEL 4)
# -----------------------------
@app.get("/admin/users/new", response_class=HTMLResponse)
async def admin_new_user_page(request: Request):
    claims = await verify_request(request)
    if int(claims.get("role_level", 0)) != 4:
        raise HTTPException(status_code=403, detail="Admins only")

    users = list_users()

    rows = ""
    for u in users:
        delete_cell = "<span style='color:#9ca3af;'>—</span>"
        if u["username"] != claims.get("sub"):
            delete_cell = f"""
            <form action="/admin/users/delete/{u['username']}" method="post" style="margin:0;"
                  onsubmit="return confirm('Delete user: {u['username']} ?');">
                <button type="submit"
                    style="padding:6px 10px; border:none; border-radius:8px; background:#ef4444; color:white; font-weight:700; cursor:pointer;">
                    Delete
                </button>
            </form>
            """

        rows += f"""
        <tr>
          <td style="padding:0.5rem; border-bottom:1px solid #374151;">{u['username']}</td>
          <td style="padding:0.5rem; border-bottom:1px solid #374151;">{u['role_level']}</td>
          <td style="padding:0.5rem; border-bottom:1px solid #374151;">{delete_cell}</td>
        </tr>
        """

    return f"""
    <html>
    <body style="font-family:sans-serif; background:#0b1220; color:#e5e7eb; padding:2rem;">
      <div style="max-width:900px; margin:0 auto;">
        <h2 style="color:#10b981;">Admin: Create User</h2>

        <div style="display:flex; gap:2rem; align-items:flex-start; flex-wrap:wrap;">
          <div style="flex:1; min-width:320px; background:#111827; border:1px solid #374151; border-radius:12px; padding:1.25rem;">
            <form action="/admin/users" method="post">
              <label>Username</label><br/>
              <input name="username" required style="width:100%; padding:0.6rem; margin:0.4rem 0 1rem; border-radius:8px; border:1px solid #374151; background:#0b1220; color:white;"/>

              <label>Password</label><br/>
              <input name="password" type="password" required style="width:100%; padding:0.6rem; margin:0.4rem 0 1rem; border-radius:8px; border:1px solid #374151; background:#0b1220; color:white;"/>

              <label>Role Level</label><br/>
              <select name="role_level" required style="width:100%; padding:0.6rem; margin:0.4rem 0 1rem; border-radius:8px; border:1px solid #374151; background:#0b1220; color:white;">
                <option value="1">1 - Everyone</option>
                <option value="2">2 - Managers</option>
                <option value="3">3 - Exec</option>
                <option value="4">4 - Admin</option>
              </select>

              <button type="submit" style="width:100%; padding:0.75rem; border:none; border-radius:8px; background:#10b981; color:white; font-weight:700; cursor:pointer;">
                Create User
              </button>
            </form>

            <div style="margin-top:1rem;">
              <a href="/" style="color:#93c5fd;">Back to App</a> |
              <a href="/admin/audit" style="color:#fbbf24; font-weight:700;">View Audit Log</a> |
              <a href="/logout" style="color:#fca5a5;">Logout</a>
            </div>
          </div>

          <div style="flex:1; min-width:360px; background:#111827; border:1px solid #374151; border-radius:12px; padding:1.25rem;">
            <h3 style="margin-top:0;">Existing Users</h3>
            <table style="width:100%; border-collapse:collapse;">
              <thead>
                <tr>
                  <th style="text-align:left; border-bottom:1px solid #374151; padding:0.5rem;">Username</th>
                  <th style="text-align:left; border-bottom:1px solid #374151; padding:0.5rem;">Role Level</th>
                  <th style="text-align:left; border-bottom:1px solid #374151; padding:0.5rem;">Actions</th>
                </tr>
              </thead>
              <tbody>
                {rows}
              </tbody>
            </table>

            <p style="margin-top:0.75rem; color:#9ca3af; font-size:0.9rem;">
              Tip: you cannot delete yourself. Also, the last admin cannot be deleted.
            </p>
          </div>
        </div>
      </div>
    </body>
    </html>
    """


@app.post("/admin/users")
async def admin_create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role_level: int = Form(...),
):
    claims = await verify_request(request)
    if int(claims.get("role_level", 0)) != 4:
        raise HTTPException(status_code=403, detail="Admins only")

    if role_level not in (1, 2, 3, 4):
        raise HTTPException(status_code=400, detail="role_level must be 1-4")

    if get_user(username):
        raise HTTPException(status_code=409, detail="Username already exists")

    create_user(username, password, int(role_level))

    log_event(
        "CREATE_USER",
        claims.get("sub", "unknown"),
        int(claims.get("role_level", 0)),
        request,
        extra=f"created_user={username} created_role={role_level}",
    )

    return RedirectResponse(url="/admin/users/new", status_code=303)


@app.post("/admin/users/delete/{username}")
async def admin_delete_user(request: Request, username: str):
    claims = await verify_request(request)
    if int(claims.get("role_level", 0)) != 4:
        raise HTTPException(status_code=403, detail="Admins only")

    if username == claims.get("sub"):
        raise HTTPException(status_code=400, detail="You cannot delete yourself")

    users = list_users()
    admins = [u for u in users if int(u["role_level"]) == 4]
    target = next((u for u in users if u["username"] == username), None)
    if target and int(target["role_level"]) == 4 and len(admins) <= 1:
        raise HTTPException(status_code=400, detail="Cannot delete the last admin")

    delete_user(username)

    log_event(
        "DELETE_USER",
        claims.get("sub", "unknown"),
        int(claims.get("role_level", 0)),
        request,
        extra=f"deleted_user={username}",
    )

    return RedirectResponse(url="/admin/users/new", status_code=303)


# -----------------------------
# ADMIN: AUDIT LOG VIEWER (LEVEL 4)
# -----------------------------
@app.get("/admin/audit", response_class=HTMLResponse)
async def admin_audit_page(request: Request):
    claims = await verify_request(request)
    if int(claims.get("role_level", 0)) != 4:
        raise HTTPException(status_code=403, detail="Admins only")

    if AUDIT_LOG_FILE.exists():
        with open(AUDIT_LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        log_text = "".join(lines[-500:])
    else:
        log_text = "No audit log entries yet."

    log_text = (
        log_text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )

    return f"""
    <html>
    <body style="font-family:sans-serif; background:#0b1220; color:#e5e7eb; padding:2rem;">
      <div style="max-width:1100px; margin:0 auto;">
        <h2 style="color:#10b981; margin-top:0;">Admin: Audit Log</h2>

        <div style="display:flex; gap:12px; margin:12px 0 18px;">
          <a href="/admin/users/new" style="color:#93c5fd;">← Back to Users</a>
          <span style="color:#475569;">|</span>
          <a href="/admin/audit/download" style="color:#fbbf24; font-weight:700;">⬇ Download Log</a>
          <span style="color:#475569;">|</span>
          <a href="/logout" style="color:#fca5a5;">Logout</a>
        </div>

        <div style="background:#111827; border:1px solid #374151; border-radius:12px; padding:1rem;">
          <div style="color:#9ca3af; margin-bottom:10px; font-size:0.9rem;">
            Showing last 500 events (UTC). File: {AUDIT_LOG_FILE.name}
          </div>
          <pre style="white-space:pre-wrap; word-wrap:break-word; margin:0; font-size:0.9rem; line-height:1.35;">{log_text}</pre>
        </div>
      </div>
    </body>
    </html>
    """


@app.get("/admin/audit/download")
async def admin_audit_download(request: Request):
    claims = await verify_request(request)
    if int(claims.get("role_level", 0)) != 4:
        raise HTTPException(status_code=403, detail="Admins only")

    if not AUDIT_LOG_FILE.exists():
        AUDIT_LOG_FILE.write_text("", encoding="utf-8")

    return FileResponse(
        path=str(AUDIT_LOG_FILE),
        filename="access_audit.log",
        media_type="text/plain",
    )


# -----------------------------
# PROXY TO DASHBOARD (:3000) + AUDIT (optional)
# -----------------------------
@app.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy(path_name: str, request: Request):
    try:
        user_claims = await verify_request(request)
    except HTTPException as e:
        if e.status_code == 307:
            return RedirectResponse(url="/login")
        raise e

    # Optional: log every access through the gateway
    try:
        log_event(
            "ACCESS",
            user_claims.get("sub", "unknown"),
            int(user_claims.get("role_level", 0)),
            request,
            extra=f"proxied_path=/{path_name}",
        )
    except Exception:
        pass

    target_url = f"http://localhost:3000/{path_name}"

    async with httpx.AsyncClient() as client:
        proxy_headers = {
            "X-User-ID": user_claims.get("sub", ""),
            "X-User-Role-Level": str(user_claims.get("role_level", "")),
        }

        content_type = request.headers.get("Content-Type")
        if content_type:
            proxy_headers["Content-Type"] = content_type

        body = await request.body()

        try:
            rp_resp = await client.request(
                method=request.method,
                url=target_url,
                headers=proxy_headers,
                data=body,
                params=request.query_params,
            )
            return Response(content=rp_resp.content, status_code=rp_resp.status_code, headers=dict(rp_resp.headers))
        except httpx.ConnectError:
            return Response("Gateway Error: Dashboard Offline", status_code=503)


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="localhost",
        port=8000,
        ssl_keyfile="certs/key.pem",
        ssl_certfile="certs/cert.pem",
        reload=True,
    )
