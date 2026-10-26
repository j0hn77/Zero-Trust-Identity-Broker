import os
import sqlite3
import uuid

from fastapi import FastAPI, Request, Form, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
import uvicorn

app = FastAPI()

DB_NAME = "dashboard.db"
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                text TEXT NOT NULL
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_name TEXT NOT NULL,
                stored_name TEXT NOT NULL,
                uploaded_by TEXT NOT NULL,
                uploaded_role_level INTEGER NOT NULL,
                uploaded_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )


init_db()


def get_current_user(request: Request):
    role_level_raw = request.headers.get("X-User-Role-Level", "1")
    try:
        role_level = int(role_level_raw)
    except ValueError:
        role_level = 1

    role_map = {
        1: "level 1 (everyone)",
        2: "level 2 (manager)",
        3: "level 3 (exec)",
        4: "level 4 (admin)",
    }

    return {
        "username": request.headers.get("X-User-ID", "Guest"),
        "role_level": role_level,
        "role_label": role_map.get(role_level, f"level {role_level}"),
    }


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    user = get_current_user(request)

    # --- Admin toolbar (links into gateway) ---
    admin_bar = ""
    if user["role_level"] == 4:
        admin_bar = """
        <div style="margin-top:20px; padding:14px; background:#fef3c7; border:1px solid #f59e0b; border-radius:8px;">
          <strong>Admin:</strong>
          <a href="https://localhost:8000/admin/users/new"
             style="margin-left:10px; margin-right:18px; color:#b45309; font-weight:700; text-decoration:none;">
             👤 Manage Users
          </a>
          <a href="https://localhost:8000/admin/audit"
             target="_blank"
             style="color:#7c2d12; font-weight:700; text-decoration:none;">
             📜 View Audit Log
          </a>
        </div>
        """

    # --- Notes list ---
    notes_html = ""
    with sqlite3.connect(DB_NAME) as conn:
        conn.row_factory = sqlite3.Row
        notes = conn.execute("SELECT * FROM notes ORDER BY id DESC").fetchall()

    for note in notes:
        delete_btn = ""
        if user["role_level"] == 4:
            delete_btn = f"""
            <form action="/delete/{note['id']}" method="post" style="display:inline; margin-left:10px;">
                <button style="color:red; background:none; border:none; cursor:pointer; font-weight:700;">[Delete]</button>
            </form>
            """
        notes_html += f"<li style='margin-bottom: 6px;'>{note['text']} {delete_btn}</li>"

    # --- Files list (shows download if allowed, lock if not) ---
    files_rows = ""
    with sqlite3.connect(DB_NAME) as conn:
        conn.row_factory = sqlite3.Row
        files = conn.execute("SELECT * FROM files ORDER BY id DESC").fetchall()

    for f in files:
        required_level = int(f["uploaded_role_level"])

        delete_file_btn = ""
        if user["role_level"] == 4:
            delete_file_btn = f"""
            <form action="/files/delete/{f['id']}" method="post" style="display:inline; margin-left:10px;">
                <button style="color:red; background:none; border:none; cursor:pointer; font-weight:700;">[Delete]</button>
            </form>
            """

        if user["role_level"] >= required_level:
            download_control = f"""
            <a href="/files/{f['id']}"
               style="display:inline-block; margin-left:10px; padding:6px 10px; border-radius:8px;
                      background:#2563eb; color:white; text-decoration:none; font-weight:700;">
               ⬇ Download
            </a>
            """
            file_title = f"<span style='font-weight:700; color:#0f172a;'>📎 {f['original_name']}</span>"
        else:
            download_control = f"""
            <span style="display:inline-block; margin-left:10px; padding:6px 10px; border-radius:8px;
                         background:#f3f4f6; color:#6b7280; font-weight:700;">
              🔒 Locked (Requires level {required_level}+)
            </span>
            """
            file_title = f"<span style='font-weight:700; color:#6b7280;'>📎 {f['original_name']}</span>"

        files_rows += f"""
        <li style="margin-bottom:10px; padding:10px; border:1px solid #e5e7eb; border-radius:10px;">
          {file_title}
          {download_control}
          {delete_file_btn}
          <div style="margin-top:6px; color:#64748b; font-size:0.9rem;">
            uploaded by <strong>{f['uploaded_by']}</strong> • {f['uploaded_at']} • visible to level {required_level}+
          </div>
        </li>
        """

    if not files_rows:
        files_rows = "<li style='color:#64748b;'>No files uploaded yet.</li>"

    # --- Upload Section (Managers+) with visibility dropdown ---
    upload_section = ""
    if user["role_level"] >= 2:
        # A manager can choose level 1 or 2
        # An exec can choose level 1/2/3
        # An admin can choose 1/2/3/4
        max_level = user["role_level"]

        options = []
        labels = {
            1: "Level 1 (Everyone)",
            2: "Level 2 (Managers+)",
            3: "Level 3 (Exec+)",
            4: "Level 4 (Admin only)",
        }

        for lvl in (1, 2, 3, 4):
            if lvl <= max_level:
                # default to the uploader’s own level
                selected = "selected" if lvl == user["role_level"] else ""
                options.append(f"<option value='{lvl}' {selected}>{labels[lvl]}</option>")

        upload_section = f"""
        <div style="background:#ecfeff; padding:15px; border-radius:8px; margin-top:16px;">
            <h3 style="margin-top:0;">File Uploads</h3>
            <form action="/upload" method="post" enctype="multipart/form-data" style="display:flex; gap:10px; flex-wrap:wrap; align-items:center;">
                <input type="file" name="file" required />

                <label style="font-weight:700; color:#0f172a;">Who can see it?</label>
                <select name="visible_level" required style="padding:6px 10px; border-radius:8px; border:1px solid #cbd5e1;">
                    {''.join(options)}
                </select>

                <button style="padding:8px 12px; cursor:pointer;">Upload</button>
            </form>
            <p style="margin:8px 0 0; color:#334155; font-size:0.9rem;">
              Upload allowed for level 2+. Visibility is enforced on downloads. Delete is admin-only.
            </p>
        </div>
        """
    else:
        upload_section = """
        <div style="background:#f3f4f6; padding:10px; margin-top:16px; color:#666;">
          🔒 File upload hidden (level 1). You can download files you have access to.
        </div>
        """

    # --- Notes Controls (Managers+) ---
    if user["role_level"] >= 2:
        controls_section = """
        <div style="background:#e0f2fe; padding:15px; border-radius:8px; margin-top:20px;">
            <h3 style="margin-top:0;">Manager/Exec/Admin Controls</h3>
            <form action="/add" method="post">
                <input type="text" name="note" placeholder="New Note" required style="padding:8px; width:70%;">
                <button style="padding:8px; cursor:pointer;">Add Note</button>
            </form>
            <p style="margin:8px 0 0; color:#334155; font-size:0.9rem;">
              Note delete is admin-only (level 4).
            </p>
        </div>
        """
    else:
        controls_section = "<div style='background:#f3f4f6; padding:10px; margin-top:20px; color:#666;'>🔒 Controls hidden (Read Only - level 1)</div>"

    return f"""
    <html>
    <body style="font-family:sans-serif; padding:40px; max-width:950px; margin:0 auto;">
        <div style="border:1px solid #ccc; padding:20px; border-radius:10px;">
            <h1 style="color:#059669;">Internal Dashboard</h1>
            <p><strong>Identity:</strong> {user['username']} | <strong>Role:</strong> {user['role_label']}</p>

            {admin_bar}

            <hr>

            <h3>Secure Notes</h3>
            <ul>{notes_html}</ul>
            {controls_section}

            <hr style="margin:24px 0;"/>

            <h3>Files</h3>
            <ul style="padding-left:0; list-style:none;">{files_rows}</ul>
            {upload_section}
        </div>

        <p style="text-align:center; margin-top:50px;">
            <a href="https://localhost:8000/logout" style="color:#999;">Log Out</a>
        </p>
    </body>
    </html>
    """


@app.post("/add")
async def add_note(request: Request, note: str = Form(...)):
    user = get_current_user(request)
    if user["role_level"] < 2:
        raise HTTPException(403, "Forbidden: managers+ only")

    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("INSERT INTO notes (text) VALUES (?)", (note,))
    return RedirectResponse("/", status_code=303)


@app.post("/delete/{note_id}")
async def delete_note(request: Request, note_id: int):
    user = get_current_user(request)
    if user["role_level"] != 4:
        raise HTTPException(403, "Forbidden: admin only")

    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    return RedirectResponse("/", status_code=303)


# ✅ Upload file with chosen visibility level
@app.post("/upload")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    visible_level: int = Form(...),
):
    user = get_current_user(request)
    if user["role_level"] < 2:
        raise HTTPException(403, "Forbidden: managers+ only")

    if visible_level not in (1, 2, 3, 4):
        raise HTTPException(400, "visible_level must be 1-4")

    # ✅ Prevent a manager from setting visibility higher than themselves
    # (Managers can set up to 2, Exec up to 3, Admin up to 4)
    if visible_level > user["role_level"]:
        raise HTTPException(403, "Forbidden: cannot set visibility above your role level")

    ext = os.path.splitext(file.filename or "")[1]
    stored_name = f"{uuid.uuid4().hex}{ext}"
    stored_path = os.path.join(UPLOAD_DIR, stored_name)

    content = await file.read()
    with open(stored_path, "wb") as f:
        f.write(content)

    with sqlite3.connect(DB_NAME) as conn:
        conn.execute(
            "INSERT INTO files (original_name, stored_name, uploaded_by, uploaded_role_level) VALUES (?, ?, ?, ?)",
            (file.filename or "unknown", stored_name, user["username"], int(visible_level)),
        )

    return RedirectResponse("/", status_code=303)


@app.get("/files/{file_id}")
async def download_file(request: Request, file_id: int):
    user = get_current_user(request)
    if user["role_level"] < 1:
        raise HTTPException(403, "Forbidden")

    with sqlite3.connect(DB_NAME) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()

    if not row:
        raise HTTPException(404, "File not found")

    required_level = int(row["uploaded_role_level"])
    if user["role_level"] < required_level:
        raise HTTPException(403, f"Forbidden: requires role level {required_level}+")

    path = os.path.join(UPLOAD_DIR, row["stored_name"])
    if not os.path.exists(path):
        raise HTTPException(404, "File missing on disk")

    return FileResponse(
        path=path,
        filename=row["original_name"],
        media_type="application/octet-stream",
    )


@app.post("/files/delete/{file_id}")
async def delete_file(request: Request, file_id: int):
    user = get_current_user(request)
    if user["role_level"] != 4:
        raise HTTPException(403, "Forbidden: admin only")

    with sqlite3.connect(DB_NAME) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()

    if not row:
        raise HTTPException(404, "File not found")

    path = os.path.join(UPLOAD_DIR, row["stored_name"])
    if os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass

    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("DELETE FROM files WHERE id = ?", (file_id,))

    return RedirectResponse("/", status_code=303)


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=3000)
