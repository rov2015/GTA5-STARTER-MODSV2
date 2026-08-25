from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json
import hashlib
import mimetypes
import re
import uuid
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent
UPLOADS = ROOT / "Uploads"
CATALOG = UPLOADS / "mods.json"
USERS = ROOT / "users.json"
SESSIONS = ROOT / "sessions.json"
UPLOADS.mkdir(exist_ok=True)


def read_catalog():
    if not CATALOG.exists():
        return []
    try:
        return json.loads(CATALOG.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []


def write_catalog(mods):
    CATALOG.write_text(json.dumps(mods, indent=2), encoding="utf-8")


def safe_folder_name(value):
    cleaned = re.sub(r"[^A-Za-z0-9 _.-]", "", value).strip().replace(" ", "-")
    return cleaned[:80] or "unnamed"


def read_users():
    if not USERS.exists():
        return {}
    try:
        return json.loads(USERS.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def hash_password(password):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), b"gta5-mod-starter", 120000).hex()


def read_sessions():
    if not SESSIONS.exists():
        return {}
    try:
        return json.loads(SESSIONS.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


sessions = read_sessions()


class ModHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def send_json(self, status, payload):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def get_session_username(self):
        authorization = self.headers.get("Authorization", "")
        token = authorization.removeprefix("Bearer ").strip()
        return sessions.get(token)

    def do_GET(self):
        if self.path == "/api/mods":
            self.send_json(200, read_catalog())
            return
        if self.path.startswith("/api/download?"):
            file_url = parse_qs(urlparse(self.path).query).get("file", [""])[0]
            mods = read_catalog()
            mod = next((item for item in mods if item.get("fileUrl") == file_url), None)
            if not mod or not file_url.startswith("Uploads/"):
                self.send_json(404, {"error": "File not found."})
                return
            file_path = (ROOT / file_url).resolve()
            if UPLOADS.resolve() not in file_path.parents or not file_path.is_file():
                self.send_json(404, {"error": "File not found."})
                return
            mod["downloads"] = int(mod.get("downloads", 0)) + 1
            write_catalog(mods)
            self.send_response(302)
            self.send_header("Location", "/" + file_url)
            self.end_headers()
            return
        if self.path == "/api/me":
            username = self.get_session_username()
            if not username:
                self.send_json(401, {"error": "Sign in required."})
                return
            self.send_json(200, {"username": username})
            return
        super().do_GET()

    def do_POST(self):
        if self.path == "/api/delete":
            username = self.get_session_username()
            if not username:
                self.send_json(401, {"error": "Sign in required."})
                return
            length = int(self.headers.get("Content-Length", "0"))
            try:
                payload = json.loads(self.rfile.read(length))
            except json.JSONDecodeError:
                self.send_json(400, {"error": "Invalid request."})
                return
            file_url = str(payload.get("fileUrl", ""))
            mods = read_catalog()
            mod = next((item for item in mods if item.get("fileUrl") == file_url), None)
            if not mod:
                self.send_json(404, {"error": "Mod not found."})
                return
            if mod.get("username") != username:
                self.send_json(403, {"error": "Only the mod owner can delete it."})
                return
            mods.remove(mod)
            write_catalog(mods)
            for relative_path in (mod.get("fileUrl"), mod.get("image")):
                if not relative_path or not relative_path.startswith("Uploads/"):
                    continue
                file_path = (ROOT / relative_path).resolve()
                if UPLOADS.resolve() in file_path.parents and file_path.is_file():
                    file_path.unlink()
            self.send_json(200, {"message": "Mod deleted."})
            return

        if self.path == "/api/change-password":
            username = self.get_session_username()
            if not username:
                self.send_json(401, {"error": "Sign in required."})
                return
            length = int(self.headers.get("Content-Length", "0"))
            try:
                payload = json.loads(self.rfile.read(length))
            except json.JSONDecodeError:
                self.send_json(400, {"error": "Invalid request."})
                return
            current_password = str(payload.get("currentPassword", ""))
            new_password = str(payload.get("newPassword", ""))
            users = read_users()
            if users.get(username) != hash_password(current_password):
                self.send_json(401, {"error": "Current password is incorrect."})
                return
            if len(new_password) < 6:
                self.send_json(400, {"error": "New password must be at least 6 characters."})
                return
            users[username] = hash_password(new_password)
            USERS.write_text(json.dumps(users, indent=2), encoding="utf-8")
            self.send_json(200, {"message": "Password updated."})
            return

        if self.path in ("/api/signup", "/api/signin"):
            length = int(self.headers.get("Content-Length", "0"))
            try:
                payload = json.loads(self.rfile.read(length))
            except json.JSONDecodeError:
                self.send_json(400, {"error": "Invalid request."})
                return
            username = str(payload.get("username", "")).strip()
            password = str(payload.get("password", ""))
            users = read_users()
            if not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", username):
                self.send_json(400, {"error": "Username must be 3-30 letters, numbers, dots, dashes, or underscores."})
                return
            if len(password) < 6:
                self.send_json(400, {"error": "Password must be at least 6 characters."})
                return
            if self.path == "/api/signup":
                if username.lower() in {name.lower() for name in users}:
                    self.send_json(409, {"error": "That username is already taken."})
                    return
                users[username] = hash_password(password)
                USERS.write_text(json.dumps(users, indent=2), encoding="utf-8")
            elif username not in users or users[username] != hash_password(password):
                self.send_json(401, {"error": "Username or password is incorrect."})
                return
            token = uuid.uuid4().hex
            sessions[token] = username
            SESSIONS.write_text(json.dumps(sessions, indent=2), encoding="utf-8")
            self.send_json(200, {"token": token, "username": username})
            return

        if self.path != "/api/upload":
            self.send_json(404, {"error": "Not found"})
            return
        content_type = self.headers.get("Content-Type", "")
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length)
        fields = {}
        files = {}
        username = self.get_session_username()
        if not username:
            self.send_json(401, {"error": "Sign in before uploading."})
            return
        boundary_match = re.search(r"boundary=\"?([^\";]+)", content_type)
        if not boundary_match:
            self.send_json(400, {"error": "Invalid multipart upload."})
            return
        boundary = b"--" + boundary_match.group(1).encode()
        for chunk in body.split(boundary)[1:-1]:
            chunk = chunk.strip(b"\r\n-")
            if b"\r\n\r\n" not in chunk:
                continue
            raw_headers, payload = chunk.split(b"\r\n\r\n", 1)
            headers = raw_headers.decode("utf-8", errors="replace")
            disposition = next((line for line in headers.split("\r\n") if line.lower().startswith("content-disposition:")), "")
            field_match = re.search(r'name="([^"]+)"', disposition)
            if not field_match:
                continue
            field_name = field_match.group(1)
            filename_match = re.search(r'filename="([^"]*)"', disposition)
            filename = filename_match.group(1) if filename_match else ""
            content_type_match = re.search(r"content-type:\s*([^\r\n]+)", headers, re.IGNORECASE)
            part_type = content_type_match.group(1).strip() if content_type_match else "application/octet-stream"
            if filename:
                files[field_name] = (Path(filename).name, payload, part_type)
            else:
                fields[field_name] = payload.decode("utf-8", errors="replace")

        if not fields.get("title") or not fields.get("description") or "modFile" not in files:
            self.send_json(400, {"error": "Title, description, and a mod file are required."})
            return

        prefix = uuid.uuid4().hex[:8]
        original_name, file_data, file_type = files["modFile"]
        mod_folder = safe_folder_name(fields["title"])
        user_folder = safe_folder_name(username)
        upload_folder = UPLOADS / mod_folder / user_folder
        upload_folder.mkdir(parents=True, exist_ok=True)
        saved_name = f"{prefix}-{original_name}"
        (upload_folder / saved_name).write_bytes(file_data)
        image_url = fields.get("modImage", "").strip()
        if "modImageFile" in files and files["modImageFile"][0]:
            image_name, image_data, image_type = files["modImageFile"]
            image_suffix = Path(image_name).suffix or mimetypes.guess_extension(image_type) or ".img"
            saved_image = f"{prefix}-cover{image_suffix}"
            (upload_folder / saved_image).write_bytes(image_data)
            image_url = f"Uploads/{mod_folder}/{user_folder}/{saved_image}"

        mod = {
            "title": fields["title"].strip(),
            "description": fields["description"].strip(),
            "username": username,
            "image": image_url,
            "fileName": original_name,
            "fileUrl": f"Uploads/{mod_folder}/{user_folder}/{saved_name}",
			"downloads": 0,
        }
        mods = read_catalog()
        mods.insert(0, mod)
        write_catalog(mods)
        self.send_json(201, mod)


if __name__ == "__main__":
    print("GTA5 Mod Starter running on port 8000")
    print("Open http://localhost:8000/mods-library.html on this computer.")
    print("Other devices can use this computer's local IP address on the same network.")
    ThreadingHTTPServer(("0.0.0.0", 8000), ModHandler).serve_forever()
