"""Serve the single-page frontend with clean local routes."""

from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


FRONTEND_DIR = Path(__file__).resolve().parent
APP_ROUTES = {
    "/login",
    "/register",
    "/smart-scan",
    "/crypto-lab",
    "/website-scan",
    "/dashboard",
    "/scan-history",
    "/extension-management",
}


class AppHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FRONTEND_DIR), **kwargs)

    def do_GET(self):
        path = urlsplit(self.path).path.rstrip("/") or "/"
        if path == "/":
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()
            return
        if path in APP_ROUTES:
            self.path = "/index.html"
        super().do_GET()


if __name__ == "__main__":
    print("Cyber Shield frontend: http://127.0.0.1:5500/login")
    ThreadingHTTPServer(("0.0.0.0", 5500), AppHandler).serve_forever()
