"""Serve the single-page frontend with the public Overview at the root route."""

from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


FRONTEND_DIR = Path(__file__).resolve().parent
APP_ROUTES = {
    "/",
    "/login",
    "/register",
    "/smart-scan",
    "/crypto-lab",
    "/website-scan",
    "/simulation-lab",
    "/dashboard",
    "/scan-history",
    "/extension-management",
}


class AppHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FRONTEND_DIR), **kwargs)

    def do_GET(self):
        path = urlsplit(self.path).path.rstrip("/") or "/"
        if path in APP_ROUTES:
            self.path = "/index.html"
        super().do_GET()


if __name__ == "__main__":
    print("Cyber Shield frontend: http://127.0.0.1:5500/")
    ThreadingHTTPServer(("0.0.0.0", 5500), AppHandler).serve_forever()
