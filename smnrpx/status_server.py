from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from os import _exit, fork
import re

KEY_PATTERN = re.compile(r"^(\s*-?\s*)([^:#\n][^:\n]*:)(\s*)(.*)$")
BOOLEAN_PATTERN = re.compile(r"\b(true|false|null)\b")
NUMBER_PATTERN = re.compile(r"\b-?\d+(?:\.\d+)?\b")
COMMENT_PATTERN = re.compile(r"(\s+#.*)$")


def _highlight_yaml_line(line: str) -> str:
    escaped_line = escape(line)

    if not escaped_line.strip():
        return ""

    comment_match = COMMENT_PATTERN.search(escaped_line)
    comment = ""
    content = escaped_line
    if comment_match:
        comment = f'<span class="yaml-comment">{comment_match.group(1)}</span>'
        content = escaped_line[: comment_match.start(1)]

    key_match = KEY_PATTERN.match(content)
    if key_match:
        indent, key, spacing, value = key_match.groups()
        value = BOOLEAN_PATTERN.sub(r'<span class="yaml-bool">\1</span>', value)
        value = NUMBER_PATTERN.sub(r'<span class="yaml-number">\g<0></span>', value)
        content = (
            f'{indent}<span class="yaml-key">{key}</span>{spacing}'
            f'<span class="yaml-value">{value}</span>'
        )
    else:
        content = BOOLEAN_PATTERN.sub(r'<span class="yaml-bool">\1</span>', content)
        content = NUMBER_PATTERN.sub(r'<span class="yaml-number">\g<0></span>', content)

    return f"{content}{comment}"


def render_status_page(config_yaml: str) -> str:
    highlighted = "\n".join(_highlight_yaml_line(line) for line in config_yaml.splitlines())
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SMNRP Status</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f4efe6;
      --panel: rgba(255, 251, 245, 0.94);
      --border: rgba(103, 76, 48, 0.16);
      --shadow: rgba(82, 58, 31, 0.16);
      --text: #2a221c;
      --muted: #6b5b4b;
      --key: #9c3f1d;
      --value: #2a221c;
      --bool: #0d6e6e;
      --number: #865d00;
      --comment: #907d6a;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      font-family: "Iowan Old Style", "Palatino Linotype", "Book Antiqua", serif;
      background:
        radial-gradient(circle at top left, rgba(210, 141, 82, 0.28), transparent 35%),
        radial-gradient(circle at bottom right, rgba(86, 140, 124, 0.18), transparent 40%),
        linear-gradient(135deg, #efe4d4 0%, #f9f6ef 48%, #e9dfd2 100%);
      color: var(--text);
      padding: 24px;
    }}
    main {{
      max-width: 1100px;
      margin: 0 auto;
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 24px;
      box-shadow: 0 24px 60px var(--shadow);
      overflow: hidden;
      backdrop-filter: blur(10px);
    }}
    header {{
      padding: 24px 28px 12px;
      border-bottom: 1px solid var(--border);
    }}
    h1 {{
      margin: 0;
      font-size: clamp(2rem, 4vw, 3.4rem);
      line-height: 1;
      letter-spacing: -0.04em;
    }}
    p {{
      margin: 10px 0 0;
      color: var(--muted);
      font-size: 1rem;
    }}
    pre {{
      margin: 0;
      padding: 28px;
      overflow-x: auto;
      font-family: "SFMono-Regular", "Menlo", "Consolas", monospace;
      font-size: 0.96rem;
      line-height: 1.6;
      background: linear-gradient(180deg, rgba(255, 252, 247, 0.9), rgba(245, 237, 226, 0.88));
    }}
    .yaml-key {{ color: var(--key); font-weight: 700; }}
    .yaml-value {{ color: var(--value); }}
    .yaml-bool {{ color: var(--bool); font-weight: 700; }}
    .yaml-number {{ color: var(--number); }}
    .yaml-comment {{ color: var(--comment); font-style: italic; }}
    @media (max-width: 640px) {{
      body {{ padding: 14px; }}
      header {{ padding: 18px 18px 10px; }}
      pre {{ padding: 18px; font-size: 0.88rem; }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <h1>SMNRP Status</h1>
      <p>Effective startup configuration rendered from the active YAML.</p>
    </header>
    <pre><code>{highlighted}</code></pre>
  </main>
</body>
</html>
"""


def start_status_server(config_yaml: str, port: int) -> int:
    html = render_status_page(config_yaml).encode("utf-8")

    class StatusHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path not in ("/", "/index.html"):
                self.send_error(404)
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)

        def log_message(self, format, *args):
            return

    pid = fork()
    if pid == 0:
        server = ThreadingHTTPServer(("0.0.0.0", port), StatusHandler)
        print(f"ℹ️ Status service enabled on port {port}")
        try:
            server.serve_forever()
        finally:
            server.server_close()
        _exit(0)
    return pid
