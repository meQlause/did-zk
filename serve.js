const http = require("http");
const fs = require("fs");
const path = require("path");

const PORT = 8080;

const MIME_TYPES = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".css": "text/css",
  ".json": "application/json",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".gif": "image/gif",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
};

const server = http.createServer((req, res) => {
  console.log(`${req.method} ${req.url}`);

  // Handle root redirect to a simple landing or just list the dirs
  let filePath = "." + (req.url === "/" ? "/index.html" : req.url);

  // Security: prevent directory traversal
  const resolvedPath = path.resolve(filePath);
  const rootPath = path.resolve(".");
  if (!resolvedPath.startsWith(rootPath)) {
    res.statusCode = 403;
    res.end("Forbidden");
    return;
  }

  const extname = String(path.extname(filePath)).toLowerCase();
  const contentType = MIME_TYPES[extname] || "application/octet-stream";

  fs.readFile(filePath, (error, content) => {
    if (error) {
      if (error.code === "ENOENT") {
        // If index.html doesn't exist at root, show a simple directory info
        if (req.url === "/") {
          res.writeHead(200, { "Content-Type": "text/html" });
          res.end(`
            <html>
              <body style="font-family: sans-serif; padding: 2rem; background: #0f172a; color: #f8fafc;">
                <h1>ZK-CRED Local Server</h1>
                <p>Select a page to open:</p>
                <ul>
                  <li><a href="/prover_page/index.html" style="color: #38bdf8;">Prover Page</a></li>
                  <li><a href="/verifier_page/index.html" style="color: #38bdf8;">Verifier Page</a></li>
                </ul>
              </body>
            </html>
          `);
          return;
        }
        res.statusCode = 404;
        res.end("Not Found");
      } else {
        res.statusCode = 500;
        res.end(`Server Error: ${error.code}`);
      }
    } else {
      res.writeHead(200, { "Content-Type": contentType });
      res.end(content, "utf-8");
    }
  });
});

server.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}/`);
  console.log(`- Prover:   http://localhost:${PORT}/prover_page/index.html`);
  console.log(`- Verifier: http://localhost:${PORT}/verifier_page/index.html`);
  console.log("Press Ctrl+C to stop.");
});
