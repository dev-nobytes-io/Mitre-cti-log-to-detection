// Spins up a static HTTP server, runs every test file under tests/e2e/
// in its own process (so each file's Playwright browser cleans up
// independently), streams the spec reporter to stdout, and exits non-zero
// on the first failure. Used both locally and from .github/workflows/test.yml.

import { spawn } from "node:child_process";
import { readdirSync } from "node:fs";
import { resolve } from "node:path";

const REPO_ROOT = resolve(import.meta.dirname, "..");
const PORT = process.env.PORT || "8765";

console.log(`[test] starting static server on :${PORT} from ${REPO_ROOT}`);
const server = spawn("python3", ["-m", "http.server", PORT, "--bind", "127.0.0.1"], {
  cwd: REPO_ROOT,
  stdio: ["ignore", "ignore", "pipe"],
});
server.stderr.on("data", () => {}); // suppress access-log noise
process.on("exit", () => server.kill());

await waitForPort(PORT, 10_000);
console.log(`[test] server ready`);

const files = readdirSync(resolve(import.meta.dirname, "e2e"))
  .filter(f => f.endsWith(".test.mjs"))
  .sort()
  .map(f => resolve(import.meta.dirname, "e2e", f));

console.log(`[test] running ${files.length} test files (per-file process)`);

// Spawn one Node process per file so each file's Playwright browser
// (closed in the after() hook) doesn't leak into the next file.
let failed = 0;
for (const file of files) {
  const rel = file.replace(REPO_ROOT + "/", "");
  console.log(`\n--- ${rel} ---`);
  const child = spawn(
    process.execPath,
    ["--test", "--test-reporter=spec", "--test-timeout=60000", file],
    { stdio: "inherit", env: { ...process.env, BASE_URL: `http://localhost:${PORT}` } },
  );
  const code = await new Promise(resolve => child.on("exit", resolve));
  if (code !== 0) failed++;
}

server.kill();
console.log(failed === 0 ? "\n[test] OK" : `\n[test] FAILED (${failed} file(s))`);
process.exit(failed === 0 ? 0 : 1);

async function waitForPort(port, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/index.html`);
      if (res.ok) return;
    } catch (_) {}
    await new Promise(r => setTimeout(r, 100));
  }
  throw new Error(`server did not come up on :${port} within ${timeoutMs} ms`);
}
