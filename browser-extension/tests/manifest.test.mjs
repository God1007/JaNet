import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const extensionRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(fs.readFileSync(path.join(extensionRoot, "manifest.json"), "utf8"));

test("Manifest V3 observes both HTTP and HTTPS without blocking or content permissions", () => {
  assert.equal(manifest.manifest_version, 3);
  assert.ok(manifest.permissions.includes("webRequest"));
  assert.ok(manifest.permissions.includes("storage"));
  assert.ok(manifest.permissions.includes("alarms"));
  assert.equal(manifest.permissions.includes("webRequestBlocking"), false);
  assert.equal(manifest.permissions.includes("cookies"), false);
  assert.equal(manifest.permissions.includes("history"), false);
  assert.ok(manifest.host_permissions.includes("http://*/*"));
  assert.ok(manifest.host_permissions.includes("https://*/*"));
  assert.equal(manifest.content_scripts, undefined);
  assert.equal(manifest.background.type, "module");
});
