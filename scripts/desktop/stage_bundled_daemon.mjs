/* global console, process */

import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(SCRIPT_DIR, "../..");
const TARGET_DIR = resolve(process.env.CARGO_TARGET_DIR || join(ROOT, "target"));
const SIDECAR_DIR = join(ROOT, "apps/desktop/src-tauri/binaries");

function output(command, args) {
  return execFileSync(command, args, { cwd: ROOT, encoding: "utf8" }).trim();
}

function hostTarget() {
  const rustc = output("rustc", ["-vV"]);
  const match = rustc.match(/^host: (.+)$/m);
  if (!match) throw new Error("rustc did not report a host target");
  return process.env.CARGO_BUILD_TARGET || process.env.TARGET || match[1];
}

const target = hostTarget();
const extension = target.includes("windows") ? ".exe" : "";
const binaryName = `runned${extension}`;
execFileSync("cargo", ["build", "-p", "runne-daemon", "--bin", "runned", "--release", "--features", "desktop-protected"], {
  cwd: ROOT,
  stdio: "inherit",
  env: process.env,
});

const candidates = [
  join(TARGET_DIR, target, "release", binaryName),
  join(TARGET_DIR, "release", binaryName),
];
const source = candidates.find((candidate) => existsSync(candidate));
if (!source) {
  throw new Error(`release daemon was not produced for ${target}`);
}

mkdirSync(SIDECAR_DIR, { recursive: true });
const destination = join(SIDECAR_DIR, `runned-${target}${extension}`);
copyFileSync(source, destination);
console.log(`staged bundled daemon: ${destination}`);
