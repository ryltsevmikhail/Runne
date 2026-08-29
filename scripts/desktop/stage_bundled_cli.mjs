/* global console, process */

import { createHash, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, lstatSync, mkdirSync, readFileSync } from "node:fs";
import { renameSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(SCRIPT_DIR, "../..");
const TARGET_DIR = resolve(ROOT, process.env.CARGO_TARGET_DIR || "target");
const SIDECAR_TARGET_DIR = join(TARGET_DIR, "sidecars", "runne");
const SIDECAR_DIR = join(ROOT, "apps/desktop/src-tauri/binaries");

function output(command, args) {
  return execFileSync(command, args, { cwd: ROOT, encoding: "utf8" }).trim();
}

function targetTriple() {
  const declared = [
    process.env.TAURI_ENV_TARGET_TRIPLE,
    process.env.CARGO_BUILD_TARGET,
    process.env.TARGET,
  ].filter(Boolean);
  if (new Set(declared).size > 1) throw new Error("conflicting build targets");
  if (process.env.TAURI_ENV_TARGET_TRIPLE) return process.env.TAURI_ENV_TARGET_TRIPLE;
  if (process.env.CARGO_BUILD_TARGET) return process.env.CARGO_BUILD_TARGET;
  if (process.env.TARGET) return process.env.TARGET;
  const rustc = output("rustc", ["-vV"]);
  const match = rustc.match(/^host: (.+)$/m);
  if (!match) throw new Error("rustc did not report a host target");
  return match[1];
}

const target = targetTriple();
const extension = target.includes("windows") ? ".exe" : "";
const binaryName = `runne${extension}`;
execFileSync("cargo", ["build", "-p", "runne-cli", "--bin", "runne", "--release", "--target", target], {
  cwd: ROOT,
  stdio: "inherit",
  env: { ...process.env, CARGO_TARGET_DIR: SIDECAR_TARGET_DIR },
});

const source = join(SIDECAR_TARGET_DIR, target, "release", binaryName);
if (!existsSync(source) || !lstatSync(source).isFile()) {
  throw new Error(`release artifact was not produced for ${target}: ${source}`);
}

ensureSidecarDirectory();
const destination = join(SIDECAR_DIR, `runne-${target}${extension}`);
stageArtifact(source, destination);
const staged = readFileSync(destination);
console.log(JSON.stringify({
  binary: "runne",
  bytes: staged.length,
  sha256: createHash("sha256").update(staged).digest("hex"),
  target,
}));

function stageArtifact(sourcePath, destinationPath) {
  const temporary = join(
    dirname(destinationPath),
    `.${binaryName}.${process.pid}.${randomUUID()}.tmp`,
  );
  try {
    copyFileSync(sourcePath, temporary);
    if (!lstatSync(temporary).isFile()) {
      throw new Error(`staged artifact is not a regular file: ${temporary}`);
    }
    // Renaming replaces a final-component link itself rather than following it.
    renameSync(temporary, destinationPath);
  } catch (error) {
    rmSync(temporary, { force: true });
    throw error;
  }
}

function ensureSidecarDirectory() {
  mkdirSync(SIDECAR_DIR, { recursive: true });
  const metadata = lstatSync(SIDECAR_DIR);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new Error(`sidecar directory must be a regular directory: ${SIDECAR_DIR}`);
  }
}
