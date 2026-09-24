/* global console, process */

import { createHash, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(SCRIPT_DIR, "../..");
const TARGET_DIR = resolve(ROOT, process.env.CARGO_TARGET_DIR || "target");
const BUILD_DIR = join(TARGET_DIR, "sidecars", "runne-credential-service");
const SOURCE_DIR = join(ROOT, "apps/desktop/src-tauri/macos/credential-service");
const STAGING_ROOT = join(SOURCE_DIR, "staged");
const FINAL_APP = join(STAGING_ROOT, "RunneCredentialService.app");
const NATIVE_ENROLLMENT_DIR = join(SOURCE_DIR, "../native-enrollment");
const NATIVE_ENROLLMENT_STAGE = join(NATIVE_ENROLLMENT_DIR, "staged");

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
  if (declared.length === 1) return declared[0];
  const match = output("rustc", ["-vV"]).match(/^host: (.+)$/m);
  if (!match) throw new Error("rustc did not report a host target");
  return match[1];
}

const target = targetTriple();
if (!target.endsWith("-apple-darwin")) {
  console.log(JSON.stringify({ binary: "runne-credential-service", skipped: target }));
  process.exit(0);
}
execFileSync(
  "cargo",
  ["build", "-p", "runne-credential-service", "--release", "--target", target],
  { cwd: ROOT, stdio: "inherit", env: { ...process.env, CARGO_TARGET_DIR: BUILD_DIR } },
);

const source = join(BUILD_DIR, target, "release", "runne-credential-service");
requireRegularFile(source, "service executable");
requireRegularFile(join(SOURCE_DIR, "Info.plist"), "service Info.plist");
requireRegularFile(join(SOURCE_DIR, "../credential-service.entitlements"), "service entitlements");
requireRegularFile(join(NATIVE_ENROLLMENT_DIR, "xpc-protocol-v1.json"), "XPC protocol descriptor");
stageProtocolDescriptor();
stageReleaseCandidateBinding(target);
const temporary = join(STAGING_ROOT, `.RunneCredentialService.${process.pid}.${randomUUID()}.tmp`);
const contents = join(temporary, "Contents");
const macos = join(contents, "MacOS");
try {
  ensureDirectory(STAGING_ROOT);
  mkdirSync(macos, { recursive: true, mode: 0o700 });
  copyFileSync(join(SOURCE_DIR, "Info.plist"), join(contents, "Info.plist"));
  copyFileSync(source, join(macos, "runne-credential-service"));
  chmodSync(join(macos, "runne-credential-service"), 0o755);
  const profile = process.env.RUNNE_CREDENTIAL_SERVICE_PROVISIONING_PROFILE;
  if (profile) {
    const resolvedProfile = resolve(profile);
    requireRegularFile(resolvedProfile, "service provisioning profile");
    copyFileSync(resolvedProfile, join(contents, "embedded.provisionprofile"));
  }
  rmSync(FINAL_APP, { recursive: true, force: true });
  renameSync(temporary, FINAL_APP);
} catch (error) {
  rmSync(temporary, { recursive: true, force: true });
  throw error;
}

const staged = readFileSync(join(FINAL_APP, "Contents/MacOS/runne-credential-service"));
console.log(JSON.stringify({
  binary: "runne-credential-service",
  bytes: staged.length,
  profile: existsSync(join(FINAL_APP, "Contents/embedded.provisionprofile")),
  sha256: createHash("sha256").update(staged).digest("hex"),
  target,
}));

function ensureDirectory(path) {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new Error(`staging directory must be a regular directory: ${path}`);
  }
}

function requireRegularFile(path, label) {
  if (!existsSync(path)) throw new Error(`${label} is missing: ${path}`);
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isFile()) {
    throw new Error(`${label} must be a regular file: ${path}`);
  }
}

function stageReleaseCandidateBinding(targetTriple) {
  const candidate = process.env.RUNNE_RELEASE_CANDIDATE_SHA256 || "0".repeat(64);
  if (!/^[0-9a-f]{64}$/.test(candidate)) {
    throw new Error("RUNNE_RELEASE_CANDIDATE_SHA256 must be lowercase SHA-256");
  }
  if (process.env.APPLE_SIGNING_IDENTITY && !process.env.RUNNE_RELEASE_CANDIDATE_SHA256) {
    throw new Error("signed package requires RUNNE_RELEASE_CANDIDATE_SHA256");
  }
  const config = JSON.parse(readFileSync(join(ROOT, "apps/desktop/src-tauri/tauri.conf.json")));
  const arch = targetTriple.startsWith("aarch64-") ? "arm64" : "x86_64";
  const bytes = JSON.stringify({
    arch,
    platform: "macos",
    productId: config.identifier,
    profileId: "gocode-ui-client/3",
    releaseCandidateSha256: candidate,
    schemaVersion: 1,
    version: config.version,
  });
  writeAtomicResource("release-candidate-binding.json", bytes);
}

function stageProtocolDescriptor() {
  const source = join(NATIVE_ENROLLMENT_DIR, "xpc-protocol-v1.json");
  const text = readFileSync(source, "utf8").trim();
  const value = JSON.parse(text);
  if (JSON.stringify(value) !== text) {
    throw new Error("XPC protocol descriptor must be canonical JSON");
  }
  writeAtomicResource("xpc-protocol-v1.json", text);
}

function writeAtomicResource(name, bytes) {
  ensureDirectory(NATIVE_ENROLLMENT_STAGE);
  const final = join(NATIVE_ENROLLMENT_STAGE, name);
  const temporary = `${final}.${process.pid}.${randomUUID()}.tmp`;
  try {
    writeFileSync(temporary, bytes, { encoding: "utf8", mode: 0o600, flag: "wx" });
    renameSync(temporary, final);
  } catch (error) {
    rmSync(temporary, { force: true });
    throw error;
  }
}
