# Standalone Linux CLI credential host

`runne provider credential login deepseek` replaces the CLI process with its
packaged `runne-credential-host` sibling. Stop the runtime before enrollment;
the host acquires the ordinary daemon bootstrap locks and uses the runtime's
managed credential lifecycle store. It does not start the HTTP server or make
provider requests.

The owner-private external daemon config explicitly opts in:

```toml
[linux_cli_credential_host]
cli_sha256 = "<SHA-256 of installed runne>"
daemon_sha256 = "<SHA-256 of installed runned>"
host_sha256 = "<SHA-256 of installed runne-credential-host>"
```

All three executable files and their ancestor directories must be owner/root
controlled and not group/world writable. Replacing an image or changing config
closes access until the configuration is explicitly updated. This mode is
separate from signed Desktop release qualification and its enrollment API.

The host requires an ordinary user's foreground controlling terminal, disables
process dumps, reads at most 4096 visible ASCII bytes without echo, and restores
terminal settings on completion, rejection, Ctrl+C, or handled termination.
Input is not accepted from stdin, argv, environment, HTTP, or a key file.

The native backend uses the existing owner-validated Secret Service/keyutils
implementation. A locked, missing, foreign, or otherwise unavailable backend
fails closed without an unlock prompt or automatic provider request. Native
entries are separated from legacy/Desktop accounts and from other runtime
DBs by runtime authority. Only the credential host writes; the daemon receives
reader-only composition.

Pairing uses durable begin/claim/effect/readback/completion transitions. Exact
native source revision and successful persistent readback precede activation.
An uncertain native effect remains pending for existing lifecycle reconciliation;
it is not reported as success or automatically retried. This command does not
implement legacy import, OAuth, native revoke, or remote verification.

`runne status` prints the selected provider readiness authenticated by the
runtime. `ready` confirms local readiness, not API key validity or provider
availability. Remote validity requires a separately initiated provider task.
