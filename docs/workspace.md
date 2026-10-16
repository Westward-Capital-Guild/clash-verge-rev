# Company workspace: smoke and deployment

The public UI and companion implement generic OIDC and provisioning. Organization
domains, policies and service adapters belong in private deployment configuration
or a separately deployed private gateway. A local device owner can still inspect
the endpoints that their device needs; upstream service topology stays behind the
gateway.

Company builds inject one trusted HTTPS bootstrap URL using
`PILGRIM_WORKSPACE_BOOTSTRAP_URL` at Rust build time. The native companion obtains
bootstrap v1, displays Feishu only, and consumes policy v2. Service URLs and OIDC
endpoints must share the bootstrap origin; redirects and employee JSON fallback
are rejected. Network and development-host grants are independent. The initial
API has no local model credential endpoint, and company mode never calls the
legacy credential action or writes a Codex provider/profile.

The source contains only generic protocol examples and synthetic fixtures. Supply
company build input outside this checkout; do not use a `VITE_` variable or commit
private build environment files. An uninjected build honestly shows unavailable
company access. Developer-only legacy JSON below remains available for reusable
OIDC regression tests, not employee onboarding.

A public bootstrap response does not establish employee identity, resource
ownership or real business acceptance. Authentication requires a real Feishu
login; resource delivery requires references bound to the correct employee.

Company Feishu members may sign in without separate Workspace approval. Resource
assignment is independent of sign-in: an employee with no delivery record remains
signed in and sees unassigned resources. The current service's
`MEMBER_NOT_REGISTERED` delivery response retains its diagnostic code but is shown
as unassigned, not as a request to register or obtain permission to sign in.

## Local smoke

Install the repository's pinned pnpm dependencies and Rust 1.99 toolchain. Then:

```sh
pnpm install --frozen-lockfile
pnpm prebuild
uv sync --project companion --extra test --frozen
uv run --project companion --extra test --frozen pytest companion/tests -q
uv run --project companion --extra test --frozen python companion/tests/browser_smoke.py /tmp/workspace-evidence
pnpm web:build
cargo check -p clash-verge --features dev-sidecar
```

The browser smoke uses `/usr/bin/chromium` on Linux and Playwright's installed
Chromium on other platforms. Set `WORKSPACE_SMOKE_BROWSER` to an existing Chromium
browser's executable to override it. It drives the actual workbench through
the actual companion using a local signed OIDC fixture with PKCE. Credentials are
held in a test-only memory store and `CODEX_HOME` points to a temporary directory.
It covers login, configuration, denial, logout and a 390px layout. The Linux
x86_64 and macOS core smoke starts the prepared real mihomo on an ephemeral loopback
port and verifies an HTTP request through it; it never changes the host proxy,
TUN or DNS. It skips explicitly if the core has not been downloaded.

For the native Linux window smoke, build with `cargo build -p clash-verge --bin
pilgrim-workspace --features dev-sidecar`, then run:

```sh
uv run --project companion --extra test --frozen python -c "import PIL"
xvfb-run -a -s '-screen 0 1280x900x24 -extension GLX' \
  companion/.venv/bin/python companion/tests/native_smoke.py /tmp/workspace-evidence
```

The native script uses isolated XDG directories, a private DBus session and no configured tenant. Inspect
its screenshot for the rendered workbench and unconfigured state. On hosts where
NVIDIA EGL initialization crashes Xvfb, prefix the command with
`env __EGL_VENDOR_LIBRARY_FILENAMES=/usr/share/glvnd/egl_vendor.d/50_mesa.json LIBGL_ALWAYS_SOFTWARE=1`
when that Mesa vendor file exists.

These tests do not establish live Authentik/Feishu, OS keyring, native login,
system proxy/TUN or installed-package acceptance. Test scripts are outside the production
Vite root and the production companion CLI has no plaintext credential-store mode.

## Desktop companion

Distribution builds run `pnpm workspace:companion` before the frontend build.
Build machines require Python 3.11+, uv and the target architecture; `companion/uv.lock`
pins the bundler and runtime dependencies. PyInstaller produces a native onedir
runtime under the ignored `src-tauri/resources/companion/` directory. Tauri includes
it as resources, and Rust resolves its executable from the app resource directory.
Employees do not install Python, install a companion separately or set environment
variables. Sign/notarize the complete bundle through the company release process.

For local development only, `PILGRIM_WORKSPACE_AGENT` may select an absolute
executable, and `PILGRIM_WORKSPACE_CONFIG` may select legacy fixture JSON. A company
build's embedded bootstrap takes precedence and suppresses the JSON wiring.

Version 2 enables independent Feishu and Authentik buttons. Each provider owns
its issuer, client and downstream endpoints; only the selected provider receives
its credentials. Remove a provider to hide its entry. Version 1 configurations
remain supported as a single Authentik entry.

Developer fixture JSON (all domains below are placeholders; not employee instructions):

```json
{
  "version": 2,
  "providers": {
    "feishu": {
      "issuer": "https://passport.example.invalid",
      "client_id": "workspace-desktop",
      "redirect_port": 47831,
      "policy_endpoint": "https://gateway.example.invalid/feishu/workspace/policy",
      "credential_endpoint": "https://gateway.example.invalid/feishu/workspace/credential"
    },
    "authentik": {
      "issuer": "https://identity.example.invalid/application/o/workspace/",
      "client_id": "workspace-desktop",
      "redirect_port": 47831,
      "policy_endpoint": "https://gateway.example.invalid/authentik/workspace/policy",
      "credential_endpoint": "https://gateway.example.invalid/authentik/workspace/credential"
    }
  }
}
```

Keep the file in a user-owned private directory outside this checkout. Do not
place secrets in it. Use HTTPS; plain HTTP is accepted only for literal loopback
hosts used by smoke fixtures. A configuration change selects a different keyring
account so a previous deployment's tokens are not reused.

The production store uses macOS Keychain, Windows Credential Manager or Linux
Secret Service/libsecret. An unavailable or unsupported backend fails closed;
there is no plaintext fallback. A headless Linux session needs a working,
unlocked session keyring before real sign-in can be tested.

## Authentik and Feishu

Configure an Authentik OAuth2/OpenID Provider as a **public** client, with an
asymmetric signing key (RS256 or ES256), Authorization Code and S256 PKCE. Register
the exact redirect URI `http://127.0.0.1:47831/callback` (or the configured fixed
port). Permit `openid profile offline_access` and refresh tokens according to
your session policy. The discovery issuer must exactly match the configured
issuer, including its trailing slash. No desktop client secret is used.

The client validates the callback state and signed ID token's issuer, audience,
expiry and nonce, and preserves the subject when refreshing. Browser cancellation
and a two-minute callback timeout do not create a session. Sign-in uses the system
browser. An expired session can be renewed by the Codex helper if a refresh token
is available, or the employee can sign out and sign in again.

The Feishu button connects to the company's Feishu OIDC service,
which owns the upstream Feishu login. It does not require Authentik federation
and never embeds a Feishu app secret. The company OIDC server must include
native public-client support: discovery advertises `none` client authentication
and `S256`, token exchange enforces the verifier, and `/oauth2/revoke` revokes the
presented native client's token. An older server is rejected; no secret-based or
non-PKCE fallback is provided. Register a distinct public desktop client with the
exact loopback callback. The private service's deployment/runbook owns registration.

Feishu requests `openid profile`; the company Feishu provider does not currently issue refresh
tokens. Expiry requires signing out and back in. Authentik requests
`openid profile offline_access` and retains refresh support. The desktop permits
one active provider at a time: sign out before switching. Session provider identity
persists in the OS keyring. The Codex helper command is bound to that provider;
after switching, synchronize Codex again before use. A stale configuration
cannot fetch the new provider's credential for the previous provider's model URL. Accounts are never merged by display name or email.
Gateway validators must accept the matching issuer/client and enforce their own
authorization; configuring two UI entries does not configure gateway trust.

## Private gateway contract

`GET policy_endpoint` receives the user's OIDC access token as a bearer credential.
The gateway must validate its issuer, audience, expiry and user authorization.
It returns only the user's allowed configuration:

```json
{
  "version": 1,
  "codex": { "base_url": "https://models.example.invalid/v1", "model": "approved-model" },
  "network": { "profile_endpoint": "https://gateway.example.invalid/workspace/network-profile" }
}
```

The profile endpoint returns a mihomo YAML profile. It must use the same origin
as the policy endpoint, because the companion sends the user's bearer credential.
HTTP redirects are not followed. Native Rust imports the YAML through upstream
profile operations; tokens and profile contents never pass through the workbench
WebView. Connecting selects the managed profile and enables the system proxy.
It does not enable TUN. Workspace disconnect/logout changes only the application-owned system proxy and does not disable unrelated TUN sessions.

`POST credential_endpoint` receives the same user bearer credential and
`{"audience":"codex"}`. It must issue a **separate**, user-scoped model credential:

```json
{ "access_token": "short-lived-model-credential", "expires_in": 300 }
```

The helper requires at least 90 seconds of remaining validity, emits only the
token on stdout, and does not persist this gateway credential. The deployment
must choose a short maximum lifetime and implement gateway-side revocation or
session checks as required. OIDC token revocation does not automatically revoke
an independently issued model or network credential.

Logout disconnects local networking and attempts to revoke both OIDC refresh and
access tokens using the discovered revocation endpoint. Local session storage is
cleared even when remote revocation fails; the UI reports that failure. The
browser's IdP SSO cookie is not cleared. The next login may reuse that SSO session.

## Codex configuration

Synchronization adds only `model_providers.pilgrim` to the user's `config.toml`,
preserving other settings, profiles and comments. It does not create a profile
file. A conflicting provider is rejected. The first previous file is saved as
`config.before-workspace.toml`; writes are atomic and companion updates serialize.
The default model/provider is not changed. Select the company provider and a
model approved by the deployment policy, for example:

```sh
codex -c 'model_provider="pilgrim"' --model <approved-model>
```

The provider uses a command-backed bearer-token helper. The deployed Codex must
support `[model_providers.<id>.auth]` with `command`, `args`, `timeout_ms` and
`refresh_interval_ms`; see the [official configuration documentation](https://developers.openai.com/codex/config-advanced/).
An older unsupported Codex must be upgraded before using this configuration.
Configuration status is not evidence that Codex is installed or a real model call
works. Never test with an existing personal `CODEX_HOME` when running local smoke.

## Release boundary

The macOS app bundle, main executable, application data, development control
record and sidecar socket use the Pilgrim Workspace identity. This smoke build
still uses upstream core execution coordination and does **not** support
concurrent mihomo/VPN clients or shared system-proxy ownership. Before any native
setup, macOS startup refuses a running official app, active upstream core or enabled system proxy and
asks the user to quit the third-party VPN/proxy. It never stops that client.
Local proxy cleanup preserves a proxy that this process did not enable or that
another client replaced. Test with `dev-sidecar`; do not install or operate the
upstream privileged service. Privileged service operations are disabled in every build, including development
service commands. All development modes use sidecar; there is no separate
privileged service to install. A distinct bundle identifier does not make
simultaneous VPN routing safe.

Personal remote development machines are a separate capability. Company mode
retrieves the signed-in employee's authorized hosts using the opaque access token,
checks the binding and revision, and displays network requirements and approved
directories. An explicit preparation/check downloads a managed Ed25519 credential
or matches an existing approved local public key/ssh-agent identity. Native code
verifies the private key fingerprint and installs it atomically with 0600
permissions in the dedicated 0700 SSH directory. Changed files, host pins and
identities stop the operation without overwriting them. No key enters WebView,
logs, command arguments or a remote model configuration.

The manager prepends a managed Include while preserving existing SSH config bytes
and keeps concrete stable aliases, strict known_hosts and fixed local directives
in separate fragments. OpenSSH resolution is checked through the personal config.
Hosts requiring the company proxy use the application's verified local SOCKS port;
Tailscale assignments require the existing Tailscale network. No proxy/TUN client
is installed or silently stopped.

Logout cancels pending application SSH operations and clears/revokes the Passport
session; installed SSH keys and entries remain. It does not terminate unrelated
connections or revoke SSH authorization. Upstream offboarding is an administrator
responsibility. Mobile templates and private mobile delivery are untouched.

Companion bundling has been exercised on Intel macOS, but a locally built/ad-hoc
signed runtime is not a signed/notarized release. Package installation, actual
company network access, real employee login and Desktop project acceptance remain
separate evidence requirements.


## Current access-service integration boundary

The contract is exercised by `companion/tests/test_workspace_access.py` through
production companion HTTP calls against synthetic fixtures with isolated XDG,
SSH and CODEX_HOME state. It covers independent capabilities, same-origin/version
checks, credential binding/revision validation, incorrect key rejection, member
isolation, 0600 permissions, idempotence, conflicts and stable error codes. Existing
SSH tests also use a real temporary loopback sshd. These tests do not establish
live employee or Desktop acceptance.

Network download is explicit on connect/update, bounded to 2 MB and validated by
the actual bundled mihomo before import. Updates publish a new profile instead
of overwriting the previous valid file. Selection/proxy failures preserve the
previous selection where rollback is possible. Status reports system-proxy
activation separately from unverified target reachability. macOS retains the
pre-takeover proxy dictionaries in memory and restores only services whose settings
still exactly match this process's applied state. A refused restoration is reported;
controlled shutdown retains the core and ownership for a restoration retry.

The supported Desktop route is Settings → Connections, add/enable the concrete
SSH alias, then select the remote folder. There is no verified public automatic
project-add API in this client. An SSH check does not mark a Desktop project as
opened or a remote task as completed. See the
[official remote connection instructions](https://learn.chatgpt.com/docs/remote-connections).
