# Company workspace: smoke and deployment

The public UI and companion implement generic OIDC and provisioning. Organization
domains, policies and service adapters belong in private deployment configuration
or a separately deployed private gateway. A local device owner can still inspect
the endpoints that their device needs; upstream service topology stays behind the
gateway.

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

The browser smoke uses `/usr/bin/chromium`. It drives the actual workbench through
the actual companion using a local signed OIDC fixture with PKCE. Credentials are
held in a test-only memory store and `CODEX_HOME` points to a temporary directory.
It covers login, configuration, denial, logout and a 390px layout. The Linux
x86_64 core smoke starts the downloaded real mihomo on an ephemeral loopback
port and verifies an HTTP request through it; it never changes the host proxy,
TUN or DNS. It skips explicitly if the core has not been downloaded.

For the native Linux window smoke, build with `cargo build -p clash-verge --bin
clash-verge --features dev-sidecar`, then run:

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

Install Python 3.11+ and the companion using an isolated environment, for example
`uv tool install ./companion`. Supply its absolute executable path to the desktop
process through `PILGRIM_WORKSPACE_AGENT`. Supply the deployment JSON path through
`PILGRIM_WORKSPACE_CONFIG`. Both are process configuration, never frontend inputs.
The default deployment path is `~/.config/pilgrim-workspace/config.json`.

Version 2 enables independent Feishu and Authentik buttons. Each provider owns
its issuer, client and downstream endpoints; only the selected provider receives
its credentials. Remove a provider to hide its entry. Version 1 configurations
remain supported as a single Authentik entry.

Example deployment JSON (all domains below are placeholders):

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
It does not silently enable TUN. Disconnecting disables system proxy and TUN.

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

Synchronization adds only `model_providers.pilgrim` and `profiles.pilgrim` to the
user's `config.toml`, preserving other settings and comments. A conflicting
provider/profile is rejected. The first previous file is saved as
`config.before-workspace.toml`; writes are atomic and companion updates serialize.
The default model/provider is not changed. Start with:

```sh
codex --profile pilgrim
```

The provider uses a command-backed bearer-token helper. The deployed Codex must
support `[model_providers.<id>.auth]` with `command`, `args`, `timeout_ms` and
`refresh_interval_ms`; see the [official configuration documentation](https://developers.openai.com/codex/config-advanced/).
An older unsupported Codex must be upgraded before using this configuration.
Configuration status is not evidence that Codex is installed or a real model call
works. Never test with an existing personal `CODEX_HOME` when running local smoke.

## Release boundary

The first candidate uses a separately installed companion executable, not a
bundled Python runtime. Before desktop distribution, package and sign the
companion, isolate privileged-service/package identifiers, provide a signed
company update channel and validate installation/startup/logout on each supported
OS. Do not install the upstream service or publish this smoke build as a finished
company desktop release.
