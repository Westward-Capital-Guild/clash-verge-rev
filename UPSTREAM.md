# Pilgrim Workspace fork

This is an unofficial company-workspace fork maintained by Westward Capital
Guild, not an official Clash Verge Rev distribution. The GPL-3.0-only license,
copyright notices and upstream history remain intact.

- Upstream: https://github.com/clash-verge-rev/clash-verge-rev
- Fork: https://github.com/Westward-Capital-Guild/clash-verge-rev
- Starting revision: `dc5a8a5ff443c020a3dec79c2b46bc1f55411d95` (upstream `dev`)
- Scope: https://github.com/Westward-Capital-Guild/clash-verge-rev/issues/1

The fork adds an employee workbench, native companion-command adapter and a
generic per-user OIDC companion. Network lifecycle stays with the upstream
implementation. Private deployments supply their own configuration and gateway;
this repository contains no production tenant or private service addresses.

Upstream upgrade seams are navigation, command registration/generated bindings,
application identity and updater isolation. Review these when rebasing. The
workspace adapter should be removed if upstream gains an equivalent supported
extension mechanism; preserve private deployment configuration outside the fork.

Company updates are disabled until an independently signed release channel is
configured. Privileged service operations are disabled; development uses sidecar without
installing or operating the upstream service. Companion runtime bundling is implemented; package signing still requires release engineering before distribution. This branch is a smoke candidate, not a signed desktop release.

See [the local smoke and deployment guide](docs/workspace.md).
