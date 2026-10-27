---
authors:
  - "@drew"
  - "@SDAChess"
state: draft
links:
  - https://github.com/NVIDIA/OpenShell/issues/4425
---

# RFC 0019 - A Smaller Core and a Wider Tent

## Summary

Let's split OpenShell into a smaller core repository and a set of focused
repositories for platforms, packaging, SDKs, and provider integrations. The goal
is to make it easier for new maintainers to own a useful part of OpenShell while
keeping the core small enough to maintain well.

## Motivation

OpenShell covers a lot of ground. Someone who wants to maintain a Kubernetes
integration, a package, or an SDK shouldn't need to take on the whole project.
We want to widen the tent: give those contributors a clear home, ownership, and
room to move.

A smaller core lets its maintainers focus on the runtime and the contracts that
hold the ecosystem together. The surrounding repositories can build communities
with their own expertise, test infrastructure, and release responsibilities.

## Proposal

Organize OpenShell around a core repository and focused ecosystem repositories.
The `openshell` core owns the runtime, CLI, Rust SDK, and shared interfaces that
hold the system together. Go, Python, and TypeScript each get an SDK repository.
Packages and Homebrew own installation and distribution; Windows, desktop, and
Kubernetes repositories own their platform integrations. Each provider gets a
repository for its integration and tests. A shared software factory repository
provides automation and agent workflows for working across the OpenShell
organization's repositories.

The proposed repository structure is:

```text
OpenShell repositories
├── openshell                      Gateway, supervisor, sandbox, CLI, Rust SDK, shared Rust interfaces
├── openshell-sdk-go                Go SDK
├── openshell-sdk-python            Python SDK
├── openshell-sdk-typescript        TypeScript SDK
├── openshell-packages              install.sh, RPM, DEB, snap
├── openshell-homebrew              Homebrew tap and formula
├── openshell-windows               MSI installer and MXC driver
├── openshell-desktop               macOS App Sandbox, Podman, Docker
├── openshell-kubernetes            Helm chart, Kubernetes driver, operator
├── openshell-providers-<provider>  One repository per provider integration
├── openshell-awesome               Curated OpenShell resources and examples
└── openshell-software-factory      Shared action templates, skills, and agents
```

This gives maintainers a focused area to own while keeping the shared contracts
in core. Each repository is responsible for its releases and compatibility with
the core versions it supports.

### Core: `openshell`

- CLI, built for Linux, Windows, and macOS.
- Gateway, built for Linux, Windows, and macOS.
- Supervisor, built for Linux, Windows, and macOS.
- Linux sandbox runtime, with support for Linux isolation, gVisor, Kata, and
  Firecracker.
- Prover.
- Rust SDK, kept alongside the CLI as the reference client.
- Shared Rust interfaces used by components across repositories.
- A compute driver that assembles these components as processes on the host.
  On Linux, use `systemd-nspawn` for launch and isolation.
- Publication of binaries.

### SDK repositories

Each other language SDK gets its own repository:

| Repository | Owns and publishes |
| --- | --- |
| `openshell-sdk-go` | Go SDK, with its own maintainers, tests, and releases. |
| `openshell-sdk-python` | Python SDK, with its own maintainers, tests, and releases. |
| `openshell-sdk-typescript` | TypeScript SDK, with its own maintainers, tests, and releases. |

The Rust SDK stays in core as the reference client used by the CLI. Keeping them
together lets changes to the gateway, SDK, and CLI be developed and tested in one
repository. Each other language SDK gets its own repository so maintainers can
own its language-specific tooling and release process.

Core remains the source of truth for the public protobuf definitions. SDK
repositories should generate bindings from a pinned, published version of those
definitions, document which core releases they support, and test against those
releases. Automation should propose updates when core publishes new definitions
so separate repositories do not depend on manual copying to stay in sync.

### Packaging and installation

| Repository | Owns and publishes |
| --- | --- |
| `openshell-packages` | The one-line `install.sh` installation path; publishes RPM, DEB, and snap packages. |
| `openshell-homebrew` | The Homebrew tap; publishes the `openshell.rb` formula. |

### Windows: `openshell-windows`

- MSI installer and its publication.
- MXC driver and its publication.

### Desktop: `openshell-desktop`

- macOS isolation through App Sandbox and container integration.
- Podman integration.
- Docker integration.
- Possible microVM support. Whether this belongs here, in core, or in a separate
  repository remains an open question.

### Kubernetes: `openshell-kubernetes`

- Helm chart and its publication.
- Kubernetes compute driver, with support for gVisor, Kata, Firecracker, and runc.
- Kubernetes operator.

### Software factory: `openshell-software-factory`

- Shared GitHub Actions templates for repository automation.
- Skills for development and maintenance across OpenShell repositories.
- Agent definitions for coordinating work across repositories.

This repository owns the shared tooling for working across the OpenShell
organization's repositories, including changes that span multiple repositories.
Component repositories use these common workflows alongside their own
component-specific tests and release processes.

### Provider repositories and ownership

Each provider gets its own `openshell-providers-<provider>` repository, such as
`openshell-providers-aws`, `openshell-providers-google`,
`openshell-providers-oci`, or `openshell-providers-github`. Each owns its provider
integration and test infrastructure suited to that integration.

Each repository should have named maintainers and own its tests and published
artifacts. Shared Rust interfaces live in core alongside the Rust SDK. Core
maintainers own these shared contracts; integration maintainers own how their
implementation uses them. We need clear compatibility expectations
so users can assemble a working OpenShell without guessing which versions fit.

## Implementation plan

Migrate in the following order, preserving history where practical:

1. **SDKs.** Move Go, Python, and TypeScript into their respective repositories.
   Keep the Rust SDK and shared Rust interfaces in core. Establish the pinned
   protobuf inputs, SDK release automation, and compatibility tests before
   retiring the existing SDK paths. Document any package or import path changes.
2. **Packages.** Move `install.sh` and RPM, DEB, and snap packaging into
   `openshell-packages`. Validate installation and removal using artifacts from
   a pinned core release.
3. **Homebrew.** Move the tap and `openshell.rb` formula into
   `openshell-homebrew`. Validate formula installation against published core
   binaries.
4. **Windows.** Move the MSI installer and MXC driver into `openshell-windows`.
   Establish builds, installer checks, and driver compatibility tests against
   core.
5. **Kubernetes.** Move the Helm chart, Kubernetes compute driver, and operator
   into `openshell-kubernetes`. Establish chart publication and deployment tests
   against a pinned core release.
6. **Core.** Consolidate `openshell` around the CLI, gateway, supervisor, Linux
   sandbox runtime, prover, Rust SDK, shared Rust interfaces, and host compute
   driver. Update core builds and releases to consume the extracted components
   where needed, and validate that the released pieces work together. Provider
   integrations remain in place until the next phase.
7. **Providers.** Break out provider integrations one at a time into
   `openshell-providers-<provider>`, with maintainers, releases, and test
   infrastructure appropriate to each integration.

Before each move, name the maintainers and identify dependencies on the shared
checkout. Each new repository owns its tests, release automation, contribution
guidance, and documented compatibility relationship with core. Update
installation paths, documentation, and contributor skills with each move, and
validate the replacement before retiring its old paths. Desktop migration timing
remains an open question.

## Risks

More repositories mean more release and CI coordination. Changes that cross a
boundary may take longer, and an integration can fall behind core. Explicit
ownership, compatibility checks, and a gradual migration should help, but this
only works if the new repositories attract maintainers.

## Alternatives

We could keep the monorepo and delegate ownership through CODEOWNERS and focused
CI. That reduces migration work, but leaves everyone sharing the same repository
and release machinery. We could also split only packaging and integrations
first, then decide whether SDKs and platform drivers benefit from moving.

## Prior art

[RFC 0012](../0012-isolation-backend/README.md) separates compute orchestration,
supervision, and isolation behind contracts. Those boundaries give us a starting
point for deciding what can live outside core.

## Open questions

None
