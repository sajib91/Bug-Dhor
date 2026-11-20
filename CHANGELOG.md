# Changelog

All notable changes to the Bug Dhor repository are documented here. The Marketplace-facing copy
for the VS Code extension is [`vscode-extension/CHANGELOG.md`](vscode-extension/CHANGELOG.md).

## [0.2.0] - 2026-11-20

> This version has **not** been published to the Visual Studio Marketplace.

- The dashboard now renders only observed VS Code workspace data, real file events, and validated
  backend responses; demo and sample data were removed from the extension runtime and VSIX.
- Added automatic local engine lifecycle management, bundled engine source, engine start/stop and
  project-review commands, and explicit non-loopback source-sharing consent.
- CI now derives VSIX names from the extension manifest and records honest blocked/NO-GO evidence
  when required gates cannot run.

## [0.1.0] - 2026-11-19

- Initial release-candidate documentation for the VS Code extension and the separately installed
  Python security engine.
- Packaging, Marketplace documentation, compatibility testing, and OIDC publishing preparation were
  audited in `reports/PHASE_01_PACKAGING_AUDIT.md`, `reports/PHASE_04_SECURITY_AUDIT.md`,
  `reports/PHASE_05_PLATFORM_COMPATIBILITY.md`, `reports/PHASE_06_MARKETPLACE_READINESS.md`, and
  `reports/PHASE_07_PUBLISHING_SETUP.md`.
- **Not published.** The repository MIT license is present, but publication remains blocked by open
  Phase 04 findings, publisher-identity verification, and owner-side Trusted Publishing setup.
