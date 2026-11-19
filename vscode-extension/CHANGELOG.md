# Changelog

All notable changes to the Bug Dhor VS Code extension are documented here. This is the
Marketplace-facing changelog for `sajib91.bug-dhor`.

## [0.1.0] - 2026-11-19

> Initial release-candidate documentation. This version has **not** been published to the
> Visual Studio Marketplace.

### Added

- Bug Dhor Activity Bar container, sidebar launcher, and editor-area Security Dashboard.
- Native VS Code diagnostics, hover explanations, and repair Quick Fixes generated only from
  validated backend scan results.
- Explicit commands for file, selection, workspace, repository, changed-file, explanation,
  counterfactual, repair, and verification workflows.
- Environment-backed API token support and source-sharing privacy controls.
- Opt-in local Phase 6 explanation, repair preview, apply, verify, revert, and history commands.
  These require the repository checkout's `src/bugdhor_ast` module and are not bundled in the VSIX.
- Marketplace documentation for backend installation, startup, configuration, troubleshooting,
  privacy controls, and limitations.

### Changed

- Packaging now stages production dependencies in a clean temporary copy to avoid npm workspace
  parent traversal.
- `@vscode/vsce` was moved to the 4.x line so release preparation can use OIDC Trusted Publishing.
- Marketplace metadata now uses the approved publisher `sajib91`, repository URLs, a 128×128 PNG
  icon, and categories limited to capabilities that are currently wired.

### Known limitations

- The Python backend is distributed separately and must be started before scanning.
- SAE feature extraction, counterfactual effects, and activation steering remain unavailable in the
  default integrated path without compatible artifacts and model access.
- Repairs are proposals. No patch is applied without explicit user approval, and static
  reverification is not a security guarantee.
- No Marketplace screenshots are bundled yet.
- The repository MIT license is now present and is staged into the VSIX by the clean packaging
  script. No license warning is suppressed.
- Publication remains blocked by the open Phase 04 release gates, publisher-identity verification,
  and owner-side Marketplace Trusted Publishing configuration.

See `../reports/PHASE_06_MARKETPLACE_READINESS.md` and `../reports/PHASE_07_PUBLISHING_SETUP.md`
for the evidence and release gates.
