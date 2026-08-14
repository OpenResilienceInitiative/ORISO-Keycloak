# ORISO Keycloak

This repository contains ORISO-specific Keycloak configuration and custom image
source used by the platform authentication stack.

## Purpose

The repository is intended as the source of truth for Keycloak-specific material
that belongs outside the platform Helm chart, including realm configuration,
custom providers, themes, helper scripts, and image build workflows.

Runtime deployment and environment configuration are managed through
[ORISO-Helm](https://github.com/OpenResilienceInitiative/ORISO-Helm).

## Repository Contents

- `realm.json`: ORISO realm configuration reference
- `keycloak-image/`: custom Keycloak image source, providers, and themes
- `scripts/`: helper scripts for Keycloak setup and maintenance
- `.github/workflows/`: CI and image release workflows

## Custom Image

The custom image bundles ORISO Keycloak extensions and theme assets. The image
is built and published by the repository workflows, then consumed by the ORISO
Helm chart.

## Working Guidelines

- Keep Keycloak runtime configuration environment-driven where possible.
- Keep deployment wiring in ORISO-Helm.
- Do not commit secrets, live credentials, or personal access details.
- Keep documentation short and focused on current repository ownership.
- Prefer small, reviewable changes for realm, provider, theme, and workflow
  updates.
