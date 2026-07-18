# Release guide

## Prerequisites

- Push the reviewed source to `github.com/exnimbus/terraform-provider-workos`.
- Add `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE` GitHub Actions secrets for the release key.
- Submit [`gpg-public-key.asc`](../gpg-public-key.asc), fingerprint `44100B8EA509D7A831880A1101447776A5455567`, through the OpenTofu Registry's **new provider signing key** issue form.
- Keep `terraform-registry-manifest.json` in every release checksum set.

## Release v2.5.0

```bash
go test ./...
go generate ./...
golangci-lint run ./...
git tag -s v2.5.0 -m "v2.5.0"
git push origin v2.5.0
```

The tag triggers `.github/workflows/release.yml`. GoReleaser builds provider archives, includes the registry manifest in SHA256SUMS, and creates a detached GPG signature for that checksum file.

Verify the release contains provider archives, `terraform-provider-workos_2.5.0_SHA256SUMS`, its `.sig`, and the manifest. Do not publish a release whose checksum is unsigned.

## OpenTofu Registry

After the signed GitHub release exists, submit the provider through the OpenTofu Registry's **new provider** issue form. The registry requires its structured browser form; CLI/API-created issues and pull requests are not accepted.

Once accepted, verify from a clean directory:

```hcl
terraform {
  required_providers {
    workos = {
      source  = "exnimbus/workos"
      version = "2.5.0"
    }
  }
}
```

```bash
tofu init
tofu providers
```

OpenTofu must report `registry.opentofu.org/exnimbus/workos` and verify the signed package before any WorkOS rollout begins.
