# Source provenance

This provider remains licensed under MPL-2.0 and preserves upstream notices.
The v2.5.0 work is based on these pinned public sources:

| Remote | Repository | Pinned commit | Use |
|---|---|---|---|
| `upstream` | [osodevops/terraform-provider-workos](https://github.com/osodevops/terraform-provider-workos) | `181d4b93cfc7ce3de444cd6bab15b084f05b5b0e` (`v2.4.0`) | Provider baseline |
| `cloudraker` | [CloudRaker/terraform-provider-workos](https://github.com/CloudRaker/terraform-provider-workos) | `061f9cdbced83741edfda1b51322b7e33a1d4166` | Environment-role provenance; no code copied because upstream v2.4.0 already contains the change |
| `linusbf` | [LinusBF/terraform-provider-workos](https://github.com/LinusBF/terraform-provider-workos) | `29963578721da9667c071bbb49dab9e102cd186a` | AuthKit redirect URI and CORS origin resources and tests only |

LinusBF's webhook resource and fork release workflow were intentionally not imported.
