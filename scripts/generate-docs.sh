#!/bin/sh
set -eu

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT
mkdir -p "$tmp_dir/bin" "$tmp_dir/config"

go build -o "$tmp_dir/bin/terraform-provider-workos"

cat >"$tmp_dir/tofurc" <<EOF
provider_installation {
  dev_overrides {
    "exnimbus/workos" = "$tmp_dir/bin"
  }
  direct {}
}
EOF

cat >"$tmp_dir/config/main.tf" <<'EOF'
terraform {
  required_providers {
    workos = {
      source = "exnimbus/workos"
    }
  }
}
EOF

TF_CLI_CONFIG_FILE="$tmp_dir/tofurc" tofu -chdir="$tmp_dir/config" providers schema -json >"$tmp_dir/schema.json"
# tfplugindocs v0.24 only recognizes HashiCorp-hosted schema keys.
sed 's#registry.opentofu.org/exnimbus/workos#registry.terraform.io/hashicorp/workos#' "$tmp_dir/schema.json" >"$tmp_dir/docs-schema.json"
go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs generate -provider-name workos -providers-schema "$tmp_dir/docs-schema.json"
