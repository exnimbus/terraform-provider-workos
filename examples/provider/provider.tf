terraform {
  required_providers {
    workos = {
      source  = "exnimbus/workos"
      version = "~> 2.5"
    }
  }
}

# Configure the WorkOS Provider
#
# Authentication can be provided via:
# 1. The api_key attribute below
# 2. The WORKOS_API_KEY environment variable
#
provider "workos" {
  # api_key = var.workos_api_key  # Or use WORKOS_API_KEY env var
}
