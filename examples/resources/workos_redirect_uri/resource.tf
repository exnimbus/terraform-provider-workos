resource "workos_redirect_uri" "production_callback" {
  uri = "https://app.example.com/api/auth/callback"
}

output "production_callback_redirect_uri_id" {
  value = workos_redirect_uri.production_callback.id
}

