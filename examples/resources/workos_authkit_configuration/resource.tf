resource "workos_authkit_configuration" "example" {
  environment_id = "environment_01H00000000000000000000000"

  application_name   = "Example"
  homepage_url       = "https://example.com"
  initiate_login_uri = "https://example.com"
  redirect_uris      = ["https://example.com/callback"]
  logout_uris        = ["https://example.com"]
  web_origins        = ["https://example.com"]

  authentication_method = "password"
  allow_signup          = true
  mfa                   = "Optional"

  password_minimum_length      = 12
  breached_password_protection = true
  password_composition_rules   = false

  access_token_expiry = 300
  inactivity_timeout  = 172800
  maximum_session     = 31536000

  deletion_protection = true
}
