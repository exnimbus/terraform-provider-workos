resource "workos_cors_origin" "production_web" {
  origin = "https://app.example.com"
}

output "production_web_cors_origin_id" {
  value = workos_cors_origin.production_web.id
}

