resource "auth0_client" "my_app" {
  name      = "My App"
  client_id = "CID_APP"
}

resource "auth0_client_grant" "app_grant" {
  client_id = "CID_APP"
  audience  = "https://api.example.com"
}
