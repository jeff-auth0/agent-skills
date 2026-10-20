resource "auth0_role" "viewer" {
  name        = "Viewer"
  description = "read only"
}

resource "auth0_role" "editor" {
  name        = "Editor"
  description = "can edit"
}

resource "auth0_client" "my_app" {
  name     = "My App"
  app_type = "spa"
}
