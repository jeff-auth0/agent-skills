resource "auth0_client" "my_app" {
  name     = "My App"
  app_type = "spa"
}

resource "auth0_client" "admin" {
  name     = "Admin Portal"
  app_type = "regular_web"
}

resource "auth0_role" "viewer" {
  name        = "Viewer"
  description = "Read only"
}

import {
  to = auth0_client.my_app
  id = "abc123"
}
