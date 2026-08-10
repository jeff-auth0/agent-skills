resource "auth0_prompt_custom_text" "en_signup_id" {
  prompt   = "signup-id"
  language = "en"
  body = jsonencode({
    "signup-id" = {
      description = "Sign up for an account.\nPlease continue."
      title        = "Create your \"account\""
    }
  })
}

resource "auth0_connection" "my_db" {
  name     = "my-db"
  strategy = "auth0"
  options {
    custom_scripts = {
      login = "function login(user, callback) {\n  callback(null, user);\n}"
    }
  }
}
