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
