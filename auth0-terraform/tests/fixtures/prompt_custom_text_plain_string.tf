# Plain-string body, the form the Auth0 CLI actually emits (escaped, one line).
resource "auth0_prompt_custom_text" "en_login" {
  prompt   = "login"
  language = "en"
  body     = "{\n    \"login\": {\n        \"title\": \"Log in to $${companyName}\",\n        \"quote\": \"say \\\"hi\\\"\",\n        \"accent\": \"café\"\n    }\n}"
}

resource "auth0_prompt_custom_text" "en_signup" {
  prompt   = "signup"
  language = "en"
  body     = "{}"
}
