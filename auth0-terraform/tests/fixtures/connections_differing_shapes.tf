# Two database connections whose options.attributes blocks differ in shape.
resource "auth0_connection" "db_a" {
  name     = "db-a"
  strategy = "auth0"
  options {
    attributes {
      email {
        identifier { active = true }
      }
    }
  }
}

resource "auth0_connection" "db_b" {
  name     = "db-b"
  strategy = "auth0"
  options {
    attributes {
      username {
        identifier { active = true }
        validation {
          min_length = 3
          max_length = 15
        }
      }
    }
  }
}
