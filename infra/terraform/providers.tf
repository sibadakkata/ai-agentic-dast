provider "aws" {
  profile = "dast-poc"
  region  = "us-east-2"

  default_tags {
    tags = {
      Project   = "dast-scanner"
      ManagedBy = "terraform"
      Env       = "poc"
    }
  }
}
