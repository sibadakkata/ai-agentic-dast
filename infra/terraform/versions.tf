terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Uncomment in a later PR when S3 backend is provisioned:
  # backend "s3" {
  #   bucket         = "dast-scanner-terraform-state"
  #   key            = "poc/terraform.tfstate"
  #   region         = "us-east-2"
  #   encrypt        = true
  #   dynamodb_table = "dast-scanner-terraform-locks"
  # }
}
