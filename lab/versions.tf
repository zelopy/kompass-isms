terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "aws" {
  region  = var.region
  profile = var.aws_profile

  default_tags {
    tags = {
      Project   = "kompass-lab"
      ManagedBy = "terraform"
      Purpose   = "intentionally-vulnerable-test-environment"
    }
  }
}

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  name   = "kompass-lab"
  suffix = random_id.suffix.hex
}

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}
