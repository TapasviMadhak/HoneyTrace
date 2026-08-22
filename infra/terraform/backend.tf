terraform {
  required_version = ">= 1.6.0"

  backend "s3" {
    bucket         = "honeytrace-tfstate-bucket"
    key            = "honeytrace/terraform.tfstate"
    region         = "ap-south-1"
    dynamodb_table = "honeytrace-tf-lock"
    encrypt        = true
  }
}