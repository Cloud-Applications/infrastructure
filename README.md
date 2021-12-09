# infrastructure

``Infrastructure As Code using Terraform``

## About the project
* Created muliple virtual private networks using terraform
* Created 3 subnets, each in a different availability zone in the same region in the same VPC.
* Created an Internet Gateway resource and attach the Internet Gateway to VPC.
* Created a public route table and attached all subnets created above to the route table.

## How To Run
* Install and set up AWS command line interface.
* Configure AWS CLI
* Install and set up Terraform
* Clone the repository into your local machine using git clone command
* Run command terraform apply for creating vpc
* To delete vpc run command terraform destroy
* To create new vpc, create a workspace and again run terraform apply
  
## Project Structure
* **main.tf** : Creation of VPC's
* **output.tf** : All outputs of terraform are defined in this file
* **variables.tf** : Variable declaration
* **terraform.tfvars**: Variable initialization
* **provider.tf** :: Declaration of aws provider
  
## Tech Stack
Terraform

## Features
Creation of multiple VPC's along with its resources

## Import ACM Certificate Command
aws acm import-certificate --certificate fileb://Certificate.pem \
      --certificate-chain fileb://CertificateChain.pem \
      --private-key fileb://PrivateKey.pem 
