resource "aws_eks_cluster" "open" {
  name     = "open"
  role_arn = "arn:aws:iam::123456789012:role/eks"

  vpc_config {
    subnet_ids              = ["subnet-0123456789abcdef0", "subnet-0123456789abcdef1"]
    endpoint_public_access  = true
    endpoint_private_access = false
    public_access_cidrs     = ["0.0.0.0/0"]
  }
}
