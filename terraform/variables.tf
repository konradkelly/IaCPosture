variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment name (e.g. dev, prod)"
  type        = string
  default     = "dev"
}

variable "project" {
  description = "Project name, used as a resource-naming prefix"
  type        = string
  default     = "iacposture"
}

variable "mapping_agent_model" {
  description = "Anthropic model ID for mapping-agent. Defaults to Opus per the project's model-choice policy; override to a cheaper model (e.g. claude-haiku-4-5) since control-mapping is a bounded classification task that doesn't need Opus-tier reasoning."
  type        = string
  default     = "claude-opus-5"
}

variable "remediation_agent_model" {
  description = "Anthropic model ID for remediation-agent. Defaults to Opus: rewriting a Terraform file correctly and minimally is a harder task than mapping-agent's bounded classification, so the Opus default is easier to justify here. Override to trade fix quality for cost."
  type        = string
  default     = "claude-opus-5"
}

variable "dashboard_allowed_origins" {
  description = "CORS allow-list for the review API. Defaults to '*' because the dashboard has no CloudFront domain yet; narrow it to that origin once it exists. CORS is a browser convention, not access control -- it does not replace the JWT authorizer noted in api_gateway.tf."
  type        = list(string)
  default     = ["*"]
}
