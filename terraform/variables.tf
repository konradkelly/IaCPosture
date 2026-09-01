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
