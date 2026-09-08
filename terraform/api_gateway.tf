# API Gateway fronting review-api (spec §4.1, §4.4 step 6).
#
# HTTP API rather than REST: the spec leaves the choice open, and nothing here
# needs REST's extra surface (request validators, usage plans, API keys).
#
# SECURITY: this API is UNAUTHENTICATED. Spec §4.1 defers Cognito to v1.1, so
# that matches the plan, but what it serves is a list of unfixed
# vulnerabilities and their locations. Add a JWT authorizer
# (aws_apigatewayv2_authorizer + authorizer_id per route) before anyone but us
# can reach it; until then keep the invoke URL private.

resource "aws_apigatewayv2_api" "review" {
  name          = "${var.project}-${var.environment}-review-api"
  protocol_type = "HTTP"
  description   = "Review dashboard API: list findings, fetch diffs, record approve/reject decisions"

  cors_configuration {
    allow_origins = var.dashboard_allowed_origins
    allow_methods = ["GET", "POST", "OPTIONS"]
    allow_headers = ["content-type"]
    max_age       = 300
  }
}

resource "aws_cloudwatch_log_group" "review_api_gateway" {
  name              = "/aws/apigateway/${var.project}-${var.environment}-review-api"
  retention_in_days = 14
}

resource "aws_apigatewayv2_integration" "review_api" {
  api_id = aws_apigatewayv2_api.review.id

  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.review_api.invoke_arn
  payload_format_version = "2.0"
  timeout_milliseconds   = 12000
}

# One route per operation rather than a $default catch-all, so an unknown path
# is rejected at the gateway instead of inside the Lambda.
locals {
  review_api_routes = [
    "GET /prs/{pr_id}/findings",
    "GET /prs/{pr_id}/findings/{finding_id}",
    "GET /prs/{pr_id}/findings/{finding_id}/events",
    "POST /prs/{pr_id}/findings/{finding_id}/review",
  ]
}

resource "aws_apigatewayv2_route" "review_api" {
  for_each = toset(local.review_api_routes)

  api_id    = aws_apigatewayv2_api.review.id
  route_key = each.value
  target    = "integrations/${aws_apigatewayv2_integration.review_api.id}"
}

resource "aws_apigatewayv2_stage" "review" {
  api_id      = aws_apigatewayv2_api.review.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.review_api_gateway.arn
    format = jsonencode({
      requestId        = "$context.requestId"
      httpMethod       = "$context.httpMethod"
      path             = "$context.path"
      routeKey         = "$context.routeKey"
      status           = "$context.status"
      responseLength   = "$context.responseLength"
      responseLatency  = "$context.responseLatency"
      integrationError = "$context.integrationErrorMessage"
    })
  }
}

# Without this every call 500s -- the route target alone does not grant API
# Gateway permission to invoke the function.
resource "aws_lambda_permission" "review_api_gateway" {
  statement_id  = "AllowInvokeFromReviewApiGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.review_api.function_name
  principal     = "apigateway.amazonaws.com"

  # Scoped to this API; the trailing wildcard covers every stage/method/path.
  source_arn = "${aws_apigatewayv2_api.review.execution_arn}/*/*"
}
