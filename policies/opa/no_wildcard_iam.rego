# Policy: no_wildcard_iam
# Denies IAM policies that use wildcard (*) actions, which grant unrestricted
# access and violate the principle of least privilege.
# Works with Terraform plan JSON format (resource_changes) and simplified
# resource definitions passed via the evaluate_policies.py script.
#
# Validates: Requirements 3.1, 3.3

package no_wildcard_iam

import rego.v1

# Deny IAM policies with wildcard actions in Terraform plan JSON (resource_changes)
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_iam_policy"
    policy_doc := json.unmarshal(resource.change.after.policy)
    some statement in policy_doc.Statement
    statement.Effect == "Allow"
    has_wildcard_action(statement)
    msg := sprintf("no_wildcard_iam: IAM policy '%s' contains wildcard (*) actions", [resource.name])
}

# Deny IAM policies with wildcard actions in planned_values format
deny contains msg if {
    some resource in input.planned_values.root_module.resources
    resource.type == "aws_iam_policy"
    policy_doc := json.unmarshal(resource.values.policy)
    some statement in policy_doc.Statement
    statement.Effect == "Allow"
    has_wildcard_action(statement)
    msg := sprintf("no_wildcard_iam: IAM policy '%s' contains wildcard (*) actions", [resource.name])
}

# Deny IAM policies with wildcard actions in simplified resource format
deny contains msg if {
    some resource in input.resources
    resource.type == "aws_iam_policy"
    some statement in resource.config.policy.Statement
    statement.Effect == "Allow"
    has_wildcard_action(statement)
    msg := sprintf("no_wildcard_iam: IAM policy '%s' contains wildcard (*) actions", [resource.name])
}

# Check if Action is a wildcard string
has_wildcard_action(statement) if {
    statement.Action == "*"
}

# Check if Action is a list containing a wildcard
has_wildcard_action(statement) if {
    some action in statement.Action
    action == "*"
}
