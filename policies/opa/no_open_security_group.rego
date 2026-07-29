# Policy: no_open_security_group
# Denies security groups that allow ingress from 0.0.0.0/0, which exposes
# resources to the entire internet.
# Works with Terraform plan JSON format (resource_changes) and simplified
# resource definitions passed via the evaluate_policies.py script.
#
# Validates: Requirements 3.1, 3.3

package no_open_security_group

import rego.v1

# Deny security groups open to the internet in Terraform plan JSON (resource_changes)
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_security_group"
    some ingress in resource.change.after.ingress
    some cidr in ingress.cidr_blocks
    cidr == "0.0.0.0/0"
    msg := sprintf("no_open_security_group: Security group '%s' allows ingress from 0.0.0.0/0", [resource.name])
}

# Deny security groups open to the internet in planned_values format
deny contains msg if {
    some resource in input.planned_values.root_module.resources
    resource.type == "aws_security_group"
    some ingress in resource.values.ingress
    some cidr in ingress.cidr_blocks
    cidr == "0.0.0.0/0"
    msg := sprintf("no_open_security_group: Security group '%s' allows ingress from 0.0.0.0/0", [resource.name])
}

# Deny security groups open to the internet in simplified resource format
deny contains msg if {
    some resource in input.resources
    resource.type == "aws_security_group"
    some ingress in resource.config.ingress
    some cidr in ingress.cidr_blocks
    cidr == "0.0.0.0/0"
    msg := sprintf("no_open_security_group: Security group '%s' allows ingress from 0.0.0.0/0", [resource.name])
}

# Also catch security group rules as separate resources (resource_changes)
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_security_group_rule"
    resource.change.after.type == "ingress"
    some cidr in resource.change.after.cidr_blocks
    cidr == "0.0.0.0/0"
    msg := sprintf("no_open_security_group: Security group rule '%s' allows ingress from 0.0.0.0/0", [resource.name])
}

# Also catch security group rules in planned_values format
deny contains msg if {
    some resource in input.planned_values.root_module.resources
    resource.type == "aws_security_group_rule"
    resource.values.type == "ingress"
    some cidr in resource.values.cidr_blocks
    cidr == "0.0.0.0/0"
    msg := sprintf("no_open_security_group: Security group rule '%s' allows ingress from 0.0.0.0/0", [resource.name])
}
