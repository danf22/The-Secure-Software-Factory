# Policy: no_unencrypted_storage
# Denies S3 buckets that do not have server-side encryption configured.
# Works with Terraform plan JSON format (resource_changes) and simplified
# resource definitions passed via the evaluate_policies.py script.
#
# Validates: Requirements 3.1, 3.3

package no_unencrypted_storage

import rego.v1

# Deny S3 buckets without encryption in Terraform plan JSON (resource_changes)
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"
    not has_encryption_config(resource.change.after)
    msg := sprintf("no_unencrypted_storage: S3 bucket '%s' does not have server-side encryption configured", [resource.name])
}

# Deny S3 buckets without encryption in planned_values format
deny contains msg if {
    some resource in input.planned_values.root_module.resources
    resource.type == "aws_s3_bucket"
    not has_encryption_config(resource.values)
    msg := sprintf("no_unencrypted_storage: S3 bucket '%s' does not have server-side encryption configured", [resource.name])
}

# Deny S3 buckets without encryption in simplified resource format
deny contains msg if {
    some resource in input.resources
    resource.type == "aws_s3_bucket"
    not has_encryption_config(resource.config)
    msg := sprintf("no_unencrypted_storage: S3 bucket '%s' does not have server-side encryption configured", [resource.name])
}

# Check if server_side_encryption_configuration is present and non-empty
has_encryption_config(values) if {
    values.server_side_encryption_configuration
    count(values.server_side_encryption_configuration) > 0
}

# Also accept if there's a related encryption configuration rule
has_encryption_config(values) if {
    values.server_side_encryption_configuration_rule
}
