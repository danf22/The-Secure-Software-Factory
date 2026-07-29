# Policy: no_root_container
# Denies container definitions that run as root user. This checks for:
# - Containers/Dockerfiles with no USER directive (defaults to root)
# - Containers explicitly running as USER root
# Works with scan results that include container/Dockerfile metadata.
#
# Validates: Requirements 3.1, 3.3

package no_root_container

import rego.v1

# Deny containers without a non-root user in simplified resource format
deny contains msg if {
    some resource in input.resources
    resource.type == "container"
    not has_non_root_user(resource.config)
    msg := sprintf("no_root_container: Container '%s' runs as root user", [resource.name])
}

# Deny containers without a non-root user in Dockerfile scan results
deny contains msg if {
    some resource in input.resources
    resource.type == "dockerfile"
    not has_non_root_user(resource.config)
    msg := sprintf("no_root_container: Container '%s' does not specify a non-root USER directive", [resource.name])
}

# Deny containers running as root in Terraform ECS task definitions (resource_changes)
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_ecs_task_definition"
    container_def := json.unmarshal(resource.change.after.container_definitions)
    some container in container_def
    runs_as_root(container)
    msg := sprintf("no_root_container: Container '%s' in task definition '%s' runs as root", [container.name, resource.name])
}

# Deny containers running as root in planned_values format
deny contains msg if {
    some resource in input.planned_values.root_module.resources
    resource.type == "aws_ecs_task_definition"
    container_def := json.unmarshal(resource.values.container_definitions)
    some container in container_def
    runs_as_root(container)
    msg := sprintf("no_root_container: Container '%s' in task definition '%s' runs as root", [container.name, resource.name])
}

# A container has a non-root user if user is set and is not "root" or "0"
has_non_root_user(config) if {
    config.user
    config.user != ""
    config.user != "root"
    config.user != "0"
}

# Check if a container runs as root - no user field
runs_as_root(container) if {
    not container.user
}

# Check if a container runs as root - empty user
runs_as_root(container) if {
    container.user == ""
}

# Check if a container runs as root - explicitly "root"
runs_as_root(container) if {
    container.user == "root"
}

# Check if a container runs as root - UID 0
runs_as_root(container) if {
    container.user == "0"
}
