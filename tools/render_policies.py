#!/usr/bin/env python3
"""Render builtin Rustmaninoff policies. The YAML files are what the binary ships."""

import os
from collections import Counter

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "crates", "cli", "policies"))
POLICIES = []

ESCALATION = [
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:PassRole",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:PutRolePolicy",
    "iam:AddUserToGroup",
    "iam:UpdateAssumeRolePolicy",
    "sts:AssumeRole",
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
    "lambda:AddPermission",
    "glue:CreateDevEndpoint",
    "glue:UpdateDevEndpoint",
    "cloudformation:CreateStack",
    "datapipeline:CreatePipeline",
    "datapipeline:PutPipelineDefinition",
]


def attr(attribute, operator, value=None, missing=None):
    node = {"cond_type": "attribute", "attribute": attribute, "operator": operator}
    if value is not None:
        node["value"] = value
    if missing:
        node["missing"] = missing
    return node


def AND(*items):
    return {"and": list(items)}


def OR(*items):
    return {"or": list(items)}


def NOT(item):
    return {"not": item}


def no_element(attribute, where):
    return {"cond_type": "no_element", "attribute": attribute, "where": where}


def forbid():
    return {"cond_type": "forbid_resource"}


def add(framework, check_id, name, severity, category, types, definition, fail, passed):
    POLICIES.append(
        {
            "framework": framework,
            "id": check_id,
            "name": name,
            "severity": severity,
            "category": category,
            "types": types if isinstance(types, list) else [types],
            "definition": definition,
            "fail": fail.strip() + "\n",
            "pass": passed.strip() + "\n",
        }
    )


def tf(rtype, name, body):
    return f'resource "{rtype}" "{name}" {{\n{body.rstrip()}\n}}'


def cfn(rtype, name, props):
    indented = "\n".join(("      " + line) if line else "" for line in props.strip().splitlines())
    return (
        'AWSTemplateFormatVersion: "2010-09-09"\n'
        "Resources:\n"
        f"  {name}:\n"
        f"    Type: {rtype}\n"
        "    Properties:\n"
        f"{indented}\n"
    )


def pod(name, spec, namespace="prod", kind="Pod"):
    ns = f"  namespace: {namespace}\n" if namespace is not None else ""
    spec_text = spec.strip("\n")
    if spec_text:
        spec_text = "\n".join("  " + line if line else "" for line in spec_text.splitlines())
    api = "v1" if kind == "Pod" else "apps/v1"
    return (
        f"apiVersion: {api}\n"
        f"kind: {kind}\n"
        "metadata:\n"
        f"  name: {name}\n"
        f"{ns}"
        "spec:\n"
        f"{spec_text}\n"
    )


def container(image="nginx:1.25", extra=""):
    extra = extra.strip("\n")
    body = f"containers:\n  - name: app\n    image: {image}\n"
    if extra:
        body += "\n".join("    " + line if line else "" for line in extra.splitlines()) + "\n"
    return body


def simple(framework, check_id, name, severity, category, rtype, attribute, operator, fail_body, pass_body, value=None, missing=None, types=None):
    definition = attr(attribute, operator, value, missing)
    if framework == "terraform":
        fail = tf(rtype, "bad", fail_body)
        passed = tf(rtype, "good", pass_body)
    else:
        fail = cfn(rtype, "Bad", fail_body)
        passed = cfn(rtype, "Good", pass_body)
    add(framework, check_id, name, severity, category, types or [rtype], definition, fail, passed)


def main():
    terraform_flags()
    terraform_complex()
    cloudformation()
    kubernetes()
    if len(POLICIES) < 160:
        raise SystemExit(f"only {len(POLICIES)} policies, expected at least 160")
    if os.path.isdir(ROOT):
        for dirpath, _, files in os.walk(ROOT):
            for name in files:
                if name.endswith((".yaml", ".yml")):
                    os.remove(os.path.join(dirpath, name))
    counts = Counter()
    for policy in POLICIES:
        counts[policy["id"]] += 1
        suffix = "" if counts[policy["id"]] == 1 else f"_{counts[policy['id']]}"
        directory = os.path.join(ROOT, policy["framework"])
        os.makedirs(directory, exist_ok=True)
        doc = {
            "metadata": {
                "id": policy["id"],
                "name": policy["name"],
                "category": policy["category"],
                "severity": policy["severity"],
                "framework": policy["framework"],
                "guidelines": f"Adapted from Checkov {policy['id']}. https://github.com/bridgecrewio/checkov",
            },
            "resource_types": policy["types"],
            "definition": policy["definition"],
            "fixtures": {"fail": policy["fail"], "pass": policy["pass"]},
        }
        path = os.path.join(directory, f"{policy['id']}{suffix}.yaml")
        with open(path, "w", encoding="utf-8") as handle:
            yaml.safe_dump(doc, handle, sort_keys=False, width=120, allow_unicode=True)
    print(f"wrote {len(POLICIES)} policies")


def terraform_flags():
    rows = [
        ("CKV_AWS_3", "Ensure all data stored in the EBS is securely encrypted", "HIGH", "ENCRYPTION", "aws_ebs_volume", "encrypted", "equals", True, "  encrypted = false", "  encrypted = true"),
        ("CKV_AWS_16", "Ensure all data stored in the RDS is securely encrypted at rest", "HIGH", "ENCRYPTION", "aws_db_instance", "storage_encrypted", "equals", True, "  storage_encrypted = false", "  storage_encrypted = true"),
        ("CKV_AWS_17", "Ensure all data stored in RDS is not publicly accessible", "HIGH", "NETWORKING", "aws_db_instance", "publicly_accessible", "not_equals", True, "  publicly_accessible = true", "  publicly_accessible = false", "pass"),
        ("CKV_AWS_157", "Ensure that RDS instances have Multi-AZ enabled", "MEDIUM", "BACKUP_AND_RECOVERY", "aws_db_instance", "multi_az", "equals", True, "  multi_az = false", "  multi_az = true"),
        ("CKV_AWS_293", "Ensure that AWS database instances have deletion protection enabled", "MEDIUM", "BACKUP_AND_RECOVERY", "aws_db_instance", "deletion_protection", "equals", True, "  deletion_protection = false", "  deletion_protection = true"),
        ("CKV_AWS_161", "Ensure RDS database has IAM authentication enabled", "MEDIUM", "IAM", "aws_db_instance", "iam_database_authentication_enabled", "equals", True, "  iam_database_authentication_enabled = false", "  iam_database_authentication_enabled = true"),
        ("CKV_AWS_96", "Ensure all data stored in Aurora is securely encrypted at rest", "HIGH", "ENCRYPTION", "aws_rds_cluster", "storage_encrypted", "equals", True, "  storage_encrypted = false", "  storage_encrypted = true"),
        ("CKV_AWS_139", "Ensure that RDS clusters have deletion protection enabled", "MEDIUM", "BACKUP_AND_RECOVERY", "aws_rds_cluster", "deletion_protection", "equals", True, "  deletion_protection = false", "  deletion_protection = true"),
        ("CKV_AWS_162", "Ensure RDS cluster has IAM authentication enabled", "MEDIUM", "IAM", "aws_rds_cluster", "iam_database_authentication_enabled", "equals", True, "  iam_database_authentication_enabled = false", "  iam_database_authentication_enabled = true"),
        ("CKV_AWS_53", "Ensure S3 bucket has block public ACLS enabled", "HIGH", "STORAGE", "aws_s3_bucket_public_access_block", "block_public_acls", "equals", True, "  block_public_acls = false", "  block_public_acls = true"),
        ("CKV_AWS_54", "Ensure S3 bucket has block public policy enabled", "HIGH", "STORAGE", "aws_s3_bucket_public_access_block", "block_public_policy", "equals", True, "  block_public_policy = false", "  block_public_policy = true"),
        ("CKV_AWS_55", "Ensure S3 bucket has ignore public ACLs enabled", "HIGH", "STORAGE", "aws_s3_bucket_public_access_block", "ignore_public_acls", "equals", True, "  ignore_public_acls = false", "  ignore_public_acls = true"),
        ("CKV_AWS_56", "Ensure S3 bucket has restrict_public_buckets enabled", "HIGH", "STORAGE", "aws_s3_bucket_public_access_block", "restrict_public_buckets", "equals", True, "  restrict_public_buckets = false", "  restrict_public_buckets = true"),
        ("CKV_AWS_67", "Ensure CloudTrail is enabled in all Regions", "HIGH", "LOGGING", "aws_cloudtrail", "is_multi_region_trail", "equals", True, "  is_multi_region_trail = false", "  is_multi_region_trail = true"),
        ("CKV_AWS_36", "Ensure CloudTrail log file validation is enabled", "MEDIUM", "LOGGING", "aws_cloudtrail", "enable_log_file_validation", "equals", True, "  enable_log_file_validation = false", "  enable_log_file_validation = true"),
        ("CKV_AWS_251", "Ensure CloudTrail logging is enabled", "HIGH", "LOGGING", "aws_cloudtrail", "enable_logging", "equals", True, "  enable_logging = false", "  enable_logging = true"),
        ("CKV_AWS_7", "Ensure rotation for customer created CMKs is enabled", "MEDIUM", "ENCRYPTION", "aws_kms_key", "enable_key_rotation", "equals", True, "  enable_key_rotation = false", "  enable_key_rotation = true"),
        ("CKV_AWS_227", "Ensure KMS key is enabled", "MEDIUM", "ENCRYPTION", "aws_kms_key", "is_enabled", "not_equals", False, "  is_enabled = false", "  is_enabled = true", "pass"),
        ("CKV_AWS_131", "Ensure that ALB drops HTTP headers", "MEDIUM", "NETWORKING", "aws_lb", "drop_invalid_header_fields", "equals", True, '  load_balancer_type = "application"\n  drop_invalid_header_fields = false', '  load_balancer_type = "application"\n  drop_invalid_header_fields = true'),
        ("CKV_AWS_150", "Ensure that Load Balancer has deletion protection enabled", "MEDIUM", "GENERAL_SECURITY", "aws_lb", "enable_deletion_protection", "equals", True, "  enable_deletion_protection = false", "  enable_deletion_protection = true"),
        ("CKV_AWS_42", "Ensure EFS is securely encrypted", "HIGH", "ENCRYPTION", "aws_efs_file_system", "encrypted", "equals", True, "  encrypted = false", "  encrypted = true"),
        ("CKV_AWS_64", "Ensure all data stored in the Redshift cluster is securely encrypted at rest", "HIGH", "ENCRYPTION", "aws_redshift_cluster", "encrypted", "equals", True, "  encrypted = false", "  encrypted = true"),
        ("CKV_AWS_87", "Redshift cluster should not be publicly accessible", "HIGH", "NETWORKING", "aws_redshift_cluster", "publicly_accessible", "not_equals", True, "  publicly_accessible = true", "  publicly_accessible = false", "pass"),
        ("CKV_AWS_74", "Ensure DocumentDB is encrypted at rest", "HIGH", "ENCRYPTION", "aws_docdb_cluster", "storage_encrypted", "equals", True, "  storage_encrypted = false", "  storage_encrypted = true"),
        ("CKV_AWS_44", "Ensure Neptune storage is securely encrypted", "HIGH", "ENCRYPTION", "aws_neptune_cluster", "storage_encrypted", "equals", True, "  storage_encrypted = false", "  storage_encrypted = true"),
        ("CKV_AWS_29", "Ensure ElastiCache replication group is encrypted at rest", "HIGH", "ENCRYPTION", "aws_elasticache_replication_group", "at_rest_encryption_enabled", "equals", True, "  at_rest_encryption_enabled = false", "  at_rest_encryption_enabled = true"),
        ("CKV_AWS_30", "Ensure ElastiCache replication group is encrypted in transit", "HIGH", "ENCRYPTION", "aws_elasticache_replication_group", "transit_encryption_enabled", "equals", True, "  transit_encryption_enabled = false", "  transit_encryption_enabled = true"),
        ("CKV_AWS_69", "Ensure MQ Broker is not publicly exposed", "HIGH", "NETWORKING", "aws_mq_broker", "publicly_accessible", "not_equals", True, "  publicly_accessible = true", "  publicly_accessible = false", "pass"),
        ("CKV_AWS_89", "DMS replication instance should not be publicly accessible", "HIGH", "NETWORKING", "aws_dms_replication_instance", "publicly_accessible", "not_equals", True, "  publicly_accessible = true", "  publicly_accessible = false", "pass"),
        ("CKV_AWS_130", "Ensure VPC subnets do not assign public IP by default", "HIGH", "NETWORKING", "aws_subnet", "map_public_ip_on_launch", "not_equals", True, "  map_public_ip_on_launch = true", "  map_public_ip_on_launch = false", "pass"),
        ("CKV_AWS_88", "EC2 instance should not have public IP", "HIGH", "NETWORKING", "aws_instance", "associate_public_ip_address", "not_equals", True, "  associate_public_ip_address = true", "  associate_public_ip_address = false", "pass"),
        ("CKV_AWS_135", "Ensure that EC2 is EBS optimized", "LOW", "GENERAL_SECURITY", "aws_instance", "ebs_optimized", "equals", True, "  ebs_optimized = false", "  ebs_optimized = true"),
        ("CKV_AWS_106", "Ensure EBS default encryption is enabled", "HIGH", "ENCRYPTION", "aws_ebs_encryption_by_default", "enabled", "equals", True, "  enabled = false", "  enabled = true"),
        ("CKV_AWS_11", "Ensure IAM password policy requires at least one lowercase letter", "MEDIUM", "IAM", "aws_iam_account_password_policy", "require_lowercase_characters", "equals", True, "  require_lowercase_characters = false", "  require_lowercase_characters = true"),
        ("CKV_AWS_12", "Ensure IAM password policy requires at least one number", "MEDIUM", "IAM", "aws_iam_account_password_policy", "require_numbers", "equals", True, "  require_numbers = false", "  require_numbers = true"),
        ("CKV_AWS_14", "Ensure IAM password policy requires at least one symbol", "MEDIUM", "IAM", "aws_iam_account_password_policy", "require_symbols", "equals", True, "  require_symbols = false", "  require_symbols = true"),
        ("CKV_AWS_15", "Ensure IAM password policy requires at least one uppercase letter", "MEDIUM", "IAM", "aws_iam_account_password_policy", "require_uppercase_characters", "equals", True, "  require_uppercase_characters = false", "  require_uppercase_characters = true"),
        ("CKV_AWS_43", "Ensure Kinesis Stream is securely encrypted", "HIGH", "ENCRYPTION", "aws_kinesis_stream", "encryption_type", "equals", "KMS", '  encryption_type = "NONE"', '  encryption_type = "KMS"'),
        ("CKV_AWS_136", "Ensure that ECR repositories are encrypted using KMS", "MEDIUM", "ENCRYPTION", "aws_ecr_repository", "encryption_type", "equals", "KMS", '  encryption_type = "AES256"', '  encryption_type = "KMS"'),
        ("CKV_AWS_2", "Ensure ALB protocol is HTTPS", "HIGH", "ENCRYPTION", "aws_lb_listener", "protocol", "not_equals", "HTTP", '  protocol = "HTTP"', '  protocol = "HTTPS"'),
        ("CKV_AWS_164", "Ensure Transfer Server is not exposed publicly", "HIGH", "NETWORKING", "aws_transfer_server", "endpoint_type", "within", ["VPC", "VPC_ENDPOINT"], '  endpoint_type = "PUBLIC"', '  endpoint_type = "VPC"'),
        ("CKV_AWS_82", "Ensure Athena workgroup enforces configuration", "MEDIUM", "ENCRYPTION", "aws_athena_workgroup", "configuration.enforce_workgroup_configuration", "equals", True, "  configuration {\n    enforce_workgroup_configuration = false\n  }", "  configuration {\n    enforce_workgroup_configuration = true\n  }"),
        ("CKV_AWS_118", "Ensure that enhanced monitoring is enabled for Amazon RDS instances", "MEDIUM", "LOGGING", "aws_db_instance", "monitoring_interval", "within", [1, 5, 10, 15, 30, 60], "  monitoring_interval = 0", "  monitoring_interval = 60"),
        ("CKV_AWS_10", "Ensure IAM password policy requires minimum length of 14 or greater", "MEDIUM", "IAM", "aws_iam_account_password_policy", "minimum_password_length", "greater_than_or_equal", 14, "  minimum_password_length = 8", "  minimum_password_length = 14"),
        ("CKV_AWS_9", "Ensure IAM password policy expires passwords within 90 days or less", "MEDIUM", "IAM", "aws_iam_account_password_policy", "max_password_age", "less_than_or_equal", 90, "  max_password_age = 120", "  max_password_age = 90"),
        ("CKV_AWS_13", "Ensure IAM password policy prevents password reuse", "MEDIUM", "IAM", "aws_iam_account_password_policy", "password_reuse_prevention", "greater_than_or_equal", 24, "  password_reuse_prevention = 1", "  password_reuse_prevention = 24"),
        ("CKV_AWS_35", "Ensure CloudTrail logs are encrypted at rest using KMS CMKs", "HIGH", "LOGGING", "aws_cloudtrail", "kms_key_id", "exists", None, "  is_multi_region_trail = true", '  kms_key_id = "arn:aws:kms:us-east-1:123:key/abc"'),
        ("CKV_AWS_26", "Ensure all data stored in the SNS topic is encrypted", "HIGH", "ENCRYPTION", "aws_sns_topic", "kms_master_key_id", "exists", None, "  name = \"plain\"", '  kms_master_key_id = "alias/aws/sns"'),
        ("CKV_AWS_27", "Ensure all data stored in the SQS queue is encrypted", "HIGH", "ENCRYPTION", "aws_sqs_queue", "kms_master_key_id", "exists", None, "  name = \"plain\"", '  kms_master_key_id = "alias/aws/sqs"'),
        ("CKV_AWS_158", "Ensure that CloudWatch Log Group is encrypted by KMS", "HIGH", "ENCRYPTION", "aws_cloudwatch_log_group", "kms_key_id", "exists", None, "  name = \"/app\"", '  kms_key_id = "arn:aws:kms:us-east-1:123:key/abc"'),
        ("CKV_AWS_149", "Ensure that Secrets Manager secret is encrypted using KMS CMK", "MEDIUM", "ENCRYPTION", "aws_secretsmanager_secret", "kms_key_id", "exists", None, "  name = \"app\"", '  kms_key_id = "arn:aws:kms:us-east-1:123:key/abc"'),
        ("CKV_AWS_18", "Ensure the S3 bucket has access logging enabled", "MEDIUM", "LOGGING", "aws_s3_bucket_logging", "target_bucket", "exists", None, "  bucket = \"data\"", '  bucket = "data"\n  target_bucket = "logs"'),
        ("CKV_AWS_77", "Ensure Athena database is encrypted at rest", "MEDIUM", "ENCRYPTION", "aws_athena_database", "encryption_configuration.encryption_option", "exists", None, "  name = \"db\"", "  encryption_configuration {\n    encryption_option = \"SSE_S3\"\n  }"),
        ("CKV_AWS_129", "Ensure that RDS logs are enabled", "LOW", "LOGGING", "aws_db_instance", "enabled_cloudwatch_logs_exports", "exists", None, "  engine = \"postgres\"", '  enabled_cloudwatch_logs_exports = ["postgresql"]'),
        ("CKV_AWS_23", "Ensure every security group and rule has a description", "LOW", "NETWORKING", "aws_security_group", "description", "exists", None, "  name = \"open\"", '  description = "application tier"'),
    ]
    for row in rows:
        missing = row[10] if len(row) > 10 else None
        value = row[7]
        operator = row[6]
        if operator in {"exists", "not_exists"}:
            value = None
        definition = attr(row[5], operator, value, missing)
        add("terraform", row[0], row[1], row[2], row[3], [row[4]], definition, tf(row[4], "bad", row[8]), tf(row[4], "good", row[9]))


def terraform_complex():
    add(
        "terraform",
        "CKV_AWS_21",
        "Ensure the S3 bucket has versioning enabled",
        "MEDIUM",
        "BACKUP_AND_RECOVERY",
        ["aws_s3_bucket_versioning"],
        attr("versioning_configuration.status", "equals", "Enabled"),
        tf("aws_s3_bucket_versioning", "bad", '  bucket = "data"\n  versioning_configuration {\n    status = "Suspended"\n  }'),
        tf("aws_s3_bucket_versioning", "good", '  bucket = "data"\n  versioning_configuration {\n    status = "Enabled"\n  }'),
    )
    add(
        "terraform",
        "CKV_AWS_19",
        "Ensure the S3 bucket has server-side-encryption enabled",
        "HIGH",
        "ENCRYPTION",
        ["aws_s3_bucket_server_side_encryption_configuration"],
        attr("rule.apply_server_side_encryption_by_default.sse_algorithm", "within", ["AES256", "aws:kms"]),
        tf("aws_s3_bucket_server_side_encryption_configuration", "bad", '  bucket = "data"\n  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm = "none"\n    }\n  }'),
        tf("aws_s3_bucket_server_side_encryption_configuration", "good", '  bucket = "data"\n  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm = "AES256"\n    }\n  }'),
    )
    add(
        "terraform",
        "CKV_AWS_20",
        "Ensure the S3 bucket does not allow READ permissions to everyone",
        "HIGH",
        "STORAGE",
        ["aws_s3_bucket"],
        attr("acl", "not_within", ["public-read", "public-read-write", "authenticated-read"], "pass"),
        tf("aws_s3_bucket", "bad", '  bucket = "data"\n  acl    = "public-read"'),
        tf("aws_s3_bucket", "good", '  bucket = "data"\n  acl    = "private"'),
    )
    add(
        "terraform",
        "CKV_AWS_20",
        "Ensure the S3 bucket ACL does not allow READ permissions to everyone",
        "HIGH",
        "STORAGE",
        ["aws_s3_bucket_acl"],
        attr("acl", "not_within", ["public-read", "public-read-write", "authenticated-read"], "pass"),
        tf("aws_s3_bucket_acl", "bad", '  bucket = "data"\n  acl    = "public-read"'),
        tf("aws_s3_bucket_acl", "good", '  bucket = "data"\n  acl    = "private"'),
    )
    open_port = lambda port: no_element(
        "ingress",
        AND(
            attr("from_port", "less_than_or_equal", port),
            attr("to_port", "greater_than_or_equal", port),
            OR(
                attr("cidr_blocks", "contains", "0.0.0.0/0"),
                attr("ipv6_cidr_blocks", "contains", "::/0"),
            ),
        ),
    )
    for check_id, port in (("CKV_AWS_24", 22), ("CKV_AWS_25", 3389)):
        add(
            "terraform",
            check_id,
            f"Ensure no security groups allow ingress from 0.0.0.0/0 to port {port}",
            "HIGH",
            "NETWORKING",
            ["aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule"],
            open_port(port),
            tf("aws_security_group", "bad", f'  description = "open"\n  ingress {{\n    from_port   = {port}\n    to_port     = {port}\n    protocol    = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }}'),
            tf("aws_security_group", "good", f'  description = "https"\n  ingress {{\n    from_port   = 443\n    to_port     = 443\n    protocol    = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }}'),
        )
        add(
            "terraform",
            check_id,
            f"Ensure no security group rule allows ingress from 0.0.0.0/0 to port {port}",
            "HIGH",
            "NETWORKING",
            ["aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule"],
            NOT(AND(
                attr("type", "equals", "ingress"),
                attr("from_port", "less_than_or_equal", port),
                attr("to_port", "greater_than_or_equal", port),
                OR(
                    attr("cidr_blocks", "contains", "0.0.0.0/0"),
                    attr("ipv6_cidr_blocks", "contains", "::/0"),
                    attr("cidr_ipv4", "equals", "0.0.0.0/0"),
                ),
            )),
            tf("aws_security_group_rule", "bad", f'  type              = "ingress"\n  from_port         = {port}\n  to_port           = {port}\n  protocol          = "tcp"\n  cidr_blocks       = ["0.0.0.0/0"]\n  security_group_id = "sg-123"'),
            tf("aws_security_group_rule", "good", f'  type              = "ingress"\n  from_port         = {port}\n  to_port           = {port}\n  protocol          = "tcp"\n  cidr_blocks       = ["10.0.0.0/8"]\n  security_group_id = "sg-123"'),
        )
    add(
        "terraform",
        "CKV_AWS_23",
        "Ensure every security group rule has a description",
        "LOW",
        "NETWORKING",
        ["aws_security_group_rule"],
        attr("description", "exists"),
        tf("aws_security_group_rule", "bad", '  type = "ingress"\n  from_port = 443\n  to_port = 443\n  protocol = "tcp"\n  security_group_id = "sg-123"'),
        tf("aws_security_group_rule", "good", '  description = "https"\n  type = "ingress"\n  from_port = 443\n  to_port = 443\n  protocol = "tcp"\n  security_group_id = "sg-123"'),
    )
    add(
        "terraform",
        "CKV_AWS_79",
        "Ensure Instance Metadata Service Version 1 is not enabled",
        "HIGH",
        "GENERAL_SECURITY",
        ["aws_instance", "aws_launch_template"],
        OR(
            attr("metadata_options.http_tokens", "equals", "required"),
            attr("metadata_options.http_endpoint", "equals", "disabled"),
        ),
        tf("aws_instance", "bad", '  metadata_options {\n    http_tokens   = "optional"\n    http_endpoint = "enabled"\n  }'),
        tf("aws_instance", "good", '  metadata_options {\n    http_tokens = "required"\n  }'),
    )
    add(
        "terraform",
        "CKV_AWS_88",
        "Launch template should not assign a public IP",
        "HIGH",
        "NETWORKING",
        ["aws_launch_template"],
        attr("network_interfaces.associate_public_ip_address", "not_equals", True, "pass"),
        tf("aws_launch_template", "bad", '  name = "bad"\n  network_interfaces {\n    associate_public_ip_address = true\n  }'),
        tf("aws_launch_template", "good", '  name = "good"\n  network_interfaces {\n    associate_public_ip_address = false\n  }'),
    )
    add(
        "terraform",
        "CKV_AWS_39",
        "Ensure Amazon EKS public endpoint disabled",
        "HIGH",
        "KUBERNETES",
        ["aws_eks_cluster"],
        attr("vpc_config.endpoint_public_access", "equals", False),
        tf("aws_eks_cluster", "bad", '  name = "bad"\n  vpc_config {\n    endpoint_public_access = true\n  }'),
        tf("aws_eks_cluster", "good", '  name = "good"\n  vpc_config {\n    endpoint_public_access = false\n  }'),
    )
    add(
        "terraform",
        "CKV_AWS_38",
        "Ensure Amazon EKS public endpoint not accessible to 0.0.0.0/0",
        "HIGH",
        "KUBERNETES",
        ["aws_eks_cluster"],
        OR(
            attr("vpc_config.endpoint_public_access", "equals", False),
            AND(
                attr("vpc_config.public_access_cidrs", "exists"),
                attr("vpc_config.public_access_cidrs", "not_contains", "0.0.0.0/0"),
            ),
        ),
        tf("aws_eks_cluster", "bad", '  name = "bad"\n  vpc_config {\n    endpoint_public_access = true\n    public_access_cidrs    = ["0.0.0.0/0"]\n  }'),
        tf("aws_eks_cluster", "good", '  name = "good"\n  vpc_config {\n    endpoint_public_access = true\n    public_access_cidrs    = ["10.0.0.0/8"]\n  }'),
    )
    add(
        "terraform",
        "CKV_AWS_58",
        "Ensure EKS Cluster has Secrets Encryption Enabled",
        "HIGH",
        "ENCRYPTION",
        ["aws_eks_cluster"],
        attr("encryption_config.resources", "contains", "secrets"),
        tf("aws_eks_cluster", "bad", '  name = "bad"\n  vpc_config {\n    endpoint_public_access = false\n  }'),
        tf("aws_eks_cluster", "good", '  name = "good"\n  encryption_config {\n    resources = ["secrets"]\n    provider {\n      key_arn = "arn:aws:kms:us-east-1:123:key/abc"\n    }\n  }'),
    )
    logs = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
    add(
        "terraform",
        "CKV_AWS_37",
        "Ensure Amazon EKS control plane logging is enabled for all log types",
        "MEDIUM",
        "LOGGING",
        ["aws_eks_cluster"],
        AND(*[attr("enabled_cluster_log_types", "contains", item) for item in logs]),
        tf("aws_eks_cluster", "bad", '  name = "bad"\n  enabled_cluster_log_types = ["api"]'),
        tf("aws_eks_cluster", "good", '  name = "good"\n  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]'),
    )
    add(
        "terraform",
        "CKV_AWS_8",
        "Ensure all data stored in the Launch configuration or instance EBS is securely encrypted",
        "HIGH",
        "ENCRYPTION",
        ["aws_instance"],
        attr("root_block_device.encrypted", "equals", True),
        tf("aws_instance", "bad", "  root_block_device {\n    encrypted = false\n  }"),
        tf("aws_instance", "good", "  root_block_device {\n    encrypted = true\n  }"),
    )
    add(
        "terraform",
        "CKV_AWS_8",
        "Ensure launch configuration EBS volumes are encrypted",
        "HIGH",
        "ENCRYPTION",
        ["aws_launch_configuration"],
        attr("root_block_device.encrypted", "equals", True),
        tf("aws_launch_configuration", "bad", '  image_id = "ami-123"\n  root_block_device {\n    encrypted = false\n  }'),
        tf("aws_launch_configuration", "good", '  image_id = "ami-123"\n  root_block_device {\n    encrypted = true\n  }'),
    )
    add(
        "terraform",
        "CKV_AWS_5",
        "Ensure Elasticsearch is encrypted at rest",
        "HIGH",
        "ENCRYPTION",
        ["aws_elasticsearch_domain", "aws_opensearch_domain"],
        attr("encrypt_at_rest.enabled", "equals", True),
        tf("aws_opensearch_domain", "bad", '  domain_name = "logs"\n  encrypt_at_rest {\n    enabled = false\n  }'),
        tf("aws_opensearch_domain", "good", '  domain_name = "logs"\n  encrypt_at_rest {\n    enabled = true\n  }'),
    )
    add(
        "terraform",
        "CKV_AWS_6",
        "Ensure Elasticsearch has node-to-node encryption enabled",
        "HIGH",
        "ENCRYPTION",
        ["aws_elasticsearch_domain", "aws_opensearch_domain"],
        attr("node_to_node_encryption.enabled", "equals", True),
        tf("aws_opensearch_domain", "bad", '  domain_name = "logs"\n  node_to_node_encryption {\n    enabled = false\n  }'),
        tf("aws_opensearch_domain", "good", '  domain_name = "logs"\n  node_to_node_encryption {\n    enabled = true\n  }'),
    )
    add(
        "terraform",
        "CKV_AWS_119",
        "Ensure DynamoDB Tables are encrypted using a KMS Customer Managed CMK",
        "HIGH",
        "ENCRYPTION",
        ["aws_dynamodb_table"],
        AND(
            attr("server_side_encryption.enabled", "equals", True),
            attr("server_side_encryption.kms_key_arn", "exists"),
        ),
        tf("aws_dynamodb_table", "bad", '  name = "items"\n  hash_key = "id"'),
        tf("aws_dynamodb_table", "good", '  name = "items"\n  server_side_encryption {\n    enabled     = true\n    kms_key_arn = "arn:aws:kms:us-east-1:123:key/abc"\n  }'),
    )
    statement = '''  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = %s
      Resource = %s
    }]
  })'''
    add(
        "terraform",
        "CKV_AWS_63",
        'Ensure no IAM policies documents allow "*" as a statement\'s actions',
        "CRITICAL",
        "IAM",
        ["aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"],
        no_element("policy.Statement", AND(attr("Effect", "equals", "Allow"), OR(attr("Action", "equals_any", "*"), attr("Action", "equals_any", "*:*")))),
        tf("aws_iam_policy", "bad", statement % ('"*"', '"arn:aws:s3:::bucket"')),
        tf("aws_iam_policy", "good", statement % ('"s3:GetObject"', '"arn:aws:s3:::bucket/*"')),
    )
    add(
        "terraform",
        "CKV_AWS_62",
        'Ensure IAM policies that allow full "*-*" administrative privileges are not created',
        "CRITICAL",
        "IAM",
        ["aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"],
        no_element(
            "policy.Statement",
            AND(
                attr("Effect", "equals", "Allow"),
                OR(attr("Action", "equals_any", "*"), attr("Action", "equals_any", "*:*")),
                OR(attr("Resource", "equals_any", "*"), attr("Resource", "equals_any", "*:*")),
            ),
        ),
        tf("aws_iam_policy", "bad", statement % ('"*"', '"*"')),
        tf("aws_iam_policy", "good", statement % ('"s3:GetObject"', '"arn:aws:s3:::bucket/*"')),
    )
    add(
        "terraform",
        "CKV_AWS_286",
        "Ensure IAM policies do not allow common privilege-escalation actions",
        "CRITICAL",
        "IAM",
        ["aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"],
        no_element("policy.Statement", AND(attr("Effect", "equals", "Allow"), attr("Action", "intersects", ESCALATION))),
        tf("aws_iam_policy", "bad", statement % ('"iam:PassRole"', '"*"')),
        tf("aws_iam_policy", "good", statement % ('"s3:GetObject"', '"arn:aws:s3:::bucket/*"')),
    )
    trust = '''  assume_role_policy = jsonencode({
    Statement = [{
      Effect = "Allow"
      Principal = %s
      Action = "sts:AssumeRole"
    }]
  })'''
    add(
        "terraform",
        "CKV_AWS_60",
        "Ensure IAM role allows only specific services or principals to assume it",
        "HIGH",
        "IAM",
        ["aws_iam_role"],
        no_element(
            "assume_role_policy.Statement",
            OR(
                attr("Principal", "equals_any", "*"),
                attr("Principal.AWS", "equals_any", "*"),
                attr("Principal.Service", "equals_any", "*"),
            ),
        ),
        tf("aws_iam_role", "bad", trust % '"*"'),
        tf("aws_iam_role", "good", trust % '{ Service = "ec2.amazonaws.com" }'),
    )
    add(
        "terraform",
        "CKV_AWS_33",
        "Ensure KMS key policy does not contain wildcard principal",
        "CRITICAL",
        "IAM",
        ["aws_kms_key"],
        no_element(
            "policy.Statement",
            OR(
                attr("Principal", "equals_any", "*"),
                attr("Principal.AWS", "equals_any", "*"),
            ),
        ),
        tf("aws_kms_key", "bad", statement % ('"kms:*"', '"*"') + "\n" + trust.split("assume_role_policy = ")[1].replace("assume_role_policy", "policy") if False else '  policy = jsonencode({\n    Statement = [{\n      Effect = "Allow"\n      Principal = "*"\n      Action = "kms:*"\n      Resource = "*"\n    }]\n  })'),
        tf("aws_kms_key", "good", '  policy = jsonencode({\n    Statement = [{\n      Effect = "Allow"\n      Principal = { AWS = "arn:aws:iam::123:root" }\n      Action = "kms:*"\n      Resource = "*"\n    }]\n  })'),
    )
    add(
        "terraform",
        "CKV_AWS_46",
        "Ensure no hard-coded secrets exist in EC2 user data",
        "HIGH",
        "SECRETS",
        ["aws_instance"],
        attr("user_data", "not_regex_match", "AKIA[0-9A-Z]{16}", "pass"),
        tf("aws_instance", "bad", '  user_data = "export KEY=AKIAIOSFODNN7EXAMPLE"'),
        tf("aws_instance", "good", '  user_data = "echo hello"'),
    )
    add(
        "terraform",
        "CKV_AWS_173",
        "Check encryption settings for Lambda environmental variable",
        "HIGH",
        "ENCRYPTION",
        ["aws_lambda_function"],
        OR(attr("environment", "not_exists"), attr("kms_key_arn", "exists")),
        tf("aws_lambda_function", "bad", '  function_name = "app"\n  environment {\n    variables = {\n      LOG = "info"\n    }\n  }'),
        tf("aws_lambda_function", "good", '  function_name = "app"\n  kms_key_arn = "arn:aws:kms:us-east-1:123:key/abc"\n  environment {\n    variables = {\n      LOG = "info"\n    }\n  }'),
    )
    add(
        "terraform",
        "CKV_AWS_133",
        "Ensure that RDS instances have a backup retention period",
        "MEDIUM",
        "BACKUP_AND_RECOVERY",
        ["aws_db_instance", "aws_rds_cluster"],
        OR(
            attr("backup_retention_period", "not_exists"),
            AND(
                attr("backup_retention_period", "greater_than", 0),
                attr("backup_retention_period", "less_than_or_equal", 35),
            ),
        ),
        tf("aws_db_instance", "bad", "  backup_retention_period = 0"),
        tf("aws_db_instance", "good", "  backup_retention_period = 7"),
    )
    add(
        "terraform",
        "CKV_AWS_40",
        "Ensure IAM policies are attached only to groups or roles",
        "MEDIUM",
        "IAM",
        ["aws_iam_user_policy"],
        forbid(),
        tf("aws_iam_user_policy", "bad", '  name = "inline"\n  user = "alice"'),
        tf("aws_iam_role", "good", '  name = "app"'),
    )
    add(
        "terraform",
        "CKV_AWS_40",
        "Ensure IAM user policy attachments are not used",
        "MEDIUM",
        "IAM",
        ["aws_iam_user_policy_attachment"],
        forbid(),
        tf("aws_iam_user_policy_attachment", "bad", '  user       = "alice"\n  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"'),
        tf("aws_iam_role", "good", '  name = "app"'),
    )
    add(
        "terraform",
        "CKV_AWS_198",
        "Ensure no aws_db_security_group resources exist",
        "LOW",
        "NETWORKING",
        ["aws_db_security_group"],
        forbid(),
        tf("aws_db_security_group", "bad", '  name = "legacy"'),
        tf("aws_security_group", "good", '  description = "modern"'),
    )


def cloudformation():
    rows = [
        ("CKV_AWS_21", "Ensure the S3 bucket has versioning enabled", "MEDIUM", "BACKUP_AND_RECOVERY", "AWS::S3::Bucket", "VersioningConfiguration.Status", "equals", "Enabled", "VersioningConfiguration:\n  Status: Suspended", "VersioningConfiguration:\n  Status: Enabled"),
        ("CKV_AWS_3", "Ensure all data stored in the EBS is securely encrypted", "HIGH", "ENCRYPTION", "AWS::EC2::Volume", "Encrypted", "equals", True, "Encrypted: false", "Encrypted: true"),
        ("CKV_AWS_16", "Ensure all data stored in the RDS is securely encrypted at rest", "HIGH", "ENCRYPTION", "AWS::RDS::DBInstance", "StorageEncrypted", "equals", True, "StorageEncrypted: false", "StorageEncrypted: true"),
        ("CKV_AWS_17", "Ensure all data stored in RDS is not publicly accessible", "HIGH", "NETWORKING", "AWS::RDS::DBInstance", "PubliclyAccessible", "not_equals", True, "PubliclyAccessible: true", "PubliclyAccessible: false", "pass"),
        ("CKV_AWS_157", "Ensure that RDS instances have Multi-AZ enabled", "MEDIUM", "BACKUP_AND_RECOVERY", "AWS::RDS::DBInstance", "MultiAZ", "equals", True, "MultiAZ: false", "MultiAZ: true"),
        ("CKV_AWS_161", "Ensure RDS database has IAM authentication enabled", "MEDIUM", "IAM", "AWS::RDS::DBInstance", "EnableIAMDatabaseAuthentication", "equals", True, "EnableIAMDatabaseAuthentication: false", "EnableIAMDatabaseAuthentication: true"),
        ("CKV_AWS_96", "Ensure all data stored in Aurora is securely encrypted at rest", "HIGH", "ENCRYPTION", "AWS::RDS::DBCluster", "StorageEncrypted", "equals", True, "StorageEncrypted: false", "StorageEncrypted: true"),
        ("CKV_AWS_139", "Ensure that RDS clusters have deletion protection enabled", "MEDIUM", "BACKUP_AND_RECOVERY", "AWS::RDS::DBCluster", "DeletionProtection", "equals", True, "DeletionProtection: false", "DeletionProtection: true"),
        ("CKV_AWS_7", "Ensure rotation for customer created CMKs is enabled", "MEDIUM", "ENCRYPTION", "AWS::KMS::Key", "EnableKeyRotation", "equals", True, "EnableKeyRotation: false", "EnableKeyRotation: true"),
        ("CKV_AWS_36", "Ensure CloudTrail log file validation is enabled", "MEDIUM", "LOGGING", "AWS::CloudTrail::Trail", "EnableLogFileValidation", "equals", True, "EnableLogFileValidation: false", "EnableLogFileValidation: true"),
        ("CKV_AWS_67", "Ensure CloudTrail is enabled in all Regions", "HIGH", "LOGGING", "AWS::CloudTrail::Trail", "IsMultiRegionTrail", "equals", True, "IsMultiRegionTrail: false", "IsMultiRegionTrail: true"),
        ("CKV_AWS_35", "Ensure CloudTrail logs are encrypted at rest using KMS CMKs", "HIGH", "LOGGING", "AWS::CloudTrail::Trail", "KMSKeyId", "exists", None, "IsLogging: true", "KMSKeyId: alias/trail"),
        ("CKV_AWS_26", "Ensure all data stored in the SNS topic is encrypted", "HIGH", "ENCRYPTION", "AWS::SNS::Topic", "KmsMasterKeyId", "exists", None, "TopicName: plain", "KmsMasterKeyId: alias/aws/sns"),
        ("CKV_AWS_27", "Ensure all data stored in the SQS queue is encrypted", "HIGH", "ENCRYPTION", "AWS::SQS::Queue", "KmsMasterKeyId", "exists", None, "QueueName: plain", "KmsMasterKeyId: alias/aws/sqs"),
        ("CKV_AWS_42", "Ensure EFS is securely encrypted", "HIGH", "ENCRYPTION", "AWS::EFS::FileSystem", "Encrypted", "equals", True, "Encrypted: false", "Encrypted: true"),
        ("CKV_AWS_64", "Ensure all data stored in the Redshift cluster is securely encrypted at rest", "HIGH", "ENCRYPTION", "AWS::Redshift::Cluster", "Encrypted", "equals", True, "Encrypted: false", "Encrypted: true"),
        ("CKV_AWS_87", "Redshift cluster should not be publicly accessible", "HIGH", "NETWORKING", "AWS::Redshift::Cluster", "PubliclyAccessible", "not_equals", True, "PubliclyAccessible: true", "PubliclyAccessible: false", "pass"),
        ("CKV_AWS_74", "Ensure DocumentDB is encrypted at rest", "HIGH", "ENCRYPTION", "AWS::DocDB::DBCluster", "StorageEncrypted", "equals", True, "StorageEncrypted: false", "StorageEncrypted: true"),
        ("CKV_AWS_44", "Ensure Neptune storage is securely encrypted", "HIGH", "ENCRYPTION", "AWS::Neptune::DBCluster", "StorageEncrypted", "equals", True, "StorageEncrypted: false", "StorageEncrypted: true"),
        ("CKV_AWS_29", "Ensure ElastiCache replication group is encrypted at rest", "HIGH", "ENCRYPTION", "AWS::ElastiCache::ReplicationGroup", "AtRestEncryptionEnabled", "equals", True, "AtRestEncryptionEnabled: false", "AtRestEncryptionEnabled: true"),
        ("CKV_AWS_30", "Ensure ElastiCache replication group is encrypted in transit", "HIGH", "ENCRYPTION", "AWS::ElastiCache::ReplicationGroup", "TransitEncryptionEnabled", "equals", True, "TransitEncryptionEnabled: false", "TransitEncryptionEnabled: true"),
        ("CKV_AWS_69", "Ensure Amazon MQ Broker should not have public access", "HIGH", "NETWORKING", "AWS::AmazonMQ::Broker", "PubliclyAccessible", "not_equals", True, "PubliclyAccessible: true", "PubliclyAccessible: false", "pass"),
        ("CKV_AWS_89", "DMS replication instance should not be publicly accessible", "HIGH", "NETWORKING", "AWS::DMS::ReplicationInstance", "PubliclyAccessible", "not_equals", True, "PubliclyAccessible: true", "PubliclyAccessible: false", "pass"),
        ("CKV_AWS_158", "Ensure that CloudWatch Log Group is encrypted by KMS", "HIGH", "ENCRYPTION", "AWS::Logs::LogGroup", "KmsKeyId", "exists", None, "LogGroupName: /app", "KmsKeyId: alias/logs"),
        ("CKV_AWS_149", "Ensure that Secrets Manager secret is encrypted using KMS CMK", "MEDIUM", "ENCRYPTION", "AWS::SecretsManager::Secret", "KmsKeyId", "exists", None, "Name: app", "KmsKeyId: alias/app"),
        ("CKV_AWS_43", "Ensure Kinesis Stream is securely encrypted", "HIGH", "ENCRYPTION", "AWS::Kinesis::Stream", "StreamEncryption.EncryptionType", "equals", "KMS", "StreamEncryption:\n  EncryptionType: NONE", "StreamEncryption:\n  EncryptionType: KMS"),
        ("CKV_AWS_136", "Ensure that ECR repositories are encrypted using KMS", "MEDIUM", "ENCRYPTION", "AWS::ECR::Repository", "EncryptionConfiguration.EncryptionType", "equals", "KMS", "EncryptionConfiguration:\n  EncryptionType: AES256", "EncryptionConfiguration:\n  EncryptionType: KMS"),
        ("CKV_AWS_53", "Ensure S3 bucket has block public ACLs enabled", "HIGH", "STORAGE", "AWS::S3::Bucket", "PublicAccessBlockConfiguration.BlockPublicAcls", "equals", True, "PublicAccessBlockConfiguration:\n  BlockPublicAcls: false", "PublicAccessBlockConfiguration:\n  BlockPublicAcls: true"),
        ("CKV_AWS_54", "Ensure S3 bucket has block public policy enabled", "HIGH", "STORAGE", "AWS::S3::Bucket", "PublicAccessBlockConfiguration.BlockPublicPolicy", "equals", True, "PublicAccessBlockConfiguration:\n  BlockPublicPolicy: false", "PublicAccessBlockConfiguration:\n  BlockPublicPolicy: true"),
        ("CKV_AWS_55", "Ensure S3 bucket has ignore public ACLs enabled", "HIGH", "STORAGE", "AWS::S3::Bucket", "PublicAccessBlockConfiguration.IgnorePublicAcls", "equals", True, "PublicAccessBlockConfiguration:\n  IgnorePublicAcls: false", "PublicAccessBlockConfiguration:\n  IgnorePublicAcls: true"),
        ("CKV_AWS_56", "Ensure S3 bucket has RestrictPublicBuckets enabled", "HIGH", "STORAGE", "AWS::S3::Bucket", "PublicAccessBlockConfiguration.RestrictPublicBuckets", "equals", True, "PublicAccessBlockConfiguration:\n  RestrictPublicBuckets: false", "PublicAccessBlockConfiguration:\n  RestrictPublicBuckets: true"),
        ("CKV_AWS_18", "Ensure the S3 bucket has access logging enabled", "MEDIUM", "LOGGING", "AWS::S3::Bucket", "LoggingConfiguration.DestinationBucketName", "exists", None, "BucketName: data", "LoggingConfiguration:\n  DestinationBucketName: logs"),
        ("CKV_AWS_20", "Ensure the S3 bucket does not allow READ permissions to everyone", "HIGH", "STORAGE", "AWS::S3::Bucket", "AccessControl", "not_within", ["PublicRead", "PublicReadWrite"], "AccessControl: PublicRead", "AccessControl: Private", "pass"),
        ("CKV_AWS_57", "Ensure the S3 bucket does not allow WRITE permissions to everyone", "HIGH", "STORAGE", "AWS::S3::Bucket", "AccessControl", "not_equals", "PublicReadWrite", "AccessControl: PublicReadWrite", "AccessControl: Private", "pass"),
        ("CKV_AWS_39", "Ensure Amazon EKS public endpoint disabled", "HIGH", "KUBERNETES", "AWS::EKS::Cluster", "ResourcesVpcConfig.EndpointPublicAccess", "equals", False, "ResourcesVpcConfig:\n  EndpointPublicAccess: true", "ResourcesVpcConfig:\n  EndpointPublicAccess: false"),
        ("CKV_AWS_2", "Ensure ALB protocol is HTTPS", "HIGH", "ENCRYPTION", "AWS::ElasticLoadBalancingV2::Listener", "Protocol", "not_equals", "HTTP", "Protocol: HTTP", "Protocol: HTTPS"),
        ("CKV_AWS_34", "Ensure CloudFront distribution ViewerProtocolPolicy is set to HTTPS", "HIGH", "ENCRYPTION", "AWS::CloudFront::Distribution", "DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy", "within", ["redirect-to-https", "https-only"], "DistributionConfig:\n  DefaultCacheBehavior:\n    ViewerProtocolPolicy: allow-all", "DistributionConfig:\n  DefaultCacheBehavior:\n    ViewerProtocolPolicy: https-only"),
        ("CKV_AWS_5", "Ensure Elasticsearch is encrypted at rest", "HIGH", "ENCRYPTION", "AWS::Elasticsearch::Domain", "EncryptionAtRestOptions.Enabled", "equals", True, "EncryptionAtRestOptions:\n  Enabled: false", "EncryptionAtRestOptions:\n  Enabled: true"),
        ("CKV_AWS_6", "Ensure Elasticsearch has node-to-node encryption enabled", "HIGH", "ENCRYPTION", "AWS::Elasticsearch::Domain", "NodeToNodeEncryptionOptions.Enabled", "equals", True, "NodeToNodeEncryptionOptions:\n  Enabled: false", "NodeToNodeEncryptionOptions:\n  Enabled: true"),
        ("CKV_AWS_119", "Ensure DynamoDB Tables are encrypted using a KMS Customer Managed CMK", "HIGH", "ENCRYPTION", "AWS::DynamoDB::Table", "SSESpecification.SSEEnabled", "equals", True, "SSESpecification:\n  SSEEnabled: false", "SSESpecification:\n  SSEEnabled: true\n  SSEType: KMS"),
        ("CKV_AWS_23", "Ensure every security group rule has a description", "LOW", "NETWORKING", "AWS::EC2::SecurityGroup", "GroupDescription", "exists", None, "GroupName: app", "GroupDescription: application tier"),
        ("CKV_AWS_79", "Ensure Instance Metadata Service Version 1 is not enabled", "HIGH", "GENERAL_SECURITY", "AWS::EC2::LaunchTemplate", "LaunchTemplateData.MetadataOptions.HttpTokens", "equals", "required", "LaunchTemplateData:\n  MetadataOptions:\n    HttpTokens: optional", "LaunchTemplateData:\n  MetadataOptions:\n    HttpTokens: required"),
    ]
    for row in rows:
        missing = row[10] if len(row) > 10 else None
        value = None if row[6] in {"exists", "not_exists"} else row[7]
        add(
            "cloudformation",
            row[0],
            row[1],
            row[2],
            row[3],
            [row[4]],
            attr(row[5], row[6], value, missing),
            cfn(row[4], "Bad", row[8]),
            cfn(row[4], "Good", row[9]),
        )
    add(
        "cloudformation",
        "CKV_AWS_19",
        "Ensure the S3 bucket has server-side-encryption enabled",
        "HIGH",
        "ENCRYPTION",
        ["AWS::S3::Bucket"],
        attr(
            "BucketEncryption.ServerSideEncryptionConfiguration.ServerSideEncryptionByDefault.SSEAlgorithm",
            "within",
            ["AES256", "aws:kms"],
            "pass",
        ),
        cfn("AWS::S3::Bucket", "Bad", "BucketEncryption:\n  ServerSideEncryptionConfiguration:\n    - ServerSideEncryptionByDefault:\n        SSEAlgorithm: none"),
        cfn("AWS::S3::Bucket", "Good", "BucketEncryption:\n  ServerSideEncryptionConfiguration:\n    - ServerSideEncryptionByDefault:\n        SSEAlgorithm: AES256"),
    )
    doc = '''PolicyDocument:
  Version: "2012-10-17"
  Statement:
    - Effect: Allow
      Action: %s
      Resource: %s'''
    add(
        "cloudformation",
        "CKV_AWS_63",
        'Ensure no IAM policies documents allow "*" as a statement\'s actions',
        "CRITICAL",
        "IAM",
        ["AWS::IAM::Policy", "AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group"],
        no_element("PolicyDocument.Statement", AND(attr("Effect", "equals", "Allow"), attr("Action", "equals_any", "*"))),
        cfn("AWS::IAM::Policy", "Bad", doc % ("'*'", "arn:aws:s3:::bucket")),
        cfn("AWS::IAM::Policy", "Good", doc % ('"s3:GetObject"', '"arn:aws:s3:::bucket/*"')),
    )
    add(
        "cloudformation",
        "CKV_AWS_62",
        "Ensure no IAM policies that allow full administrative privileges are created",
        "CRITICAL",
        "IAM",
        ["AWS::IAM::Policy", "AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group"],
        no_element(
            "PolicyDocument.Statement",
            AND(attr("Effect", "equals", "Allow"), attr("Action", "equals_any", "*"), attr("Resource", "equals_any", "*")),
        ),
        cfn("AWS::IAM::Policy", "Bad", doc % ("'*'", "'*'")),
        cfn("AWS::IAM::Policy", "Good", doc % ('"s3:GetObject"', '"arn:aws:s3:::bucket/*"')),
    )
    add(
        "cloudformation",
        "CKV_AWS_110",
        "Ensure IAM policies do not allow common privilege-escalation actions",
        "CRITICAL",
        "IAM",
        ["AWS::IAM::Policy"],
        no_element("PolicyDocument.Statement", AND(attr("Effect", "equals", "Allow"), attr("Action", "intersects", ESCALATION))),
        cfn("AWS::IAM::Policy", "Bad", doc % ("iam:PassRole", "'*'")),
        cfn("AWS::IAM::Policy", "Good", doc % ('"s3:GetObject"', '"arn:aws:s3:::bucket/*"')),
    )


def kubernetes():
    def k8(check_id, name, severity, category, definition, fail_spec, pass_spec, kinds=None, fail_ns="prod", pass_ns="prod"):
        kinds = kinds or ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"]
        add("kubernetes", check_id, name, severity, category, kinds, definition, pod("bad", fail_spec, fail_ns), pod("good", pass_spec, pass_ns))

    k8("CKV_K8S_16", "Container should not be privileged", "CRITICAL", "KUBERNETES", attr("_containers.securityContext.privileged", "not_equals", True, "pass"), container(extra="securityContext:\n  privileged: true"), container(extra="securityContext:\n  privileged: false"))
    k8("CKV_K8S_20", "Containers should not run with allowPrivilegeEscalation", "HIGH", "KUBERNETES", attr("_containers.securityContext.allowPrivilegeEscalation", "equals", False), container(extra="securityContext:\n  allowPrivilegeEscalation: true"), container(extra="securityContext:\n  allowPrivilegeEscalation: false"))
    k8("CKV_K8S_22", "Use read-only filesystem for containers where possible", "MEDIUM", "KUBERNETES", attr("_containers.securityContext.readOnlyRootFilesystem", "equals", True), container(extra="securityContext:\n  readOnlyRootFilesystem: false"), container(extra="securityContext:\n  readOnlyRootFilesystem: true"))
    k8("CKV_K8S_23", "Minimize the admission of root containers", "HIGH", "KUBERNETES", attr("_containers.securityContext.runAsNonRoot", "equals", True), container(extra="securityContext:\n  runAsNonRoot: false"), container(extra="securityContext:\n  runAsNonRoot: true"))
    k8("CKV_K8S_17", "Containers should not share the host process ID namespace", "HIGH", "KUBERNETES", attr("_pod_spec.hostPID", "not_equals", True, "pass"), "hostPID: true\n" + container(), "hostPID: false\n" + container())
    k8("CKV_K8S_18", "Containers should not share the host IPC namespace", "HIGH", "KUBERNETES", attr("_pod_spec.hostIPC", "not_equals", True, "pass"), "hostIPC: true\n" + container(), "hostIPC: false\n" + container())
    k8("CKV_K8S_19", "Containers should not share the host network namespace", "HIGH", "KUBERNETES", attr("_pod_spec.hostNetwork", "not_equals", True, "pass"), "hostNetwork: true\n" + container(), "hostNetwork: false\n" + container())
    k8("CKV_K8S_14", "Image Tag should be fixed - not latest or blank", "MEDIUM", "KUBERNETES", attr("_containers.image", "image_tag_pinned"), container("nginx:latest"), container("nginx:1.25"))
    k8("CKV_K8S_43", "Image should use digest", "LOW", "KUBERNETES", attr("_containers.image", "contains", "@"), container("nginx:1.25"), container("nginx@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
    k8("CKV_K8S_15", "Image Pull Policy should be Always", "LOW", "KUBERNETES", attr("_containers.imagePullPolicy", "equals", "Always"), container(extra="imagePullPolicy: IfNotPresent"), container(extra="imagePullPolicy: Always"))
    k8("CKV_K8S_10", "CPU requests should be set", "MEDIUM", "KUBERNETES", attr("_containers.resources.requests.cpu", "exists"), container(), container(extra="resources:\n  requests:\n    cpu: 100m"))
    k8("CKV_K8S_11", "CPU limits should be set", "MEDIUM", "KUBERNETES", attr("_containers.resources.limits.cpu", "exists"), container(), container(extra="resources:\n  limits:\n    cpu: 500m"))
    k8("CKV_K8S_12", "Memory requests should be set", "MEDIUM", "KUBERNETES", attr("_containers.resources.requests.memory", "exists"), container(), container(extra="resources:\n  requests:\n    memory: 128Mi"))
    k8("CKV_K8S_13", "Memory limits should be set", "MEDIUM", "KUBERNETES", attr("_containers.resources.limits.memory", "exists"), container(), container(extra="resources:\n  limits:\n    memory: 256Mi"))
    k8("CKV_K8S_8", "Liveness Probe Should be Configured", "LOW", "KUBERNETES", attr("_containers.livenessProbe", "exists"), container(), container(extra="livenessProbe:\n  httpGet:\n    path: /health\n    port: 80"))
    k8("CKV_K8S_9", "Readiness Probe Should be Configured", "LOW", "KUBERNETES", attr("_containers.readinessProbe", "exists"), container(), container(extra="readinessProbe:\n  httpGet:\n    path: /ready\n    port: 80"))
    k8("CKV_K8S_29", "Apply security context to your pods and containers", "MEDIUM", "KUBERNETES", attr("_pod_spec.securityContext", "exists"), container(), "securityContext:\n  runAsNonRoot: true\n" + container())
    k8("CKV_K8S_30", "Apply security context to your containers", "MEDIUM", "KUBERNETES", attr("_containers.securityContext", "exists"), container(), container(extra="securityContext:\n  runAsNonRoot: true"))
    k8("CKV_K8S_31", "Ensure that the seccomp profile is set to RuntimeDefault or Localhost", "MEDIUM", "KUBERNETES", attr("_pod_spec.securityContext.seccompProfile.type", "within", ["RuntimeDefault", "Localhost"]), container(), "securityContext:\n  seccompProfile:\n    type: RuntimeDefault\n" + container())
    k8("CKV_K8S_28", "Minimize the admission of containers with the NET_RAW capability", "HIGH", "KUBERNETES", OR(attr("_containers.securityContext.capabilities.drop", "contains", "NET_RAW"), attr("_containers.securityContext.capabilities.drop", "contains", "ALL")), container(extra="securityContext:\n  capabilities:\n    drop:\n      - KILL"), container(extra="securityContext:\n  capabilities:\n    drop:\n      - ALL"))
    k8("CKV_K8S_25", "Minimize the admission of containers with added capability", "HIGH", "KUBERNETES", attr("_containers.securityContext.capabilities.add", "not_exists"), container(extra="securityContext:\n  capabilities:\n    add:\n      - NET_ADMIN"), container(extra="securityContext:\n  capabilities:\n    drop:\n      - ALL"))
    k8("CKV_K8S_39", "Do not use the CAP_SYS_ADMIN linux capability", "CRITICAL", "KUBERNETES", attr("_containers.securityContext.capabilities.add", "not_contains", "SYS_ADMIN", "pass"), container(extra="securityContext:\n  capabilities:\n    add:\n      - SYS_ADMIN"), container())
    k8("CKV_K8S_26", "Do not specify hostPort unless absolutely necessary", "MEDIUM", "KUBERNETES", attr("_containers.ports.hostPort", "not_exists"), container(extra="ports:\n  - containerPort: 80\n    hostPort: 80"), container(extra="ports:\n  - containerPort: 80"))
    k8("CKV_K8S_40", "Containers should run as a high UID to avoid host conflict", "MEDIUM", "KUBERNETES", attr("_containers.securityContext.runAsUser", "greater_than_or_equal", 10000), container(extra="securityContext:\n  runAsUser: 0"), container(extra="securityContext:\n  runAsUser: 10000"))
    k8("CKV_K8S_38", "Ensure that Service Account Tokens are only mounted where necessary", "MEDIUM", "KUBERNETES", attr("_pod_spec.automountServiceAccountToken", "equals", False), "automountServiceAccountToken: true\n" + container(), "automountServiceAccountToken: false\n" + container())
    k8(
        "CKV_K8S_21",
        "The default namespace should not be used",
        "MEDIUM",
        "KUBERNETES",
        attr("metadata.namespace", "not_equals", "default", "fail"),
        container(),
        container(),
        kinds=["Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob", "Service", "ConfigMap", "Secret"],
        fail_ns="default",
        pass_ns="prod",
    )
    k8(
        "CKV_K8S_27",
        "Do not expose the docker daemon socket to containers",
        "CRITICAL",
        "KUBERNETES",
        no_element("_pod_spec.volumes", attr("hostPath.path", "contains", "docker.sock")),
        "volumes:\n  - name: sock\n    hostPath:\n      path: /var/run/docker.sock\n" + container(),
        container(),
    )
    k8(
        "CKV_K8S_35",
        "Prefer using secrets as files over secrets as environment variables",
        "HIGH",
        "KUBERNETES",
        no_element("_containers.env", attr("valueFrom.secretKeyRef.name", "exists")),
        container(extra="env:\n  - name: TOKEN\n    valueFrom:\n      secretKeyRef:\n        name: db\n        key: password"),
        container(extra="env:\n  - name: LOG\n    value: info"),
    )
    add(
        "kubernetes",
        "CKV_K8S_49",
        "Minimize wildcard use in Roles and ClusterRoles",
        "HIGH",
        "IAM",
        ["Role", "ClusterRole"],
        no_element("rules", OR(attr("verbs", "equals_any", "*"), attr("resources", "equals_any", "*"))),
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: bad\nrules:\n  - apiGroups: [\"\"]\n    resources: [\"pods\"]\n    verbs: [\"*\"]\n",
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: good\nrules:\n  - apiGroups: [\"\"]\n    resources: [\"pods\"]\n    verbs: [\"get\", \"list\"]\n",
    )
    k8("CKV_K8S_37", "Minimize the admission of containers with capabilities assigned", "MEDIUM", "KUBERNETES", attr("_containers.securityContext.capabilities.drop", "contains", "ALL"), container(extra="securityContext:\n  capabilities:\n    drop:\n      - NET_RAW"), container(extra="securityContext:\n  capabilities:\n    drop:\n      - ALL"))


if __name__ == "__main__":
    main()
