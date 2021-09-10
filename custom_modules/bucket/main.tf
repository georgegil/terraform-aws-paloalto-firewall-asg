data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "bucket" {
  bucket = lower(var.bucket_name)
  acl    = var.bucket_acl

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = var.kms_encrypted == true ? var.kms_key_arn : null
        sse_algorithm     = var.kms_encrypted == true ? "aws:kms" : "AES256"
      }
    }
  }

  lifecycle_rule {
    id                                     = "DeleteIncompleteUploads"
    enabled                                = true
    abort_incomplete_multipart_upload_days = 30
  }

  dynamic "lifecycle_rule" {
    for_each = var.current_version_transitions
    iterator = each

    content {
      id      = each.key
      enabled = each.value.enabled
      prefix  = each.value.prefix

      transition {
        days          = each.value.transition_days
        storage_class = each.value.storage_class
      }
    }
  }

  dynamic "lifecycle_rule" {
    for_each = var.current_version_expirations
    iterator = each

    content {
      id      = each.key
      enabled = each.value.enabled
      prefix  = each.value.prefix

      expiration {
        days = each.value.expiration_days
      }
    }
  }

  dynamic "lifecycle_rule" {
    for_each = var.previous_version_transitions
    iterator = each

    content {
      id      = each.key
      enabled = each.value.enabled
      prefix  = each.value.prefix

      noncurrent_version_transition {
        days          = each.value.transition_days
        storage_class = each.value.storage_class
      }
    }
  }

  dynamic "lifecycle_rule" {
    for_each = var.previous_version_expirations
    iterator = each

    content {
      id      = each.key
      enabled = each.value.enabled
      prefix  = each.value.prefix

      noncurrent_version_expiration {
        days = each.value.expiration_days
      }
    }
  }

  versioning {
    enabled = var.enable_versioning
  }

  dynamic "replication_configuration" {
    for_each = var.crr_configuration != null ? [1] : []
    iterator = config

    content {
      role = var.crr_role_arn

      dynamic "rules" {
        for_each = var.crr_configuration
        iterator = rule

        content {
          id       = rule.key
          priority = rule.value.priority
          status   = rule.value.status
          prefix   = rule.value.prefix

          destination {
            bucket             = var.crr_dest_bucket_arn
            replica_kms_key_id = var.crr_dest_cmk_arn
            storage_class      = rule.value.dest_storage_class
          }

          source_selection_criteria {
            sse_kms_encrypted_objects {
              enabled = true
            }
          }
        }
      }
    }
  }

  tags = var.tags
}

resource "aws_s3_bucket_public_access_block" "block" {
  depends_on = [aws_s3_bucket.bucket]
  bucket     = aws_s3_bucket.bucket.id

  block_public_acls       = var.block_public_access
  block_public_policy     = var.block_public_access
  ignore_public_acls      = var.block_public_access
  restrict_public_buckets = var.block_public_access
}
