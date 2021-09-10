variable "tags" {
  type        = map(string)
}

variable "bucket_name" {
  description = "The name of the S3 bucket."
  type        = string
}

variable "bucket_acl" {
  description = "The 'Canned ACL' to apply. See related links."
  type        = string
  default     = "private"
}

variable "kms_encrypted" {
  description = "Boolean value if 'true' to use Amazon S3 server side encryption with your own AWS KMS key (CMK), or 'false' to use a key managed by Amazon S3."
  type        = bool
  default     = false
}

variable "kms_key_arn" {
  description = "Amazon CMK ARN for KMS key used for Amazon S3 server side encryption. This value can only be set when 'kms_encrypted' is 'true'. This value _must_ be an AWS CMK ARN and not an ID or alias."
  type        = string
  default     = null
}

variable "block_public_access" {
  description = "Specifies whether or not to allow objects to be public.  Accepts 'true' or 'false'"
  type        = bool
}

variable "enable_versioning" {
  description = "Specifies whether or not to enable versioning on the bucket. Accepts 'true' or 'false'"
  type        = bool
  default     = false
}

variable "current_version_transitions" {
  description = "Lifecycle rule to manage storage tier transitions for current bucket object versions. See object specific arguments in the README."
  type = map(object({
    enabled         = bool
    prefix          = string
    storage_class   = string
    transition_days = number
  }))
  default = null
}

variable "current_version_expirations" {
  description = "Lifecycle rule to automatically delete current bucket object versions after a set number of days. See object specific arguments in the README."
  type = map(object({
    enabled         = bool
    prefix          = string
    expiration_days = number
  }))
  default = null
}

variable "previous_version_transitions" {
  description = "Lifecycle rule to manage storage tier transitions for previous bucket object versions.  Only applicable if 'enable_versioning' is set to 'true'. See object specific arguments in the README."
  type = map(object({
    enabled         = bool
    prefix          = string
    storage_class   = string
    transition_days = number
  }))
  default = null
}

variable "previous_version_expirations" {
  description = "Lifecycle rule to automatically delete previous bucket object versions after a set number of days.  Only applicable if 'enable_versioning' is set to 'true'. See object specific arguments in the README."
  type = map(object({
    enabled         = bool
    prefix          = string
    expiration_days = number
  }))
  default = null
}

variable "crr_role_arn" {
  description = "Specify the ARN of the IAM role for Amazon S3 to assume when replicating the objects. Must be provided for both source and destination buckets."
  type        = string
  default     = null
}

variable "crr_dest_bucket_arn" {
  description = "If using 'crr_configuration', specify the ARN of the S3 bucket where you want Amazon S3 to replicate to."
  type        = string
  default     = null
}

variable "crr_dest_cmk_arn" {
  description = "If using 'crr_configuration', specify the destination bucket's KMS encryption key ARN for SSE-KMS replication."
  type        = string
  default     = null
}

variable "crr_configuration" {
  description = "Cross-region replication configuration for the source bucket. See object specific arguments in the README."
  type = map(object({
    priority           = string
    status             = string
    prefix             = string
    dest_storage_class = string
  }))
  default = {}
}
