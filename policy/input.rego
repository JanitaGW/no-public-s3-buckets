package s3policy

deny[message] {
    input.resource_type == "aws_s3_bucket"
    input.acl == "public-readd"
    message := "S3 buckets cannot be publicy readable (acl: public-read)'
}