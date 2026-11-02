resource "aws_ebs_volume" "bad" {
  availability_zone = "us-east-1a"
  size              = 8
  encrypted         = false
}
