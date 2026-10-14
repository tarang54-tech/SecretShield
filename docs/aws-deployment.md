# AWS deployment notes

AWS integration is not implemented in the current SecretShield slice. Local use needs no AWS account or credentials.

If deployed later, use a small Linux EC2 instance with Docker Compose, an instance profile for any AWS SDK operations, and a security group that restricts SSH to a trusted IP. Do not pass AWS access keys through the browser or `.env`; use the AWS credential provider chain and a narrowly scoped read-only IAM policy. Do not expose PostgreSQL. Put the web app behind HTTPS and authentication before serving a network audience.

For a classroom demonstration, run locally with Docker Compose first. If using EC2 later, configure a budget, verify all requested IAM permissions are read-only, monitor charges, and terminate the instance/delete unused disks after the exercise. No AWS resources are created by SecretShield.
