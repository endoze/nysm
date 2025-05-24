# Nysm (Now You See Me)

![Build Status](https://github.com/endoze/nysm/actions/workflows/ci.yml/badge.svg?branch=master)
[![Coverage Status](https://coveralls.io/repos/github/endoze/nysm/badge.svg?branch=master)](https://coveralls.io/github/endoze/nysm?branch=master)
[![Crate](https://img.shields.io/crates/v/nysm.svg)](https://crates.io/crates/nysm)
[![Docs](https://docs.rs/nysm/badge.svg)](https://docs.rs/nysm)

#### Manage your secrets via the command line

Nysm is a command line utility designed to make interacting with secrets management providers simple and intuitive. Whether you need to quickly view a secret, update configuration values, or manage your secrets workflow, Nysm provides a streamlined interface with support for multiple data formats and your preferred editor.

## Features

- **List all secrets** in your account with names and descriptions
- **View secret values** in multiple formats (JSON, YAML, plain text)
- **Edit secrets** using your preferred editor with format conversion
- **Create new secrets** interactively with optional descriptions
- **Delete secrets** when no longer needed
- **Multi-format support** for seamless workflow integration
- **Syntax highlighting** and pagination for better readability

# Installation

```sh
cargo install nysm
```

# Usage

List secrets:

```sh
nysm list
```

Show a specific secret:

```sh
nysm show some-secret-id
```

Edit an existing secret:

```sh
nysm edit some-secret-id
```

Create a new secret:

```sh
nysm create some-new-secret-id -d "This is a description for the secret"
```

Delete a secret:

```sh
nysm delete some-secret-id
```

## Advanced Usage

### Format Options

Nysm supports multiple data formats for viewing and editing secrets:

- `json` - JSON format (default for stored secrets)
- `yaml` - YAML format (default for editing)
- `text` - Plain text format

You can specify different formats for storage and editing:

```sh
# View a JSON secret as YAML (default behavior)
nysm show my-secret

# View a secret as JSON
nysm show my-secret --print-format json

# Edit a secret, converting from JSON storage to YAML for editing
nysm edit my-secret --secret-format json --edit-format yaml

# Create a secret and store it as JSON (converted from YAML editing)
nysm create my-new-secret --secret-format json --edit-format yaml
```

### Region Selection

Specify a different region using the `-r` or `--region` flag:

```sh
nysm -r us-west-2 list
nysm --region eu-west-1 show my-secret
```

### Editor Integration

When creating or editing secrets, Nysm will open your preferred editor:

- Uses the `EDITOR` environment variable (defaults to `vim`)
- Temporary files are created with appropriate extensions for syntax highlighting
- Changes are only saved if the file content is modified

## Configuration

### AWS Credentials

Nysm uses standard AWS credential resolution:

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. AWS credentials file (`~/.aws/credentials`)
3. IAM roles (when running on EC2)
4. AWS SSO

### Required Permissions

Your AWS credentials need the following IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:ListSecrets",
        "secretsmanager:GetSecretValue",
        "secretsmanager:CreateSecret",
        "secretsmanager:UpdateSecret",
        "secretsmanager:DeleteSecret"
      ],
      "Resource": "*"
    }
  ]
}
```

## Examples

### Managing Application Configuration

```sh
# List all secrets to find your app config
nysm list

# View current database configuration
nysm show myapp/database/config

# Update database password
nysm edit myapp/database/config

# Create new API key secret
nysm create myapp/api/keys -d "API keys for external services"
```

### Working with Different Formats

```sh
# View a plaintext secret (like an SSL certificate)
nysm show ssl-cert --print-format text --secret-format text

# Convert YAML configuration to JSON storage
nysm create app-config --secret-format json --edit-format yaml
```
