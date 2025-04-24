# AWS Resource Management & Security Scanning Bot

## Overview

The AWS Resource Management & Security Scanning Bot is a Python-based tool designed to help Cloud Operation and Cloud Engineering teams quickly query and analyze AWS resources and security postures using natural language processing.

## Features

### 1. AWS Config Resource Querying

- Query AWS resources using natural language
- Translates natural language queries into AWS Config SQL
- Supports complex resource searches across multiple AWS accounts
- Outputs results in CSV format for easy analysis

#### Example Queries:

- "Show me all S3 buckets without encryption"
- "Find EC2 instances running Windows"
- "List RDS instances that are publicly accessible"

### 2. Security Posture Scanning

- Check security status of AWS accounts
- Supports filtering by account name or keywords
- Provides comprehensive security insights including:
  - EKS Access Endpoint status
  - Access Keys Rotation
  - Unused IAM Roles
  - Unused Permissions
  - SecurityHub Status (multiple regions)

#### Example Queries:

- "Please scan account Tools"
- "Is there any security issue on MyTelkomsel?"
- "Check security posture for all Production accounts"

## Prerequisites

- Python 3.10
- AWS Account with appropriate permissions
- OpenAI API Key
- Grafana API Key (for security posture data)

## Installation

1. Clone the repository

```bash
git clone https://github.com/dwikikurnia/aws-config-query-mcp.git
```

2. Install required dependencies

```bash
pip install -r requirements.txt
```

3. Set up environment variables
   Create a `.env` file with the following:

```
AWS_REGION=your_region
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AWS_SESSION_TOKEN=your_aws_session_token
CONFIG_AGGREGATOR_NAME=your_config_aggregator_name
OPENAI_API_KEY=your_openai_api_key
GRAFANA_API_KEY=your_grafana_api_key
```

## Usage

Run the bot interactively:

```bash
python server.py
```

Select from two main tools:

1. AWS Config Resource Query
2. Security Scanning Check

### Command-Line Interaction Example

```
AWS Resource Management Bot
Available tools:
1. Query AWS Config Resources
2. Scan & Check Security Scanning Account Based

Select a tool (1 or 2): 1
Enter your resource query: List EC2 Instance Type t3.small
```

## Key Technologies

- Python
- AWS SDK (boto3)
- AWS Config
- AWS IAM
- OpenAI GPT Models
- MCP Framework
- Grafana API

## Contact

Dwiki Kurnia - dwikikurnia1@gmail.com
