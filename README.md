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
git clone https://github.com/your-org/aws-resource-management-bot.git
cd aws-resource-management-bot
```

2. Install required dependencies

```bash
pip install -r requirements.txt
```

3. Set up environment variables
   Create a `.env` file with the following:

```
AWS_REGION=ap-southeast-3
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
python bot.py
```

Select from two main tools:

1. AWS Config Resource Query
2. Security Posture Check

### Command-Line Interaction Example

```
AWS Resource Management Bot
Available tools:
1. Query AWS Config Resources
2. Scan & Check Security Posture Account Based

Select a tool (1 or 2): 1
Enter your resource query: Show me all S3 buckets without encryption
```

## Key Technologies

- Python
- AWS SDK (boto3)
- OpenAI GPT Models
- Pandas
- AsyncIO
- Grafana API
- AWS Config

## Security Considerations

- Supports multi-account AWS environments
- Uses secure API authentication
- Generates temporary output files for each query
- Supports filtering and keyword-based searching

## Limitations

- Requires valid AWS, OpenAI, and Grafana API credentials
- Performance depends on the complexity of queries and number of resources
- Natural language processing accuracy is model-dependent

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

Distributed under the MIT License. See `LICENSE` for more information.

## Contact

Your Name - dwikikurnia1@gmail.com
