import os
import json
import boto3
import pandas as pd
import asyncio
import requests
import nest_asyncio
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from openai import OpenAI

load_dotenv()

# Apply nest_asyncio to ensure compatibility with asyncio in environments like Jupyter
nest_asyncio.apply()

# Get configuration from environment variables
AWS_REGION = os.environ.get("AWS_REGION")
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
AWS_SESSION_TOKEN = os.environ.get("AWS_SESSION_TOKEN")
CONFIG_AGGREGATOR_NAME = os.environ.get("CONFIG_AGGREGATOR_NAME")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")

# Grafana API configuration
GRAFANA_API_URL = os.environ.get("GRAFANA_API_URL")
GRAFANA_API_KEY = os.environ.get("GRAFANA_API_KEY")

# Initialize OpenAI client with new SDK syntax
client = OpenAI(api_key=OPENAI_API_KEY)

# Function to convert NLP query to AWS Config SQL query
def nlp_to_config_query(prompt: str) -> str:
    system_prompt = (
        "You are an expert in AWS Config Advanced Queries. "
        "Translate natural language requests into AWS Config SQL (SELECT ...) statements only. "
        "Always include accountId in the SELECT clause to identify the account. "
        "Always include resourceId or the specific resource identifier in the SELECT clause. "
        "Include the configuration field for accessing resource-specific attributes."
        "Dont use FROM and configuration.region in query"
    )
    
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ],
        temperature=0
    )
    
    sql = response.choices[0].message.content.strip()
    if not sql.lower().startswith("select"):
        raise ValueError("⚠️ Model did not return a valid SQL query.")
    return sql

# Function to extract keywords from natural language query
def extract_account_keywords(query: str) -> list:
    system_prompt = (
        "You are an expert in extracting AWS account keywords from natural language queries. "
        "Given a query about AWS accounts or applications, extract all potential keywords that "
        "could be used to identify accounts or applications. Break compound terms into individual words "
        "and remove common terms like 'account', 'aws', etc. Return ONLY a JSON array of keywords."
        "\n\nExamples:"
        "\nQuery: 'Please scan account Dev Tools'"
        "\nResponse: [\"dev\", \"tools\"]"
        "\n\nQuery: 'Is there any security issue on MyTelkomsel?'"
        "\nResponse: [\"mytelkomsel\", \"telkomsel\"]"
        "\n\nQuery: 'Is there any issue on digipos apps?'"
        "\nResponse: [\"digipos\"]"
        "\n\nQuery: 'Check security for digiposss'"
        "\nResponse: [\"digipos\"]"
        "\n\nQuery: 'What are the security issues in our environment?'"
        "\nResponse: []"
    )
    
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": query}
        ],
        temperature=0
    )
    
    try:
        keywords = json.loads(response.choices[0].message.content)
        if isinstance(keywords, list):
            # Convert all keywords to lowercase
            return [keyword.lower() for keyword in keywords if keyword.strip()]
        return []
    except:
        # Fallback in case the model doesn't return valid JSON
        content = response.choices[0].message.content.strip()
        if content.startswith("[") and content.endswith("]"):
            try:
                keywords = json.loads(content)
                return [keyword.lower() for keyword in keywords if keyword.strip()]
            except:
                pass
        
        # Extract keywords manually as a last resort
        words = re.findall(r'\b\w+\b', content.lower())
        # Filter out common words
        common_words = {'account', 'aws', 'check', 'issue', 'security', 'the', 'on', 'in', 'for'}
        return [word for word in words if word not in common_words and len(word) > 2]

# Function to query AWS Config with aggregator and return DataFrame
def query_aws_config_aggregator(expression: str) -> pd.DataFrame:
    # Initialize AWS Config client with credentials
    config_client = boto3.client(
        'config', 
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY_ID if AWS_ACCESS_KEY_ID != "xxx" else None,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY if AWS_SECRET_ACCESS_KEY != "xxx" else None,
        aws_session_token=AWS_SESSION_TOKEN if AWS_SESSION_TOKEN != "xxx" else None
    )
    
    # Initialize an empty list to store all query results
    all_results = []
    
    # Initialize NextToken for pagination
    next_token = None
    
    # Paginate through all results
    while True:
        # Execute the query against the aggregator
        if next_token:
            response = config_client.select_aggregate_resource_config(
                Expression=expression,
                ConfigurationAggregatorName=CONFIG_AGGREGATOR_NAME,
                NextToken=next_token
            )
        else:
            response = config_client.select_aggregate_resource_config(
                Expression=expression,
                ConfigurationAggregatorName=CONFIG_AGGREGATOR_NAME
            )
        
        # Extract the results
        query_results = response.get('Results', [])
        
        # Append current page results to all_results list
        all_results.extend(query_results)
        
        # Check if there are more pages
        if 'NextToken' in response:
            next_token = response['NextToken']
        else:
            break  # No more pages
    
    # Convert JSON strings to dictionaries
    results_dicts = []
    for result in all_results:
        try:
            # Parse the JSON result
            result_dict = json.loads(result)
            
            # Extract resource-specific fields if possible
            # This part might need customization based on resource type
            if 'configuration' in result_dict:
                for key, value in result_dict['configuration'].items():
                    if key not in result_dict:  # Don't overwrite existing keys
                        result_dict[key] = value
            
            results_dicts.append(result_dict)
        except json.JSONDecodeError:
            print(f"Could not parse result: {result}")
    
    # Convert to DataFrame if we have results
    if results_dicts:
        return pd.DataFrame(results_dicts)
    else:
        return pd.DataFrame()  # Return empty DataFrame if no results

# Function to get security posture data from Grafana API
def get_security_posture(keywords=None):
    """
    Query the Grafana API to get security posture data
    If keywords is provided, filter results for accounts matching any of those keywords
    """
    # Default Grafana query payload
    payload = {
        "queries": [
            {
                "refId": "A",
                "datasource": {
                    "type": "grafana-postgresql-datasource",
                    "uid": "cdfowczxgqxhcb"
                },
                "rawSql": "SELECT \naccount_name,\nCOALESCE(status_eks_access_endpoint,'OK') as \"EKS Access Endpoint\",\nCONCAT(COALESCE(status_access_keys_review,'OK'), ' (', COALESCE(total_key,0), ')') as \"Access Keys Rotation\",\nCONCAT(COALESCE(status_unused_role,'OK'), ' (', COALESCE(total_unused_role,0), ')') as \"Unused Role\",\nCONCAT(COALESCE(status_unused_permission,'OK'), ' (', COALESCE(total_unused_permission,0), ')') as \"Unused Permission\",\nCONCAT(COALESCE(status_securityhub,'NOK')) as \"SecurityHub AP3 Status\",\nCONCAT(COALESCE(status_securityhub_nvirginia,'NOK')) as \"SecurityHub US1 Status\"\nFROM (SELECT account_id, account_name FROM account_list WHERE ingest_date = (SELECT MAX(ingest_date) FROM account_list))\n--EKS Access Endpoint\nLEFT JOIN \n(SELECT DISTINCT account_id, 'NOK' as status_eks_access_endpoint FROM security_eks_access_endpoint \nWHERE ingest_date = (SELECT MAX(ingest_date) FROM security_eks_access_endpoint) AND public_access = 'true')\nUSING (account_id)\n--Access Keys Rotation 90 Days\nLEFT JOIN\n(SELECT accountid as account_id, 'NOK' as status_access_keys_review, COUNT(*) as total_key FROM security_access_keys_review_mod \nWHERE ingest_date = (SELECT MAX(ingest_date) FROM security_access_keys_review_mod) AND status_days = 'NOK'\nGROUP BY 1,2)\nUSING (account_id)\n--Access Analyzer Unused Role\nLEFT JOIN \n(SELECT resourceowneraccount as account_id, 'NOK' as status_unused_role, COUNT(*) as total_unused_role FROM security_access_analyzer_finding\nWHERE findingtype = 'UnusedIAMRole' AND ingest_date = (SELECT MAX(ingest_date) FROM security_access_analyzer_finding)\nGROUP BY 1,2)\nUSING (account_id)\n--Access Analyzer Unused Permission\nLEFT JOIN\n(SELECT resourceowneraccount as account_id, 'NOK' as status_unused_permission, COUNT(*) as total_unused_permission FROM security_access_analyzer_finding\nWHERE findingtype = 'UnusedPermission' AND ingest_date = (SELECT MAX(ingest_date) FROM security_access_analyzer_finding)\nGROUP BY 1,2)\nUSING (account_id)\n--SecurityHub Status Jakarta\nLEFT JOIN \n(SELECT DISTINCT account_id, 'OK' as status_securityhub FROM security_securityhub_audit\nWHERE status = 'Enabled' AND region = 'ap-southeast-3' AND ingest_date = (SELECT MAX(ingest_date) FROM security_securityhub_audit))\nUSING (account_id)\n--SecurityHub Status N Virginia\nLEFT JOIN \n(SELECT DISTINCT account_id, 'OK' as status_securityhub_nvirginia FROM security_securityhub_audit\nWHERE status = 'Enabled' AND region = 'us-east-1' AND ingest_date = (SELECT MAX(ingest_date) FROM security_securityhub_audit))\nUSING (account_id)\nORDER BY account_name",
                "format": "table",
                "intervalMs": 60000,
                "maxDataPoints": 2077
            }
        ],
        "from": "now-1h",
        "to": "now"
    }
    
    # Set up headers with authentication
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {GRAFANA_API_KEY}"
    }
    
    try:
        # Make the POST request to the Grafana API
        response = requests.post(
            GRAFANA_API_URL,
            json=payload,
            headers=headers,
            timeout=30  # 30 second timeout
        )
        
        # Check if the request was successful
        response.raise_for_status()
        
        # Parse the JSON response
        response_data = response.json()
        
        # Convert the Grafana results to a pandas DataFrame
        if 'results' in response_data and 'A' in response_data['results']:
            # Extract the frame data from the response
            frame_data = response_data['results']['A']['frames'][0]
            
            # Extract column names and data
            columns = [field['name'] for field in frame_data['schema']['fields']]
            
            # Extract the data from each column
            data = []
            for i in range(len(frame_data['data']['values'][0])):
                row = {}
                for j, col in enumerate(columns):
                    row[col] = frame_data['data']['values'][j][i]
                data.append(row)
            
            # Create DataFrame
            df = pd.DataFrame(data)
            
            # If keywords are provided, filter the DataFrame using flexible matching
            if keywords and len(keywords) > 0:
                filtered_df = pd.DataFrame()
                
                # Convert account names to lowercase for case-insensitive matching
                df['account_name_lower'] = df['account_name'].str.lower()
                
                # Try different matching strategies
                for keyword in keywords:
                    # Exact match first
                    exact_matches = df[df['account_name_lower'].str.contains(keyword, regex=False)]
                    
                    # Try fuzzy match if exact match doesn't yield results
                    if exact_matches.empty:
                        # Handle common typos or variations
                        keyword_variations = [keyword]
                        
                        # Add variation with one less character (for typos like extra letters)
                        if len(keyword) > 3:
                            for i in range(len(keyword)):
                                variation = keyword[:i] + keyword[i+1:]
                                keyword_variations.append(variation)
                        
                        # Try matching with any variation
                        for variation in keyword_variations:
                            variation_matches = df[df['account_name_lower'].str.contains(variation, regex=False)]
                            filtered_df = pd.concat([filtered_df, variation_matches])
                    else:
                        filtered_df = pd.concat([filtered_df, exact_matches])
                
                # Remove the temporary lowercase column
                filtered_df = filtered_df.drop(columns=['account_name_lower'])
                
                # Remove duplicates
                if not filtered_df.empty:
                    filtered_df = filtered_df.drop_duplicates().reset_index(drop=True)
                    return filtered_df
                
                # If still no matches, try more aggressive matching with word parts
                df['account_name_lower'] = df['account_name'].str.lower()
                for keyword in keywords:
                    if len(keyword) >= 4:  # Only use keywords of reasonable length
                        # Try matching any part of the keyword (at least 4 chars)
                        for start in range(len(keyword) - 3):
                            for end in range(start + 4, len(keyword) + 1):
                                part = keyword[start:end]
                                part_matches = df[df['account_name_lower'].str.contains(part, regex=False)]
                                filtered_df = pd.concat([filtered_df, part_matches])
                
                # Remove the temporary lowercase column
                filtered_df = filtered_df.drop(columns=['account_name_lower'])
                
                # Remove duplicates again
                if not filtered_df.empty:
                    filtered_df = filtered_df.drop_duplicates().reset_index(drop=True)
                    return filtered_df
                
                # Return empty DataFrame if no matches found after all attempts
                return pd.DataFrame()
            else:
                return df
        else:
            return pd.DataFrame()  # Return empty DataFrame if no results
        
    except requests.exceptions.RequestException as e:
        raise Exception(f"Error communicating with Grafana API: {str(e)}")
    except json.JSONDecodeError:
        raise Exception("Received invalid JSON response from Grafana API")
    except Exception as e:
        raise Exception(f"Security posture query failed: {str(e)}")

# Initialize FastMCP bot
mcp = FastMCP("AWS Resource Management Bot")

# TOOL 1: AWS Config Query Tool
@mcp.tool()
async def ask(query: str) -> str:
    """
    Query AWS resources using natural language. This tool translates your question
    into AWS Config SQL and returns matching resources.
    
    Examples:
    - "Show me all S3 buckets without encryption"
    - "Find EC2 instances running Windows"
    - "List RDS instances that are publicly accessible"
    """
    try:
        # Convert natural language to SQL
        sql = nlp_to_config_query(query)
        print(f"Executing query: {sql}")
        
        # Execute the query and get results as DataFrame
        results_df = query_aws_config_aggregator(sql)
        uuid = os.urandom(4).hex()  # Generate a random UUID for the file name
        
        # Save results to CSV
        results_df.to_csv(f'results_{uuid}.csv', index=False)
        
        if results_df.empty:
            return "✅ No results found for your query."
        
        # Format as text response
        result_text = f"📊 SQL:\n`{sql}`\n\n📄 Results:\n"
        
        # Add dataframe info
        result_text += f"Found {len(results_df)} resources.\n"
        result_text += f"Columns: {', '.join(results_df.columns.tolist())}\n\n"
        
        result_text += f"Results saved to results_{uuid}.csv\n\n"
        
        # Add sample rows (first 5)
        result_text += "Sample rows:\n"
        sample_df = results_df.head(5)
        
        # Limit output size for large DataFrames
        if sample_df.shape[1] > 10:
            # Too many columns, show only key columns
            key_columns = ['accountId', 'resourceId', 'resourceType', 'resourceName', 'awsRegion']
            available_keys = [col for col in key_columns if col in sample_df.columns]
            
            if len(available_keys) > 0:
                result_text += sample_df[available_keys].to_string(index=False) + "\n"
                result_text += "(...more columns available but not shown)\n"
            else:
                # If no key columns found, show the first 5 columns
                result_text += sample_df.iloc[:, :5].to_string(index=False) + "\n"
                result_text += f"(...{sample_df.shape[1] - 5} more columns available but not shown)\n"
        else:
            # DataFrame is small enough to show everything
            result_text += sample_df.to_string(index=False) + "\n"
        
        return result_text
        
    except Exception as e:
        return f"❌ Error: {str(e)}"

# TOOL 2: Security Posture Tool with Natural Language
@mcp.tool()
async def security_check(query: str) -> str:
    """
    Check security status of AWS accounts using natural language.
    You can ask about specific accounts or general security status.
    
    Examples:
    - "Please scan account Dev Tools"
    - "Is there any security issue on MyTelkomsel?"
    - "Check security posture for all Production accounts"
    - "What are the security issues in our environment?"
    - "Is there any issue on digipos apps?"
    """
    try:
        print(f"Processing security query: {query}")
        
        # Extract account keywords from the query
        keywords = extract_account_keywords(query)
        if keywords:
            print(f"Extracted keywords: {', '.join(keywords)}")
        else:
            print("No specific keywords found, querying all accounts")
        
        # Get security posture data with optional filtering
        posture_df = get_security_posture(keywords)
        
        if posture_df.empty and keywords:
            return f"❌ No security data found for accounts matching: {', '.join(keywords)}\n\nTry a different search term or check 'all accounts' for a complete list."
        elif posture_df.empty:
            return "❌ No security posture data found."
        
        # Save results to CSV
        uuid = os.urandom(4).hex()
        csv_filename = f'security_posture_{uuid}.csv'
        posture_df.to_csv(csv_filename, index=False)
        
        # Format the response
        if keywords:
            result_text = f"🔒 Security Check Results for: {', '.join(keywords)}\n\n"
        else:
            result_text = f"🔒 Security Check Results for All Accounts\n\n"
        
        # Add matched accounts information
        result_text += f"📊 Accounts Found: {len(posture_df)}\n"
        result_text += f"Matching account names: {', '.join(posture_df['account_name'].tolist())}\n\n"
        
        # Count accounts with issues
        eks_issues = posture_df[posture_df['EKS Access Endpoint'] == 'NOK'].shape[0]
        access_key_issues = posture_df[posture_df['Access Keys Rotation'].str.startswith('NOK')].shape[0]
        unused_role_issues = posture_df[posture_df['Unused Role'].str.startswith('NOK')].shape[0]
        unused_perm_issues = posture_df[posture_df['Unused Permission'].str.startswith('NOK')].shape[0]
        securityhub_ap3_issues = posture_df[posture_df['SecurityHub AP3 Status'] == 'NOK'].shape[0]
        securityhub_us1_issues = posture_df[posture_df['SecurityHub US1 Status'] == 'NOK'].shape[0]
        
        # Add issue counts if they exist
        issue_lines = []
        if eks_issues > 0:
            issue_lines.append(f"⚠️ Accounts with EKS public endpoint: {eks_issues}")
            # Add account names with this issue
            issue_accounts = posture_df[posture_df['EKS Access Endpoint'] == 'NOK']['account_name'].tolist()
            issue_lines.append(f"   Affected: {', '.join(issue_accounts)}")
        
        if access_key_issues > 0:
            issue_lines.append(f"⚠️ Accounts with access key rotation issues: {access_key_issues}")
            issue_accounts = posture_df[posture_df['Access Keys Rotation'].str.startswith('NOK')]['account_name'].tolist()
            issue_lines.append(f"   Affected: {', '.join(issue_accounts)}")
        
        if unused_role_issues > 0:
            issue_lines.append(f"⚠️ Accounts with unused roles: {unused_role_issues}")
            issue_accounts = posture_df[posture_df['Unused Role'].str.startswith('NOK')]['account_name'].tolist()
            issue_lines.append(f"   Affected: {', '.join(issue_accounts)}")
        
        if unused_perm_issues > 0:
            issue_lines.append(f"⚠️ Accounts with unused permissions: {unused_perm_issues}")
            issue_accounts = posture_df[posture_df['Unused Permission'].str.startswith('NOK')]['account_name'].tolist()
            issue_lines.append(f"   Affected: {', '.join(issue_accounts)}")
        
        if securityhub_ap3_issues > 0:
            issue_lines.append(f"⚠️ Accounts without SecurityHub in ap-southeast-3: {securityhub_ap3_issues}")
            issue_accounts = posture_df[posture_df['SecurityHub AP3 Status'] == 'NOK']['account_name'].tolist()
            issue_lines.append(f"   Affected: {', '.join(issue_accounts)}")
        
        if securityhub_us1_issues > 0:
            issue_lines.append(f"⚠️ Accounts without SecurityHub in us-east-1: {securityhub_us1_issues}")
            issue_accounts = posture_df[posture_df['SecurityHub US1 Status'] == 'NOK']['account_name'].tolist()
            issue_lines.append(f"   Affected: {', '.join(issue_accounts)}")
        
        if issue_lines:
            result_text += "Issues Found:\n" + "\n".join(issue_lines) + "\n\n"
        else:
            result_text += "✅ No security issues found in the scanned accounts.\n\n"
        
        # Show the actual data table
        result_text += "📋 Security Posture Details:\n"
        result_text += posture_df.to_string(index=False) + "\n\n"
        
        result_text += f"Results saved to {csv_filename}\n"
        
        return result_text
        
    except Exception as e:
        return f"❌ Error checking security posture: {str(e)}"

# Create a synchronous wrapper for the async functions
def run_tool_sync(tool_name, *args):
    """Synchronous wrapper for MCP tools"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        # Get the right tool based on name
        if tool_name == "ask":
            return loop.run_until_complete(ask(*args))
        elif tool_name == "security_check":
            return loop.run_until_complete(security_check(*args))
        else:
            return f"Unknown tool: {tool_name}"
    finally:
        loop.close()

# Main entry point for running the bot (purely synchronous)
if __name__ == "__main__":
    print("AWS Resource Management Bot")
    print("Available tools:")
    print("1. Query AWS Config Resources")
    print("2. Scan & Check Security Scanning Account Based")
    print("Type 'exit' to quit")
    
    while True:
        try:
            # Get tool selection from user
            tool_choice = input("\nSelect a tool (1 or 2): ")
            
            # Check if user wants to exit
            if tool_choice.lower() in ['exit', 'quit', 'q']:
                print("Exiting...")
                break
            
            # Process based on tool selection
            if tool_choice == "1":
                query = input("Enter your resource query: ")
                response = run_tool_sync("ask", query)
                print(f"\nResponse:\n{response}")
                
            elif tool_choice == "2":
                query = input("Enter your security question: ")
                response = run_tool_sync("security_check", query)
                print(f"\nResponse:\n{response}")
                
            else:
                print("Invalid selection. Please choose 1 for Config Query or 2 for Security Check.")
                
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"\nUnexpected error: {str(e)}")
    
    print("Bot terminated.")