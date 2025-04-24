import requests
import base64
import json
import boto3
from botocore.exceptions import ClientError

def get_parameters_from_aws(secret_name="saltSensor", region_name="us-east-1"):
    """Retrieve SaltAuthToken and CustomerId from AWS Secrets Manager."""
    session = boto3.session.Session()
    client = session.client(service_name='secretsmanager', region_name=region_name)

    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        raise RuntimeError(f"Failed to retrieve secret from AWS Secrets Manager: {e}")

    secret = get_secret_value_response.get('SecretString')
    if not secret:
        raise ValueError("SecretString is empty")

    try:
        secret_dict = json.loads(secret)
    except json.JSONDecodeError as e:
        raise ValueError(f"SecretString is not valid JSON: {e}")

    salt_token = secret_dict.get("saltToken")
    salt_org = secret_dict.get("saltOrg")

    if not salt_token:
        raise ValueError("SaltAuthToken is missing in the secret")
    if not salt_org:
        raise ValueError("CustomerId is missing in the secret")

    return salt_token, salt_org

def get_integration_data(auth_token, salt_org):
    url = f"https://salt.secured-api.com/api/v2/integrationsHub/{salt_org}/types/668290dd06aa2471b1aa62bd"
    headers = {
        "accept": "application/json, text/plain, */*",
        "authorization": f"Bearer {auth_token}",
        "referer": f"https://salt.secured-api.com/{salt_org}/integrations-hub/inbound/salt-sensor-for-vm/668290dd06aa2471b1aa62bd",
        "user-agent": "Mozilla/5.0"
    }
    
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

def decode_codeblock(codeblock):
    return base64.b64decode(codeblock).decode('utf-8')

def replace_placeholders(codeblock, data):
    script_url = data.get('downloadItems', [{}])[0].get('versions', [{}])[0].get('url', '')
    token = data.get('token', '')
    artifacts_url = data.get('downloadItems', [{}])[1].get('versions', [{}])[0].get('url', '')

    command = codeblock.replace('<SCRIPT>', script_url)
    command = command.replace('<TOKEN>', token)
    command = command.replace('<ARTIFACTS>', artifacts_url)
    command = command.replace('<SALT_BACKEND_HOST>', 'traffic-receiver-ws-a.dnssf.com')

    # Clear unused placeholders
    placeholders = [
        '<SALT_LABELS>', '<SALT_LOGS_LEVEL>', '<SALT_INPUT_RAW_ENGINE>',
        '<SALT_PROMISCUOUS_MODE>', '<SALT_VLAN_MODE>', '<SALT_VLAN_VIDS>',
        '<SALT_VXLAN_MODE>', '<SALT_VXLAN_PORT>', '<SALT_ALLOWED_HOSTS>',
        '<SALT_DISALLOWED_HOSTS>', '<SALT_HTTP_ALLOW_URLS>', '<SALT_HTTP_DISALLOW_URLS>',
        '<SALT_HTTP_ALLOW_HEADERS>', '<SALT_HTTP_DISALLOW_HEADERS>', '<SALT_INTERFACES>',
        '<SALT_FIXED_PORTS>', '<SALT_EBPF_UPROBE_USE>', '<SALT_EBPF_UPROBE_FILTER>',
        '<SALT_EBPF_KPROBE_USE>', '<SALT_EBPF_KPROBE_FILTER>'
    ]
    for placeholder in placeholders:
        command = command.replace(placeholder, '')
    
    return command

def main():
    auth_token, salt_org = get_parameters_from_aws()
    data = get_integration_data(auth_token, salt_org)
    codeblock = data.get('twoClicksConfigs', [{}])[0].get('codeBlock', '')
    if not codeblock:
        raise ValueError("No codeBlock found in response")
    decoded_command = decode_codeblock(codeblock)
    final_command = replace_placeholders(decoded_command, data)
    return replace_placeholders(decoded_command, data)

