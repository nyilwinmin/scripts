import boto3
import requests
from requests_aws4auth import AWS4Auth

host = '...' # domain endpoint with trailing /
region = 'ap-southeast-1' # e.g. us-west-1
service = 'es'
credentials = boto3.Session().get_credentials()
print(credentials.access_key, credentials.secret_key, credentials.token)
awsauth = AWS4Auth(credentials.access_key, credentials.secret_key, region, service, session_token=credentials.token)

# # Register repository

# path = '_snapshot/manual-snapshot-repo' # the OpenSearch API endpoint
# url = host + path

# payload = {
  # "type": "s3",
  # "settings": {
    # "bucket": "ec2-ssnet-dev-patching",
    # "region": "ap-southeast-1",
    # "role_arn": "arn:aws:iam::509413501238:role/OSSnapshotRole"
  # }
# }

# headers = {"Content-Type": "application/json"}

# r = requests.put(url, auth=awsauth, json=payload, headers=headers)
# print(r.status_code)
# print(r.text)

# # Take snapshot
#
# path = '_snapshot/my-snapshot-repo-name/my-snapshot'
# url = host + path
#
# r = requests.put(url, auth=awsauth)
#
# print(r.text)
#
# # Delete index
#
# path = 'my-index'
# url = host + path
#
# r = requests.delete(url, auth=awsauth)
#
# print(r.text)
#
# Restore snapshot (all indexes except Dashboards and fine-grained access control)

# path = '_snapshot/my-snapshot-repo-name/my-snapshot/_restore'
# path = '_snapshot/manual-snapshot-repo/manual-snapshot/_restore'
# url = host + path

# payload = {
  # "indices": "-.kibana*,-.opendistro_security,-.opendistro-*",
  # "include_global_state": False
# }

# headers = {"Content-Type": "application/json"}

# r = requests.post(url, auth=awsauth, json=payload, headers=headers)

# print(r.text)
# 
# Restore snapshot (one index)

path = '_snapshot/manual-snapshot-repo/manual-snapshot/_restore'
url = host + path

payload = {
    "indices": "cwl*",
    "index_settings": {"index.number_of_replicas": 2}
}

headers = {"Content-Type": "application/json"}

r = requests.post(url, auth=awsauth, json=payload, headers=headers)

print(r.text)