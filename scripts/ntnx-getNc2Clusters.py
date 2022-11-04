import hashlib
import hmac
import time
import requests
import base64
import json
​

client_id = "a67ebb97-e009-4717-943a-eabc82a67b9b.img.frame.nutanix.com"
client_secret = "87eaadae1c9131078c0fc82b90010c72eca990fb"
cluster_id ="0005E8B2-F486-33A6-D2E5-8AC71181EEB8"

# Create signature
timestamp = int(time.time())
to_sign = "%s%s" % (timestamp, client_id)
to_sign = bytes(to_sign, 'utf-8')
client_secret = bytes(client_secret, 'utf-8')
signature = hmac.new(client_secret, to_sign, hashlib.sha256).hexdigest()

headers = { "X-Frame-ClientId": client_id, "X-Frame-Timestamp": str(timestamp), "X-Frame-Signature": signature }
prod_domain = "https://api-gateway-prod.frame.nutanix.com"
domain = prod_domain

r = requests.get(domain + "/v1/clusters/" + cluster_id, headers=headers) 