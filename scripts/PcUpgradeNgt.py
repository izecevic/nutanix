# region headers
"""
# escript-template v20190523 / stephane.bourdeaud@nutanix.com,igor.zecevic@nutanix.com
# * author:       stephane.bourdeaud@nutanix.com, igor.zecevic@nutanix.com
# * version:      2022/10/27
# task_name:      PcUpgradeNgt
# description:    This script mounts and upgrade the Nutanix Guest Tools (latest available version) 
#                 on the AHV virtual machine provisioned by Calm using v3 api.
#                 
"""
# endregion

# region capture Calm macros
pc_user = "@@{prism_central.username}@@"
pc_password = "@@{prism_central.secret}@@"
vm_uuid = "@@{platform.metadata.uuid}@@"
pc_ip = "@@{prism_central_ip}@@"
# endregion

# region prepare variables
vm_uuid_url = "https://{}:9440/api/nutanix/v3/vms/{}".format(
    pc_ip,
    vm_uuid
)
headers = {
    'Accept': 'application/json',
    'Content-Type': 'application/json; charset=UTF-8'
}
# endregion


# region functions
import requests

def process_request(url, method, user, password, headers, payload=None, secure=False):
    """
    Processes a web request and handles result appropriately with retries.
    Returns the content of the web request if successfull.
    """
    if payload is not None:
        payload = json.dumps(payload)

    #configuring web request behavior
    timeout=10
    retries = 5
    sleep_between_retries = 5

    while retries > 0:
        try:

            if method is 'GET':
                response = requests.get(
                    url,
                    headers=headers,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method is 'POST':
                response = requests.post(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method is 'PUT':
                response = requests.put(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method is 'PATCH':
                response = requests.patch(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method is 'DELETE':
                response = requests.delete(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )

        except requests.exceptions.HTTPError as error_code:
            print ("Http Error!")
            print("status code: {}".format(response.status_code))
            print("reason: {}".format(response.reason))
            print("text: {}".format(response.text))
            print("elapsed: {}".format(response.elapsed))
            print("headers: {}".format(response.headers))
            if payload is not None:
                print("payload: {}".format(payload))
            print(json.dumps(
                json.loads(response.content),
                indent=4
            ))
            exit(response.status_code)
        except requests.exceptions.ConnectionError as error_code:
            print ("Connection Error!")
            if retries == 1:
                print('Error: {c}, Message: {m}'.format(c = type(error_code).__name__, m = str(error_code)))
                exit(1)
            else:
                print('Error: {c}, Message: {m}'.format(c = type(error_code).__name__, m = str(error_code)))
                sleep(sleep_between_retries)
                retries -= 1
                print ("retries left: {}".format(retries))
                continue
            print('Error: {c}, Message: {m}'.format(c = type(error_code).__name__, m = str(error_code)))
            exit(1)
        except requests.exceptions.Timeout as error_code:
            print ("Timeout Error!")
            if retries == 1:
                print('Error: {c}, Message: {m}'.format(c = type(error_code).__name__, m = str(error_code)))
                exit(1)
            print('Error! Code: {c}, Message: {m}'.format(c = type(error_code).__name__, m = str(error_code)))
            sleep(sleep_between_retries)
            retries -= 1
            print ("retries left: {}".format(retries))
            continue
        except requests.exceptions.RequestException as error_code:
            print ("Error!")
            exit(response.status_code)
        break

    if response.ok:
        return response
    if response.status_code == 401:
        print("status code: {0}".format(response.status_code))
        print("reason: {0}".format(response.reason))
        exit(response.status_code)
    elif response.status_code == 500:
        print("status code: {0}".format(response.status_code))
        print("reason: {0}".format(response.reason))
        print("text: {0}".format(response.text))
        exit(response.status_code)
    else:
        print("Request failed!")
        print("status code: {0}".format(response.status_code))
        print("reason: {0}".format(response.reason))
        print("text: {0}".format(response.text))
        print("raise_for_status: {0}".format(response.raise_for_status()))
        print("elapsed: {0}".format(response.elapsed))
        print("headers: {0}".format(response.headers))
        if payload is not None:
            print("payload: {0}".format(payload))
        print(json.dumps(
            json.loads(response.content),
            indent=4
        ))
        exit(response.status_code)
      
# endregion

# region get the VM payload and ngt_version
method = 'GET'
url = vm_uuid_url
print("Retrieving VM payload...")
print("Making a {} API call to {}".format(method, url))
resp = process_request(url, method, pc_user, pc_password, headers)

if resp.ok:
    result = json.loads(resp.content)
    # print the content of the response
    print(json.dumps(json.loads(resp.content), indent=4))
    vm_payload = json.loads(resp.content)
else:
    exit(1)
# endregion

#region update NGT
#getting NGT current and availaible version for update
ngt_version_current = vm_payload['status']['resources']['guest_tools']['nutanix_guest_tools']['version']
ngt_version_update = vm_payload['status']['resources']['guest_tools']['nutanix_guest_tools']['available_version']

if ngt_version_update != ngt_version_current:
    print("Updating current NGT version {} to {}".format(ngt_version_current, ngt_version_update))
    ngt_payload = {
        "nutanix_guest_tools": {
            "iso_mount_state": "MOUNTED",
            "ngt_state": "INSTALLED",
            "state": "ENABLED",
            "version": ngt_version_update,
            "enabled_capability_list": [
                "VSS_SNAPSHOT"
            ]
        }
    }
    #removing status section
    vm_payload.pop('status')
    #adding ngt section in spec
    if 'guest_tools' in vm_payload['spec']['resources']:
        vm_payload['spec']['resources']['guest_tools'].update(ngt_payload)
    else:
        vm_payload['spec']['resources'].update({"guest_tools": ngt_payload})
    #increasing spec version
    vm_payload['metadata']['spec_version'] += 1

    print("Modified VM payload:")
    print(json.dumps(vm_payload, indent=4))

    #region PUT vm
    method = 'PUT'
    url = vm_uuid_url
    payload = vm_payload
    resp = process_request(url, method, pc_user, pc_password, headers, payload)

    if resp.ok:
        result = json.loads(resp.content)
        # print the content of the response
        print(json.dumps(json.loads(resp.content), indent=4))
    else:
        exit(1)
    #endregion
else:
    print("Current NGT version installed is the latest NGT available")
    exit(0)
#endregion