import requests,json,getpass,urllib3
from time import sleep
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# region functions
# region function process_request
def process_request(url, method, user, password, headers, payload=None, secure=False, binary=False):
    """
    Processes a web request and handles result appropriately with retries.
    Returns the content of the web request if successfull.
    """
    if payload != None and binary == False:
       payload = json.dumps(payload)
    elif payload != None and binary == True:
        payload = payload

    #configuring web request behavior
    if binary == True: 
        timeout = 900 
    else:
        timeout = 10
    retries = 5
    sleep_between_retries = 5

    while retries > 0:
        try:
            if method == 'GET':
                response = requests.get(
                    url,
                    headers=headers,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'POST':
                response = requests.post(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'PUT':
                response = requests.put(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'PATCH':
                response = requests.patch(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'DELETE':
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
        print("Request suceedded!")
        return json.loads(response.content)
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

# region get pulse
# Get the status of Pulse on a cluster.
# def pulse_status(cluster_ip):
#     operation = "GET"
#     api_url = "/api/nutanix/v1/pulse"
#     pulse_data = peApiCall(operation=operation, pecluster_ip=cluster_ip, api_url=api_url, cred_pass=cred_pass)
#     pulse_state = pulse_data['enable']
#     return pulse_state
# endregion

# region function get_filers
def prism_get_filers(api_server,username,secret,secure=False):
    """Retrieve the list of filers from Prism Element.
    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        
    Returns:
        A list of filers (entities part of the json response).
    """
    entities = []
    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/vfilers/"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    
    #endregion
    print("Making a {} API call to {} with secure set to {}".format(method, url, secure))
    resp = process_request(url,method,username,secret,headers,secure)

    # deal with the result/response
    if resp.ok:
        json_resp = json.loads(resp.content)
        entities.extend(json_resp['entities'])
        return entities
    else:
        print("Request failed!")
        print("status code: {}".format(resp.status_code))
        print("reason: {}".format(resp.reason))
        print("text: {}".format(resp.text))
        print("raise_for_status: {}".format(resp.raise_for_status()))
        print("elapsed: {}".format(resp.elapsed))
        print("headers: {}".format(resp.headers))
        print("payload: {}".format(payload))
        print(json.dumps(
            json.loads(resp.content),
            indent=4
        ))
        raise
# endregion

# region function get dns
def prism_get_dns(api_server,username,secret,secure=False):
    """Retrieve the list of DNS from Prism Element.
    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        
    Returns:
        A list of DNS (entities part of the json response).
    """
    entities = []
    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v2.0/cluster/name_servers/"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    
    #endregion
    print("Making a {} API call to {} with secure set to {}".format(method, url, secure))
    resp = process_request(url,method,username,secret,headers,secure)

    # deal with the result/response
    if resp.ok:
        json_resp = json.loads(resp.content)
        return json_resp
        #entities.extend(json_resp['entities'])
        #return entities
    else:
        print("Request failed!")
        print("status code: {}".format(resp.status_code))
        print("reason: {}".format(resp.reason))
        print("text: {}".format(resp.text))
        print("raise_for_status: {}".format(resp.raise_for_status()))
        print("elapsed: {}".format(resp.elapsed))
        print("headers: {}".format(resp.headers))
        print("payload: {}".format(payload))
        print(json.dumps(
            json.loads(resp.content),
            indent=4
        ))
        raise
# endregion

# region foundation_get_aos
def foundation_get_aos (api_server,username=None,secret=None,secure=False):
    """Retrieve the list of AOS images from Foundation.
    Args:
        api_server: The IP or FQDN of Foundation.
    Returns:
        A list of AOS (entities part of the json response).
    """
    entities = []
    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "8000"
    api_server_endpoint = "/foundation/enumerate_nos_packages"
    url = "http://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET" 
    #endregion

    print("Making a {} API call to {} with secure set to {}".format(method, url, secure))
    resp = process_request(url,method,username,secret,headers,secure)

    # deal with the result/response
    if resp.ok:
        json_resp = json.loads(resp.content)
        return json_resp
        #entities.extend(json_resp['entities'])
        #return entities
    else:
        print("Request failed!")
        print("status code: {}".format(resp.status_code))
        print("reason: {}".format(resp.reason))
        print("text: {}".format(resp.text))
        print("raise_for_status: {}".format(resp.raise_for_status()))
        print("elapsed: {}".format(resp.elapsed))
        print("headers: {}".format(resp.headers))
        print("payload: {}".format(payload))
        print(json.dumps(
            json.loads(resp.content),
            indent=4
        ))
        raise
# endregion

# region foundation_get_hypervisors
def foundation_get_hypervisors (api_server,username=None,secret=None,secure=False):
    """Retrieve the list of hypervisors images from Foundation.
    Args:
        api_server: The IP or FQDN of Foundation.
    Returns:
        A list of hypervisors (entities part of the json response).
    """
    entities = []
    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "8000"
    api_server_endpoint = "/foundation/enumerate_hypervisor_isos"
    url = "http://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET" 
    #endregion

    print("Making a {} API call to {} with secure set to {}".format(method, url, secure))
    resp = process_request(url,method,username,secret,headers,secure)

    # deal with the result/response
    if resp.ok:
        json_resp = json.loads(resp.content)
        return json_resp
        #entities.extend(json_resp['entities'])
        #return entities
    else:
        print("Request failed!")
        print("status code: {}".format(resp.status_code))
        print("reason: {}".format(resp.reason))
        print("text: {}".format(resp.text))
        print("raise_for_status: {}".format(resp.raise_for_status()))
        print("elapsed: {}".format(resp.elapsed))
        print("headers: {}".format(resp.headers))
        print("payload: {}".format(payload))
        print(json.dumps(
            json.loads(resp.content),
            indent=4
        ))
        raise
# endregion

# region get networks
def prism_get_networks(api_server,username,secret,secure=False):
    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v2.0/networks"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET" 
    #endregion

    # Making the call
    print("Making a {} API call to {} with secure set to {}".format(method, url, secure))
    resp = process_request(url,method,username,secret,headers,secure)
    return resp
# endregion

# region create network
def prism_create_network(api_server,username,secret,network_name,network_vlan,secure=False):
    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v2.0/networks"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {'name': network_name, 'vlan_id': network_vlan} 
    #endregion

    # Making the call
    print("Making a {} API call to {} with secure set to {}".format(method, url, secure))
    resp = process_request(url,method,username,secret,headers,payload,secure)
    return resp
# endregion

# region get containers
def prism_get_storage_container(api_server,username,secret,container_name,secure=False):
    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/containers/?searchString={}".format(container_name)
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET" 
    #endregion

    # Making the call
    print("Making a {} API call to {} with secure set to {}".format(method, url, secure))
    resp = process_request(url,method,username,secret,headers,secure)
    return resp
# endregion

#region get images
def prism_get_images(api_server,username,secret,secure=False):
    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v0.8/images"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    #endregion

    # Making the call
    print("Making a {} API call to {} with secure set to {}".format(method, url, secure))
    resp = process_request(url,method,username,secret,headers,secure)
    return resp
# endregion

# region prism_push_image_metadata
def prism_push_image_metadata(api_server,username,secret,image_name,image_description,secure=False):
    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v0.8/images"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {'name': image_name, 'annotation': image_description, 'imageType':'DISK_IMAGE'}
    #endregion

    print("Making a {} API call to {} with secure set to {}".format(method, url, secure))
    resp = process_request(url,method,username,secret,headers,payload,secure)
    return resp
# endregion

# region prism_upload_image
def prism_upload_image(api_server,username,secret,image_content,image_uuid,container_uuid,secure=False):
    #region prepare the api call
    headers = {'Content-Type': 'application/octet-stream;charset=UTF-8','x-nutanix-destination-container': container_uuid}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v0.8/images/{}/upload".format(image_uuid)
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "PUT"
    payload = image_content
    #endregion
    print("Making a {} API call to {} with secure set to {}".format(method, url, secure))
    resp = process_request(url,method,username,secret,headers,payload,secure,binary=True)
    return resp
# endregion

# region prism_upload_image2
def prism_upload_image2(api_server,username,secret,image_name,image_description,container_name,secure=False):

    # get container
    container = prism_get_storage_container(prism_api,user,pwd,container_name)
    container_uuid = container['entities'][0]['containerUuid']

    # create image metadata
    image_metadata_task = prism_push_image_metadata(prism_api,user,pwd,image_name,image_description)
    image_metadata_task_uuid = image_metadata_task['taskUuid']

    # pool task for image_uuid
    image_task = prism_get_task(prism_api,user,pwd,image_metadata_task_uuid)
    image_uuid = image_task['entityList'][0]['uuid']

    #region prepare the api call
    f = open(image_name, 'rb') # opening a binary file
    image_content = f.read() # reading all lines
    headers = {'Content-Type': 'application/octet-stream;charset=UTF-8','x-nutanix-destination-container': container_uuid}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v0.8/images/{}/upload".format(image_uuid)
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "PUT"
    payload = image_content
    #endregion

    print("Making a {} API call to {} with secure set to {}".format(method, url, secure))
    resp = process_request(url,method,username,secret,headers,payload,secure,binary=True)
    return resp
# endregion

# region prism_get-task
def prism_get_task(api_server,username,secret,task_uuid,secure=False):
    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v0.8/tasks/{}".format(task_uuid)
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    
    #endregion
    print("Making a {} API call to {} with secure set to {}".format(method, url, secure))
    resp = process_request(url,method,username,secret,headers,secure)
    return resp
# endregion

# region prism_software_upload_validate
def prism_software_upload_validate(api_server,username,secret,metadata_type,metadata_file,secure=False):
    
    # open the file as binary
    metadata_content = open(metadata_file, 'rb').read() # opening a binary file

    #region prepare the api call
    headers = {'Content-Type': 'application/octet-stream;charset=UTF-8'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/upgrade/{}/softwares/validate_upload".format(metadata_type)
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = metadata_content
    #endregion

    print("Making a {} API call to {} with secure set to {}".format(method, url, secure))
    resp = process_request(url,method,username,secret,headers,payload,secure,binary=True)
    return resp
# endregion

# region prism_software_upload
def prism_software_upload(api_server,username,secret,metadata_file,binary_file,secure=False):

    # get values from metadata
    metadata_json = json.load(open(metadata_file))
    metadata_type = metadata_json['type']
    metadata_version = metadata_json['version_id']
    metadata_size = metadata_json['size']
    metadata_hex_md5 = metadata_json['hex_md5']

    # validate_upload first
    prism_software_upload_validate(prism_api,user,pwd,metadata_type,metadata_file)

    # open the binary_file
    binary_content = open(binary_file, 'rb').read() # opening a binary file

    #region prepare the api call
    headers = {'Content-Type': 'application/octet-stream;charset=UTF-8'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/upgrade/{}/softwares/{}/upload?fileSize={}&md5Sum={}&overwrite=false&fileName={}&version={}".format(metadata_type,metadata_version,metadata_size,metadata_hex_md5,metadata_version,metadata_version)
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = binary_content
    #endregion

    print("Making a {} API call to {} with secure set to {}".format(method, url, secure))
    resp = process_request(url,method,username,secret,headers,payload,secure,binary=True)
    return resp
# endregion
# endregion

# region load config files
file_config = "config.json"
file_foundation = "hci-ntnx-foundation-cfg.json"
json_config = json.load(open(file_config))
json_foundation = json.load(open(file_foundation))
# endregion

# region variables
prism_api = json_config['prism']
user = json_config['user']
pwd = json_config['pwd']
foundation_config = json_config['foundation']
foundation_api = json_config['foundation']['foundation_ip']
networks_config = json_config['networks']
# endregion


# region upload softwares
# metadata_file = "generated-nutanix-ncc-el7.3-release-ncc-4.6.2-x86_64-latest.metadata.json"
# binary_file = "nutanix-ncc-el7.3-release-ncc-4.6.2-x86_64-latest.tar.gz"
# prism_software_upload(prism_api,user,pwd,metadata_file,binary_file)

metadata_file = "pc_upgrade-pc.2020.8.0.1.json"
binary_file = "pc.2020.8.0.1.tar"
prism_software_upload(prism_api,user,pwd,metadata_file,binary_file)

# endregion

# region network
# prism_net = prism_get_networks(prism_api,user,pwd)
# network_prism_list = []
# for network in prism_net['entities']:
#     network_prism_list.append(network['name'])
# print(network_prism_list)

# network_list = []
# for network in networks_config: 
#     network_list.append(network['name'])
#     network_name =  network['name']   
# print(network_list)

# to_create_net = list(set(network_list) - set(network_prism_list))
# print("to_create_net:", to_create_net)
#endregion

# region images
#images = prism_get_images(prism_api,user,pwd)
#print([image['name'] for image in images['entities']])

# get container uuid
#container_name = "SelfServiceContainer"
#container = prism_get_storage_container(prism_api,user,pwd,container_name)
#container_uuid = container['entities'][0]['containerUuid']
#print("Container uuid is {}".format(container['entities'][0]['containerUuid']))

# # push image metadata
#image = "CentOS-7-x86_64-GenericCloud.qcow2"
#image_description = "my image test"
#image_metadata_task = prism_push_image_metadata(prism_api,user,pwd,image,image_description)
#print("image_metadata_task: {}".format(image_metadata_task))
#image_metadata_task_uuid = image_metadata_task['taskUuid']

# # get task
#image_task = prism_get_task(prism_api,user,pwd,image_metadata_task_uuid)
#print(image_task)
#image_uuid = image_task['entityList'][0]['uuid']

# # upload image
#f = open(image, 'rb') # opening a binary file
#image_content = f.read() # reading all lines
#upload_image = prism_upload_image(prism_api,user,pwd,image_content,image_uuid,container_uuid)
#print(upload_image)

# container_name = "SelfServiceContainer"
# image_name = "alpine-virt-3.16.2-x86_64.qcow2"
# image_description = "my image test"
# upload_image = prism_upload_image2(prism_api,user,pwd,image_name,image_description,container_name)
# print(upload_image)
# endregion

# region Foundation
# region populate foundation
# for key,value in foundation_config.items():
#     if key != "nodes":
#         #print(key,value)
#         json_foundation[key] = value
#print(json_foundation)
# endregion

# region foundation nodes 
# push = {
#     "nodes": [],
#     "block_id": "null"
# }

# for n in foundation_config['nodes']:
#     pushNode = json.load(open(file_foundation))
#     pushNode = pushNode['blocks'][0]['nodes'][0]
#     pushNode['hypervisor'] = foundation_config['hypervisor']
#     pushNode['node_position'] = n['node_position']
#     pushNode['hypervisor_hostname'] = n['hypervisor_hostname']
#     pushNode['hypervisor_ip'] = n['hypervisor_ip']
#     pushNode['cvm_ip'] = n['cvm_ip']
#     pushNode['ipmi_ip'] = n['ipmi_ip']
#     pushNode['ipmi_password'] = n['serial']
#     push['nodes'].append(pushNode)

# json_foundation['blocks'][0] = push
#print(json.dumps(json_foundation,indent=4))
# endregion

# region foundation cluster creation
# cluster = {
#     "cluster_external_ip": prism_api,
#     "cluster_init_successful" : True,
#     "redundancy_factor" : int(foundation_config['replication_factor']),
#     "cluster_name" : "myCluster",
#     "cluster_members" : [node['cvm_ip'] for node in foundation_config['nodes']],
#     "cvm_dns_servers": "10.48.108.10,10.48.104.10",
#     "cvm_ntp_servers": "pool.ntp.org",
#     "timezone": "America/Phoenix",
#     "cluster_init_now" : True
# }
# print(json.dumps(cluster,indent=4))
# json_foundation['clusters'] = [cluster]
# print(json.dumps(json_foundation,indent=4))
# endregion
# endregion

#filers
#filers = prism_get_filers(prism_api,user,pwd)
#print("First File Server Name: {0}".format(filers[0]['name']))
#filer_uuid = filers[0]['uuid']
#print("Filer UUUID: {0}".format(filer_uuid))

#dns
#dns = prism_get_dns(prism_api,user,pwd)
#print(dns)
#print("First DNS name: {0}".format(dns[0]['name']))


# foundation get images
# image_aos = foundation_get_aos(foundation_api)

# # foundation get images
# image_hypervisors = foundation_get_hypervisors(foundation_api)
# print(image_hypervisors)
# #print(image_hypervisors[0])
# for image in image_hypervisors:
#     if image == "esx":
#         print(image_hypervisors[image][0]['filename'])


#containers = prism_get_storage_containers(prism_api,user,pwd)
#print(containers['entities'][0]['name'])


#endregion