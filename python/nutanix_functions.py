import requests,json,urllib3,uuid,sys
from time import sleep
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# region functions
# region function process_request
def process_request(url, method, user, password, headers, payload=None, secure=False, upload_binary=False, return_cookies=False, upload_files=None):
    """
    Processes a web request and handles result appropriately with retries.
    Returns the content of the web request if successfull.
    """
    if payload != None and (upload_binary == True or upload_files != None):
       payload = payload
    elif payload != None and upload_binary == False:
        payload = json.dumps(payload)

    #configuring web request behavior
    if upload_binary == True: 
        timeout = 9000 # 15 mins (usually for binary uploads)
    else:
        timeout = 30
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
                    timeout=timeout,
                )
            elif method == 'POST':
                response = requests.post(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout,
                    files=upload_files
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
                    timeout=timeout,
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

    if response.ok and return_cookies == False:
        print("Request suceedded!")
        print(response.headers)
        #return json.loads(response.content)
    if response.ok and return_cookies == True:
        print("Request suceedded!")
        return response
    if response.status_code == 401:
        print("status code: {0}".format(response.status_code))
        print("reason: {0}".format(response.reason))
        return (response.status_code)
    elif response.status_code == 500:
        print("status code: {0}".format(response.status_code))
        print("reason: {0}".format(response.reason))
        print("text: {0}".format(response.text))
        exit(response.status_code)
    elif response.status_code == 404:
        print("status code: {0}".format(response.status_code))
        print("reason: {0}".format(response.reason))
        print("text: {0}".format(response.text))
        return (response.status_code)
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

# region nutanix_idp_auth
def nutanix_idp_auth(api_server,username,secret):
    # region prepare the api call
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    api_server_port = "443"
    api_server_endpoint = "/commonauth"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {
        'username':username,
        'password':secret
    }
    # endregion

    # make the call
    print("Configuring Pulse on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)
    
    # return
    return resp
# endregion

# region foundation_get_aos
def foundation_get_aos (api_server,username=None,secret=None):
    """
        Retrieve a list of all AOS packages available on the foundation server

    Args:
        api_server: The Foundation API server
        username: None (no authentication on the foundation API)
        secret: None (no authentication on the foundation API)
        
    Returns:
         A list of AOS packages
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "8000"
    api_server_endpoint = "/foundation/enumerate_nos_packages"
    url = "http://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET" 
    # endregion

    # make the api call
    print("Retrieve a list of AOS packages available on the foundation server {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)

    # return
    return resp
# endregion

# region foundation_get_hypervisors
def foundation_get_hypervisors (api_server,username=None,secret=None):
    """
        Retreive a list of all hypervisors packages available on the foundation server

    Args:
        api_server: The Foundation API server
        username: None (no authentication on the foundation API)
        secret: None (no authentication on the foundation API)
        
    Returns:
         A list of AOS hypervisors
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "8000"
    api_server_endpoint = "/foundation/enumerate_hypervisor_isos"
    url = "http://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET" 
    # endregion

    # make the api call
    print("Retrieve a list of hypervisors available on the foundation server {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)
    
    # return
    return resp
# endregion

# region foundation_generate_image_payload
def foundation_generate_image_payload(foundation_config:dict):
    """
        Generates a json payload for foundation imaging endppoint to image a given set of nodes
        and create a Nutanix AHV cluster

    Args:
        foundation_config: json object with all keys required for node and cluster imaging
        The foundation_config json object should include the following keys (ipmi_netmask,
        hypervisor_netmask, cvm_netmask, ipmi_gateway, cvm_gateway, hypervisor_gateway, nos_package,
        cluster_virtual_ip, cluster_name, redundancy_factor, dns, ntp, timezone. For each node,
        the object should include node_position, hypervisor_hostame, hypervisor_ip, cvm_ip, ipmi_ip,
        ipmi_user and ipmi_pwd)
        
    Returns:
         A json payload used by Foundation to image a given set of nodes and create a Nutanix AHV cluster
    """

    # variables
    foundation_payload = {} # foundation payload
    
    # region populate foundation core details
    print("Populating foundation core details..")
    foundation_payload = {
        'clusters': [],
        'blocks': [{'block_id': None,'nodes': [],}],
        "current_cvm_vlan_tag":  foundation_config['hyp_cvm_vlan'],
        'ipmi_netmask': foundation_config['ipmi_netmask'], 
        'ipmi_gateway': foundation_config['ipmi_gateway'], 
        'cvm_netmask': foundation_config['hyp_cvm_netmask'],
        'cvm_gateway': foundation_config['hyp_cvm_gateway'], 
        'hypervisor_netmask': foundation_config['hyp_cvm_netmask'], 
        'hypervisor_gateway': foundation_config['hyp_cvm_gateway'],  
        'nos_package': foundation_config['nos_package'],
        'hypervisor': 'kvm', 
        'hypervisor_iso': {},
        'skip_network_setup': True,
        'is_imaging': True, 
        'is_installing_hypervisor': True, 
        'is_installing_cvm': True 
    }
    # endregion

    # region populate foundation nodes details
    print("Populating foundation nodes details..")
    for node in foundation_config['nodes']:
        # populate each node details
         foundation_payload['blocks'][0]['nodes'].append({ 
            'ipmi_user': node['ipmi_user'],
            'ipmi_password': node['ipmi_pwd'],
            'node_position': node['node_position'],
            'hypervisor_hostname': node['hypervisor_hostname'],
            'hypervisor_ip':node['hypervisor_ip'],
            'cvm_ip': node['cvm_ip'],
            'ipmi_ip': node['ipmi_ip'],
            'image_now': True
        })
    # endregion
    
    # region populate foundation cluster details
    print("Populating foundation cluster details..")
    foundation_payload['clusters'] = [{
        'cluster_external_ip': foundation_config['virtual_ip'],
        'cluster_name' : foundation_config['name'],
        'redundancy_factor' : int(foundation_config['replication_factor']),
        'cluster_members' : [cvm['cvm_ip'] for cvm in foundation_config['nodes']],
        'cvm_dns_servers': (' '.join(map(str, foundation_config['dns']))),
        'cvm_ntp_servers': (' '.join(map(str, foundation_config['ntp']))),
        'timezone': foundation_config['timezone'],
        'cluster_init_now' : True
    }]
    # endregion

    # return
    return foundation_payload
# endregion

# region foundation_image_nodes
def foundation_image_nodes (api_server,foundation_payload,username=None,secret=None):
    """
        Trigger a foundation imaging process

    Args:
        api_server: The Foundation API server
        foundation_payload: json payload used by Foundation to image a given set of nodes 
        and create a Nutanix AHV cluster
        username: None (no authentication on the foundation API)
        secret: None (no authentication on the foundation API)
        
    Returns:
        A foundation session-id
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "8000"
    api_server_endpoint = "/foundation/image_nodes"
    url = "http://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = foundation_payload
    # endregion

    # make the api call
    print("Triggering a foundation imaging process on the foundation server {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)
   
    # return
    return resp
 # endregion

# region foundation_configure_ipmi
def foundation_configure_ipmi (api_server,ipmi_user,ipmi_pwd,ipmi_mac,ipmi_ip,ipmi_netmask,ipmi_gateway,username=None,secret=None):
    """
        Configure IPMI/ILO IP address for a given nove

    Args:
        api_server: The Foundation API server
        ipmi_user: IPMI user
        ipmi_pwd: IPMI password
        ipmi_mac: IPMI mac address
        ipmi_ip: IPMI IP address
        ipmi_netmask: IPMI netmask
        ipmi_gateway: IPMI gateway
        username: None (no authentication on the foundation API)
        secret: None (no authentication on the foundation API)

    Returns:
        None
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "8000"
    api_server_endpoint = "/foundation/ipmi_config"
    url = "http://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST" 
    payload = {
        'ipmi_user': ipmi_user,
        'ipmi_netmask': ipmi_netmask,
        'ipmi_gateway': ipmi_gateway,
        'ipmi_password': ipmi_pwd,
        'blocks': [{
            'nodes': [{
                'ipmi_mac': ipmi_mac,
                'ipmi_ip': ipmi_ip,
                'ipmi_configure_now': True
                }]
            }
        ]
    }
    # endregion

    # make the api call
    print("Configuring IPMI IP {} for IPMI mac address {}".format(ipmi_ip,ipmi_mac))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # return
    return resp
# endregion

# region foundation_ping_ipmi
def foundation_ping_ipmi(api_server,ipmi_ip,username=None,secret=None):
    """
        Configure IPMI/ILO IP address for a given nove

    Args:
        api_server: The Foundation API server
        ipmi_ip: IPMI IP address
        username: None (no authentication on the foundation API)
        secret: None (no authentication on the foundation API)

    Returns:
        True/False
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "8000"
    api_server_endpoint = "/foundation/ping_multiple"
    url = "http://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST" 
    payload = [ipmi_ip]
    # endregion

    # make the api call
    print("Checking IPMI IP {} ".format(ipmi_ip))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # return
    return resp
# endregion

# region foundation_get_imaging_progress
def foundation_get_imaging_progress (api_server,username=None,secret=None):
    """
        Retreive status of current foundation imaging progress

    Args:
        api_server: The Foundation API server
        username: None (no authentication on the foundation API)
        secret: None (no authentication on the foundation API)
        
    Returns:
         json response with current foundation imaging progress details
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "8000"
    api_server_endpoint = "/foundation/progress"
    url = "http://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET" 
    # endregion

    # make the api call
    print("Retrieve current imaging progress details on the foundation server {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)
    
    # return
    return resp
# endregion

# region foundation_monitor_progress
def foundation_monitor_progress (api_server,username=None,secret=None,max_attemps=120,retry_delay_secs=60):
    """
        Monitor current foundation imaging progress with a maximum attemps and retry configurable. 

    Args:
        api_server: The Foundation API server
        username: None (no authentication on the foundation API)
        secret: None (no authentication on the foundation API)
        max_attemps: default 120
        retry_delay_secs: default 60 seconds
        
    Returns:
        Success or Failure
    """

    # variables
    attempt = 1
    max_attempts = max_attemps # default 2 hours
    retry_delay_secs = retry_delay_secs #default 60 seconds

    # track foundation imaging process
    while attempt <= max_attempts:
        # calling the function
        foundation_progress = foundation_get_imaging_progress(api_server)
        # track progress
        print("Foundation Time Spent: {} mins".format(attempt))
        print("Foundation Percentage Complete: {}%".format(foundation_progress['aggregate_percent_complete']))
        print("Cluster Name: {0}, Status: {1}, Percentage Complete {2}%".format(foundation_progress['clusters'][0]['cluster_name'],foundation_progress['clusters'][0]['status'],foundation_progress['clusters'][0]['percent_complete']))
        for node in foundation_progress['nodes']:
            print("Hypervivor IP: {0}, CVM IP: {1}, Installation: {2}%, Status: {3}".format(node['hypervisor_ip'], node['cvm_ip'], node['percent_complete'],node['status']))
        if foundation_progress['aggregate_percent_complete'] == 100:
            print("foundation succeeded")
            return
        elif foundation_progress['imaging_stopped'] == True or foundation_progress['abort_session'] == True:
            print("Error: during foundation, image stopped")
            exit(1)
        else:
            print("WARNING: remaining minutes before failure: {0} mins".format(max_attempts-attempt))
            print("let's wait for {} seconds..".format(retry_delay_secs))
            attempt +=1
            sleep(retry_delay_secs)
            
    print ("Error: Exceeded max attempts {}".format(max_attempts))

    # return
    return
# endregion

# region prism_update_default_pwd
def prism_update_default_pwd(api_server,new_secret,username='admin',default_secret='nutanix/4u'):
    """
        Change Prism default admin password with new provided password

    Args:
        api_server: The IP or FQDN of Prism/PC.
        username: The Prism/PC user name.
        new_secret : The Prism/PC user name password
        default_secret: default password upon foundation (nutanix/4u)
        
    Returns:
        True or False
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/utils/change_default_system_password"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {
        'oldPassword': default_secret,
        'newPassword': new_secret    
    }
    # endregion

    # Making the call
    print("Updating default Prism admin password on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,default_secret,headers,payload)

    # return
    return
# endregion

# region get pulse
def prism_get_pulse(api_server,username,secret):
    """
        Retrieve pulse details on Prism Element

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        
    Returns:
         Pulse details (part of the json response)
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/pulse"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    # endregion

    # make the call
    print("Retrieve Pulse details on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)
    
    # return
    return resp
# endregion

# region enable pulse
def prism_enable_pulse(api_server,username,secret,enable_pulse):
    """
        Enable Pulse on Prism Element

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        enable_pulse: True or False
        
    Returns:
         Eulas details (part of the json response)
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/pulse"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "PUT"
    payload = {
        'enable':enable_pulse, 
        'enableDefaultNutanixEmail':False, 
        'isPulsePromptNeeded':False, 
        'remindLater':False
    }
    # endregion

    # make the call
    print("Configuring Pulse on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)
    
    # return
    return resp
# endregion

# region prism_get_eula
def prism_get_eula(api_server,username,secret):
    """
        Retrieve eulas details on Prism Element

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        
    Returns:
         Eulas details (part of the json response)
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/eulas"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    # endregion

    # make the call
    print("Retrieve Eula details on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)
    
    # return
    return resp
# endregion

# region prism_accept_eula
def prism_accept_eula(api_server,username,secret,eula_username,eula_companyname,eula_jobtitle):
    """
        Accept eulas on Prism Element

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        eula_username: Username for the eulas
        eula_companyname: Company Name for the eulas
        eula_jobtitle: Job Title for the Eulas
        
    Returns:
         True
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/eulas/accept"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {
        'username': eula_username,
        'companyName': eula_companyname,
        'jobTitle': eula_jobtitle
    }
    # endregion

    # make the call
    print("Accepting Eulas on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)
    
    # return
    return resp
# endregion

# region prism_get_cluster
def prism_get_cluster(api_server,username,secret):
    """
        Retrieve Cluster details on Prism Element

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        
    Returns:
         Cluster details (part of the json response)
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/cluster/"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    # endregion

    # make the call
    print("Retrieve cluster details on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)
    
    # return
    return resp
# endregion

# region prism_get_cluster
def prism_get_cluster_v2(api_server,username,secret):
    """
        Retrieve Cluster details on Prism Element

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        
    Returns:
         Cluster details (part of the json response)
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v2.0/cluster/"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    # endregion

    # make the call
    print("Retrieve cluster details on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)
    
    # return
    return resp
# endregion

# region configure data service ip
def prism_set_dsip(api_server,username,secret,cluster_dsip):
    """
        Configure a Data Service IP (DSIP) on Prism Element

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        cluster_dsip: Data service IP
        
    Returns:
         None
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/cluster/"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "PATCH"
    payload = {'clusterExternalDataServicesIPAddress': cluster_dsip}
    # endregion

    # make the call
    print("Configuring a Data Service IP on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # return
    return resp
# endregion

# region configure stig
def prism_set_stig(api_server,username,secret,stig_key,stig_value):
    """
        Configure asecurity_compliance_config on Prism Element

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        stig_key: stig_key to configure
        stig_value: stig_value to configure
        
    Returns:
         None
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/cluster/"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "PATCH"
    payload = {
        'security_compliance_config': {
            stig_key: stig_value
        }
    }
    # endregion

    # make the call
    print("Configuring STIG setting {} to {} on {}".format(stig_key,stig_value,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # return
    return resp
# endregion

# region prism_get_networks
def prism_get_networks(api_server,username,secret,network_name=None):
    """
       Retreive the list of networks from Prism Element.
       If a network_name is specified, only details for that given network will be returned.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        network_name (optional): Name of the network
        
    Returns:
         A list of networks (entities part of the json response).
    """

    # variables
    net_list = []

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v2.0/networks"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET" 
    # endregion

    # Making the call
    print("Retieving networks details on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)

    # processing
    if network_name == None:
        print("Returning all networks on {}".format(api_server))
        net_list.extend(resp['entities'])
    else: 
        for network in resp['entities']:
            if network['name'] == network_name:
                print("Returning network {} on {}".format(network_name,api_server))
                net_list.append(network)
                break
    
    # return
    return net_list
# endregion

# region prism_get_network_uuid
def prism_get_network_uuid(api_server,username,secret,network_name):
    """
        Retreive provided network name uuid

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        network_name: Name of the network.
        
    Returns:
         uuid of the provided network name (string).
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/subnets/list"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {'kind':'subnet','filter':'name=={}'.format(network_name)} 
    # endregion

    # Making the call
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # return
    print ("Return network {} uuid".format(network_name))
    return resp['entities'][0]['metadata']['uuid']
# endregion

# region prism_create_network
def prism_create_network(api_server,username,secret,network_name,network_vlan,network_ipam_address=None,network_ipam_gateway=None,network_ipam_prefix=None,network_ipam_pool=None):
    """
       Create a network on Prism Element

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        network_name: Name of the network
        network_vlan: Vlan of the network
        network_ipam_address (optional): IPAM network address
        network_ipam_gateway (optional): IPAM network default gateway
        network_ipam_prefix (optional): IPAM network prefix
        network_ipam_pool (optional): IPAM network pool
        
    Returns:
         Network created
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v2.0/networks"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {
        'name': network_name, 
        'vlan_id': network_vlan
    } 

    # updating payload with ipam when relevant
    if network_ipam_address != None:
        payload.update(ip_config = {
            'default_gateway': network_ipam_gateway,
            'network_address': network_ipam_address,
            'prefix_length': network_ipam_prefix,
            'pool': [
                {'range': network_ipam_pool}
             ]
        })

    # endregion

    # # Making the call
    print("Creating network {} on {}".format(network_name,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)
    
    # return
    return resp
# endregion

# region prism_get_containers
def prism_get_containers(api_server,username,secret,container_name=None):
    """
        Retreive the list of containers from Prism Element.
        If a container_name is specified, only details for that given container will be returned.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        container_name (optional): Name of the container
        
    Returns:
         A list of containers (entities part of the json response).
    """

    # variables
    containers_list = []

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v2.0/storage_containers"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET" 
    # endregion

    # Making the call
    print("Retieving containers details on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)

    # processing
    if container_name == None:
        print("Returning all containers on {}".format(api_server))
        containers_list.extend(resp['entities'])
    else: 
        for container in resp['entities']:
            if container['name'] == container_name:
                print("Returning container {} on {}".format(container_name,api_server))
                containers_list.append(container)
                break

    # return
    return containers_list
# endregion

# region prism_get_container_uuid
def prism_get_container_uuid(api_server,username,secret,container_name):
    """
        Retreive provided container uuid

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        container_name Name of the container.
        
    Returns:
         uuid of the provided container name (string).
    """
        
    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/containers?filterCriteria=container_name=={}".format(container_name)
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    # endregion

    # Making the call
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)

    # return
    print ("Return container {} uuid".format(container_name))
    return resp['entities'][0]['containerUuid']
# endregion

# region prism_get_vms
def prism_get_vms(api_server,username,secret,vm_name=None):
    """
        Retreive the list of vms from Prism Element.
        If a container_name is specified, only details for that given container will be returned.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        vm_name (optional): Name of the vm.
        
    Returns:
         A list of vms (entities part of the json response).
    """
    # variables
    vms_list = []

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/vms"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET" 
    # endregion

    # Making the call
    print("Retrieve VMs details on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)

    # processing
    if vm_name == None:
        print("Returning all vms on {}".format(api_server))
        vms_list.extend(resp['entities'])
    else: 
        for vm in resp['entities']:
            if vm['vmName'] == vm_name:
                print("Returning vm {} on {}".format(vm_name,api_server))
                vms_list.append(vm)
                break

    # return
    return vms_list
# endregion

# region prism_get_vms
def prism_set_vm_powerstate(api_server,username,secret,vm_uuid,vm_powerstate):
    """
        Retreive the list of vms from Prism Element.
        If a container_name is specified, only details for that given container will be returned.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        vm_uuid: uuid of the virutal machine.
        vm_powerstate: Powerstate of the virutal machine (off, on, powercycle, reset, acpi_shutdown, acpi_reset)
        
    Returns:
         A list of vms (entities part of the json response).
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v2.0/vms/{}/set_power_state".format(vm_uuid)
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {'transition': vm_powerstate} 
    # endregion

    # Making the call
    print("Changing VM uuid {} powerstate on {}".format(vm_uuid, api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

  
    # return
    return resp
# endregion

# region prism_get_images
def prism_get_images(api_server,username,secret,image_name=None):
    """
       Retreive the list of images from Prism Element.
       If a image_name is specified, only details for that given network will be returned.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        imamge_name (optional): Name of the image
        
    Returns:
         A list of images (entities part of the json response).
    """
    
    # variables
    images_list = []
    
    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v0.8/images"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    # endregion

    # Making the call
    print("Retieving images details on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)

    # filtering
    if image_name == None:
        print("Returning all images on {}".format(api_server))
        images_list.extend(resp['entities'])
    else: 
        for image in resp['entities']:
            if image['name'] == image_name:
                print("Return single image {} on {}".format(image_name,api_server))
                images_list.append(image)
                break

    # return
    return images_list
# endregion

# region prism_get_image_uuid
def prism_get_image_uuid(api_server,username,secret,image_name):
    """
        Retreive provided image name uuid

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        image_name: Name of the image.
        
    Returns:
         uuid of the provided image name (string).
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/images/list"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {'kind':'image','filter':'name=={}'.format(image_name)} 
    # endregion

    # Making the call
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # return
    print ("Return image {} uuid".format(image_name))
    return resp['entities'][0]['metadata']['uuid']
# endregion

# region prism_upload_image_url
def prism_upload_image_url(api_server,username,secret,image_name,image_description,image_url,container_uuid,image_type='DISK_IMAGE'):
    """
        Upload an image on Prism Element using the url method

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        image_name: Image name.
        image_description: Image description.
        image_url: Image url.
        container_uuid: destination container uuid.
        image_type: DISK_IMAGE (default) or ISO.
        
    Returns:
         container uuid
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v0.8/images"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {
        'name': image_name,
        'annotation': image_description,
        'imageType': image_type,
        'imageImportSpec': {
            'containerUuid': container_uuid,
            'url': image_url
        }
    }
    # endregion

    # Making the call
    print("Uploading image {} on {}".format(image_name,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # return
    return resp
# endregion

# region prism_monitor_task_v2
def prism_monitor_task_v2(api_server,username,secret,task_uuid,retry_delay_secs=10,max_attemps=30):
    """
        Monitor a given task on Prism Element 

    Args:
        api_server: The Foundation API server
        username: None (no authentication on the foundation API)
        secret: None (no authentication on the foundation API)
        task_uuid: task uuid to monitor
        max_attemps: 30 (default)
        retry_delay_secs: 10 seconds (default)
        
    Returns:
        Success or Failure
    """
    
    # variables
    attempt = 1
    max_attempts = max_attemps # default is 30
    retry_delay_secs = retry_delay_secs # default is 10 seconds
    
    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v2.0/tasks/{}".format(task_uuid)
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    # endregion

    # track task process
    print("Monitoring task uuid progress {} on {}".format(task_uuid,api_server))
    while attempt <= max_attempts:
        # make the api call
        print("Making a {} API call to {}".format(method, url))
        task_progress = process_request(url,method,username,secret,headers)
        print("Percentage_complete: {}".format(task_progress['percentage_complete']))
        print("Progress_status: {}".format(task_progress['progress_status']))
        print("Attempt number: {}".format(attempt))
        if task_progress['percentage_complete'] == 100 and task_progress['progress_status'] == "Succeeded":
            print("Task succeeded")
            return
        elif task_progress['progress_status'] == "Failed":
            print("Task failed")
            print(json.dumps(task_progress, indent=4))
            exit(1)
        else:
            print("WARNING: remaining attemps before failure: {0}".format(max_attempts-attempt))
            print("Let's wait for {} seconds..".format(retry_delay_secs))
            attempt +=1
            sleep(retry_delay_secs)

    print ("Error: Exceeded max attempts {}".format(max_attempts))

    # return
    return
# endregion

# region prism_set_timezone
def prism_set_timezone(api_server,username,secret,timezone):
    """
        Add DNS on Prism Element

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        timezone: Timezone to set
        
    Returns:
         True/False
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "PATCH"
    payload = {'timezone': timezone}
    # endregion

    # make the call
    print("Configuring Timezone {} on {}".format(timezone,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # return
    return resp
# endregion

# region prism_get_dns
def prism_get_dns(api_server,username,secret):
    """
        Retrieve DNS details on Prism Element

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        
    Returns:
         DNS details (part of the json response)
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/cluster/name_servers"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    # endregion

    # make the call
    print("Retrieve DNS details on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)

    # return
    return resp
# endregion

# region prism_add_dns
def prism_add_dns(api_server,username,secret,dns_server):
    """
        Add DNS on Prism Element

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        dns_server: DNS server to add
        
    Returns:
         True/False
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/cluster/name_servers/add_list"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = [{'ipv4': dns_server}]
    # endregion

    # make the call
    print("Configuring DNS {} on {}".format(dns_server,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # return
    return resp
# endregion

# region prism_get_ntp
def prism_get_ntp(api_server,username,secret):
    """
        Retrieve NTP details on Prism Element

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        
    Returns:
         NTP details (part of the json response)
    """
    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/cluster/ntp_servers"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    # endregion

    # make the call
    print("Retrieve NTP details on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)

    # return
    return resp
# endregion

# region prism_add_ntp
def prism_add_ntp(api_server,username,secret,ntp_server):
    """
        Add NTP on Prism Element

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        ntp_server: NTP server to add
        
    Returns:
         True/False
    """

    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/cluster/ntp_servers/add_list"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = [{'ipv4': ntp_server}]
    #endregion

    # make the call
    print("Configuring NTP {} on {}".format(ntp_server,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)
    
    # return
    return resp
# endregion

# region prism_get_directory
def prism_get_directory(api_server,username,secret,directory_domain=None):
    """
        Retrieve the list of configured authentication directories on Prism Element

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        directory_domain: Directory domain name
        
    Returns:
         A list of directories (entities part of the json response).
    """

    # variables
    directories_list = []

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/authconfig/directories"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    # endregion

    # Making the call
    print("Retrieve directories details on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)

    # filtering
    if directory_domain == None:
        print("Returning all directories on {}".format(api_server))
        directories_list.extend(resp)
    else: 
        for directory in resp:
            if directory['domain'] == directory_domain:
                print("Returning directory {} on {}".format(directory_domain,api_server))
                directories_list.append(directory)
                break
    
    # return
    return directories_list
# endregion

# region prism_set_directory
def prism_set_directory(api_server,username,secret,directory_name,directory_domain,directory_url,svc_user,svc_pwd):
    """
        Set Active Directory on Prism Element

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        directory_name: Directory name.
        directory_donain: Directory full FQDN domain.
        directory_url: Directory domain url.
        svc_user: Directory service account full domain (ie: svc_user@domain.net)
        svc_pwd: Directoryservice account pwd
        
    Returns:
         None
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/authconfig/directories"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {
        'name': directory_name,
        'domain': directory_domain,
        'directoryUrl': directory_url,
        'groupSearchType': 'NON_RECURSIVE',
        'directoryType': 'ACTIVE_DIRECTORY',
        'connectionType': 'LDAP',
        'serviceAccountUsername': svc_user,
        'serviceAccountPassword': svc_pwd
    }
    # endregion

    # Making the call
    print("Configuring AD domain {} on {}".format(directory_name,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)
    
    # return
    return resp
# endregion

# region prism_get_role_mappings
def prism_get_role_mappings(api_server,username,secret,directory_name):
    """
        Retrieve role mappings for a given directory on Prism Element

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        directory_name: Directory domain name (default None)
        
    Returns:
         A list of role mappings (entities part of the json response).
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/authconfig/directories/{}/role_mappings".format(directory_name)
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    # endregion

    # Making the call
    print("Retrieve role mappings for the directory {} on {}".format(directory_name,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)
    
    # return
    return resp
# endregion

# region prism_set_role_mapping
def prism_set_role_mapping(api_server,username,secret,directory_name,role_name,role_type,role_value):
    """
        Configure role mappings for a given directory on Prism Element

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        directory_name: Directory domain name (default None)
        role_name: ROLE_USER_ADMIN, ROLE_CLUSTER_ADMIN, ROLE_USER_VIEWER
        role_type: GROUP or USER
        role_value: directory user or directory group
        
    Returns:
        Role mapping configured
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/authconfig/directories/{}/role_mappings".format(directory_name)
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {
        'directoryName': directory_name,
        'role': role_name,
        'entityType' : role_type,
        'entityValues' : [role_value]
    }
    # endregion

    # Making the call
    print("Configuring role mapping {} for the directory {} on {}".format(role_name,directory_name,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)
    
    # return
    return resp
# endregion

# region prism_software_metadata_validate
def prism_software_metadata_validate(api_server,username,secret,metadata_type,metadata_file):
    """
        Validate software metadata on Prism Element

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        metadata_type: Metadata software type (ie: NCC, PRISM_CENTRAL, etc.)
        metadata_file: Metadata software file (usually a JSON file)
        
    Returns:
        Response cookies
    """
    
    # region prepare the api call
    headers = {'Content-Type': 'application/octet-stream;charset=UTF-8'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/upgrade/{}/softwares/validate_upload".format(metadata_type)
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = open(metadata_file, 'rb').read() # open as binary file
    #payload = metadata_file
    # endregion

    # Making the call
    print("Validating software {} metadata on {}".format(metadata_type,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload,upload_binary=True,return_cookies=True)

    # return
    print("Returning Cookies..")
    return resp.cookies
# endregion

# region prism_software_upload
def prism_software_upload(api_server,username,secret,metadata_file,binary_file):
    """
        Upload a software on Prism Element using the old Upload Software mechanism

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        metadata_file: Metadata software file (usually a JSON file)
        binary_file: Binary sotware file (usually a TAR or TAR.GZ file)
        
    Returns:
        Uploading software on Prism Element
    """

    # validate metadata first
    metadata_json = json.load(open(metadata_file))
    #metadata_json = json.loads(metadata_file)
    metadata_type = metadata_json['type']
    metadata_version = metadata_json['version_id']
    metadata_size = metadata_json['size']
    metadata_md5 = metadata_json['hex_md5']
    metadata_validate = prism_software_metadata_validate(api_server,username,secret,metadata_type,metadata_file)
    metadata_cookies = metadata_validate.get_dict()['NTNX_SOFTWARE_UPLOAD']

    # region prepare the api call
    headers = {'Content-Type': 'application/octet-stream;charset=UTF-8','Cookie':'NTNX_SOFTWARE_UPLOAD={}'.format(metadata_cookies)}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/upgrade/{}/softwares/{}/upload?fileSize={}&md5Sum={}&fileName={}&version={}".format(metadata_type,metadata_version,metadata_size,metadata_md5,metadata_version,metadata_version)
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = open(binary_file, 'rb').read() # open as binary file
    #payload = binary_file
    # endregion

    # Making the call
    print("Uploading software {} version {} on {}".format(metadata_type,metadata_version,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload,upload_binary=True)

    # return
    return resp
# endregion

# region prism_get_pc_deploy_softwares
def prism_get_pc_software(api_server,username,secret):
    """
        Retrieve list of Prism Central softwares details available on Prism Element 
        (through Download or Upload)

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        
    Returns:
        List of available Prism Central Details (part of the json response)
    """

    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/upgrade/prism_central_deploy/softwares"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET" 
    #endregion

    # Making the call
    print("Retieving PC softwares details on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)
    
    # return
    return resp['entities']
# endregion

# region prism_create_pc_vm
def prism_create_pc_vm(api_server,username,secret,pc_version,pc_name,pc_ip,pc_cpu,pc_mem,pc_disk,pc_dns,pc_network_mask,pc_network_gateway,container_uuid,network_uuid):
    """
        Retrieve list of Prism Central softwares details available on Prism Element 
        (through Download or Upload)

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        pc_version: Version for the Prism Central VM.
        pc_name: Name for the Prism Central VM.
        pc_ip: List (array) of IP addresses for the Prism Central VM.
        pc_cpu: Number of vCPUs for the Prism Central VM.
        pc_mem: Memory (GB) for the Prism Central VM.
        pc_disk: Disk size (GB) for the Prism Central VM.
        pc_dns: List (array) of dns server for the Prism Central VM.
        pc_network_mask: Network netmask for the Prism Central VM.
        pc_network_gateway: Network gayeway for the Prism Central VM.
        container_uuid: Container uuid on which the Prism Central VM will be provisioned.
        network_uuid: Network uuid on which the Prism Central VM will be provisioned.
        
    Returns:
        Task operation (part of the json response)
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/prism_central"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {
        'resources': {
            'version': pc_version,
            'should_auto_register': False,
            'pc_vm_list': [
                {
                    'vm_name': pc_name,
                    'container_uuid': container_uuid,
                    'num_sockets': pc_cpu,
                    'data_disk_size_bytes': ((pc_disk)*1024*1024*1024),
                    'memory_size_bytes': ((pc_mem)*1024*1024*1024),
                    'dns_server_ip_list': pc_dns,
                    'nic_list': [
                        {
                            'ip_list': [pc_ip],
                            'network_configuration': {
                                'network_uuid': network_uuid,
                                'subnet_mask': pc_network_mask,
                                'default_gateway': pc_network_gateway
                            }
                        }
                    ]
                }
            ]
        }
    }
    # endregion

    # Making the call
    print("Deploying a Prism Central VM named {} on {}".format(pc_name,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)
    
    # return
    return resp
# endregion

# region prism_create_vm_from_image
def prism_create_vm_from_image(api_server,username,secret,vm_name,vm_cpu,vm_mem,image_uuid,network_uuid,vm_ip=None):
    """
        Create a VM  on Prism Element 
    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        vm_name: Name of the VM to provision.
        vm_cpu: Number of vCPUs for the VM to provision.
        vm_mem: Number of memory (GB) for the VM to provision.
        image_uuid: Image uuid the VM should be based on.
        network_uuid: Network uuid on which the Prism Central VM will be provisioned.
        vm_ip (Optional): Ip address for the VM to provision.
        
    Returns:
        Task operation (part of the json response)
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/vms"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {
        'spec': {
            'name': vm_name,
            'resources': {
                'num_sockets': int(vm_cpu),
                'num_vcpus_per_socket': 1,
                'memory_size_mib': int((vm_mem)*1024),
                'power_state': 'OFF',
                'disk_list': [
                    {
                        'device_properties': {
                            'device_type': 'DISK',
                            'disk_address': {
                                'adapter_type': 'SCSI',
                                'device_index': 0
                            }
                        },
                        'data_source_reference': {
                            'kind': 'image',
                            'uuid': image_uuid
                        }
                    }
                ],
                'nic_list': [
                    {
                        'subnet_reference': {
                            'kind': 'subnet',
                            'uuid': network_uuid
                        },
                        'ip_endpoint_list': []
                    }
                ]
                # 'guest_customization': {
                #     'cloud_init': {
                #         'user_data': 'IyBjbG91ZC1jb25maWcKaG9zdG5hbWU6IHRlc3Q='
                #     }
                # }
            }
        },
        'metadata': {
            'kind': 'vm'
        },
        'api_version': '3.0'
    }
    # endregion

    # update payload with vm_ip info
    if vm_ip:
        payload_vm_ip = {'ip': vm_ip }
        payload['spec']['resources']['nic_list'][0]['ip_endpoint_list'].append(payload_vm_ip)

    # Making the call
    print("Creating VM named {} on {}".format(vm_name,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)
    
    # return
    return resp
# endregion

# region prism_register_pc
def prism_register_pc(api_server,username,secret,pc_ip,pc_username="admin",pc_secret="nutanix/4u"):
    """
        Register a Nutanix cluster on provided Prism Central instance

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        pc_ip: List (array) of IP addresses for the Prism Central VM.
        pc_username: Username of the Prism Central instance (default: admin)
        pc_secret: Username secret of the the Prism Central instance (default: nutanix/4u)
        
    Returns:
        Task operation (part of the json response)
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/multicluster/prism_central/register"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload =  {
        'ipAddresses': [pc_ip],
        'username': pc_username,
        'password': pc_secret,
        'port': 9440
    }
    # endregion

    # # Making the call
    print("Registering Nutanix Cluster {} to the Prism Central instance {}".format(api_server,pc_ip))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)
    
    # return
    return resp
# endregion

# region pc_check_calm
def pc_check_calm(api_server,username,secret):
    """
        Retrieve Calm details on Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        
    Returns:
        Calm service details (part of the json response)
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/services/nucalm/status"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    # endregion

    # Making the call
    print("Checking Calm status on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)
    
    # return
    return resp
# endregion

# region pc_enable_calm
def pc_enable_calm(api_server,username,secret):
    """
        Enabling Calm on Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        
    Returns:
        Task operation (part of the json response)
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/services/nucalm"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {
        'enable_nutanix_apps': False,
        'state': 'ENABLED'
    }
    # endregion

    # Making the call
    print("Enabling Calm status on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)
    
    # return
    return resp
# endregion

# region pc_monitor_calm_health
def pc_monitor_calm_health(api_server,username,secret,retry_delay_secs=30,max_attemps=30):
    """
        Monitor a Calm service status on PC. Upon Enablement, PC spin up Calm containers
        Calm containers takes a few minutes to start.

    Args:
        api_server: The Foundation API server
        username: None (no authentication on the foundation API)
        secret: None (no authentication on the foundation API)
        max_attemps: 30 (default)
        retry_delay_secs: 30 seconds (default)
        
    Returns:
        None
    """
    
    # variables
    attempt = 1
    max_attempts = max_attemps # default is 30
    retry_delay_secs = retry_delay_secs # default is 30 seconds
    
    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/services/nucalm/status"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    # endregion

    # track task process
    print("Monitoring Calm service health status on {}".format(api_server))
    while attempt <= max_attempts:
        # make the api call
        print("Making a {} API call to {}".format(method, url))
        calm_service_status = process_request(url,method,username,secret,headers)
        print("Attempt number: {}".format(attempt))
        if calm_service_status['service_running_status'] == "HEALTHY":
            print("Calm service health is now HEALTHY")
            return
        elif calm_service_status['service_running_status'] == "UNHEALTHY":
            print("Calm service health is still not HEALTHY")
            print("WARNING: remaining attemps before failure: {0}".format(max_attempts-attempt))
            print("Let's wait for {} seconds..".format(retry_delay_secs))
            attempt +=1
            sleep(retry_delay_secs)

    print ("Error: Exceeded max attempts {}".format(max_attempts))

    # return
    return
# endregion

# region pc_check_flow
def pc_check_flow(api_server,username,secret):
    """
        Retrieve Flow details on Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        
    Returns:
        Flow service details (part of the json response)
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/services/microseg/status"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    # endregion

    # Making the call
    print("Checking Flow status on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)
    
    # return
    return resp
# endregion

# region pc_enable_flow
def pc_enable_flow(api_server,username,secret):
    """
        Enabling Flow on Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        
    Returns:
        Task operation (part of the json response)
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/services/microseg"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {
        'state': 'ENABLE'
    }
    # endregion

    # Making the call
    print("Enabling Flow status on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)
    
    # return
    return resp
# endregion

# region pc_get_permissions
def pc_get_permissions(api_server,username,secret):
    """
        Retrieve a list of permissions on Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        
    Returns:
        A list of permissions (entities part of the json response).
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/permissions/list"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {'kind':'permission', 'length': 500} # max 500
    # endregion

    # Making the call
    print("Retrieving permissions on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # return
    return resp['entities']    
# endregion

# region pc_get_permission_uuid
def pc_get_permission_uuid(api_server,username,secret,permission_name):
    """
        Retrieve permission uuid on Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        permission_name: name of the permission to retrieve
        
    Returns:
        Permission uuid
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/permissions/list"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {'kind':'permission', 'filter': 'name=={}'.format(permission_name)}
    # endregion

    # Making the call
    print("Retrieving permission {} uuid on {}".format(permission_name, api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    #return
    return resp['entities'][0]['metadata']['uuid']

# endregion

# region pc_create_role
def pc_create_role(api_server,username,secret,role_name,permissions_uuid_list):
    """
        Create a custon role on Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        role_name: Name of the role to create.
        permission_uuid_list: list of permissions uuid to include on the role.
        
    Returns:
        Role creation containing a task exeuction (json response).
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/roles"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {
        'spec': { 
            'name': role_name,
            'resources': { 
                'permission_reference_list': []
                }
            },
        'metadata': { 
            'kind': 'role'
        },
        'api_version': '3.1.0'
    }

    # pushing permissions_uuid_list
    for permission_uuid in permissions_uuid_list:
        permission_payload = { 
            'kind': 'permission', 
            'uuid': permission_uuid
        }
        payload['spec']['resources']['permission_reference_list'].append(permission_payload)
    # endregion

    # Making the call
    print("Creating custom role {} on {}".format(role_name,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)
    
    # return
    return resp
# endregion

# region pc_get_roles
def pc_get_roles(api_server,username,secret,role_name=None):
    """
        Retrieve a list of roles on Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        role_name: role name to retrieve
        
    Returns:
        A list of roles (entities part of the json response).
    """

    # variables
    roles_list = []

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/roles/list"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = { 'kind':'role','length': 200 }
    # endregion

    # Making the call
    print("Retrieving roles details on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)
    
    # processing
    if role_name == None:
        print("Returning all roles on {}".format(api_server))
        roles_list.extend(resp['entities'])
    else: 
        for role in resp['entities']:
            if role['status']['name'] == role_name:
                print("Return single role {} on {}".format(role_name,api_server))
                roles_list.append(role)
                break

    # return
    return roles_list
# endregion

# region pc_get_role_uuid
def pc_get_role_uuid(api_server,username,secret,role_name=None):
    """
        Retrieve a role uuid on Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        role_name: Role name to retrieve
        
    Returns:
        Role uuid (string).
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/roles/list"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {'kind':'role','filter':'name=={}'.format(role_name)}
    # endregion

    # Making the call
    print("Retrieving role {} uuid on {}".format(role_name,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)
    
    # returning
    return resp['entities'][0]['metadata']['uuid']
# endregion

# region pc_import_image_from_pe
def pc_import_image_from_pe(api_server,username,secret,cluster_uuid,image_uuid=None):
    """
        Import a list of images fron Prism Element on Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        cluster_uuid: uuid of the cluster on which the images are.
        image_uuid: uuid of a specific image to import.
        
    Returns:
        A task execution (json response).
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/batch"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {
        'action_on_failure': 'CONTINUE',
        'execution_order': 'NON_SEQUENTIAL',
        'api_request_list': [
            {
                'operation': 'POST',
                'path_and_params': '/api/nutanix/v3/images/migrate',
                'body': {
                    'image_reference_list': [],
                    'cluster_reference': {
                        'uuid': cluster_uuid,
                        'kind': 'cluster',
                        'name': 'string'
                    }
                }
            }
        ],
        'api_version': '3.0'
    }
    # endregion

    # update payload (in case image_uuid provided)
    if image_uuid:
        image_payload =  {
            'uuid': image_uuid,
            'kind': 'image',
            'name': 'string'
        }
        
        payload['api_request_list'][0]['body']['image_reference_list'].append(image_payload)

    # Making the call
    print("Importing images from PE to PC {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)
    
    # return
    return resp
# endregion

# region prism_get_cluster
def pc_get_cluster(api_server,username,secret,cluster_name=None):
    """
        Retrieve Prism Element Clusters details on Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        cluster_name: Cluster name to retrieve.
        
    Returns:
         Prism Element cluster details (entities part of the json response)
    """

    # variables
    clusters_list = []

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/clusters/list"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = { 'kind':'cluster','length':500 }
    # endregion

    # Making the call
    print("Retrieving clusters details on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # processing
    if cluster_name == None:
        print("Returning all clusters on {}".format(api_server))
        clusters_list.extend(resp['entities'])
    else: 
        for cluster in resp['entities']:
            if cluster['status']['name'] == cluster_name:
                print("Return single cluster {} on {}".format(cluster_name,api_server))
                clusters_list.append(cluster)
                break

    # return
    return clusters_list
# endregion

# region prism_get_cluster_uuid
def pc_get_cluster_uuid(api_server,username,secret,cluster_name):
    """
        Retrieve Prism Element cluster uuid from Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        cluster_name: cluster name uuid to retrieve.
        
    Returns:
         Prism Element cluster uuid (json response)
    """

    # variables
    cluster_uuid = []

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/clusters/list"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = { 'kind':'cluster','length': 200 }
    # endregion

    # Making the call
    print("Retrieving clusters details on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # processing
    for cluster in resp['entities']:
        if cluster['status']['name'] == cluster_name:
            cluster_uuid = cluster['metadata']['uuid']

    # return
    print("Return cluster uuid {} found on {}".format(cluster_uuid,api_server))
    return cluster_uuid
# endregion

# region pc_get_image_by_uuid
def pc_get_image_by_uuid(api_server,username,secret,image_uuid):
    """
        Retrieve image details  on Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        image_uuid: uuid of the image to retrieve.
        
    Returns:
        A list of roles (entities part of the json response).
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/images/{}".format(image_uuid)
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    # endregion

    # Making the call
    print("Retrieving image details on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)
    
    # return
    return resp
# endregion

# region pc_get_projects
def pc_get_projects(api_server,username,secret,project_name=None):
    """
        Retrieve projects details on Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        project_name: specific project details to retrieve.
        
    Returns:
        A list of project details (entities part of the json response).
    """
    
    # variables
    projects_list = []
    
    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/projects/list"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {'kind':'project'}
    # endregion

    # Making the call
    print("Retrieving project details on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # processing
    if project_name == None:
        print("Return all projects..")
        projects_list.extend(resp['entities'])
    else: 
        for project in resp['entities']:
            if project['status']['name'] == project_name:
                print("Return single project")
                projects_list.append(project)
                break
    # return
    return projects_list

# endregion

# region get pc_get_projects_internal
def pc_get_projects_internal(api_server,username,secret,project_uuid):
    """
        Retrieve projects internal details on Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        project_uuid: uuid of the project
        
    Returns:
        Project internal details (json response).
    """
        
    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/projects_internal/{}".format(project_uuid)
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    # endregion

    # Making the call
    print("Retrieving project internal {} details on".format(project_uuid,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)

    # return
    return resp
# endregion

# region get pc_get_project_uuid
def pc_get_project_uuid(api_server,username,secret,project_name):
    """
        Retrieve project uuid on Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        project_name: project details to retrieve.
        
    Returns:
        Project uuid (string).
    """
        
    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/projects/list"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {'kind':'project','filter': 'name=={}'.format(project_name)}
    # endregion

    # Making the call
    print("Retrieving project {} uuid on {}".format(project_name,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # return
    return resp['entities'][0]['metadata']['uuid']
# endregion

# region pc_get pc_get_account_uuid
def pc_get_account_uuid(api_server,username,secret,account_name="NTNX_LOCAL_AZ"):
    """
        Retrieve account uuid on Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        account_name: account details to retrieve. (default PC)
        
    Returns:
        account uuid (string).
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/accounts/list"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {'kind': 'account',"filter":"name=={}".format(account_name)}
    # endregion

    # Making the call
    print("Retrieving account {} uuid on {}".format(account_name,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)
    
    # returning
    return resp['entities'][0]['metadata']['uuid']
# endregion

# region pc_get_subnet_uuid
def pc_get_subnet_uuid(api_server,username,secret,subnet_name):
    """
        Retrieve subnet uuid on Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        subnet_name: subnet details to retrieve.
        
    Returns:
        subnet uuid (string).
    """
    
    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/subnets/list"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {'kind':'subnet','filter': 'name=={}'.format(subnet_name)}
    # endregion

    # make the call
    print("Retrieving subnet {} uuid on {}".format(subnet_name,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # return
    return resp['entities'][0]['metadata']['uuid']
# endregion

# region pc_create_project
def pc_create_project(api_server,username,secret,project_name):
    """
        Creates a project on Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        project_name: Name of the project to create
        
    Returns:
        Project creation response (json response).
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/projects_internal"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {
        'spec': {
            'project_detail': {
                'name': project_name,
                'resources': {}
            },
            'user_list': [],
            'user_group_list': [],
            'access_control_policy_list': []
        },
        'api_version': '3.0',
        'metadata': {'kind': 'project'}
    }
    # endregion

    # Making the call
    print("Creatint project {} on {}".format(project_name,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # return
    return resp
# endregion

# region get pc_get_directory_service_uuid
def pc_get_directory_service_uuid(api_server,username,secret,directory_service_name):
    """
        Retrieves directory service uuid on Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        directory_service_name: Name of the directory service to retrieve
        
    Returns:
        Uuid of the directory service (string).
    """
        
    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/directory_services/list"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {'filter':'name=={}'.format(directory_service_name)}
    # endregion

    # Making the call
    print("Retrieving directory service uuid {} on {}".format(directory_service_name,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)
    
    # return
    return resp['entities'][0]['metadata']['uuid']
# endregion

# region pc_calm_group_search
def pc_calm_search_users(api_server,username,secret,directory_service_uuid,search_name):
    """
        Retrieves distinguished_name group on Prism Central

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        directory_service_uuid: Uuid of the directory service
        group_name: group name to retrieve on the directory service
        
    Returns:
        distinguished_name group (string).
    """
    
    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/calm/v3.0/calm_users/search"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {
        'query':search_name,
        'provider_uuid': directory_service_uuid,
        'user_type':"ACTIVE_DIRECTORY",
        'is_wildcard_search':True
    }
    # endregion

    # Making the call
    print("Retrieving {} uuid".format(search_name))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # filterng
    for entity in resp['search_result_list']:
        if entity['type'] == "Group":
            for attribute in entity['attribute_list']:
                if attribute['name'] == "distinguishedName":
                    search_value = attribute['value_list'][0]
        elif entity['type'] == "Person":
            for attribute in entity['attribute_list']:
                if attribute['name'] == "userPrincipalName":
                    search_value = attribute['value_list'][0]
    
    # return
    return search_value
# endregion

# region pc_get_acp_user
def pc_get_acp_user_id(api_server,username,secret,acp_user):
    """
        Retrieves distinguished_name user entity_id on Calm

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        acp_user: Name of user to retrieve
        
    Returns:
        distinguished_name group id (string).
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/groups"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {
        'entity_type':'abac_user_capability',
        'group_member_attributes':[{'attribute':'user_uuid'}],
        'query_name':'prism:BaseGroupModel',
        'filter_criteria':'username=={}'.format(acp_user)
    }
    # endregion

    # Making the call
    print("Retreiving user uuid {}".format(acp_user))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)
    print(resp)

    # return
    return resp['group_results'][0]['entity_results'][0]['entity_id'] 
# endregion

# region pc_get_acp_group
def pc_get_acp_group_id(api_server,username,secret,acp_group):
    """
        Retrieves distinguished_name group entity_id on Calm

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        dn_group: Name of the dn group to retrieve
        
    Returns:
        distinguished_name group id (string).
    """

    # variables
    # calculate acp_distinguished_name variable required for the payload
    # from CN=Developers,CN=Users,DC=ntnxlab,DC=loca to cn%3Ddevelopers%2Ccn%3Dusers%2Cdc%3Dntnxlab%2Cdc%3Dlocal
    count = 1
    acp_distinguished_name = ""
    for entity in acp_group.rsplit(","):
        entity_string = entity.lower().replace("=","%3D") # replace '=' with '%3D'
        if count < (len(acp_group.rsplit(","))):
            entity_string += ("%2C") #replace ',' with '%2C'  
        acp_distinguished_name += entity_string
        count += 1
    
    acp_distinguished_name.replace(" ","%20") #remove space (if any)

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/groups"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {
        'entity_type': 'user_group',
        'group_member_attributes': [
            {
                'attribute': 'uuid'
            },
            {
                'attribute': 'distinguished_name'
            }
        ],
        'query_name': 'prism:BaseGroupModel',
        'filter_criteria': 'distinguished_name=={}'.format(acp_distinguished_name)
    }
    # endregion


    # Making the call
    print("Retreiving dn_group uuid {}".format(acp_group))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # return
    return resp['group_results'][0]['entity_results'][0]['entity_id'] 
# endregion

# region pc_set_project_acp_group
def pc_set_project_acp_group(api_server,username,secret,project_uuid,acp_group_id,group_role_uuid):
    """
        Set group and role on a given Calm project

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        project_uuid: Uuid of the project.
        acp_group_id: group entity id to add to the calm project.
        group_role_uuid: role uuid to add to the calm project.
        
    Returns:
        Task execution (json response).
    """

    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/projects_internal/{}".format(project_uuid)
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    # endregion

    # get project_json details first
    print("Retrieving project {} details on {}".format(project_uuid,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)
    project_json = resp

    # update existing access_control_policy_list
    for acccess_control_policy in project_json['spec']['access_control_policy_list']:
        operation = {'operation': "UPDATE"}
        acccess_control_policy.update(operation)

    # payload
    add_acp_group = {
        'operation': 'ADD',
        'acp': {
            'name': 'nuCalmAcp-'+str(uuid.uuid4()),
            'resources': {
                'role_reference': {
                    'uuid': group_role_uuid,
                    'kind': 'role'
                },
                'user_group_reference_list': [
                    {
                    'kind': 'user_group',
                    'uuid': acp_group_id
                    }
                ],
                'filter_list': {
                    'context_list': [{
                            'scope_filter_expression_list': [
                                {
                                    'operator': 'IN',
                                    'left_hand_side': 'PROJECT',
                                    'right_hand_side': {
                                        'uuid_list': [project_uuid]
                                    }
                                }
                            ],
                            'entity_filter_expression_list': [
                                {
                                    'operator': 'IN',
                                    'left_hand_side': {
                                        'entity_type': 'ALL'
                                    },
                                    'right_hand_side': {
                                        'collection': 'ALL'
                                    }
                                }
                            ]
                        }
                    ]
                }
            },
            'description': 'ACPDescription-'+str(uuid.uuid4())
        },
        'metadata': {
            'kind': 'access_control_policy'
        }
    }
        
    # push acp_group to payload
    project_json['spec']['access_control_policy_list'].append(add_acp_group)
    add_acp_group = {'kind': 'user_group','uuid': acp_group_id}
    project_json['spec']['project_detail']['resources']['external_user_group_reference_list'].append(add_acp_group)

    # update json
    project_json.pop('status', None) # don't need status for the update
    project_json['metadata'].pop('owner_reference', None)
    project_json['metadata'].pop('create_time', None)
    payload = project_json

    # updating the project
    method = "PUT"
    print("Updating project {} details on {}".format(project_uuid,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # return
    return resp
# endregion

# region pc_set_project_acp_user
def pc_set_project_acp_user(api_server,username,secret,project_uuid,acp_user_id,user_role_uuid):
    """
        Set group and role on a given Calm project

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        project_uuid: Uuid of the project.
        acp_user_id: user entity id to add to the calm project.
        user_role_uuid: role uuid to add to the calm project.
        
    Returns:
        Task execution (json response).
    """

    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/projects_internal/{}".format(project_uuid)
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    # endregion

    # get project_json details first
    print("Retrieving project {} details on {}".format(project_uuid,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)
    project_json = resp
    
    # update existing access_control_policy_list
    for acccess_control_policy in project_json['spec']['access_control_policy_list']:
        operation = {'operation': "UPDATE"}
        acccess_control_policy.update(operation)

    # payload
    add_acp_user = {
        'operation': 'ADD',
        'acp': {
            'name': 'nuCalmAcp-'+str(uuid.uuid4()),
            'resources': {
                'role_reference': {
                    'uuid': user_role_uuid,
                    'kind': 'role'
                },
                'user_reference_list': [
                    {
                        'kind': 'user',
                        'uuid': acp_user_id
                    }
                ],
                'filter_list': {
                    'context_list': [{
                            'scope_filter_expression_list': [
                                {
                                    'operator': 'IN',
                                    'left_hand_side': 'PROJECT',
                                    'right_hand_side': {
                                        'uuid_list': [project_uuid]
                                        }
                                }
                            ],
                            'entity_filter_expression_list': [
                                {
                                    'operator': 'IN',
                                    'left_hand_side': {
                                        'entity_type': 'ALL'
                                        },
                                    'right_hand_side': {
                                        'collection': 'ALL'
                                        }
                                }
                            ]
                        }
                    ]
                }
            },
            'description': 'ACPDescription-'+str(uuid.uuid4())
        },
        'metadata': {'kind': 'access_control_policy'}
    }

    # push acp_user to payload
    project_json['spec']['access_control_policy_list'].append(add_acp_user)
    add_acp_user = {'kind': 'user','uuid': acp_user_id}
    project_json['spec']['project_detail']['resources']['user_reference_list'].append(add_acp_user)

    # update json
    project_json.pop('status', None) # don't need status for the update
    project_json['metadata'].pop('owner_reference', None)
    project_json['metadata'].pop('create_time', None)
    payload = project_json

    # Making the call
    method = "PUT"
    print("Updating project {} details on {}".format(project_uuid,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # return
    return resp
# endregion

# region create pc_set_project_infrastructure
def pc_set_project_infrastructure(api_server,username,secret,project_uuid,account_uuid,subnet_uuid):
    """
        Set infrastructure resources for a given project on Calm

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        project_uuid: Uuid of the project.
        account_uuid: uuid of the account (default account_name is NTNX_LOCAL_AZ (PC))
        cluster_uuid: uuid of the cluster
        subnet_uuid: uuid of the subnet (Default subnet for the calm project)
        
    Returns:
        Task execution (json response).
    """

    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    method = "GET"
    api_server_endpoint = "/api/nutanix/v3/projects_internal/{}".format(project_uuid)
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    # endregion

    # get project_json details first
    print("Retrieving project {} details on {}".format(project_uuid,api_server))
    print("Making a {} API call to {}".format(method, url))
    project_json = process_request(url,method,username,secret,headers)

    # region updating project payload
    # update existing access_control_policy_list
    for acccess_control_policy in project_json['spec']['access_control_policy_list']:
        operation = {'operation': "UPDATE"}
        acccess_control_policy.update(operation)

    # push account and default_subnet details
    if not project_json['spec']['project_detail']['resources']['account_reference_list']:
        account_payload = {'kind': 'account','uuid': account_uuid}
        project_json['spec']['project_detail']['resources']['account_reference_list'].append(account_payload)

    if not project_json['spec']['project_detail']['resources']['subnet_reference_list']:
        subnet_payload = {'kind': 'subnet','uuid': subnet_uuid}
        project_json['spec']['project_detail']['resources']['subnet_reference_list'].append(subnet_payload)

    # update json
    project_json.pop('status', None) # don't need status for the update
    payload = project_json
    # endregion

    # make the api call
    method = "PUT"
    print("Updating project {} details on {}".format(project_uuid,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # return
    return resp
# endregion

# region pc_get_runbooks
def pc_get_runbooks(api_server,username,secret,runbook_name=None):
    """
        Retrieve runbooks details on Calm

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        runbook_name: specific runbook details to retrieve.
        
    Returns:
        A list of runbook details (entities part of the json response).
    """
    
    # variables
    runbook_list = []
    
    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/runbooks/list"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {'kind':'runbook'}
    #endregion

    # Making the call
    print("Retrieving runbook details on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # filtering
    if runbook_name == None:
        print("Return all runbooks..")
        runbook_list.extend(resp['entities'])
    else: 
        for runbook in resp['entities']:
            if runbook['status']['name'] == runbook_name:
                print("Return single runbook")
                runbook_list.append(runbook)
                break

    # return
    return runbook_list
# endregion

# region get pc_get_runbook_uuid
def pc_get_runbook_uuid(api_server,username,secret,runbook_name):
    """
        Retrieve runbooks uuid on Calm

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        runbook_name: specific runbook details to retrieve.
        
    Returns:
        Runbook uuid (string).
    """
        
    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/runbooks/list"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {'kind':'runbook','filter': 'name=={}'.format(runbook_name)}
    # endregion

    # Making the call
    print("Retreiving runbook {} uuid on {}".format(runbook_name,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # return
    return resp['entities'][0]['metadata']['uuid']
# endregion

# region pc_get_endpoints
def pc_get_endpoints(api_server,username,secret,endpoint_name=None):
    """
        Retrieve endpoints details on Calm

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        endpoint_name: specific runbook details to retrieve.
        
    Returns:
        A list of endpoint details (entities part of the json response).
    """
    
    # variables
    endpoint_list = []
    
    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/endpoints/list"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {'kind':'endpoint'}
    #endregion

    # Making the call
    print("Retrieving endpoint details on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # filtering
    if endpoint_name == None:
        print("Return all endpoints..")
        endpoint_list.extend(resp['entities'])
    else: 
        for endpoint in resp['entities']:
            if endpoint['status']['name'] == endpoint_name:
                print("Return single endpoint")
                endpoint_list.append(endpoint)
                break
    
    # return
    return endpoint_list

# endregion

# region pc_upload_runbook
def pc_upload_runbook(api_server,username,secret,project_uuid,runbook_name,runbook_file,passphrase=None):
    """
        Upload a runbook on Calm (json file)

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        project_uuid: Project uuid.
        runbook_json_file: Runbook json file to upload.
        passphrase (Optional): Runbook's passphrase.
        
    Returns:
        Runbook details (json response).
    """

    # region prepare the api call
    headers = {'Accept':'*/*'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/runbooks/import_file"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    # endregion

    # open the runbook as binary_file
    #files = [('file',(runbook_json_file, open(runbook_json_file, 'rb'),'application/json'))]
    files = [('file',(runbook_file, runbook_file,'application/json'))]
    payload = {'name': runbook_name, 'project_uuid': project_uuid,'passphrase': passphrase}

    # Making the call
    print("Uploading runbook {} on {}".format(runbook_name,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload,upload_files=files)

    # return
    return resp
# endregion

# region upload endpoint
def pc_upload_endpoint(api_server,username,secret,project_uuid,endpoint_name,endpoint_file,passphrase=None):
    """
        Upload a runbook on Calm (json file)

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        project_uuid: Project uuid.
        endpoint_json_file: Endpoint json file to upload.
        passphrase (Optional): Endpoint's passphrase.
        
    Returns:
        Endpoint details (json response).
    """
    #region prepare the api call
    headers = {'Accept':'*/*'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/endpoints/import_file"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    #endregion

    # open the endpoint as binary_file
    #files = [('file',(endpoint_json_file, open(endpoint_json_file, 'rb'),'application/json'))]
    files = [('file',(endpoint_file, endpoint_file,'application/json'))]
    payload = {'name': endpoint_name, 'project_uuid': project_uuid,'passphrase': passphrase}

    # Making the call
    print("Uploading endpoint {} on {}".format(endpoint_name,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload,upload_files=files)
   
    # return
    return resp
# endregion

# region pc_get_marketplace_items
def pc_get_marketplace_items(api_server,username,secret,marketplace_item_name=None):
    """
        Retrieve marketplace items details on Calm

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        marketplace_item_name: specific runmarketplace_item_name details to retrieve.
        
    Returns:
        A list of marketplace_item details (entities part of the json response).
    """
    
    # variables
    marketplace_item_list = []
    
    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/calm_marketplace_items/list"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {'kind':'marketplace_item'}
    #endregion

    # Making the call
    print("Retreiving marketplace item details on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # filtering
    if marketplace_item_name == None:
        print("Return all marketplace_item..")
        marketplace_item_list.extend(resp['entities'])
    else: 
        for marketplace_item in resp['entities']:
            if marketplace_item['status']['name'] == marketplace_item_name:
                print("Return single marketplace_item")
                marketplace_item_list.append(marketplace_item)

    # return
    return marketplace_item_list
# endregion

# region get pc_get_marketplace_item_uuid
def pc_get_marketplace_item_uuid(api_server,username,secret,marketplace_item_name):
    """
        Retrieve marketplace item uuid on Calm

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        marketplace_item_name: specific marketplace_item_name to retrieve.
        
    Returns:
        A marketplace uuid (string).
    """
        
    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/calm_marketplace_items/list"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {'kind':'marketplace_item','filter': 'name=={}'.format(marketplace_item_name)}
    # endregion

    # Making the call
    print("Retrieving marketplace item {} uuid on {}".format(marketplace_item_name,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # return
    return resp['entities'][0]['metadata']['uuid']
# endregion

# region get pc_get_marketplace_item_details
def pc_get_marketplace_item_details(api_server,username,secret,marketplace_item_uuid):
    """
        Retrieve marketplace item details on Calm

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        marketplace_item_uuid: uuid of the martketplace_item to retrieve.
        
    Returns:
        marketplace_item details (entities part of the json response).
    """
        
    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/calm_marketplace_items/{}".format(marketplace_item_uuid)
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    #endregion

    # Making the call
    print("Retreiving marketplace item details on {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)

    # return
    return resp
# endregion

# region pc_create_marketplace_item
def pc_create_marketplace_item(api_server,username,secret,runbook_name,runbook_uuid):
    """
        Retrieve marketplace item details on Calm

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        runbook_name: Name of the runbook
        runbook_uuid: Uuid of the runbook
        
    Returns:
       Marketplace item detail (json response).
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/calm_marketplace_items"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {
        'spec': {
            'name': runbook_name,
            'resources': {
                'type': 'runbook',
                'author': 'admin',
                'runbook_template_info': {
                    'source_runbook_reference': {
                        'kind': 'runbook',
                        'uuid': runbook_uuid
                    },
                    'is_published_with_endpoints': True,
                    'is_published_with_secrets': True
                },
                'version': '1,0',
                'app_group_uuid': str(uuid.uuid4())
            }
        },
        'api_version': '3.0',
        'metadata': {
            'kind': 'marketplace_item'
        },
    }
    # endregion

    # Making the call
    print("Creating marketplace item {} on {}".format(runbook_name,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # return
    return resp
# endregion

# region pc_publish_marketplace_item
def pc_publish_marketplace_item(api_server,username,secret,marketplace_item_uuid):
    """
        Retrieve marketplace item details on Calm

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        marketplace_item_uuid: Uuid of the marketplace item to publish
        
    Returns:
        Task exeuction (Markeptlace item details - json response).
    """
        

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v3/calm_marketplace_items/{}".format(marketplace_item_uuid)
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "PUT"

    # get marketplace_item details first and update the payload
    marketplace_item_payload = pc_get_marketplace_item_details(api_server,username,secret,marketplace_item_uuid)
    marketplace_item_payload.pop("status",None)
    marketplace_item_payload['spec']['resources']['app_state'] = 'PUBLISHED'
    payload = marketplace_item_payload
    #endregion

    # Making the call
    print("Publishing marketplace item uuid {} on {}".format(marketplace_item_uuid,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)

    # return
    return resp
# endregion

# endregion