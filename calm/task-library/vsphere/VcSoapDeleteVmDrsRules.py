# region headers
# * author:     igor.zecevic@nutanix.com, stephane.bourdeaud@nutanix.com
# * version:    v1.0 - initial version (igor)
# *             v1.1 - added login/logout (stephane)
# * date:       17/03/2020
# task_name:    VcSoapDeleteVmDrsRules
# description:  Deletes a ClusterAntiAffinityRules (Separates VMs)
#               This script retreives an existing drs rules and deletes it           
# input vars:   vc_cookie, api_server, cluster_id, vms_id
#               drs_rule_name, drs_operation, vms_id
# output vars:  none
# endregion

# region dealing with Scaling In/Out the application
# this script will be executed only on the second Service/Instance
# (ie: Service[1])
if "@@{calm_array_index}@@" != "1":
    print("This task is not required on this Instance ..")
    print("Skipping this task ..")
    exit(0)
# endregion

# region capture Calm variables
username = "@@{vc.username}@@"
password = "@@{vc.secret}@@"
cluster_id = "@@{vc_cluster_id}@@" #retreived from VcSoapGetObjects
drs_rule_name = "@@{calm_application_name}@@"
drs_operation = "remove" #add / edit / remove
api_server = "@@{vc_endpoint}@@"
vms_id = "@@{calm_array_vc_vm_id}@@"
# endregion

#region API call function
def process_request(url, method, headers, payload):
    r = urlreq(url, verb=method, params=payload, verify=False, headers=headers)
    if r.ok:
        print("Request was successful")
        print("Status Code: {}".format(r))
    else:
        print("Request failed")
        print("Status Code: {}".format(r))
        print("Headers: {}".format(headers))
        print("Payload: {}".format(payload))
        print("Response: {}".format(r.text))
        resp_parse = ET.fromstring(r.text)
        for element in resp_parse.iter('*'):
          if "faultstring" in element.tag:
            print("")
            print("Error: {}".format(element.text))
            break
        exit(1)
    return r
#endregion

#region login
#region prepare login API call
ET = xml.etree.ElementTree
api_server_port = "443"
api_server_endpoint = "/sdk/vimService.wsdl"
method = "POST"
url = "https://{}:{}{}".format(api_server, api_server_port, api_server_endpoint)
headers = {'Content-Type': 'application/xml', 'Accept': 'application/xml'}
#endregion

#region login API call
payload = '''
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns="urn:vim25">
   <soapenv:Body>
      <Login>
         <_this type="SessionManager">SessionManager</_this>
         <userName>'''+username+'''</userName>
         <password>'''+password+'''</password>
      </Login>
   </soapenv:Body>
</soapenv:Envelope>'''

# making the api call
print("STEP: Logging in to vCenter...")
print("Making a {} API call to {}".format(method, url))
resp = process_request(url, method, headers, payload)

# pass the cookie in vc_soap_session so that it may be captured by Calm.
vc_cookie = resp.headers.get('Set-Cookie').replace('"','').split(";")[0]
#endregion
#endregion

#region main processing
# region prepare api call
ET = xml.etree.ElementTree
api_server_port = "443"
api_server_endpoint = "/sdk/vimService.wsdl"
method = "POST"
url = "https://{}:{}{}".format(api_server, api_server_port, api_server_endpoint)
headers = {'Content-Type': 'application/xml', 'Accept': 'application/xml', 'Cookie': vc_cookie}
# endregion

# region get application drs rules
payload = '''
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns="urn:vim25" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
   <soapenv:Body> 
    <RetrieveProperties>  
      <_this xsi:type="ManagedObjectReference" type="PropertyCollector">propertyCollector</_this>  
      <specSet> 
        <propSet> 
          <type>ClusterComputeResource</type>  
          <all>false</all>  
          <pathSet>configuration.rule</pathSet>
        </propSet>  
        <objectSet> 
          <obj xsi:type="ManagedObjectReference" type="ClusterComputeResource">'''+cluster_id+'''</obj>  
          <skip>false</skip> 
        </objectSet> 
      </specSet> 
    </RetrieveProperties> 
  </soapenv:Body> 
</soapenv:Envelope>'''

# make the api call
print("STEP: Fetching drs rule...")
print("Making a {} API call to {}".format(method, url))
resp = process_request(url, method, headers, payload)

# getting drs rules
resp_parse = ET.fromstring(resp.text)
payload_find = resp_parse.findall(".//{urn:vim25}ClusterRuleInfo")
for element in payload_find:
    for name in element.findall("{urn:vim25}name"):
        if name.text == drs_rule_name:
            drs_rule_key = format(element.find("{urn:vim25}key").text)
# endregion

# region delete drs rules
payload = '''
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns="urn:vim25" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"> 
  <soapenv:Body> 
    <ReconfigureComputeResource_Task>  
      <_this type="ClusterComputeResource">'''+cluster_id+'''</_this>  
        <spec xsi:type="ClusterConfigSpecEx">  
        <rulesSpec> 
          <operation>'''+drs_operation+'''</operation>
          <removeKey xsi:type="int">'''+drs_rule_key+'''</removeKey>
          <info xsi:type="ClusterAntiAffinityRuleSpec">
            <enabled>true</enabled>   
            <userCreated>true</userCreated>
          </info> 
        </rulesSpec>  
      </spec>  
      <modify>true</modify> 
    </ReconfigureComputeResource_Task> 
  </soapenv:Body> 
</soapenv:Envelope>'''
# endregion

# region add vms to the payload
payload_parse = ET.fromstring(payload)
payload_find = payload_parse.find(".//{urn:vim25}info")
for vm in vms_id.split(","):
    payload_push = ET.SubElement(payload_find,"vm")
    payload_push.attrib["type"] = "VirtualMachine"
    payload_push.text = vm
payload = ET.tostring(payload_parse)

# make the api call
print("STEP: Deleting drs rule...")
print("Making a {} API call to {}".format(method, url))
resp = process_request(url, method, headers, payload)
# endregion

# print the task id
for element in resp_parse.iter('*'):
    if "returnval" in element.tag:
        print("Task is: {}".format(element.text))
#endregion

#region logout
#region prepare api call
ET = xml.etree.ElementTree
api_server_port = "443"
api_server_endpoint = "/sdk/vimService.wsdl"
method = "POST"
url = "https://{}:{}{}".format(api_server, api_server_port, api_server_endpoint)
headers = {'Content-Type': 'application/xml', 'Accept': 'application/xml', 'Cookie': vc_cookie}
#endregion

#region logout API call
payload = '''
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns="urn:vim25">
   <soapenv:Body>
      <Logout>
         <_this type="SessionManager">SessionManager</_this>
      </Logout>
   </soapenv:Body>
</soapenv:Envelope>'''

# making the api call
print("STEP: Logging out of vCenter...")
print("Making a {} API call to {}".format(method, url))
resp = process_request(url, method, headers, payload)
#endregion
#endregion

exit (0)