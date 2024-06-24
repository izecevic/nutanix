# import functions
from nutanix_functions import *

# check if argument was passed to the script
if len(sys.argv) == 1:
   print('ERROR: you should pass a json config file as argument to the script')
   exit(1)

# load config and variables
file_config = sys.argv[1]
json_config = json.load(open(file_config))
foundation_api = json_config['foundation_ip']
foundation_config = json_config['cluster']
foundation_aos = foundation_config['nos_package']
foundation_ipmi_netmask = foundation_config['ipmi_netmask']
foundation_ipmi_gateway = foundation_config['ipmi_gateway']
prism_api = foundation_config['virtual_ip']
prism_user = json_config['user']
prism_pwd = json_config['pwd']

# main

# region get nutanix aos package
print("--- Retreive AOS packages section ---")
foundation_get_aos_details =  foundation_get_aos(foundation_api)
if foundation_aos not in foundation_get_aos_details:
    print("ERROR: provided AOS package {} doesn't exist on foundation server {}".format(foundation_aos,foundation_api))
    print("List of all AOS package available on the foundation server {}: {}".format(foundation_api,foundation_get_aos_details))
    exit(1)
# endregion

# region configure ipmi IP based on mac add
for node in foundation_config['nodes']:
    ipmi_ip = node['ipmi_ip']
    ipmi_mac = node['ipmi_mac']
    ipmi_user = node['ipmi_user']
    ipmi_pwd = node['ipmi_pwd']
    ping_ipmi_details = foundation_ping_ipmi(foundation_api,node['ipmi_ip'])
    if ping_ipmi_details[0][1] == False:
        foundation_configure_ipmi(foundation_api,ipmi_user,ipmi_pwd,ipmi_mac,ipmi_ip,foundation_ipmi_netmask,foundation_ipmi_gateway)
    elif ping_ipmi_details[0][1] == True:
        print("IPMI IP {} already configured for IPMI mac address {}".format(ipmi_ip,ipmi_mac))
# endregion

# region prepare foundation payload
print("\n--- Prepare foundation payload ---")
foundation_payload = foundation_generate_image_payload(foundation_config)
print(json.dumps(foundation_payload,indent=4))
# endregion

# region foundation imaging
print("\n--- Trigger foundation process ---")
foundation_image_nodes(foundation_api,foundation_payload)
foundation_monitor_progress(foundation_api)
# endregion