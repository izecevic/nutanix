# import functions
from nutanix_functions import *

# # check if argument was passed to the script
# if len(sys.argv) == 1:
#    print('ERROR: you should pass a json config file as argument to the script')
#    exit(1)

# # load config and variables
# file_config = sys.argv[1]
# json_config = json.load(open(file_config))
# prism_api = json_config['cluster']['virtual_ip']
user = "igor.zecevic@nutanix.com"
pwd = "Samedi11!"
api_server = "idp.nutanix.com"
# main
# region update prism admin default password
print("\n--- TEST ---")

idp_auth = nutanix_idp_auth(api_server,user,pwd)

# endregion
