# import functions
from nutanix_functions import *

# check if argument was passed to the script
if len(sys.argv) == 1:
   print('ERROR: you should pass a json config file as argument to the script')
   exit(1)

# load config and variables
file_config = sys.argv[1]
json_config = json.load(open(file_config))
prism_api = json_config['cluster']['virtual_ip']
prism_user = json_config['user']
prism_pwd = json_config['pwd']
cluster_eula = json_config['eulas']
cluster_pulse = json_config['pulse']
cluster_timezone = json_config['cluster']['timezone']
cluster_dsip = json_config['cluster']['data_service_ip']
cluster_networks = json_config['networks']
cluster_images = json_config['images']
cluster_dns = json_config['cluster']['dns']
cluster_ntp = json_config['cluster']['ntp']
cluster_directories = json_config['directory']
cluster_pc_metadata_file = json_config['pc']['metadata_file']
cluster_pc_binary_file = json_config['pc']['binary_file']
cluster_pc_ip = json_config['pc']['virtual_ip']
cluster_vms = json_config['vms']
cluster_stig = json_config ['stig']
pc_details = json_config['pc']
pc_name = pc_details['name']
pc_ip = pc_details['virtual_ip']
pc_dns = cluster_dns
pc_network_mask =  pc_details['network_mask']
pc_network_gateway = pc_details['network_gateway']

# main
# region update prism admin default password
print("\n--- Update prism default password section ---")
prism_cluster_details = prism_get_cluster(prism_api,prism_user,prism_pwd)
if prism_cluster_details == 401: # (UNAUTHORIZED)
    prism_update_default_pwd(prism_api,prism_pwd,username="admin",default_secret="nutanix/4u")
else:
    print("Default password already updated on Nutanix cluster {}".format(prism_api))
# endregion

# region eulas
print("\n--- Eulas section ---")
prism_eula_details = prism_get_eula(prism_api,prism_user,prism_pwd)
if 'userDetailsList' not in prism_eula_details['entities'][0]:
    prism_accept_eula(prism_api,prism_user,prism_pwd,cluster_eula['username'],cluster_eula['company'],cluster_eula['jobtitle'])
else:
    print("Eulas aready accepted on Nutanix cluster {}".format(prism_api))
# endregion

# region pulse
print("\n--- Pulse section ---")
prism_pulse_status = prism_get_pulse(prism_api,prism_user,prism_pwd)
if prism_pulse_status['isPulsePromptNeeded'] != False or prism_pulse_status['enable'] != cluster_pulse:
    prism_enable_pulse(prism_api,prism_user,prism_pwd,cluster_pulse)
else:
    print("Pulse already configured on Nutanix cluster {}".format(prism_api))
# endregion

# # region data service ip
print("\n--- Data service ip section ---")
prism_cluster_details = prism_get_cluster(prism_api,prism_user,prism_pwd)
if prism_cluster_details['clusterExternalDataServicesIPAddress'] != cluster_dsip:
    prism_set_dsip(prism_api,prism_user,prism_pwd,cluster_dsip)
else:
    print("Cluster Data Service IP {} already configured on Nutanix cluster".format(cluster_dsip,prism_api))
# # endregion

# region timezone
print("\n--- Timezone section ---")
prism_cluster_details = prism_get_cluster(prism_api,prism_user,prism_pwd)
if prism_cluster_details['timezone'] != cluster_timezone:
    prism_set_timezone(prism_api,prism_user,prism_pwd,cluster_timezone)
else:
    print("Timezone already configured on Nutanix cluster {}".format(prism_api))
# endregion

# region networks
print("\n--- Network section ---")
for network in cluster_networks:
    prism_network_details = prism_get_networks(prism_api,prism_user,prism_pwd,network_name=network['name'])
    if not prism_network_details:
        if 'ipam' in network:
            prism_create_network(prism_api,prism_user,prism_pwd,network['name'],network['vlan'],network['ipam']['address'],network['ipam']['gateway'],network['ipam']['prefix'],network['ipam']['pool'])
        else:
            prism_create_network(prism_api,prism_user,prism_pwd,network['name'],network['vlan'])
    else:
        print("Network {} already created on Nutanix cluster {}".format(network['name'],prism_api))
#endregion

# region upload images (qcow2)
print("\n--- Images section ---")
for image in cluster_images:
    prism_image_details = prism_get_images(prism_api,prism_user,prism_pwd,image_name=image['name'])
    if not prism_image_details:
        prism_container_uuid = prism_get_container_uuid(prism_api,prism_user,prism_pwd,image['container'])
        prism_image_task = prism_upload_image_url(prism_api,prism_user,prism_pwd,image['name'],image['description'],image['url'],prism_container_uuid)
        prism_image_task_uuid = prism_image_task['taskUuid']
        prism_monitor_task_v2(prism_api,prism_user,prism_pwd,prism_image_task_uuid,retry_delay_secs=30,max_attemps=100)
    else:
        print("Image {} already uploaded on Nutanix cluster {}".format(image['name'],prism_api))
# endregion

# region dns
print("\n--- DNS section ---")
prism_dns_details = prism_get_dns(prism_api,prism_user,prism_pwd)
for dns_server in cluster_dns:
    if dns_server not in prism_dns_details:
        prism_add_dns(prism_api,prism_user,prism_pwd,dns_server)
    else:
        print("DNS {} already configured on Nutanix cluster {}".format(dns_server,prism_api))
# endregion

# region ntp
print("\n--- NTP section ---")
prism_ntp_details = prism_get_ntp(prism_api,prism_user,prism_pwd)
for ntp_server in cluster_ntp:
    if ntp_server not in prism_ntp_details:
        prism_add_ntp(prism_api,prism_user,prism_pwd,ntp_server)
    else:
        print("NTP {} already configured on Nutanix cluster {}".format(ntp_server,prism_api))
# endregion

# region configure stig
print("\n--- Configure stig section ---")
prism_cluster_details = prism_get_cluster_v2(prism_api,prism_user,prism_pwd)
for stig_key, stig_value in cluster_stig.items():
    if prism_cluster_details['security_compliance_config'][stig_key] != stig_value:
        prism_set_stig(prism_api,prism_user,prism_pwd,stig_key,stig_value)
    else:
        print("Stig key {} already configured to value {} on Nutanix cluster {}".format(stig_key,stig_value,prism_api))
# endregion

# # region create VM 
# print("\n--- Create VM section ---")
# for vm in cluster_vms:
#     prism_get_vms(prism_api,prism_user,prism_pwd,vm_name=vm['name'])
#     if not prism_get_vms:
#         vm_image_uuid = prism_get_image_uuid(prism_api,prism_user,prism_pwd,image_name=vm['image']) # retrieve image_uuids
#         vm_network_uuid = prism_get_network_uuid(prism_api,prism_user,prism_pwd,network_name=vm['network'])
#         vm_create_vm_task = prism_create_vm_from_image(prism_api,prism_user,prism_pwd,vm_name=vm['image'],vm_cpu=vm['cpu'],vm_mem=vm['memory'],image_uuid=vm_image_uuid,network_uuid=vm_network_uuid,vm_ip=vm['ip'])
#         vm_create_vm_task_uuid = vm_create_vm_task['status']['execution_context']['task_uuid']
#         prism_monitor_task_v2(prism_api,prism_user,prism_pwd,vm_create_vm_task_uuid,retry_delay_secs=10,max_attemps=10)
#         vm_uuid = prism_get_vms(prism_api,prism_user,prism_pwd,vm_name=vm['name'])[0]['uuid']
#         prism_set_vm_powerstate(prism_api,prism_user,prism_pwd,vm_uuid,vm_powerstate='on') # power on the VM
#     else:
#         print("VM {} already deployed on Nutanix Cluster {}".format(vm['name'],prism_api))
# # endregion

# region AD
print("\n--- Active Directory section ---")
for directory in cluster_directories:
    prism_directory_details = prism_get_directory(prism_api,prism_user,prism_pwd,directory['domain'])
    if not prism_directory_details:
        prism_set_directory(prism_api,prism_user,prism_pwd,directory['name'],directory['domain'],directory['url'],directory['svc_user'],directory['svc_pwd'])
    else:
        print("Directory {} already configured on Nutanix cluster {}".format(directory['domain'],prism_api))
#endregion

# region role mapping
print("\n--- Role Mapping section ---")
for directory in cluster_directories:
    prism_directory_details = prism_get_directory(prism_api,prism_user,prism_pwd,directory['domain'])
    if prism_directory_details:
        prism_role_mappings_details = prism_get_role_mappings(prism_api,prism_user,prism_pwd,directory['name'])
        if not prism_role_mappings_details:
            for role in directory['role_mapping']:
                prism_set_role_mapping(prism_api,prism_user,prism_pwd,directory['name'],role['name'],role['type'],role['value'])
        else:
            for role in directory['role_mapping']:
                role_exist = False
                for role_detail in prism_role_mappings_details:
                    if role['name'] in role_detail['role']:
                        role_exist = True # role exist
                if role_exist == False:
                    prism_set_role_mapping(prism_api,prism_user,prism_pwd,directory['name'],role['name'],role['type'],role['value'])
                else:
                    print("Role {} already configured on Nutanix cluster {}".format(role['name'],prism_api))
    else:
        print("Directory {} not configured on Nutanix cluster {}".format(directory['domain'],prism_api))
# endregion

#region PC software upload (works only on a dark site environment - upload binary method instead of downloading)
print("\n--- PC softwares upload section ---")
prism_pc_softwares_details = prism_get_pc_software(prism_api,prism_user,prism_pwd)
if not prism_pc_softwares_details: # if empty, we upload provided PC binary
    print("PC softwares not available on Nutanix Cluster {}".format(prism_api))
    prism_software_upload(prism_api,prism_user,prism_pwd,cluster_pc_metadata_file,cluster_pc_binary_file)
else:
    print("PC software already available on Nutanix cluster {}".format(prism_api))
# endregion

# region PC VM deploy
# region retreiving PC softwares details
print("\n--- PC deploy section ---")
prism_pc_vm_details = prism_get_vms(prism_api,prism_user,prism_pwd,vm_name=pc_name)
if not prism_pc_vm_details:
    pc_softwares_details = prism_get_pc_software(prism_api,prism_user,prism_pwd)
    if pc_softwares_details:
        prism_cluster_details = prism_get_cluster(prism_api,prism_user,prism_pwd)
        prism_cluster_aos_version = prism_cluster_details['version'] # get aos version
        for pc in pc_softwares_details:
            if pc['status'] == "COMPLETED" and prism_cluster_aos_version in pc['compatiblePeNosVersions']:
                pc_version = pc['version']
                for pc_size in pc['prismCentralSizes']:
                    if pc_size['pcVmFormFactor'] == "small": # get cpu/mem/disk details
                        pc_form_factor_details = pc_size
                        break  # get the first one
        # endregion

        # region deploying PC VM         
        pc_cpu = pc_form_factor_details['vcpus']
        pc_mem = pc_form_factor_details['memorySizeInGib']
        pc_disk = pc_form_factor_details['diskSizeInGib']
        network_uuid = prism_get_network_uuid(prism_api,prism_user,prism_pwd,network_name=pc_details['network_name']) 
        container_uuid =  prism_get_container_uuid(prism_api,prism_user,prism_pwd,container_name=pc_details['container_name'])  
        
        # deploy and monitor progress
        prism_pc_deploy_vm_task = prism_create_pc_vm(prism_api,prism_user,prism_pwd,pc_version,pc_name,pc_ip,pc_cpu,pc_mem,pc_disk,pc_dns,pc_network_mask,pc_network_gateway,container_uuid,network_uuid)
        prism_pc_deploy_vm_task_uuid = prism_pc_deploy_vm_task['task_uuid']
        prism_monitor_task_v2(prism_api,prism_user,prism_pwd,prism_pc_deploy_vm_task_uuid,retry_delay_secs=60,max_attemps=60)
        # endregion
    else:
        print("PC softwares not available on Nutanix Cluster {} - Skipping PC VM deployment".format(prism_api))
elif prism_pc_vm_details and prism_pc_vm_details[0]['vmType'] == 'kPCVM':
        print("PC VM {} already deployed on Nutanix cluster {}".format(pc_name,prism_api))
# endregion