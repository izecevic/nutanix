# import functions
from nutanix_functions import *

# check if argument was passed to the script
if len(sys.argv) == 1:
   print('ERROR: you should pass a json config file as argument to the script')
   exit(1)

# load config and variables
file_config = sys.argv[1]
json_config = json.load(open(file_config))
pc_api = json_config['pc']['virtual_ip']
pc_user = json_config['user']
pc_pwd = json_config['pwd']
pc_details = json_config['pc']
pc_name = pc_details['name']
prism_api = json_config['cluster']['virtual_ip']
prism_user = json_config['user']
prism_pwd = json_config['pwd']
pc_eula = json_config['eulas']
pc_pulse = json_config['pulse']
cluster_name = json_config['cluster']['name']
cluster_dns = json_config['cluster']['dns']
cluster_ntp = json_config['cluster']['ntp']
cluster_directories = json_config['directory']
pc_roles = json_config['pc_custom_role']
pc_calm_projects = json_config['calm']
pc_directory = json_config['directory'][0]['name']

#main

# region update prism admin default password
print("--- Update prism default password section ---")
pc_cluster_details = prism_get_cluster(pc_api,pc_user,pc_pwd)
if pc_cluster_details == 401: # (UNAUTHORIZED)
    prism_update_default_pwd(pc_api,new_secret=pc_pwd,username="admin",default_secret="Nutanix/4u")
else:
    print("Default password already updated on PC {}".format(pc_api))
# endregion

# region PC registration
print("\n--- PC registration section ---")
prism_pc_vm_details = prism_get_vms(prism_api,prism_user,prism_pwd,pc_name)
prism_cluster_details = prism_get_cluster(prism_api,prism_user,prism_pwd)
print(prism_cluster_details['isRegisteredToPC'])
if prism_cluster_details['isRegisteredToPC'] == None and not prism_pc_vm_details: 
    print("Prism Central {} not deployed on Nutanix cluster {}".format(pc_api,prism_api))
elif prism_cluster_details['isRegisteredToPC'] == None and prism_pc_vm_details: # if PE not registered and PC vm exist
    prism_register_pc(prism_api,prism_user,prism_pwd,pc_api,pc_username="admin",pc_secret="Nutanix/4u")
else:
    print("Nutanix Cluster {} already registered on Prism Central instance {}".format(prism_api,pc_api))
# endregion

# region eulas
print("\n--- Eulas section ---")
pc_eula_details = prism_get_eula(pc_api,pc_user,pc_pwd)
if 'userDetailsList' not in pc_eula_details['entities'][0]:
    prism_accept_eula(pc_api,pc_user,pc_pwd,pc_eula['username'],pc_eula['company'],pc_eula['jobtitle'])
else:
    print("Eulas aready accepted on PC {}".format(pc_api))
# endregion

# region pulse
print("\n--- Pulse section ---")
pc_pulse_status = prism_get_pulse(pc_api,pc_user,pc_pwd)
if pc_pulse_status['isPulsePromptNeeded'] != False or pc_pulse_status['enable'] != pc_pulse:
    prism_enable_pulse(pc_api,pc_user,pc_pwd,pc_pulse)
else:
    print("Pulse already configured on PC {}".format(pc_api))
# endregion

# region dns
print("\n--- DNS section ---")
pc_dns_details = prism_get_dns(pc_api,pc_user,pc_pwd)
for dns_server in cluster_dns:
    if dns_server not in pc_dns_details:
        prism_add_dns(pc_api,pc_user,pc_pwd,dns_server)
    else:
        print("DNS {} already configured on PC {}".format(dns_server,pc_api))
# endregion

# region ntp
print("\n--- NTP section ---")
pc_ntp_details = prism_get_ntp(pc_api,pc_user,pc_pwd)
for ntp_server in cluster_ntp:
    if ntp_server not in pc_ntp_details:
        prism_add_ntp(pc_api,pc_user,pc_pwd,ntp_server)
    else:
        print("NTP {} already configured on PC {}".format(ntp_server,pc_api))
# endregion

#region AD
print("\n--- AD section ---")
for directory in cluster_directories:
    pc_directory_details = prism_get_directory(pc_api,pc_user,pc_pwd,directory['domain'])
    if not pc_directory_details:
        prism_set_directory(pc_api,pc_user,pc_pwd,directory['name'],directory['domain'],directory['url'],directory['svc_user'],directory['svc_pwd'])
    else:
        print("Directory {} already configured on PC {}".format(directory['domain'],pc_api))
# endregion

# region role mapping
print("\n--- Role mapping section ---")
for directory in cluster_directories:
    pc_directory_details = prism_get_directory(pc_api,pc_user,pc_pwd,directory['domain'])
    if pc_directory_details:
        pc_role_mappings_details = prism_get_role_mappings(pc_api,pc_user,pc_pwd,directory['name'])
        if not pc_role_mappings_details:
            for role in directory['role_mapping']:
                prism_set_role_mapping(pc_api,pc_user,pc_pwd,directory['name'],role['name'],role['type'],role['value'])
        else:
            for role in directory['role_mapping']:
                role_exist = False
                for role_detail in pc_role_mappings_details:
                    if role['name'] in role_detail['role']:
                        role_exist = True # role exist
                if role_exist == False:
                    prism_set_role_mapping(pc_api,pc_user,pc_pwd,directory['name'],role['name'],role['type'],role['value'])
                else:
                    print("Role {} already configured on PC {}".format(role['name'],pc_api))
    else:
        print("Directory {} not configured on PC {}".format(directory['domain'],pc_api))
# endregion

#region role
print("\n--- Role section ---")
permissions_uuid_list = []
for role in pc_roles:
    role_name = role['name']
    pc_role_details = pc_get_roles(pc_api,pc_user,pc_pwd,role_name)
    if not pc_role_details:
        print ("Creating role {} on PC {}".format(role_name,pc_api))
        for permission in role['permissions']:
            permission_uuid = pc_get_permission_uuid(pc_api,pc_user,pc_pwd,permission)
            permissions_uuid_list.append(permission_uuid) # push each permission in a list
        pc_role_task = pc_create_role(pc_api,pc_user,pc_pwd,role_name,permissions_uuid_list)
        pc_role_task_uuid = pc_role_task['status']['execution_context']['task_uuid']
        prism_monitor_task_v2(pc_api,pc_user,pc_pwd,pc_role_task_uuid,retry_delay_secs=10,max_attemps=10)
    else:
        print("Role {} already created on PC {}".format(role_name,pc_api))
#endregion


# region import images from PE to PC
print("\n--- Import images section ---")
prism_cluster_uuid = pc_get_cluster_uuid(pc_api,pc_user,pc_pwd,cluster_name)
pc_prism_get_images = prism_get_images(prism_api,prism_user,prism_pwd)
for image in pc_prism_get_images:
    image_name = image['name']
    image_uuid = image['uuid']
    pc_image_details = pc_get_image_by_uuid(pc_api,pc_user,pc_pwd,image_uuid)
    if pc_image_details == 404: # entity not found
        pc_import_image_task = pc_import_image_from_pe(pc_api,pc_user,pc_pwd,prism_cluster_uuid)
        pc_import_image_task_uuid = json.loads(pc_import_image_task['api_response_list'][0]['api_response'])['task_uuid']
        prism_monitor_task_v2(pc_api,pc_user,pc_pwd,pc_import_image_task_uuid,retry_delay_secs=10,max_attemps=10)
    elif pc_image_details and pc_image_details != 404:
        print("Image {} already imported on PC {}".format(image_name,pc_api))
# endregion

# region enable flow
print("\n--- Enable Flow section ---")
pc_flow_status = pc_check_flow(pc_api,pc_user,pc_pwd)
if pc_flow_status['service_enablement_status'] != "ENABLE":
    pc_enable_flow_task = pc_enable_flow(pc_api,pc_user ,pc_pwd)
    pc_enable_flow_task_uuid = pc_enable_flow_task['task_uuid']
    prism_monitor_task_v2(pc_api,pc_user,pc_pwd,pc_enable_flow_task_uuid,retry_delay_secs=30,max_attemps=10)
else:
    print("Flow already enabled on PC {}".format(pc_api))
# endregion

# region enable calm
print("\n--- Enable Calm section ---")
pc_calm_status = pc_check_calm(pc_api,pc_user,pc_pwd)
if pc_calm_status['service_enablement_status'] != "ENABLED":
    pc_enable_calm_task = pc_enable_calm(pc_api,pc_user ,pc_pwd)
    pc_enable_calm_task_uuid = pc_enable_calm_task['task_uuid']
    prism_monitor_task_v2(pc_api,pc_user,pc_pwd,pc_enable_calm_task_uuid,retry_delay_secs=30,max_attemps=10)
    pc_monitor_calm_health(pc_api,pc_user,pc_pwd,retry_delay_secs=30,max_attemps=30)
else:
    print("Calm already enabled on PC {}".format(pc_api))
# endregion

# region create calm project
print("\n--- Create Calm project section ---")
for project in pc_calm_projects:
    project_name = project['project_name']
    pc_projects_details = pc_get_projects(pc_api,pc_user,pc_pwd,project_name)
    if not pc_projects_details:
        pc_create_project_task = pc_create_project(pc_api,pc_user,pc_pwd,project_name)
        pc_create_project_task_uuid = pc_create_project_task['status']['execution_context']['task_uuid']
        prism_monitor_task_v2(pc_api,pc_user,pc_pwd,pc_create_project_task_uuid,retry_delay_secs=10,max_attemps=6)
    else:
        print("Project {} already created on PC {}".format(project_name,pc_api))
# endregion

# region update permissions calm project
print("\n--- Update permission Calm project section ---")
for project in pc_calm_projects:
    project_name = project['project_name']
    pc_project_uuid = pc_get_project_uuid(pc_api,pc_user,pc_pwd,project_name)
    if pc_project_uuid:
        pc_project_internal_details = pc_get_projects_internal(pc_api,pc_user,pc_pwd,pc_project_uuid)
        if not pc_project_internal_details['spec']['access_control_policy_list']:
            for permission in project['project_permissions']:
                directory_service_name=permission['directory']
                pc_directory_uuid = pc_get_directory_service_uuid(pc_api,pc_user,pc_pwd,directory_service_name)
                if permission['type'] == "group":
                    group_name = permission['name']
                    role_name = permission['role']
                    pc_dn_group = pc_calm_search_users(pc_api,pc_user,pc_pwd,pc_directory_uuid,group_name)
                    pc_acp_group_id = pc_get_acp_group_id(pc_api,pc_user,pc_pwd,pc_dn_group)
                    pc_group_role_uuid = pc_get_role_uuid(pc_api,pc_user,pc_pwd,role_name)
                    pc_set_project_acp_group_task = pc_set_project_acp_group(pc_api,pc_user,pc_pwd,pc_project_uuid,pc_acp_group_id,pc_group_role_uuid)
                    pc_set_project_acp_group_task_uuid = pc_set_project_acp_group_task['status']['execution_context']['task_uuid']
                    prism_monitor_task_v2(pc_api,pc_user,pc_pwd,pc_set_project_acp_group_task_uuid,retry_delay_secs=10,max_attemps=6)
                if permission['type'] == "user":
                    user_name = permission['name']
                    role_name = permission['role']
                    pc_dn_user = pc_calm_search_users(pc_api,pc_user,pc_pwd,pc_directory_uuid,user_name)
                    pc_acp_user_id = pc_get_acp_user_id(pc_api,pc_user,pc_pwd,pc_dn_user)
                    pc_user_role_uuid = pc_get_role_uuid(pc_api,pc_user,pc_pwd,role_name)
                    pc_set_project_acp_user_task = pc_set_project_acp_user(pc_api,pc_user,pc_pwd,pc_project_uuid,pc_acp_user_id,pc_user_role_uuid)
                    pc_set_project_acp_user_task_uuid = pc_set_project_acp_group_task['status']['execution_context']['task_uuid']
                    prism_monitor_task_v2(pc_api,pc_user,pc_pwd,pc_set_project_acp_user_task_uuid,retry_delay_secs=10,max_attemps=6)

        else:
            print("Permissions already set for project {}".format(project_name))
    else:
        print("Project {} doesn't exist on PC {} - Skipping".format(project_name,pc_api))
# endregion

# region update infrastructure calm project
print("\n--- Update infrastructure Calm project section ---")
for project in pc_calm_projects:
    project_name = project['project_name']
    project_network = project['project_network']
    pc_project_uuid = pc_get_project_uuid(pc_api,pc_user,pc_pwd,project_name)
    if pc_project_uuid:
        pc_project_internal_details = pc_get_projects_internal(pc_api,pc_user,pc_pwd,pc_project_uuid)
        if not pc_project_internal_details['spec']['project_detail']['resources']['account_reference_list'] or not pc_project_internal_details['spec']['project_detail']['resources']['subnet_reference_list']:
            account_uuid = pc_get_account_uuid(pc_api,pc_user,pc_pwd)
            subnet_uuid =  pc_get_subnet_uuid(pc_api,pc_user,pc_pwd,subnet_name=project_network)
            pc_set_project_infra_task = pc_set_project_infrastructure(pc_api,pc_user,pc_pwd,pc_project_uuid,account_uuid,subnet_uuid)
            pc_set_project_infra_task_uuid = pc_set_project_infra_task['status']['execution_context']['task_uuid']
            prism_monitor_task_v2(pc_api,pc_user,pc_pwd,pc_set_project_infra_task_uuid,retry_delay_secs=10,max_attemps=6)
        else: 
            print("Infrastructure already set for project {}".format(project_name))
    else:
        print("Project {} doesn't exist on PC {} - Skipping".format(project_name,pc_api))
# endregion

# region endpoint calm
print("\n--- Endpoint Calm section ---")
for project in pc_calm_projects:
    endpoint_name = project['endpoint']['name']
    endpoint_json = project['endpoint']['json_file']
    endpoint_file = (requests.get(endpoint_json)).content
    pc_endpoint_details = pc_get_endpoints(pc_api,pc_user,pc_pwd,endpoint_name)
    if not pc_endpoint_details:
        project_name = project['project_name']
        project_uuid = pc_get_project_uuid(pc_api,pc_user,pc_pwd,project_name)
        if project['endpoint']['passphrase']:
            endpoint_passphrase = project['endpoint']['passphrase']
            pc_upload_endpoint(pc_api,pc_user,pc_pwd,project_uuid,endpoint_name,endpoint_file,endpoint_passphrase)
        else:
            pc_upload_endpoint(pc_api,pc_user,pc_pwd,project_uuid,endpoint_name,endpoint_file,passphrase=None)
    else:
        print("Endpoint {} already imported on Caln {}".format(endpoint_name,pc_api))
# endregion

# region runbook calm
print("\n--- Runbook Calm section ---")
for project in pc_calm_projects:
    runbook_name = project['runbook']['name']
    runbook_json = project['runbook']['json_file']
    runbook_file = (requests.get(runbook_json)).content
    pc_runbook_details = pc_get_runbooks(pc_api,pc_user,pc_pwd,runbook_name)
    if not pc_runbook_details:
        project_name = project['project_name']
        project_uuid = pc_get_project_uuid(pc_api,pc_user,pc_pwd,project_name)
        if project['runbook']['passphrase']:
            runbook_passphrase = project['runbook']['passphrase']
            pc_upload_runbook(pc_api,pc_user,pc_pwd,project_uuid,runbook_name,runbook_file,runbook_passphrase)
        else:
            pc_upload_runbook(pc_api,pc_user,pc_pwd,project_uuid,runbook_name,runbook_file,passphrase=None)
    else:
        print("Runbook {} already imported on Caln {}".format(runbook_name,pc_api))

# endregion

# region marketplace calm
print("\n--- Marketplace Calm section ---")
for project in pc_calm_projects:
    runbook_name = project['runbook']['name']
    marketplace_item_detail = pc_get_marketplace_items(pc_api,pc_user,pc_pwd,runbook_name)
    if not marketplace_item_detail:
        runbook_uuid = pc_get_runbook_uuid(pc_api,pc_user,pc_pwd,runbook_name)
        if runbook_uuid:
            print(runbook_uuid)
            marketplace_item_creation = pc_create_marketplace_item(pc_api,pc_user,pc_pwd,runbook_name,runbook_uuid)
            marketplace_item_uuid = pc_get_marketplace_item_uuid(pc_api,pc_user,pc_pwd,runbook_name)
            pc_publish_marketplace_item(pc_api,pc_user,pc_pwd,marketplace_item_uuid)
        else:
            print("Runbook {} doesn't exist on PC {}".format(runbook_name,pc_api))
    elif marketplace_item_detail and marketplace_item_detail[0]['status']['app_state'] != 'PUBLISHED':
        marketplace_item_uuid = pc_get_marketplace_item_uuid(pc_api,pc_user,pc_pwd,runbook_name)
        pc_publish_marketplace_item(pc_api,pc_user,pc_pwd,marketplace_item_uuid)
    else:
        print("Marketplace item {} already published on PC".format(runbook_name,pc_api))
# endregion