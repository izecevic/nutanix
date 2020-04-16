userdata="""<?xml version="1.0" encoding="utf-8"?>\n<unattend xmlns="urn:schemas-microsoft-com:unattend">\n    <settings pass="oobeSystem">\n        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n            <InputLocale>en-US</InputLocale>\n            <SystemLocale>en-US</SystemLocale>\n            <UILanguage>en-US</UILanguage>\n            <UILanguageFallback>en-US</UILanguageFallback>\n            <UserLocale>en-US</UserLocale>\n        </component>\n        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n            <AutoLogon>\n                <Password>\n                    <Value>bgB1AHQAYQBuAGkAeAAvADQAdQBQAGEAcwBzAHcAbwByAGQA</Value>\n                    <PlainText>false</PlainText>\n                </Password>\n                <Enabled>true</Enabled>\n                <Username>Administrator</Username>\n            </AutoLogon>\n            <OOBE>\n                <HideEULAPage>true</HideEULAPage>\n                <HideLocalAccountScreen>true</HideLocalAccountScreen>\n                <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>\n                <NetworkLocation>Work</NetworkLocation>\n                <SkipMachineOOBE>true</SkipMachineOOBE>\n                <SkipUserOOBE>true</SkipUserOOBE>\n            </OOBE>\n            <UserAccounts>\n                <AdministratorPassword>\n                    <Value>bgB1AHQAYQBuAGkAeAAvADQAdQBBAGQAbQBpAG4AaQBzAHQAcgBhAHQAbwByAFAAYQBzAHMAdwBvAHIAZAA=</Value>\n                    <PlainText>false</PlainText>\n                </AdministratorPassword>\n            </UserAccounts>\n        </component>\n    </settings>\n    <settings pass="specialize">\n        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n            <ComputerName>RobClone-@@{calm_random}@@</ComputerName>\n            <RegisteredOwner>Nutanix</RegisteredOwner>\n        </component>\n        <component name="Microsoft-Windows-UnattendedJoin" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n            <Identification>\n                <Credentials>\n                    <Domain>tsapac.local</Domain>\n                    <Password>nutanix/4u</Password>\n                    <Username>administrator</Username>\n                </Credentials>\n                <JoinDomain>tsapac.local</JoinDomain>\n            </Identification>\n        </component>\n    </settings>\n    <cpi:offlineImage cpi:source="wim:f:/install.wim#Windows Server 2016 SERVERSTANDARD" xmlns:cpi="urn:schemas-microsoft-com:cpi" />\n</unattend>"""

for vm_name in ["win_2016_gold1","win_2016_gold1","win_2016_gold1"]:
  cluster_ip="@@{clone.cluster_ip}@@"
  base_url="https://"+cluster_ip+":9440"
  url=base_url + "/PrismGateway/services/rest/v1/vms?searchString="+vm_name
  he = {'content-type': 'application/json'}
  resp=urlreq(url, verb="GET", auth="BASIC", user="admin", passwd="@@{clone.cluster_password}@@", headers=he, verify=False)
  print type(resp.text)
  config=json.loads(resp.text)
  vm_uuid=config["entities"][0]["vmId"]
  print vm_uuid
  url2=base_url+"/api/nutanix/v0.8/snapshots"
  snap_payload= {"snapshotSpecs":[{"vmUuid":vm_uuid,"snapshotName":"test"}]}
  resp2=urlreq(url2, verb="POST", auth="BASIC", user="admin", passwd="@@{clone.cluster_password}@@", params=json.dumps(snap_payload),headers=he, verify=False)
  print resp2.text
  
  url3= base_url+ "/PrismGateway/services/rest/v2.0/vms/" + vm_uuid + "/clone"
  clone_payload={"spec_list":[{"name":vm_name+"-"+"@@{calm_now}@@"}],"vm_customization_config": {"userdata":userdata}}
  resp3=urlreq(url3, verb="POST", auth="BASIC", user="admin", passwd="@@{clone.cluster_password}@@", params=json.dumps(clone_payload),headers=he, verify=False)
  print resp3.text 
  task_uuid=json.loads(resp3.text)["task_uuid"]
  while True:
      response=urlreq(base_url+"/PrismGateway/services/rest/v2.0/tasks/"+task_uuid, verb="GET", auth="BASIC", user="admin", passwd="@@{clone.cluster_password}@@",headers=he, verify=False)
      task=json.loads(response.text)
      percentage = task['percentage_complete']
      status = task['progress_status']
      print "Task %s is currently at %s and in %s state" %(task_uuid, percentage, status)
      if percentage < 100 and status in ['Queued', 'Running']:
          sleep(30)
      elif status == "Succeeded":
          clone_vm_id=json.loads(response.text)["entity_list"][0]["entity_id"]
          break
      elif status == "Failed":
          print "Task %s has failed with following message" % (task_uuid, task["message"])
          result=False
          exit(1)
  
  print "Powering on the VM with id %s" % clone_vm_id
  poweron={"transition":"on"}
  url4=base_url+"/PrismGateway/services/rest/v2.0/vms/"+clone_vm_id+"/set_power_state"
  response=urlreq(url4,verb="POST", auth="BASIC", user="admin", passwd="@@{clone.cluster_password}@@",params=json.dumps(poweron),headers=he, verify=False)
  print response.text