import json
F={}
def put(kind,scope,name,data,pos=None):
    F[f"{kind}|{scope}|{name}|{pos or ''}"]=data
setup={
 "folders":[
  {"id":"f-all","name":"All","parent":"","type":"container"},
  {"id":"f-ngfw","name":"ngfw-shared","parent":"All","type":"container"},
  {"id":"f-br","name":"Branches","parent":"ngfw-shared","type":"container","snippets":["branch-snippet"]},
  {"id":"d-1","name":"012345678901","parent":"Branches","type":"on-prem"},
 ],
 "snippets":[
  {"id":"s-br","name":"branch-snippet","type":"custom"},
 ]}
# ngfw-shared
put("addresses","folder","ngfw-shared",[{"id":"a-1","name":"web-srv","folder":"ngfw-shared","ip_netmask":"10.1.1.10/32","description":"web server"},{"id":"a-2","name":"unused-addr","folder":"ngfw-shared","ip_netmask":"10.9.9.9/32"}])
put("zones","folder","ngfw-shared",[
 {"id":"z-1","name":"trust","folder":"ngfw-shared","network":{"layer3":["$trust-if"]},"enable_user_identification":True},
 {"id":"z-2","name":"untrust","folder":"ngfw-shared","network":{"layer3":["$untrust-if"],"zone_protection_profile":"zpp-existing"}}])
put("zone-protection-profiles","folder","ngfw-shared",[
 {"id":"zp-1","name":"zpp-existing","folder":"ngfw-shared",
  "scan":[{"name":"8001","action":{"block":{}},"interval":2,"threshold":100},
          {"name":"8002","action":{"block-ip":{"track_by":"source","duration":300}},"interval":10,"threshold":100}],
  "flood":{"tcp_syn":{"enable":True,"red":{"alarm_rate":10000,"activate_rate":10000,"maximal_rate":40000}}}}])
put("profile-groups","folder","ngfw-shared",[
 {"id":"pg-1","name":"best-practice","folder":"ngfw-shared","spyware":["strict-as"],"vulnerability":["strict-vp"]}])
put("anti-spyware-profiles","folder","ngfw-shared",[
 {"id":"as-1","name":"strict-as","folder":"ngfw-shared","description":"strict",
  "rules":[{"name":"crit","severity":["critical","high"],"category":"any","threat_name":"any","packet_capture":"disable","action":{"reset_both":{}}}],
  "cloud_inline_analysis":False}])
put("vulnerability-protection-profiles","folder","ngfw-shared",[
 {"id":"vp-1","name":"strict-vp","folder":"ngfw-shared",
  "rules":[{"name":"crit","severity":["critical","high"],"category":"any","threat_name":"any","host":"any","cve":["any"],"vendor_id":["any"],"packet_capture":"disable","action":{"reset_both":{}}}]}])
put("security-rules","folder","ngfw-shared",[
 {"id":"r-1","name":"allow-web","folder":"ngfw-shared","position":"pre","action":"allow","from":["trust"],"to":["untrust"],
  "source":["any"],"destination":["web-srv"],"source_user":["any"],"category":["any"],"application":["web-browsing"],
  "service":["application-default"],"log_end":True,"log_start":False,"disabled":False,"tag":[]},
 {"id":"r-2","name":"deny-all","folder":"ngfw-shared","position":"pre","action":"deny","from":["any"],"to":["any"],
  "source":["any"],"destination":["any"],"source_user":["any"],"category":["any"],"application":["any"],
  "service":["any"],"log_end":True,"disabled":False},
 {"id":"r-3","name":"allow-bp","folder":"ngfw-shared","position":"pre","action":"allow","from":["trust"],"to":["untrust"],
  "source":["any"],"destination":["any"],"source_user":["any"],"category":["any"],"application":["ssl"],
  "service":["application-default"],"log_setting":"lfp-existing","log_end":True,"disabled":False,
  "profile_setting":{"group":["best-practice"]}}],pos="pre")
put("log-forwarding-profiles","folder","ngfw-shared",[
 {"id":"lf-1","name":"lfp-existing","folder":"ngfw-shared","match_list":[{"name":"traffic","log_type":"traffic","filter":"All Logs","send_http":[],"send_syslog":[]}]}])
# Branches
put("security-rules","folder","Branches",[
 {"id":"r-10","name":"branch-allow","folder":"Branches","position":"pre","action":"allow","from":["trust"],"to":["untrust"],
  "source":["any"],"destination":["any"],"source_user":["any"],"category":["any"],"application":["dns"],
  "service":["application-default"],"log_end":False,"disabled":False}],pos="pre")
# snippet
put("addresses","snippet","branch-snippet",[{"id":"a-20","name":"snip-addr","snippet":"branch-snippet","ip_netmask":"192.168.20.0/24"}])
put("security-rules","snippet","branch-snippet",[
 {"id":"r-20","name":"snip-allow","snippet":"branch-snippet","position":"pre","action":"allow","from":["trust"],"to":["untrust"],
  "source":["snip-addr"],"destination":["any"],"source_user":["any"],"category":["any"],"application":["ntp"],
  "service":["application-default"],"log_end":True,"disabled":False}],pos="pre")
setup["snippets"].insert(0,{"id":"s-pre","name":"predefined-snippet","type":"predefined"})
json.dump({"setup":setup,"res":F},open("scm-fixtures.json","w"),indent=1)
print(len(F),"resource fixtures")
