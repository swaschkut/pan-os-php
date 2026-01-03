## Migration process

### General approach
By using PAN-OS-PHP during the complete migration process there is always the full Panorama XML config and Fawkes XML config available in memory.
All manipulations during the migration happen in memory and store at the end in Fawkes config file

Additional migration log text is send to 'stdOut' - in JSON format:
{
    "error": "ONLY AVAILABLE, if migration stopped to display the reason",
    "log": "MIGRATION LOG information"
}

** NOTE: in this markdown file additional Xpatch must be mentioned for the specific migration task**

### NOT supported panorama config settings:
- DLP in Plugin => more information needed to implemeny migration
- IoT -> device-objcts
- multi-tenant

### possible arguments to run script:
- in=
  - 'in=panorama.xml' - assume Panorama XML config file
- out=
  - 'out=MIGRATED_file.xml' the file/filepath where the final file is stored 
- fawkes=
  - 'fawkes=fawkes.xml' it assumes Fawkes XML config file - best is to use the default available empty [Fawkes config file](fawkes_baseconfig.xml)
- 'optimise'
- 'testing'
  - single argument - only using in unit testing mode
- 'debugapi'
- 'help'
- 'shadow-json'
  - to change from human readable stdout to JSON syntax stdout


### Fawkes base config
- per default Fawkes base config version 3 is used
- available default settings:
   - Container:
     - All
     - Prisma Access
     - Mobile Users Container
   - Device Cloud:
     - Mobile Users
     - Mobile Users Explicit Proxy
        - predefined EDLs: 
           - PA-SWG-bulletproof-ip-list
           - PA-SWG-highrisk-ip-list
           - PA-SWG-known-ip-list
        - predefined SecurityPolicy:
           - "BlockBadIPs"
     - Remote Networks
     - Service Connections

### Plug-in - 
1. "/config/devices/entry/plugins"
2. check if XML node "dlp" is available
   1. if available and Fawkes feature is not supported => error out, stop migration 
3. search for XML node "cloud_services"
   1. if not available => error out, stop migration
   1. if XML node "multi-tenant-enable" is set to 'yes' and Fawkes does not support this feature => error out, stop migration
   1. if XML node "multi-tenant-enable" is set to 'no'; remove XML node "multi-tenant" and continue

4. create plugin enable section
   - mobile-users-explicit-proxy -> set to yes, if 'mobile-users-explicit-proxy' and 'users' XML node is found in Panorama Plugin
   - mobile-users-global-protect -> set to yes, if 'mobile-users' is found in Panorama Plugin
5. move XML node "dir-sync" from plugin section into the correct Panorama template
6. remove XML node "bgp" from plugin 'onboarding'->'entry'->'protocol' section if BGP is not enabled 
7. get template setting for 'service-connection', 'mobile-users', 'remote-networks' from plug-in
8. get DG and DG hierarchy from Panorama
9. get Trusted Zones for 'mobile-users', 'remote-networks' from plug-in
10. remove template section from Panorama plug-in setting
11. import Panorama plug-in cloud_services into Fawkes plug-in XML section




### Panorama DeviceGroup(s)
1. delete all DGs which are not relevant for this Fawkes migration


### Panorama Template(s)
1. preparation
   1. check if relevant Container or DeviceCloud is available
 
3. NOT COMPLETE migration process mentioned here
4. template Mobile Users -> Device Cloud "Mobile Users"
    1. 'entry/network/tunnel/global-protect-gateway'
    1. 'entry/vsys/entry/global-protect'
    1. 'authentication-profile'
    1. move "authentication-profile", "certificate", "certificate-profile", "ssl-tls-service-profile", "server-profile" from 'template/config/shared' to 'template/config/entry [@name='localhost.localdomain']'
5. template SN
    1. 'profiles/monitor-profile'
    1. move "authentication-profile", "certificate", "certificate-profile", "ssl-tls-service-profile", "server-profile" from 'template/config/shared' to 'template/config/entry [@name='localhost.localdomain']'
6. template RN
    1. 'profiles/monitor-profile'
    1. move "authentication-profile", "certificate", "certificate-profile", "ssl-tls-service-profile", "server-profile" from 'template/config/shared' to 'template/config/entry [@name='localhost.localdomain']'
7. template shared section is migrated to each Container/DeviceCloud 'vsys', but 'certificate','scep' and 'ocsp-responder' are always migrated to Container/DeviceCloud shared
8. move from every template 'template/config/devices' to Fawkes 'Container/DeviceCloud->devices'
           

### DGs migration


1. use SecurityProfileGroup instead of SecurityProfil
    1. create SecurityProfileGroup base on defined SecurityProfiles in Security Rules
    2. use defined SecurityProfiles as members
    3. migrate all used SecurityProfiles

2. migrate all not used SecurityProfiles

3. if argument 'optimise' is used
    1. delete unused address/addressgroup objects
    2. delete unused service/servicegroup objects
    3. delete unused tag objects
    4. replace IP-addresses used in Rules SRC/DST and create valid address-objects
    5. move address/service/tag to Panorama sharedDG
    6. add address/addressgroup objects from Panorama sharedDG to Fawkes Prisma Access Container
    7. add service/servicegroup objects from Panorama sharedDG to Fawkes Prisma Access Container
    8. add tag objects from Panorama sharedDG to Fawkes Prisma Access Container
    
4. migrate from each relevant DG and also from shared to specific Container/DeviceCloud
    - 'tag'
    - 'address'
    - 'address-group'
    - 'service'
    - 'service-group'
    - 'application'
    - 'application-filter'
    - 'application-group'
    - 'schedule'
    - 'region'
    - 'external-list'
       - validation check for 'entry'->'type': 'imsi' and 'imei' not supported => migration stop with error
    
    - 'dynamic-user-group'
    - 'authentication-object'
    - 'threats' -> custom settings
    - 'device-object' => IoT related, if found and IoT feature flag is set to false -> error out

5. migrate SecurityProfiles
    - custom-url-category
    - decyrption
    - hip-objects
    - hip-profiles
    - file-blocking
    - vulnerability
    - url-filtering -> split into url-filtering/saas-security
    - spyware -> split into spyware/dns-security
    - wildfire-analysis -> combined into virus-and-wildfire-analysis
      - add virus best-practice if no virus SecurityProfile is used at same time in SecurityProfileGroup
    - virus -> combined into virus-and-wildfire-analysis

6. migrate SecurityProfileGroups
    - migrate member SecurityProfile
    - take care for specifics
        - 'virus' and 'wildfire-analyses' is now 'virus-and-wildfire-analysis' in Fawkes
        - 'spyware' is split => 'botnet-domain' is now part of new 'dns-security' SecurityProfile
        - 'url-filtering' split => 'http-header-insertion' is now part of new 'saas-security' SecurityProfile 
    - default => migrate to best-practice
    - strict => migrate to best-practice-strict

7. move rules from DG Prisma Access 'security', --'decryption', 'qos', 'appoverride'-- to DG shared

8. Remote Network - rule migration
    1. 'security', 'decryption', 'qos', 'appOverride', 'authentication'

9. Service Connections - rule migration
    1. 'qos'

10. Mobile users - rule migration
    1. 'security', 'decryption', 'appOverride', 'authentication'

11. shared - rule migration => into Prisma Access Container
    1. 'security', 'decryption', 'qos', 'appOverride', 'authentication'

12. rule manipulation
    1. security
        1. trust / untrust Zone manipulation for MU / RN
        1. Log Forwarding => 'Cortex Data Lake'

### Final step
1. save Fawkes config to file which is define in argument 'out=XYZ.xml'
2. save migrated object counters to file '.json'
        

### Migration Feature check
file from "/opt/features-list/features-list.json" is read:
syntax can be find in [file:](tests/migrationCheck.json)

threat-exception:
- migrate securityprofile as is
- create for each container threat-exception/secprof-type/entry(name=ID)