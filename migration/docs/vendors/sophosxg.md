###SophosXG

To Export the available Sophos XG Firewall configuration,
please enable API as mentioned there:
https://docs.sophos.com/nsg/sophos-firewall/19.5/Help/en-us/webhelp/onlinehelp/AdministratorHelp/BackupAndFirmware/API/index.html

Also for Sophos XG there is an export script available:
export script is available in ../SOPHOSXG/sophosxg_config_export.sh


You need to manipulate variables and bring in your own MGMT-IP, User and Password

- username="USER from SOPHOS XG"
- password="Password from SOPHOS XG"
- fqdn="SOPHOS IP / FQDN"

Please run the bash script to export all needed objects into a tmp folder.
- sh sophosxg_config_export.sh


Finally run the migration script

- pan-os-php type=vendor-migration vendor=sophosxg directory=TMP_path out=sophosXG.xml