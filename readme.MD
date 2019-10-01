# Fortinet PBR Switcher Portal (pbrportal)

This project's purpose is to change the belonging group of the client IP accessing it to a group listed on the portal on a target FortiGate device. The workflow is the following:

1. User establishes a connection to the portal using a web browser
1. The portal polls the target FortiGate for a list of address group objects with the comment set to "pbrprofile". The portal lists those address groups for the user to click on.
1. The user clicks on the desired target group.
1. *pbrportal* detects the client source IP and deletes all group memberships associated with that IP address.
1. *pbrportal* adds the client source IP object to the clicked profile (the matching address group)

*pbrportal* also listens for REST calls made from the FortiGate device, which can be issued by the automation framework in FortiOS 6.2.2 and above, in order to receive messages when a user initiates a connection of any kind. This API's purpose is to "reset" the source IP by removing all existing group memberships for the address object in question.

The following is a sample "config system automation-action" that can be used to call this specific API. In this example, we are resetting an IP when a user connects to the FortiGate via SSL VPN:

```
config system automation-trigger
    edit "newtun"
        set event-type event-log
        set logid 39947
    next
    edit "asdasd"
    next
end
config system automation-action
    edit "apinewconnect"
        set action-type webhook
        set method put
        set uri "192.168.10.5/newtun/%%log.tunnelip%%"
        set port 4000
    next
end
```

## How to install

This is not currently OS-packaged, and thus the current process for Linux based platforms (tested on Debian):
1. Install Golang (see online docs on doing this for your platform)
1. mkdir /opt/
1. git clone https://github.com/mnantel/pbrportal
1. cd pbrportal
1. cp config.example.json config.json (modify as needed)
1. go get -d ./... (download all necessary dependancies)
1. go build .
1. cp pbrportal.service /etc/systemd/system/
1. systemctl daemon-reload
1. systemctl enable pbrportal.service
1. systemctl start pbrportal.service

Verify that the service is operating:
1. systemctl status pbrportal.service

Review the logs for the service if it is not starting:
1. journalctl -u pbrportal.service
Logs from this command will also show ongoing activity for PBRPortal.

If you need to upgrade:
1. cd /opt/pbrportal
1. git pull
1. systemctl restart pbrportal.service

## How to configure

You will need an api-admin user account on the target FortiOS device, which you can enable by creating the user under 'config system api-user' and then running command 'exec api-user generate MYUSER' to generate the apikey. Ensure that this account has trusted-host set to point only to the PBRPortal IP address.

The config.json is split in backend/frontend config options, for security reasons: backend config is not transmitted to the client-side SPA JS, to ensure only the backend has access to the device APIkey.

Frontend config allows changing the logo image file, header text and descriptive text, along with whether to show the VPN user info.

The logo image file must reside in the /web subfolder. Since the frontend is responsive, no need to resize.
