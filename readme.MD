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