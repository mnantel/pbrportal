package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/julienschmidt/httprouter"
)

type Backendconfig struct {
	Firewallip string `json:"firewallip"`
	Apikey     string `json:"apikey"`
}

type Frontendconfig struct {
	Hostname     string `json:"hostname"`
	Port         string `json:"port"`
	Headertext   string `json:"headertext"`
	Logofile     string `json:"logofile"`
	Showuserinfo bool   `json:"showuserinfo"`
	Headertitle  string `json:"headertitle"`
}

type Config struct {
	BE Backendconfig  `json:"backend"`
	FE Frontendconfig `json:"frontend"`
}

type FOSAddrgrpResponse struct {
	FOSResponse
	Results []FOSAddrgrp `json:"results"`
}
type FOSAddrgrp struct {
	QOriginKey string `json:"q_origin_key"`
	Name       string `json:"name"`
	UUID       string `json:"uuid"`
	Member     []struct {
		QOriginKey string `json:"q_origin_key"`
		Name       string `json:"name"`
	} `json:"member"`
	Comment       string        `json:"comment"`
	Exclude       string        `json:"exclude"`
	ExcludeMember []interface{} `json:"exclude-member"`
	Visibility    string        `json:"visibility"`
	Color         int           `json:"color"`
	Tagging       []interface{} `json:"tagging"`
	AllowRouting  string        `json:"allow-routing"`
}

type FOSPBRResponse struct {
	FOSResponse
	Results []FOSPBR `json:"results"`
}

type FOSPBR struct {
	InputDevice []struct {
		Name string `json:"name"`
	} `json:"input-device"`
	Srcaddr []struct {
		Name string `json:"name"`
	} `json:"srcaddr"`
	OutputDevice string `json:"output-device"`
}

type FOSPolicyResponse struct {
	FOSResponse
	Results []FOSPolicy `json:"results"`
}
type FOSPolicy struct {
	Srcintf []struct {
		Name string `json:"name"`
	} `json:"srcintf"`
	Dstintf []struct {
		Name string `json:"name"`
	} `json:"dstintf"`
	Action string `json:"action"`
	Groups []struct {
		Name string `json:"name"`
	} `json:"groups"`
}

type FOSFirewallUserResponse struct {
	FOSResponse
	Results []FOSFirewallUser `json:"results"`
}

type FOSFirewallUser struct {
	Type      string `json:"type"`
	Username  string `json:"username"`
	Server    string `json:"server"`
	Usergroup []struct {
		Type string `json:"type"`
		Name string `json:"name"`
	} `json:"usergroup"`
	ID           int    `json:"id"`
	Duration     string `json:"duration"`
	DurationSecs int    `json:"duration_secs"`
	AuthType     int    `json:"auth_type"`
	Ipaddr       string `json:"ipaddr"`
	SrcType      string `json:"src_type"`
	Expiry       string `json:"expiry"`
	ExpirySecs   int    `json:"expiry_secs"`
	Method       string `json:"method"`
}

type FOSVPNSSLUserResponse struct {
	FOSResponse
	Results []FOSVPNSSLUser `json:"results"`
}

type FOSVPNSSLUser struct {
	Index              int              `json:"index"`
	UserName           string           `json:"user_name"`
	RemoteHost         string           `json:"remote_host"`
	LastLoginTime      string           `json:"last_login_time"`
	LastLoginTimestamp int              `json:"last_login_timestamp"`
	Subsessions        []SSLSubsessions `json:"subsessions"`
	SubsessionType     string           `json:"subsession_type"`
	SubsessionDesc     string           `json:"subsession_desc"`
}

type SSLSubsessions struct {
	Index       int    `json:"index"`
	ParentIndex int    `json:"parent_index"`
	Mode        string `json:"mode"`
	Type        string `json:"type"`
	Aip         string `json:"aip"`
	InBytes     int    `json:"in_bytes"`
	OutBytes    int    `json:"out_bytes"`
	Desthost    string `json:"desthost"`
}

type FOSResponse struct {
	HTTPMethod string `json:"http_method"`
	Revision   string `json:"revision"`
	Vdom       string `json:"vdom"`
	Path       string `json:"path"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	HTTPStatus int    `json:"http_status"`
	Serial     string `json:"serial"`
	Version    string `json:"version"`
	Build      int    `json:"build"`
}

type AllowedGroup struct {
	Name   string `json:"name"`
	Active bool   `json:"active"`
}

var conf Config

func main() {

	// fs := http.FileServer(http.Dir("./web"))
	log.Println("PBRPortal: Loading config.json")
	jsonFile, err := os.Open("config.json")
	if err != nil {
		panic(err)
	}
	defer jsonFile.Close()
	jsonBytes, _ := ioutil.ReadAll(jsonFile)
	err = json.Unmarshal(jsonBytes, &conf)
	if err != nil {
		panic(err)
	}

	router := httprouter.New()

	router.GET("/api/v2/cmdb/firewall/addrgrp/", apiGetAddressGroups)
	router.POST("/selectProfile/:grp", apiSelectProfile)
	router.PUT("/newtun/:tunip", newTunnel)
	router.GET("/getuserinfo", apiGetUserInfo)
	router.GET("/config.json", apiGetConfigJS)
	router.NotFound = http.FileServer(http.Dir("./web"))
	log.Printf("PBRPortal: Starting server, hostname: %s port:%s\r\n", conf.FE.Hostname, conf.FE.Port)

	log.Fatal(http.ListenAndServe(":"+conf.FE.Port, router))

}

/////////////////////////////////
// API-facing functions follow //
/////////////////////////////////

// Deliver parsed config to frontend as config.json
func apiGetConfigJS(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	marshalConf, err := json.Marshal(conf.FE)
	if err != nil {
		panic(err)
	}
	jsconf := fmt.Sprintf(`
	window.CONFIG = %s

	`, marshalConf)
	w.Header().Add("Content-Type", "application/json")
	fmt.Fprint(w, bytes.NewBuffer([]byte(jsconf)))

}

// Call from FortiOS to designate a new connection, for which we scrub the IP from anything it currently exists as.
// Automation-action on FOS should call url in the form of /newtun/%%log.tunnelip%%
func newTunnel(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	tunip := ps.ByName("tunip")
	log.Println("--> FOS NEW TUNNEL:", tunip)

	// Delete address
	deleteAddress(tunip)

}

func apiGetUserInfo(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	clientip := strings.Split(r.RemoteAddr, ":")[0]
	var sslclients FOSVPNSSLUserResponse
	fosGetToStruct("/api/v2/monitor/vpn/ssl/select/", &sslclients)

	for _, user := range sslclients.Results {
		if len(user.Subsessions) > 0 {
			if user.Subsessions[0].Aip == clientip {

				founduser, err := json.Marshal(user)
				if err != nil {
					return
				}
				fmt.Fprint(w, string(founduser))
				return
			}
		}
	}
	baduser := FOSVPNSSLUser{
		UserName: "notfound",
		Subsessions: []SSLSubsessions{
			SSLSubsessions{Aip: "255.255.255.255"},
		},
		RemoteHost:    "254.254.254.254",
		LastLoginTime: "Mon Sep 1 00:00:00 1534",
	}
	founduser, _ := json.Marshal(baduser)
	fmt.Fprint(w, string(founduser))

}

func apiGetAddressGroups(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	clientip := strings.Split(r.RemoteAddr, ":")[0]
	log.Println("--> API GET ALLOWED GROUPS:", clientip)

	fwusers := getFirewallUser()
	fwpolicy := getFirewallPolicy()
	addrgrpres := getAddressGroups()
	pbr := getPBR()
	found := false
	var currentuser FOSFirewallUser
	for _, u := range fwusers {
		if u.Ipaddr == clientip {
			currentuser = u
			found = true
		}
	}
	if found == false {
		log.Println("USER NOT FOUND!")
		return
	}
	log.Println("USER FOUND: ", currentuser.Username, " GROUPS: ", currentuser.Usergroup)

	var currentallowedintf []string
	for _, group := range currentuser.Usergroup {
		for _, policy := range fwpolicy {
			for _, polgroup := range policy.Groups {
				if group.Name == polgroup.Name && policy.Action == "accept" {
					for _, dstintf := range policy.Dstintf {
						currentallowedintf = append(currentallowedintf, dstintf.Name)

					}
				}
			}
		}
	}
	currentallowedintf = strRemoveDups(currentallowedintf)
	log.Println("ALLOWED INTERFACES: ", currentallowedintf)
	var currentallowedgroups []string
	var grpDupCheck map[string]bool
	for _, pbrrule := range pbr {
		for _, intf := range currentallowedintf {
			if intf == pbrrule.OutputDevice {
				for _, srcaddr := range pbrrule.Srcaddr {
					if _, ok := grpDupCheck["foo"]; ok == false {
						currentallowedgroups = append(currentallowedgroups, srcaddr.Name)
						grpDupCheck[srcaddr.Name] = true
					}

				}

			}
		}
	}
	log.Println("ALLOWED GROUPS: ", currentallowedgroups)

	var activegroup string
	for _, group := range addrgrpres.Results {
		for _, member := range group.Member {
			if member.Name == clientip {
				activegroup = group.Name

			}
		}
	}
	log.Println("ACTIVE GROUP FOR USER IP: ", activegroup)

	var output []AllowedGroup
	for _, e := range currentallowedgroups {
		if e == activegroup {
			newgroup := AllowedGroup{
				Name:   e,
				Active: true,
			}
			output = append(output, newgroup)
		} else {
			newgroup := AllowedGroup{
				Name:   e,
				Active: false,
			}
			output = append(output, newgroup)
		}

	}
	jsonout, _ := json.Marshal(output)

	fmt.Fprint(w, string(jsonout))

}

func apiSelectProfile(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	clientip := strings.Split(r.RemoteAddr, ":")[0]
	group := ps.ByName("grp")

	w.WriteHeader(http.StatusOK)
	log.Println("--> ASSIGN ADDRESS:", clientip, " TO GROUP: ", group)

	// Delete address
	deleteAddress(clientip)
	// Create address
	createAddress(clientip)
	// Add address to groups
	groupAddMember(group, clientip)

}

/////////////////////////////////
// Supporting functions follow //
/////////////////////////////////
func getPBR() []FOSPBR {
	log.Print("<-- GET ROUTER POLICY ")
	var fosresp FOSPBRResponse
	fosGetToStruct("/api/v2/cmdb/router/policy", &fosresp)
	return fosresp.Results
}

func getFirewallUser() []FOSFirewallUser {
	log.Print("<-- GET FIREWALL USERS ")
	var fosresp FOSFirewallUserResponse
	fosGetToStruct("/api/v2/monitor/user/firewall/select/", &fosresp)
	return fosresp.Results
}

func getFirewallPolicy() []FOSPolicy {
	log.Print("<-- GET FIREWALL POLICIES ")
	var fosresp FOSPolicyResponse
	fosGetToStruct("/api/v2/cmdb/firewall/policy/", &fosresp)
	return fosresp.Results
}

func createAddress(address string) {

	log.Print("<-- CREATE ADDRESS: ", address)
	obj := "{\"name\": \"" + address + "\",\"subnet\": \"" + address + " 255.255.255.255\",\"type\": \"ipmask\"}"
	log.Println("Object: ", obj)
	res, err := fosClient("POST", "/api/v2/cmdb/firewall/address/", []byte(obj), nil)
	if err != nil {
		return
	}
	log.Print(" [" + res.Status + "]\r")
}

func deleteAddress(address string) {

	groups := getAddressGroups()
	for _, v := range groups.Results {
		if v.Comment == "pbrprofile" {
			addrgrpRemoveMember(v.Name, address)
		}
	}

	log.Print("<-- DELETE ADDRESS: ", address)
	res, err := fosClient("DELETE", "/api/v2/cmdb/firewall/address/"+address, nil, nil)
	if err != nil {
		log.Println(err)
	}
	log.Print(" [" + res.Status + "]\r")
}

func groupAddMember(group string, address string) {

	log.Print("<-- ADD MEMBER: ", address, " TO GROUP: ", group)
	obj := "{\"name\": \"" + address + "\"}"

	res, err := fosClient("POST", "/api/v2/cmdb/firewall/addrgrp/"+group+"/member", []byte(obj), nil)
	if err != nil {
		log.Println(err)
	}
	log.Print(" [" + res.Status + "]\r")
}

func getAddressGroup(group string) FOSAddrgrpResponse {

	log.Println("<-- GET ADDRESS GROUP: ", group)
	var addrgrp FOSAddrgrpResponse
	fosGetToStruct("/api/v2/cmdb/firewall/addrgrp/"+group, &addrgrp)
	return addrgrp
}

func getAddressGroups() FOSAddrgrpResponse {

	log.Println("<-- GET ALL ADDRESS GROUP")
	var addrgrp FOSAddrgrpResponse
	fosGetToStruct("/api/v2/cmdb/firewall/addrgrp/", &addrgrp)
	return addrgrp
}

func addrgrpRemoveMember(group string, address string) {

	log.Print("<-- REMOVE MEMBER: ", address, " FROM GROUP: ", group)
	res, err := fosClient("DELETE", "/api/v2/cmdb/firewall/addrgrp/"+group+"/member?filter=name=="+address, nil, nil)
	if err != nil {
		return
	}
	log.Print(" [" + res.Status + "]\r")
}

func fosGetToStruct(uri string, obj interface{}) {

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{}
	req, _ := http.NewRequest("GET", "https://"+conf.BE.Firewallip+uri, nil)
	req.Header.Set("Authorization", "Bearer "+conf.BE.Apikey)
	res, err := client.Do(req)
	if err != nil {
		log.Println(err)
	}
	resbody, err := ioutil.ReadAll(res.Body)
	json.Unmarshal(resbody, &obj)

}

func fosClient(method string, path string, data []byte, param []byte) (FOSResponse, error) {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{}
	req, _ := http.NewRequest(method, "https://"+conf.BE.Firewallip+path, bytes.NewBuffer(data))
	req.Header.Set("Authorization", "Bearer "+conf.BE.Apikey)
	res, err := client.Do(req)
	if err != nil {
		return FOSResponse{}, err
	}
	resbody, _ := ioutil.ReadAll(res.Body)
	var response FOSResponse
	_ = json.Unmarshal(resbody, &response)
	return response, nil
}

func strRemoveDups(a []string) []string {
	seen := map[string]bool{}
	for _, v := range a {
		seen[v] = true
	}
	var b []string
	for k := range seen {
		b = append(b, k)
	}
	return b
}
