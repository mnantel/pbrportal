<template>
    <div class="container">
        <div class="row">
            <div class="col-sm">
                &nbsp;
            </div>
        </div>
        <div class="row">
            <div class="col-sm">
                 <img v-bind:src="logofile" class="img-fluid"> 
            </div>
            <div class="col-lg">
            </div>
            <div class="col-sm">
             
                <table v-if="showuserinfo" class="table table-sm table-bordered">
                <tr class="table-info"><td colspan="2">User Information</td></tr>
                <tr class="userinfo"><td><strong>Username: </strong></td><td class="text-right ">{{this.username}}</td></tr>
                <tr class="userinfo"><td><strong>Remote IP: </strong></td><td class="text-right">{{this.remoteip}}</td></tr>
                <tr class="userinfo"><td><strong>Tunnel IP: </strong></td><td class="text-right">{{this.tunnelip}}</td></tr>
                <tr class="userinfo"><td><strong>Login Time:</strong> </td><td class="text-right">{{this.logintime}}</td></tr>
                </table>

            </div>
        </div>
        <div class="row">
            <div class="col-sm">
                &nbsp;
            </div>
        </div>
        <div class="row">
            <div class="col-sm">
                <h3>{{headertitle}}</h3>
                <p>{{headertext}}</p>
            </div>
        </div>
        <div class="row">
            <div class="col-sm">
                <div class="list-group">
                    <a 
                    v-for="grp in grplist" 
                    v-bind:key="grp.name" 
                    v-on:click="selectProfile(grp.name)" 
                    v-bind:class="{ 'list-group-item-danger': grp.active }"
                    href="#" class="list-group-item list-group-item-action">
                        {{grp.name}}
                    </a>
                </div>
            </div>
        </div>
    </div>
</template>
<script>
module.exports = {
    data: function() {
        return {
            title: 'title',
            grplist: [],
            username: '',
            remoteip: '',
            tunnelip: '',
            logintime: '',
        }
    },
    $_veeValidate: {
        validator: "new"
    },
    async mounted () {
        await this.dataGet()
    },
    computed: {
        apitarget: function () { 
            return window.CONFIG['hostname'] + ":" + window.CONFIG['port']; 
        },
        headertext: function () { 
            return window.CONFIG['headertext']
        },
        headertitle: function () { 
            return window.CONFIG['headertitle']
        },
        logofile: function () { 
            return window.CONFIG['logofile']
        },
        showuserinfo: function () { 
            return window.CONFIG['showuserinfo']
        },
    },
    methods: {
        dataGet: async function(){
            try {
                this.grplist = []
                const response = await axios.get('http://'+this.apitarget+'/api/v2/cmdb/firewall/addrgrp/')
                
                for (grp of response.data){
                    this.grplist.push({name: grp.name, active: grp.active})
                }
                
            } catch (e) { console.log(e) }
            try{
                const response = await axios.get('http://'+this.apitarget+'/getuserinfo/')
                this.username = response.data.user_name
                this.remoteip = response.data.remote_host
                this.tunnelip = response.data.subsessions[0].aip
                this.logintime = response.data.last_login_time
            } catch (e) { console.log(e) }

        },
        selectProfile: async function(targetgrp){
            try {
                const response = await axios.post('http://'+this.apitarget+'/selectProfile/'+targetgrp)
                await this.dataGet()

            } catch (e) { console.log(e) }
        }
    }
}
</script>
<style>
.userinfo{
    font-size:0.6rem;
}


</style>