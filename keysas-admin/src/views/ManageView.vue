<template>
  <NavBar />
  <h1>Manage your registered Keysas stations</h1>
  <div class="box">
    <h5 class="text-dark">Check the status, update and manage your Keysas stations here.</h5>
    <ul class="list-group">
      <li class="list-group-item transparent" v-for="device in stations">
          <button class="btn btn-dark btn-lg shadow" @click="hide = !hide; ShowActionButtons = true;
          flush();
          this.current_keysas = device.name;
          this.current_ip = device.ip;
          getKeysasIP(device.name);
          this.current_keysas = device.name">
          {{ device.name }}
        </button>
        <i class="bi bi-arrow-right">
        </i>
          <!--<div class="btn-group" role="group">-->
          <button class="btn btn-primary btn-lg shadow" @click="flush();
          hide = false;
          ShowActionButtons = false;
          this.current_keysas = device.name;
          reboot_status = undefined;
          ShowRebootKeysas = true;
          rebootKeysas(device.name)">
            <span class="bi bi-arrow-counterclockwise">Reboot</span>
          </button>
          <button class="btn btn-primary btn-lg shadow" @click="flush();
          hide = false;
          ShowActionButtons = false;
          this.current_keysas = device.name;
          shutdown_status = undefined;
          ShowShutdownKeysas = true;
          shutdownKeysas(device.name)">
            <span class="bi bi-arrow-down-circle-fill"> Shutdown</span>
          </button>
          <button class="btn btn-primary btn-lg shadow" @click="flush();
          hide = false;
          ShowActionButtons = false;
          this.current_keysas = device.name;
          export_ssh_status = undefined;
          ShowExportSSH = true;
          AddSSHPubKey(device.name)">
            <span class="bi bi-send"> Export SSH pubkey</span>
          </button>
          <button class="btn btn-danger btn-lg shadow" @click="removeKeysas(device.name);
          flush();
          hide = true">
            <span class="bi bi-exclamation-circle"> Delete</span>
          </button>
          <button class="btn btn-outline-secondary btn-lg shadow" @click="hide = !hide; ShowActionButtons = true;
          flush();
          this.current_keysas = device.name;
          this.current_ip = device.ip;
          getKeysasIP(device.name);
          this.current_keysas = device.name">
            <span class="bi bi-arrows-expand"> More...</span>
          </button>
      </li>
    </ul>
  </div>
  <div v-if="!hide" class="box animate__animated animate__pulse">
    <ul class="box-small-left">
      <li class="list-group-item list-group-item-action list-group-item-light">
        <h4><b>Name:</b> {{ current_keysas }}</h4>
      </li>
      <li class="list-group-item list-group-item-action list-group-item-light">
        <h4><b>IP:</b> {{ current_ip }}</h4>
      </li>
      <li class="list-group-item list-group-item-action list-group-item-light" v-if="KeysasAlive === true">
        <h4><b>Status: </b> 
          <span class="bi bi-check-square text-success"> Online</span>
        </h4>
      </li>
      <li class="list-group-item list-group-item-action list-group-item-light" v-if="KeysasAlive === false">
        <h4><b>Status: </b>
        <span class="bi bi-x-square text-danger"> Offline</span>
        </h4>
      </li>
      <li class="list-group-item list-group-item-action list-group-item-light"
        v-if="KeysasAlive != false && KeysasAlive != true">
        <h4><b>Status: </b> 
        <span class="bi bi-x-square text-dark"> Unknown</span>
        </h4>
      </li>
    </ul>
    <div v-if="ShowActionButtons">

      <ul class="list-group">
        <li class="list-group-item transparent">
          <div aria-label="Basic outlined example">
            <button class="send btn btn-lg btn-primary shadow" @click="flush();
            ShowPasswordInit = !ShowPasswordInit">
              <span class="bi bi-magic"> Enroll</span>
            </button>
            <button class="send btn btn-lg btn-primary shadow" @click="flush();
            ShowAddYubikey = !ShowAddYubikey">
              <span class="bi bi-cart-check"> Add a Yubikey</span>
            </button>
            <button class="send btn btn-lg btn-primary shadow" @click="flush();
            ShowRevYubikey = !ShowRevYubikey">
              <span class="bi bi-x-square"> Revoke a Yubikey</span>
            </button>
            <button class="send btn btn-lg btn-primary shadow" @click="flush();
            ShowUpdateKeysas = !ShowUpdateKeysas;
            update_status = undefined;
            updateKeysas(current_keysas)">
              <span class="bi bi-tools"> Update this Keysas</span>
            </button>
          </div>
        </li>
      </ul>
    </div>
    <div v-if="ShowPasswordInit" class="add-form">
      <div class="container">
        <div class="row">
          <div class="col-sm">
            <div class="tip">
              <h4 class="text-info"><i class="bi bi-moon-stars-fill"> HELP</i></h4>
              <span class="tip-text">Type your <b>IKPQPKI</b> password to enroll this <b>Keysas</b> station.
              </span>
              <br><br>
              <h4 class="text-warning"><i class="bi bi-exclamation-triangle"> WARNING</i></h4>
              <span class="tip-text">This action will create private keys and CSRs on this Keysas station. Then, it will sign the CSRs with the PKi. This may be long !</span>
            </div>
          </div>
          <div class="col-sm">
            <form class="add-form password" @submit.prevent="onSubmitInit">
              <label type="text">IKPQPKI password:</label>
              <input type="password" required v-model="password" placeholder="8 characters minimum" id="password" />
              <div v-if="passwordError" class="error"> {{ passwordError }}</div>
              <div class="submit">
                <button class="send btn btn-success btn-lg shadow"><i class="bi bi-check-square"> Enroll it</i></button>
                <br><br>
                <p v-if="confirmed === true && !init_status" class="validate animate__animated animate__zoomIn">Processing  <span class="spinner-border text-info"></span></p>
                <p v-else-if="confirmed === true && init_status == 'true' " class="validate animate__animated animate__zoomIn text-success">Done !</p>
                <p v-else-if="init_status == false" class="validate animate__animated animate__zoomIn text-danger">PKI error !</p>
                <span v-else></span>
                <br>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
    <AddYubikey v-if="ShowAddYubikey"></AddYubikey>
    <RevokeYubikey v-if="ShowRevYubikey"></RevokeYubikey>
    <UpdateKeysas v-if="ShowUpdateKeysas" :updateStatus="update_status"></UpdateKeysas>
    <RebootKeysas v-if="ShowRebootKeysas" :rebootStatus="reboot_status"></RebootKeysas>
    <ShutdownKeysas v-if="ShowShutdownKeysas" :shutdownStatus="shutdown_status"></ShutdownKeysas>
    <ExportSSH v-if="ShowExportSSH" :exportSSHStatus="export_ssh_status"></ExportSSH>
  </div>
  <div style="display:none" id="pwdpopup">
    <div>Enter PKI password:</div>
    <input id="pass" type="password"/>
    <button onclick="done()">OK</button>
  </div>
</template>

<script>
"use strict";

import NavBar from '../components/NavBar.vue'
import AddYubikey from '../components/AddYubikey.vue'
import RevokeYubikey from '../components/RevokeYubikey.vue'
import UpdateKeysas from '../components/UpdateKeysas.vue'
import RebootKeysas from '../components/RebootKeysas.vue'
import ShutdownKeysas from '../components/ShutdownKeysas.vue'
import ExportSSH from '../components/ExportSSH.vue'

import { reboot, shutdown, addsshpukey, update, init, generate_keypair, sign_USB, revoke_USB } from '../utils/utils.js'
import { confirm } from '@tauri-apps/plugin-dialog';
import { invoke } from "@tauri-apps/api/core";

export default {
  name: 'ManageView',
  components: {
    NavBar,
    AddYubikey,
    RevokeYubikey,
    UpdateKeysas,
    RebootKeysas,
    ShutdownKeysas,
    ExportSSH,
  },
  computed: {
  },
  data() {
    return {
      stations: '',
      db: [],
      hide: true,
      current_keysas: '',
      current_ip: '',
      ShowRevDeviceValidate: false,
      ShowAddYubikey: false,
      ShowRevYubikey: false,
      ShowUpdateKeysas: false,
      ShowRebootKeysas: false,
      ShowShutdownKeysas: false,
      ShowExportSSH: false,
      ShowActionButtons: true,
      ShowPasswordInit: false,
      ShowPasswordSign: false,
      reboot_status: undefined,
      update_status: undefined,
      init_status: undefined,
      shutdown_status: undefined,
      export_ssh_status: undefined,
      create_keypair_status: undefined,
      sign_usb_status: undefined,
      revoke_usb_status: undefined,
      password: undefined,
      passwordError: '',
      alive: false,
      KeysasAlive: undefined,
      confirmed: false,
    }
  },
  mounted() {
    invoke('list_stations')
      .then((list) => {
        console.log(list);
        this.stations = JSON.parse(list);
      })
      .catch((error) => console.error(error));
  },
  onUpdated() {
    invoke('list_stations')
      .then((list) => {
        console.log(list);
        this.stations = JSON.parse(list);
      })
      .catch((error) => console.error(error));
  },
  methods: {
    flush() {
      this.ShowRevKeypair = false;
      this.ShowAddYubikey = false;
      this.ShowRevYubikey = false;
      this.ShowRevDeviceValidate = false;
      this.ShowRevDevice = false;
      this.ShowUpdateKeysas = false;
      this.ShowRebootKeysas = false;
      this.ShowShutdownKeysas = false;
      this.ShowExportSSH = false;
      this.ShowPasswordGenerateKeypair = false;
      this.ShowPasswordSign = false;
      this.ShowPasswordInit = false;
      this.password = undefined;
      this.passwordError = '';
      this.confirmed = false;
    },
    displayKeysasList() {
      invoke('list_stations')
        .then((list) => {
          console.log(list);
          this.stations = JSON.parse(list);
        })
        .catch((error) => console.error(error));
    },
    async removeKeysas(keysas) {
      this.confirmed = await confirm('Please confirm', { title: 'Remove this Keysas ?', type: 'warning' });
      if (this.confirmed == true) {
        await invoke('remove_station', {name: keysas})
                .then((res) => console.log("Station deleted"))
                .catch((error) => console.error(error));
        this.confirmed = false;
        await this.displayKeysasList();
      }
    },
    async getKeysasIP(keysas) {
      invoke('get_station_ip', {name: keysas})
        .then((ip) => this.current_ip = ip)
        .catch((error) => console.error(error));
    },
    async rebootKeysas(device) {
      await this.getKeysasIP(device);
      this.confirmed = await confirm('Please confirm', { title: 'Ready to reboot this Keysas ?', type: 'info' });
      if (this.confirmed == true) {
        this.reboot_status = await reboot(this.current_ip);
        this.confirmed = false;
      } else {
        this.ShowRebootKeysas = false;
      }
    },
    async updateKeysas(device) {
      await this.getKeysasIP(device);
      this.confirmed = await confirm('This action cannot be reverted. Are you sure?', { title: 'Ready to update this Keysas', type: 'warning' });
      if (this.confirmed == true) {
        this.update_status = await update(this.current_ip);
        this.confirmed = false;
      } else {
        this.ShowUpdateKeysas = false;
      }
    },
    async shutdownKeysas(device) {
      await this.getKeysasIP(device);
      this.confirmed = await confirm('Please confirm', { title: 'Ready to shutdown this Keysas', type: 'info' });
      if (this.confirmed == true) {
        this.shutdown_status = await shutdown(this.current_ip);
        this.confirmed = false;
      } else {
        this.ShowShutdownKeysas = false;
      }
    },
    async AddSSHPubKey(device) {
      await this.getKeysasIP(device);
      this.confirmed = await confirm('Please confirm', { title: 'Ready to export the SSH public key', type: 'info' });
      if (this.confirmed == true) {
        this.export_ssh_status = await addsshpukey(this.current_ip);
        this.confirmed = false;
      } else {
        this.ShowExportSSH = false;
      }
    },
    async CreateKeypair(device, password) {
      await this.getKeysasIP(device);
      this.create_keypair_status = await generate_keypair(this.current_ip, password);
    },
    async SignUSB(device, password) {
      //console.log("signusb: ", device + password);
      await this.getKeysasIP(device);
      this.sign_usb_status = await sign_USB(this.current_ip, password);
    },
    async RevokeUSB(device) {
      //console.log("RevokeUSB: ", device);
      await this.getKeysasIP(device);
      this.revoke_usb_status = await revoke_USB(this.current_ip);
    },
    /**
     * Called when the initialization form is submited
     */
    async onSubmitInit() {
      await this.getKeysasIP(this.current_keysas);
      this.confirmed = await confirm('Are you sure ?', { title: 'Ready to initialize this Keysas', type: 'warning' });
      //console.log("confirmed1:" + this.confirmed);
      if (this.confirmed === true) {
        //console.log("confirmed2:" + this.confirmed);
        this.init_status = await init(this.current_ip, this.current_keysas, this.password);
        this.password = undefined;
        //console.log("init_status:" + this.init_status);
        //console.log("global:" + (this.confirmed === true && this.init_status == 'true' ));
        // Set this.confirmed = true for 5s showing the success message
        this.ShowTwoSec();
      } else {
        this.password = undefined;
        this.confirmed = false;
      }
    },
    async onSubmitSign() {
      this.sign_usb_status = undefined;
      //console.log('Form submitted (Signing password)');
      this.passwordError = this.password.length > 7 ?
        '' : "Password should have been created with at least 8 chars"
      //console.log("Password is:", this.password);
      if (!this.passwordError) {
        this.ShowSignKey = true;
        await this.SignUSB(this.current_keysas, this.password);
        this.password = undefined;
        console.log("sign_usb_status: " + this.sign_usb_status);
      }
      else {
        console.log('SignUSB not called!')
      }
    },
    async isalive() {
      this.polling = setInterval(() => {
        this.statusButton(this.current_keysas);
      }, 20000);
    },
    async statusButton(device) {
      await invoke('is_alive', {name: device})
        .then((status) => this.KeysasAlive = status)
        .catch((error) => {
          console.error(error);
          this.KeysasAlive = false;
        })
    },
    ShowTwoSec() {
      this.confirmed = true;
      setTimeout(() => {
        this.confirmed = false
      }, 5000)
    }
  },
  beforeUnmount() {
    clearInterval(this.alive)
  },
  created() {
    this.isalive();
  }
}
</script>

<style lang="scss">
body {
  margin: 0;
  //background: rgb(86, 206, 235);
}

h2 {
  font-weight: bold;
  color: #fff;
  font-size: 24px;
}

.i {
  //font-weight: bold;
  font-style: normal;
  //font-size: 18px;
}

label,
p {
  //color: #aaa;
  color: rgb(132, 132, 132);
  display: inline-block;
  margin: 25px 0 15px;
  font-size: 1.1em;
  text-transform: uppercase;
  font-weight: bold;
}

.box {
  max-width: 1000px;
  /*margin: 15px 50px;*/
  margin: 15px 0 15px 12%; /* Ajoute 20px de marge uniquement à gauche */
  background-color: #fff;
  text-align: center;
  padding: 1em;
  border-radius: 18px;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); /* Ombre légère pour moderniser */
}

.password {
  max-width: 300px;
  margin: 40px auto;
  background: white;
  //text-align: center;
  padding: 40px;
  border-radius: 15px;
  box-shadow: 10px 5px 5px black;
}

.tip {
  max-width: 1000px;
  text-align: left;
  margin: 30px auto;
  background: white;
  padding: 40px;
  border-radius: 10px;
  box-shadow: 5px 5px 5px black;
  color: white;
  display: inline-block;
  //margin: 25px 0 15px;
  font-size: 1.0em;
}

.tip-text {
  font-weight: normal;
  color: rgb(101, 101, 101);
  font-size: 1.2em;
}

.box-small-left {
  text-align: left;
  font-size: 1em;
  font-weight: bold;
}

input {
  display: block;
  padding: 10px 6px;
  width: 100%;
  box-sizing: border-box;
  border: none;
  border-bottom: 1px solid #ddd;
  color: #555;
}

button {
  border-radius: 20px;
  font-style: normal;
}

.submit {
  text-align: center;
}

.error {
  color: #ff0062;
  margin-top: 10px;
  font-size: 0.8em;
  font-weight: bold;
}

.custom-li {
  color: #101112;
  margin-top: 10px;
  font-size: 0.8em;
  text-align: left;
}
</style>
