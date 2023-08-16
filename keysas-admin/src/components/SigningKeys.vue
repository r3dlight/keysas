<template>
  <div class="row align-items-start box">
    <div class="col">
      <button class="send btn btn-outline-info btn-lg shadow"
              @click="showLoadPKIForm = !showLoadPKIForm;
                      showRootKeyForm = false;
                      showPkiDirForm = false;">
        Load from local IKPQPKI
      </button>
    </div>
    <!-- No pkcs11 for now-->
    <!--<div class="col">
      <button class="send btn btn-light btn-lg shadow"
              @click="showLoadPKIForm = false;
                      showRootKeyForm = !showRootKeyForm;
                      showPkiDirForm = false;">
        Generate from Root CA
      </button>      
    </div>-->
    <div class="col">
      <button class="send btn btn-outline-info btn-lg shadow" 
              @click="showLoadPKIForm = false;
                      showRootKeyForm = false;
                      showPkiDirForm = !showPkiDirForm;">
        Create a new IKPQPKI
      </button>      
    </div>
  <!--</div>-->
  <div v-if="showLoadPKIForm">
    <form class="add-form" @submit.prevent="onSubmit">
      <label type="text"> Path to your IKPQPKI folder:</label>
      <input type="text" required v-model="pkiFolder" id="pkiFolder"/>
      <div class="text-center">
        <button class="btn btn-outline-secondary btn-sm shadow" @click="PKIFolder">Browse</button>
      </div>
      <div v-if="keysError" class="error"> {{ keysError }}
      </div>
      <label type="text"> Your #PKCS8 password:</label>
      <input type="password" required v-model="p8Password" id="p8Password"/>
      <br><br>
      <div class="submit">
        <button class="send btn btn-outline-success btn-lg shadow"
                @click="submitPKIFolderForm">
          <i class="bi bi-check-square"> Ok</i>
        </button>
        <br><br>
        <h3 v-if="show" class="validate animate__animated animate__zoomIn text-success">Done !</h3>
      </div>
    </form>
    <div>
      <br>
      <div v-if="pkiRestore == 'waiting'">
        Wait while importing IKPQPKI... <span class="spinner-border text-info"></span>
      </div>
      <div v-if="pkiRestore === false">
       <h3 class="text-danger"> Error while importing IKPQPKI !</h3>
      </div>
   </div>
  </div>
  <div v-if="showRootKeyForm">
    <form class="add-form" @submit.prevent="onSubmit">
      <label type="text"> Path to your Root CA key file (PKCS#8):</label>
      <input type="text" required v-model="rootKeyPath" id="rootKey"/>
      <div class="text-center">
        <button class="btn btn-outline-secondary btn-sm shadow" @click="RootKeyPath">Browse</button>
      </div>
      <div v-if="keysError" class="error"> {{ keysError }}
      </div>
      <br><br>
      <div class="submit">
        <button class="send btn btn-outline-success btn-lg shadow"
                @click="submitRootCAForm">
          <i class="bi bi-check-square"> Ok</i>
        </button>
        <br><br>
        <h3 v-if="show" class="validate animate__animated animate__zoomIn text-success">Done !</h3>
      </div>
    </form>
  </div>
  <div v-if="showPkiDirForm">
    <form class="add-form" @submit.prevent="onSubmit">
      <label type="text"> Organization name:</label>
      <input type="text" required v-model="orgName" id="orgName"/>
      <label type="text"> IKPQPKI name:</label>
      <input type="text" required v-model="orgUnit" id="orgUnit"/>
      <label type="text"> Country (first two letters):</label>
      <input type="text" required v-model="country" id="country"/>
      <div v-if="countryError" class="error"> {{ countryError }}</div>
      <label type="text"> Validity (days):</label>
      <input type="text" required v-model="validity" id="validity"/>
      <label type="text"> Select directory:</label>
      <input type="text" required v-model="pkiDir" id="pkiDir"/>
      <div class="text-center">
        <button class="btn btn-outline-secondary btn-sm shadow" @click="PKIDir">Browse</button>
      </div>
      <label type="text"> Password:</label>
      <input type="password" required v-model="adminPwd" id="adminPwd"/>
      <div v-if="passwordError" class="error"> {{ passwordError }}
      </div>
      <br><br>
      <div class="submit">
        <button v-if="!waiting" class="send btn btn-outline-success btn-lg shadow"
                @click="submit();">
          <i class="bi bi-check-square"> Ok</i>
        </button>
        <div v-if="waiting">
          Wait while creating IKPQPKI... <span class="spinner-border text-info"></span>
        </div>
        <br>
        <h3 v-if="show" class="validate animate__animated animate__zoomIn text-success">IKPQPKI successfully created !</h3>
      </div>
    </form>
  </div>
</div>

</template>

<script>
//"use strict";

import {getRootKeyPath, getPKIFolder, getPKIDir} from "../utils/utils";

import { invoke } from "@tauri-apps/api";

export default {
  name: 'SigningKeys',
  computed: {
    },
  data() {
    return {
      rootKeyPath: '',
      pkiDir: '',
      orgName: '',
      orgUnit: '',
      country: '',
      validity: '',
      adminPwd: '',
      pkiFolder: '',
      pkiRestore: '',
      keysError: '',
      show: false,
      waiting: false,
      showLoadPKIForm: false,
      showRootKeyForm: false,
      showPkiDirForm: false,
      passwordError: '',
      countryError: '',
      p8Password: '',
    }
  },

  methods: {
    // Test root key path validity
    async RootKeyPath(){
      this.rootKey = await getRootKeyPath();
    },
    // Test PKI folder validity
    async PKIFolder(){
      this.pkiFolder = await getPKIFolder();
    },
    // Test PKI Directory validity
    async PKIDir(){
      this.pkiDir = await getPKIDir();
    },
    async submitPKIFolderForm() {
      this.pkiRestore = 'waiting';
      await invoke('restore_pki', {
          basePath: this.pkiFolder,
         })
        .then((res) => this.pkiRestore = res)
        .catch((error) => console.error(error));
      console.log('PKI Folder form submission');
    },
    async submitRootCAForm() {
      console.log('Root CA form submission');
    },
    async submit() {
      await this.submitPKIDirForm();
    },
    async submitPKIDirForm() {
      console.log('PKI Dir form submission');
      this.passwordError = this.adminPwd.length > 7 ?
        '' : "Password should have been created with at least 8 chars";
        this.countryError = this.country.length < 3 ?
        '' : "Country must be 2 chars long";
      if (!this.passwordError && !this.countryError) {
        this.waiting = true;
        await invoke('generate_pki_in_dir', {
             orgName: this.orgName,
             orgUnit: this.orgUnit,
             country: this.country,
             validity: this.validity,
             adminPwd: this.adminPwd,
             pkiDir: this.pkiDir
         })
        .then((res) => this.pkiGenerated())
        .catch((error) => console.error(error));
      } else {console.log("Password incorrect lengh !")}
    },
    async pkiGenerated(){
      this.waiting = false;
      this.ShowFiveSec();
    },
    ShowFiveSec() {
      this.show=true;
      setTimeout(() => {
        this.show = false
        }, 5000)
      }  
    }
}
</script>

<style lang="scss">
h2 {
  font-weight: bold;
  color: #fff;
  font-size: 24px;
}
.validate {
  font-weight: bold;
  font-size: 24px;
}
label, p{
  color: rgb(132, 132, 132);
  display: inline-block;
  margin: 25px 0 15px;
  font-size: 1.1em;
  text-transform: uppercase;
  font-weight: bold;
}
form {
  max-width: 600px;
  margin: 30px auto;
  background: white;
  text-align: left;
  padding: 40px;
  border-radius: 10px;
  box-shadow: 10px 5px 5px black;
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
button{
  border-radius: 20px;
}
.submit{
  text-align: center;
}
.error{
  color: #ff0062;
  margin-top: 10px;
  font-size: 0.8em;
  font-weight: bold;

}
</style>
