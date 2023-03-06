<template>
  <div class="row align-items-start">
    <div class="col">
      <button class="send btn btn-outline-success btn-lg shadow"
              @click="showLoadPKIForm = !showLoadPKIForm;
                      showRootKeyForm = false;
                      showPkiDirForm = false;">
        Load PKI
      </button>
    </div>
    <div class="col">
      <button class="send btn btn-outline-success btn-lg shadow"
              @click="showLoadPKIForm = false;
                      showRootKeyForm = !showRootKeyForm;
                      showPkiDirForm = false;">
        Generate from Root CA
      </button>      
    </div>
    <div class="col">
      <button class="send btn btn-outline-success btn-lg shadow" 
              @click="showLoadPKIForm = false;
                      showRootKeyForm = false;
                      showPkiDirForm = !showPkiDirForm;">
        Do it for me
      </button>      
    </div>
  </div>
  <div v-if="showLoadPKIForm">
    <form class="add-form" @submit.prevent="onSubmit">
      <label type="text"> Path to your PKI folder:</label>
      <input type="text" required v-model="pkiFolder" id="pkiFolder"/>
      <div class="text-center">
        <button class="btn btn-outline-secondary btn-sm shadow" @click="PKIFolder">Browse</button>
      </div>
      <div v-if="keysError" class="error"> {{ keysError }}
      </div>
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
  </div>
  <div v-if="showRootKeyForm">
    <form class="add-form" @submit.prevent="onSubmit">
      <label type="text"> Path to your Root CA key file (PKCS#12):</label>
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
      <label type="text"> PKI name:</label>
      <input type="text" required v-model="orgUnit" id="orgUnit"/>
      <label type="text"> Country (first two letters):</label>
      <input type="text" required v-model="country" id="country"/>
      <label type="text"> Validity (days):</label>
      <input type="text" required v-model="validity" id="validity"/>
      <label type="text"> Signature algorithm (default ed25519 / ed448):</label>
      <input type="text" required v-model="sigAlgo" id="sigAlgo"/>
      <label type="text"> Select directory:</label>
      <input type="text" required v-model="pkiDir" id="pkiDir"/>
      <label type="text"> Password:</label>
      <input type="text" required v-model="adminPwd" id="adminPwd"/>
      <div class="text-center">
        <button class="btn btn-outline-secondary btn-sm shadow" @click="PKIDir">Browse</button>
      </div>
      <div v-if="keysError" class="error"> {{ keysError }}
      </div>
      <br><br>
      <div class="submit">
        <button class="send btn btn-outline-success btn-lg shadow"
                @click="submitPKIDirForm">
          <i class="bi bi-check-square"> Ok</i>
        </button>
        <br><br>
        <h3 v-if="show" class="validate animate__animated animate__zoomIn text-success">Done !</h3>
      </div>
    </form>
  </div>
</template>

<script>

import {getRootKeyPath, getPKIFolder, getPKIDir, loadPKI, generateFromRootKey, generatePKI} from "../utils/utils";


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
      sigAlgo: '',
      adminPwd: '',
      pkiFolder: '',
      keysError: '',
      show: false,
      showLoadPKIForm: false,
      showRootKeyForm: false,
      showPkiDirForm: false
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
      console.log('PKI Folder form submission');
    },
    async submitRootCAForm() {
      console.log('Root CA form submission');
    },
    async submitPKIDirForm() {
      console.log('PKI Dir form submission');
      this.keysError = '';
      this.keysError = await generatePKI(this.orgName,
                                          this.orgUnit,
                                          this.country,
                                          this.validity,
                                          this.sigAlgo,
                                          this.adminPwd,
                                          this.pkiDir) ?
                                '' : 'Failed to generate PKI in directory';
      console.log("keysError:", this.keysError);
    },
    ShowTwoSec() {
      this.show=true;
      setTimeout(() => {
        this.show = false
        }, 2000)
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
