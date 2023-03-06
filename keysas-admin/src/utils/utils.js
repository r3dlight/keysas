import { invoke } from "@tauri-apps/api";
import { open } from "@tauri-apps/api/dialog";


export async function reboot(ip) {
    try {
        var paths = localStorage.getItem('ssh');
        var priv_key = JSON.parse(paths).priv;
        console.log("Rebooting':", ip);
        let res = await invoke('reboot', {
            ip: ip,
            privateKey: priv_key,
        });
        console.log("Rebooting result:" + res);
        return res;
    } catch(e) {
        console.log(e)
        return Promise.reject(e);
    }
}

export async function shutdown(ip) {
    try {
        var paths = localStorage.getItem('ssh');
        var priv_key = JSON.parse(paths).priv;
        console.log("Poweroff:", ip);
        let res = await invoke('shutdown', {
            ip: ip,
            privateKey: priv_key,
        })
        console.log(res)
        return res;
    } catch(e) {
        console.log(e)
        return Promise.reject(e);
    }
}

export async function addsshpukey(ip) {
    try {
        var paths = localStorage.getItem('ssh');
        var public_key = JSON.parse(paths).pub;
        console.log("Adding SSH pubkey to host:", ip);
        let res = await invoke('export_sshpubkey', {
            ip: ip,
            publicKey: public_key,
        })
        console.log(res)
        return res;
    } catch(e) {
        console.log(e)
        return Promise.reject(e);
    }
}

export async function update(ip) {
    try {
        var paths = localStorage.getItem('ssh');
        var priv_key = JSON.parse(paths).priv;
        console.log("Trying to update Keysas:", ip);
        let res = await invoke('update', {
            ip: ip,
            privateKey: priv_key,
        })
        console.log(res)
        return res;
    } catch(e) {
        console.log(e)
        return Promise.reject(e);
    }
}

export async function is_alive(ip) {
    try {
        var paths = localStorage.getItem('ssh');
        var priv_key = JSON.parse(paths).priv;
        console.log("Trying to ping Keysas:", ip);
        let res = await invoke('is_alive', {
            ip: ip,
            privateKey: priv_key,
        })
        console.log(res)
        return res;
    } catch(e) {
        console.log(e)
        return Promise.reject(e);
    }
}

export async function generate_keypair(ip, password) {
    try {
        var paths = localStorage.getItem('ssh');
        var priv_key = JSON.parse(paths).priv;
        console.log("Trying to generate a new keypair:", ip);
        let res = await invoke('generate_keypair', {
            ip: ip,
            privateKey: priv_key,
            password: password,
        })
        console.log("generate_keypair: " + res)
        return res;
    } catch(e) {
        console.log(e)
        return Promise.reject(e);
    }
}

export async function sign_USB(ip, password) {
    try {
        var paths = localStorage.getItem('ssh');
        var priv_key = JSON.parse(paths).priv;
        console.log("Trying to sign a new USB device: ", ip);
        let res = await invoke('sign_key', {
            ip: ip,
            privateKey: priv_key,
            password: password,
        })
        console.log("sign_USB: " + res)
        return res;
    } catch(e) {
        console.log(e)
        return Promise.reject(e);
    }
}

export async function revoke_USB(ip) {
    try {
        var paths = localStorage.getItem('ssh');
        var priv_key = JSON.parse(paths).priv;
        console.log("Trying to revoke the USB device: ", ip);
        let res = await invoke('revoke_key', {
            ip: ip,
            privateKey: priv_key,
        })
        console.log("revoke_USB: " + res)
        return res;
    } catch(e) {
        console.log(e)
        return Promise.reject(e);
    }
}

export async function validateKeys(publicKey, privateKey) {
    try {
        console.log("Pubkey: " + publicKey + "Privkey: " + privateKey);
        let res = await invoke('validate_privatekey', {
            publicKey: publicKey,
            privateKey: privateKey,
        })
        console.log("validate_privatekey: " + res)
        return res;
    } catch(e) {
        console.log(e)
        return Promise.reject(e);
    }
}

// Generate a new PKI from a Root CA keypair
export async function generateFromRootKey(rootKey) {
    try {
        console.log("Rootkey: " + rootKey);
        let res = await invoke('validate_rootkey', {
            rootKey: rootKey
        })
        console.log("validate_rootkey: " + res)
        return res;
    } catch(e) {
        console.log(e)
        return Promise.reject(e);
    }
}

// Generate a new PKI from scratch
export async function generatePKI(pkiDir) {
    try {
        console.log("PKI Directory: " + pkiDir);
        let res = await invoke('generate_pki_in_dir', {
            pkiDir: pkiDir,
            adminPwd: "root"

        })
        console.log("generate_pki_in_dir: " + res)
        return res;
    } catch(e) {
        console.log(e)
        return Promise.reject(e);
    }
}

// Load an existing PKI from a folder
export async function loadPKI(pkiFolder) {
    try {
        console.log("Rootkey: " + rootKey);
        let res = await invoke('validate_rootkey', {
            rootKey: rootKey
        })
        console.log("validate_rootkey: " + res)
        return res;
    } catch(e) {
        console.log(e)
        return Promise.reject(e);
    }
}

export async function getPublicKeyPath() {
    try {
      const SelectedPath = await open({
        multiple: false,
        title: "Select your public key..."
      });
      console.log(SelectedPath);
      return SelectedPath;
    } catch(e){
      console.log(e);
      return Promise.reject(e);
    }
}

export async function getPrivateKeyPath() {
    try {
      const SelectedPath = await open({
        multiple: false,
        title: "Select your private key..."
      });
      console.log(SelectedPath);
      return SelectedPath;
    } catch(e){
      console.log(e);
      return Promise.reject(e);
    }
}

export async function getRootKeyPath() {
    try {
      const SelectedPath = await open({
        multiple: false,
        directory: false,
        title: "Select your root CA key file..."
      });
      console.log(SelectedPath);
      return SelectedPath;
    } catch(e){
      console.log(e);
      return Promise.reject(e);
    }
}

export async function getPKIFolder() {
    try {
      const SelectedPath = await open({
        multiple: false,
        directory: true,
        title: "Select your PKI folder..."
      });
      console.log(SelectedPath);
      return SelectedPath;
    } catch(e){
      console.log(e);
      return Promise.reject(e);
    }
}

export async function getPKIDir() {
    try {
      const SelectedPath = await open({
        multiple: false,
        directory: true,
        title: "Select a directory for your PKI..."
      });
      console.log(SelectedPath);
      return SelectedPath;
    } catch(e){
      console.log(e);
      return Promise.reject(e);
    }
}