"use strict";

import { invoke } from "@tauri-apps/api/core";
import { open } from '@tauri-apps/plugin-dialog';

export async function reboot(ip) {
    try {
        console.log("Rebooting':", ip);
        let res = await invoke('reboot', {
            ip: ip
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
        console.log("Poweroff:", ip);
        let res = await invoke('shutdown', {
            ip: ip
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
        console.log("Adding SSH pubkey to host:", ip);
        let res = await invoke('export_sshpubkey', {
            ip: ip
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
        console.log("Trying to update Keysas:", ip);
        let res = await invoke('update', {
            ip: ip
        })
        console.log(res)
        return res;
    } catch(e) {
        console.log(e)
        return Promise.reject(e);
    }
}

/**
 * 
 * @param {String} ip         IP address of the station
 * @param {String} name       Name of the station
 * @param {String} caPwd      Password to load the CA keys
 * @param {String} stCaFile   Path to the Station CA key file
 * @param {String} usbCaFile  Path to the USB CA key file
 * @returns Result of the call to the back-end and the initilization of the station
 */
export async function init(ip, name, caPwd,
                                stCaFile, usbCaFile) {
    try {
        console.log("Trying to initialize Keysas:", ip);
        let res = await invoke('init_keysas', {
            ip: ip,
            name: name,
            caPwd: caPwd,
            stCaFile: stCaFile,
            usbCaFile: usbCaFile
        })
        console.log(res)
        return res;
    } catch(e) {
        console.log(e)
        //return Promise.reject(e);
        return false;
    }
}

export async function is_alive(ip) {
    try {
        console.log("Trying to ping Keysas:", ip);
        let res = await invoke('is_alive', {
            ip: ip
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
        console.log("Trying to generate a new keypair:", ip);
        let res = await invoke('generate_keypair', {
            ip: ip,
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
        console.log("Trying to sign a new USB device: ", ip);
        let res = await invoke('sign_key', {
            ip: ip,
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
        console.log("Trying to revoke the USB device: ", ip);
        let res = await invoke('revoke_key', {
            ip: ip
        })
        console.log("revoke_USB: " + res)
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
