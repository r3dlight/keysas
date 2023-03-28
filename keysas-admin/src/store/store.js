import { Store } from 'tauri-plugin-store-api';
import { invoke } from "@tauri-apps/api";

const Path = '.keysas.dat';
const store = new Store(Path);


export async function setData(data) {
    let { key, val } = data;

    //console.log("setData in");
    //console.log(key);
    //console.log(val);
    try {
      await store.set(key, val);
      await store.save();
    } catch(e) {
        return Promise.reject(e);
    }
}

export async function getData(key) {
    try {
       let res = await store.get(key);
       return res;
    } catch(e) {
        return Promise.reject(e);
    }
}

export async function removeKey(key) {
    try {
        let res = await store.delete(key);
        await store.save();
        return res;
     } catch(e) {
        return Promise.reject(e);
     }
}

export async function getKeys(){
    console.log("Getting Keysas keys from store:");
    try {
        let res = await store.keys();
        console.log(res);
        return res;
     } catch(e) {
        return Promise.reject(e);
     }
}

export async function loadStore(){
    console.log("Loading store");
    try {
        let res = await store.load(Path);
        return res;
     } catch(e) {
        return Promise.reject(e);
     }
}

export async function getStatus(keys){
    try {
        var paths = localStorage.getItem('ssh');
        var priv_key = JSON.parse(paths).priv;
        for (let i = 0; i < keys.length; i++) {
            await loadStore();
            let KeysasData = await getData(keys[i]);
            let ip = JSON.stringify(KeysasData[0]);
            ip = await JSON.parse(ip).ip;
            //console.log("Storing:", KeysasData[0], ip);
            let res = await invoke('is_alive', {
                ip: ip,
                privateKey: priv_key,
            })
            //console.log(res)
            if (res){
                sessionStorage.setItem(keys[i], "true");
                console.log("Storage returns: ", res);
            }else{
                sessionStorage.setItem(keys[i], "false");
                console.log("storage return: ", res);
            }
        }
    } catch(e) {
        console.log(e)
        return Promise.reject(e);
    }
}