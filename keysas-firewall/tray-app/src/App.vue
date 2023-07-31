<script setup lang="ts">
import 'bootstrap-icons/font/bootstrap-icons.css'
import {listen} from '@tauri-apps/api/event'
</script>

<template>
  <div class="app_container">
    <table>
      <thead>
        <tr>
          <th><span class="app_icon"></span></th>
          <th class="app_title">Keysas USB Firewall</th>
        </tr>
      </thead>
    </table>
    <table v-if="showUsbList">
      <tr v-for="usb in usb_list">
        <td class="usb_device">
          <button @click="showUsbDevice(usb)">{{ usb.name }} - {{ usb.path }}</button>
        </td>
        <td class="usb_auth" v-if="usb.authorization == AuthorizationMode.Allowed_RW">
          <button class="bi-folder-check"></button>
        </td>
        <td class="usb_auth" v-if="usb.authorization == AuthorizationMode.Allowed_Read">
          <button class="bi-folder-plus"></button>
        </td>
        <td class="usb_auth" v-if="usb.authorization == AuthorizationMode.Blocked">
          <button class="bi-folder-x"></button>
        </td>
      </tr>
    </table>
    <table v-if="showUsbDetails">
      <thead>
        <tr>
          <th style="width:85%">{{ usb_device.name }}</th>
          <th>
            <button class="bi-arrow-left" @click="backToUsbList()"></button>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="file in file_list">
          <td>{{ file.path }}</td>
          <td v-if="file.authorization == AuthorizationMode.Allowed_Read"><button class="bi-file-earmark-check" @click="toggleFileAuth(file, AuthorizationMode.Allowed_RW)"></button></td>
          <td v-if="file.authorization == AuthorizationMode.Allowed_RW"><button class="bi-file-earmark-plus" @click="toggleFileAuth(file, AuthorizationMode.Blocked)"></button></td>
          <td v-if="file.authorization == AuthorizationMode.Blocked"><button class="bi-file-earmark-x" @click="toggleFileAuth(file, AuthorizationMode.Allowed_Read)"></button></td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script lang="ts">
import {invoke} from "@tauri-apps/api"

enum AuthorizationMode {
  Blocked = 0,
  Allowed_Read,
  Allowed_RW
}

declare interface UsbDevice {
  name: string,
  path: string,
  authorization: AuthorizationMode
}

declare interface File {
  device: string,
  id: number[],
  path: string,
  authorization: AuthorizationMode
}

export default {
  name: 'App',
  components: {
  },
  data() {
    return {
      showUsbList: true,
      showUsbDetails: false,
      usb_list:  [] as UsbDevice[],
      file_list: [] as File[],
      usb_device: {} as UsbDevice,
    }
  },
  async mounted() {
    this.usb_list.push({
      name: "Kingston USB",
      path: "D:",
      authorization: AuthorizationMode.Allowed_RW
    });
    
    await listen('file_update', (event) => {
      this.refreshFileList(event.payload as string);
    });
  },
  methods: {
    async refreshFileList(device_path: string) {
      if (device_path === this.usb_device.path) {
        invoke('get_file_list', {devicePath: device_path})
          .then((result) => {
            const file_list = JSON.parse(result as string);
            file_list.forEach((file: File) => {
              if (!this.file_list.some(f => f.path === file.path)) {
                this.file_list.push(file);
              }
            });
          })
          .catch((error) => console.error(error));
      }
    },
    async showUsbDevice(usb_device: UsbDevice) {
      // Set the selected device
      this.usb_device = usb_device;

      // Fetch the file list from the backend
      this.refreshFileList(usb_device.path);
      
      // Display the details window
      this.showUsbList = false;
      this.showUsbDetails = true;
    },
    async toggleFileAuth(file: File, new_mode: AuthorizationMode) {
      let auth = 0; // Blocked
      if (new_mode == AuthorizationMode.Allowed_Read) {
        auth = 1;
      } else if (new_mode == AuthorizationMode.Allowed_RW) {
        auth = 2;
      }
      console.log("New authorization");
      invoke('toggle_file_auth', {device: file.device, id: file.id, path: file.path, newAuth: auth})
        .then((result) => {
          console.log("New authorization result OK");
          file.authorization = new_mode;
        })
        .catch((error) => alert("Toggle file authorization failed"));
    },
    backToUsbList() {
      this.showUsbDetails = false;
      this.showUsbList = true;
    }
  },
};

</script>

<style scoped>
.app_container {
  position: absolute;
  left: 0px;
  right: 0px;
  top: 0px;
}

.app_icon {
  background: url('logo-keysas-short-48.png');
  background-size: 20px;
  height: 20px;
  width: 20px;
  display: block;
}

.app_title {
  width: 95%;
  text-align: start;
  padding-left: 2%;
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
  border-bottom: 1px solid lightgray;
}

.usb_device {
  width: 85%;
}

.usb_auth {
  width: 5%;
}

button {
  background-color: transparent;
}

table {
  border-collapse: collapse;
  width: 100%;
}

tbody tr td {
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
  border-bottom: 1px solid grey;
}
</style>
