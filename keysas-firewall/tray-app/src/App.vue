<script setup lang="ts">
import "bootstrap/dist/css/bootstrap.min.css"
import "bootstrap"
import 'bootstrap-icons/font/bootstrap-icons.css'
</script>

<template>
  <div class="d-flex h-1 bg-dark text-white">
    <h1>Keysas USB Firewall</h1>
  </div>
  <div v-if="showUsbList">
    <ul class="list-group bg-dark text-white">
      <li class="list-group-item bg-dark text-white" v-for="usb in usb_list">
          <div class="row d-inline-flex w-100 bg-dark text-white">
            <div class="col bg-dark text-white">
              <button class="btn btn-outline-light" @click="showUsbDevice(usb)">
                {{ usb.name }} - {{ usb.path }}
              </button>
            </div>
            <div class="col bg-dark text-white">
              <button class="btn btn-outline-light bi bi-folder-check" :disabled="usb.authorization != AuthorizationMode.Blocked"></button>
            </div>
            <div class="col bg-dark text-white">
              <button class="btn btn-outline-light bi bi-folder-plus" :disabled="usb.authorization != AuthorizationMode.Allowed_RW"></button>
            </div>
            <div class="col bg-dark text-white">
              <button class="btn btn-outline-light bi bi-folder-x" :disabled="usb.authorization != AuthorizationMode.Allowed_Read"></button>
            </div>
          </div>
      </li>
    </ul>
  </div>
  <div v-if="showUsbDetails">
    <nav class="navbar bg-dark text-white">
      <a class="navbar-brand bg-dark text-white">
        {{ usb_device.name }}
      </a>
      <button class="btn btn-outline-light bi bi-arrow-left bg-dark text-white" @click="backToUsbList()"></button>
    </nav>
    <ul class="list-group bg-dark text-white">
      <li class="list-group-item bg-dark text-white" v-for="file in file_list">
          <div class="row d-inline-flex w-100 bg-dark text-white">
            <div class="col bg-dark text-white">
              <span>
                {{ file.path }}
              </span>
            </div>
            <div class="col bg-dark text-white">
              <button class="btn btn-outline-light bi bi-folder-check" disabled></button>
            </div>
            <div class="col bg-dark text-white">
              <button class="btn btn-outline-light bi bi-folder-plus"></button>
            </div>
            <div class="col bg-dark text-white">
              <button class="btn btn-outline-light bi bi-folder-x" disabled></button>
            </div>
          </div>
      </li>
    </ul>
  </div>
</template>

<script lang="ts">
import {invoke} from "@tauri-apps/api"

enum AuthorizationMode {
  Blocked = 1,
  Allowed_Read,
  Allowed_RW
}

declare interface UsbDevice {
  name: string,
  path: string,
  authorization: AuthorizationMode
}

declare interface File {
  path: string,
  allowed: boolean
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
  mounted() {
    this.usb_list.push({
      name: "Kingston USB",
      path: "D:/",
      authorization: AuthorizationMode.Allowed_RW
    });
  },
  methods: {
    showUsbDevice(usb_device: UsbDevice) {
      // Set the selected device
      this.usb_device = usb_device;

      // Fetch the file list from the backend
      invoke('get_file_list')
        .then((result) => console.log(result))
        .catch((error) => console.error(error));
      
      // Display the details window
      this.showUsbList = false;
      this.showUsbDetails = true;
    },
    backToUsbList() {
      this.showUsbDetails = false;
      this.showUsbList = true;
    }
  },
};

</script>

<style scoped>
</style>
