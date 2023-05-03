<script setup lang="ts">
import "bootstrap/dist/css/bootstrap.min.css"
import "bootstrap"
import 'bootstrap-icons/font/bootstrap-icons.css'

import {invoke} from "@tauri-apps/api"

let usb_list: {name: string, path: string}[] = [
  {"name": "Kingstong USB", "path": "D:"}
];

function showUsbDevice(name: string) {
  invoke('show_usb_device', {name: name});
}
</script>

<template>
  <div class="container">
    <ul class="list-group">
      <li class="list-group-item" v-for="usb in usb_list">
        <div class="container">
          <div class="row">
            <div class="col-sm">
              <button class="btn btn-outline-dark btn-lg shadow" @click="showUsbDevice(usb.name)">
                {{ usb.name }}
              </button>
            </div>
            <div class="col-sm">
              <p>
                {{ usb.path }}
              </p>
            </div>
            <div class="col-sm">
              Authorization status
            </div>
          </div>
        </div>
      </li>
    </ul>
  </div>
</template>

<style scoped>
</style>
