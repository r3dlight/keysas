<template>
  <AppHeader
    :wizardMode="wizardMode"
    :forcedWizardMode="forcedWizardMode"
    :analysingIN="analysingIN"
    :analysingOUT="analysingOUT"
    :usb_in="usb_in"
    :usb_out="usb_out"
    :yubikeys="yubikeys"
    :filesIN="filesIN"
    :filesOUT="filesOUT"
    :deamonStatus="StatusIn && StatusTransit && StatusOut"
    :analysingTRANSIT="analysingTRANSIT"
    @open-wizard="(isOpen) => { this.openWizard = isOpen }"
  />

  <AppWizard v-if="this.wizardMode" :ip="ip" class="user-select-none" />
  <div v-else-if="this.appStarted" class="user-select-none">
    <div class="container">
      <div class="row">
        <div class="col-sm-5 panel panel-left">
          <AppGuichet 
          type="IN"
          ref="GuichetIn"
          :working="analysingIN || analysingTRANSIT || analysingOUT"
          :usb="usb_in"
          :files="filesIN"
          @guichet-in-cleared="onGuichetInCleared"
          />
        </div>
        <div class="col-sm-7 panel panel-right">
          <AppGuichet 
          type="OUT"
          ref="GuichetOut"
          :working="false"
          :usb="usb_out"
          :files="filesOUT"
          @guichet-out-cleared="onGuichetOutCleared"
          />
        </div>
      </div>
    </div>
  </div>

  <footer v-if="this.debug" class="bg-dark container fixed-bottom p-0 d-inline-flex justify-content-around">
  
  <button :class="'btn btn-sm btn-'+ (this.has_signed_once ? 'primary' : 'secondary')" @click="this.has_signed_once = !this.has_signed_once">has_signed_once</button>
  <button :class="'btn btn-sm btn-'+ (this.StatusIn ? 'primary' : 'secondary')" @click="this.StatusIn = !this.StatusIn">StatusIn</button>
  <button :class="'btn btn-sm btn-'+ (this.StatusTransit ? 'primary' : 'secondary')" @click="this.StatusTransit = !this.StatusTransit">StatusTransit</button>
  <button :class="'btn btn-sm btn-'+ (this.StatusOut ? 'primary' : 'secondary')" @click="this.StatusOut = !this.StatusOut">StatusOut</button>
  <button :class="'btn btn-sm btn-'+ (this.analysingIN ? 'primary' : 'secondary')" @click="this.analysingIN = !this.analysingIN">analysingIN</button>
  <button :class="'btn btn-sm btn-'+ (this.filesIN.length > 0 ? 'primary' : 'secondary')" @click="this.filesIN = (this.filesIN.length > 0 ? [] : ['foo.jpg', 'bar.png', 'baz.pdf', 'zab.docx.ioerror'])">filesIN</button>
  <button :class="'btn btn-sm btn-'+ (this.analysingTRANSIT ? 'primary' : 'secondary')" @click="this.analysingTRANSIT = !this.analysingTRANSIT">analysingTRANSIT</button>
  <button :class="'btn btn-sm btn-'+ (this.analysingOUT ? 'primary' : 'secondary')" @click="if(this.analysingOUT) {this.analysingOUT = false; this.filesOUT = ['oof.jpg.sha256', 'oof.jpg', 'rab.png.sha256', 'rab.png', 'zab.pdf.krp', 'toto.png', 'toto.png.krp', 'tutu.png.krp'] } else { this.analysingOUT = true }">analysingOUT</button>
  <button :class="'btn btn-sm btn-'+ (this.filesOUT.length > 0 ? 'primary' : 'secondary')" @click="this.filesOUT = (this.filesOUT.length > 0 ? [] : ['oof.jpg', 'rab.png', 'zab.pdf'])">filesOUT</button>
  <button :class="'btn btn-sm btn-'+ (this.usb_in.length > 0 ? 'primary' : 'secondary')" @click="if(this.usb_in.length > 0) {this.usb_in = [];} else { this.analysingIN = true; this.filesIN = ['foo.jpg', 'bar.png', 'baz.pdf']; this.usb_in = ['NO-NAME', 'my_dongle']; }">usb_in</button>
  <button :class="'btn btn-sm btn-'+ (this.usb_out.length > 0 ? 'primary' : 'secondary')" @click="if(this.usb_out.length > 0) {this.usb_out = [];} else { this.usb_out = ['ma_cle_secure']; }">usb_out</button>
  <button :class="'btn btn-sm btn-'+ (this.yubikeys.active ? 'primary' : 'secondary')" @click="this.yubikeys.active = !this.yubikeys.active">yubi.active</button>
  <button :class="'btn btn-sm btn-'+ (this.yubikeys.yubikeys.length > 0 ? 'primary' : 'secondary')" @click="this.yubikeys.yubikeys.length > 0 ? this.yubikeys.yubikeys = [] : this.yubikeys.yubikeys = ['toto']">yubi.length</button>
  <div v-if="this.usb_undef != 0" >
      <div class="container text-warning text-center fw-bolder">
        {{ $t('main.usb_device.unregistered') }}
      </div>
    </div>
  </footer>
</template>

<script>
import AppHeader from "./components/AppHeader.vue";
import AppGuichet from "./components/AppGuichet.vue";
import AppWizard from "./components/AppWizard-fr.vue";

export default {
  //name: 'app',
  components: {
    AppHeader,
    AppGuichet,
    AppWizard
  },
  data() {
    return {
      debug: (process.env.NODE_ENV === 'development'),
      appStarted: false,
      StatusIn: undefined,
      StatusTransit: undefined,
      StatusOut: undefined,
      nameIN: undefined,
      analysingIN: undefined,
      filesIN: [],
      nameOUT: undefined,
      analysingTRANSIT: undefined,
      analysingOUT: undefined,
      filesOUT: [],
      connection: null,
      jsonMsg: null,
      usb_in: [],
      usb_out: [],
      usb_undef: [],
      yubikeys: {
        active: false,
        yubikeys: [],
      },
      openWizard: false,
      has_signed_once: true,
      ip: undefined,
    };
  },
  methods: {
    onGuichetInCleared() {
      this.$refs.GuichetIn.clearListIn();
    },
    onGuichetOutCleared() {
      this.$refs.GuichetIn.clearAllLists();
      this.$refs.GuichetOut.clearAllLists();
    },
    wsUdev() {
      this.connection_udev = new WebSocket("ws://127.0.0.1:3013/socket");
      this.connection_udev.onopen = function (event) {
        console.log(event);
        console.log("Successfully connected to websocket server udev");
      };
      var self = this;
      this.connection_udev.onmessage = function (event) {
        console.log(event.data),
          (self.usb_in = JSON.parse(event.data).usb_in),
          (self.usb_out = JSON.parse(event.data).usb_out),
          (self.usb_undef = JSON.parse(event.data).usb_undef),
          (self.yubikeys = JSON.parse(event.data).yubikeys)
        ;
      };

      //DEACTIVATED FOR DEV FRONT
      if(!this.debug) {
        //Connection error
        this.connection_udev.onerror = function () {
          console.log("wsUdev: connection error. Reconnecting...");
          self.wsUdev();
        };
        //Connection closed
        this.connection_udev.onclose = function () {
          console.log("wsUdev: connection closed. Reconnecting...");
          self.wsUdev();
        };
      }
    },
    wsBackend() {
      this.connection_backend = new WebSocket("ws://127.0.0.1:3012/socket");
      this.connection_backend.onopen = function (event) {
        console.log(event);
        console.log("Successfully connected to websocket server backend");
      };
      var self = this;
      this.connection_backend.onmessage = function (event) {
          let parsedData = JSON.parse(event.data);

          //JSON.parse(event.data = JSON.parse(event.data),
          console.log(event.data),
          //console.log(parsedData.health.In),
          //console.log(parsedData.health.Out),
          (self.ip = parsedData.ip),
          (self.has_signed_once = parsedData.has_signed_once),
          (self.StatusIn = parsedData.health.status_in),
          (self.StatusTransit = parsedData.health.status_transit),
          (self.StatusOut = parsedData.health.status_out),
          (self.nameIN = parsedData.guichetin.name),
          (self.analysingIN = parsedData.guichetin.analysing),
          (self.filesIN = parsedData.guichetin.files),
          (self.analysingTRANSIT = parsedData.guichettransit),
          (self.nameOUT = parsedData.guichetout.name),
          (self.analysingOUT = parsedData.guichetout.analysing),
          (self.filesOUT = parsedData.guichetout.files)
      };

      // DECTIVATED FOR DEV FRONT
      if(!this.debug) {
        //Connection error
        this.connection_backend.onerror = function () {
          console.log("wsBackend: connection error. Reconnecting...");
          self.wsBackend();
        };
        //Connection closed
        this.connection_backend.onclose = function () {
          console.log("wsBackend: connection closed. Reconnecting...");
          self.wsBackend();
        };
      }
    },
    updateState() {
      // Start app when all deamons are ready
      this.appStarted = this.appStarted || (this.StatusIn && this.StatusTransit && this.StatusOut);
    }
  },
  created() {
    this.wsUdev();
    this.wsBackend();

    if(this.debug) {
    // >>> For Dev Only >>>
      setTimeout(() => {
        this.StatusIn = true;
        this.StatusTransit = true;
        this.StatusOut = true;
      }, 2000);
    // <<< For Dev Only <<<
    }

    this.updateState();
  },
  updated() {
    this.updateState();
  },
  computed: {
    wizardMode: function () {
      return !this.has_signed_once || this.openWizard;
    },
    forcedWizardMode: function () {
      return !this.has_signed_once;
    }
  }
};
</script>

<style lang="scss">
@import "./assets/style/app.scss";

body {
	background: $grey-light;
}

#app {
	height: 100%;
}

.panel {
	min-height: 685px;
	padding: 30px 20px 15px;
	@include media-breakpoint-down(lg) {
		padding: 15px 12px 5px;
		min-height: 400px;
	}
	&-left {
		border-right: 1px solid $grey-medium;
	}
	&-right {
		border-left: 1px solid $white;
	}
}


</style>
