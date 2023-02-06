<template>
  <nav class="AppHeader-navbar">
    <div class="container">
      <div class="row">
        <div class="col-sm-3">
          <div class="AppHeader-logo">
            <img src="../assets/img/logo-keysas.png" alt="Logo Keysas" />
          </div>
        </div>

        <div class="col-sm-6">
          <div v-if="!wizardMode"  :class="'AppHeader-status AppHeader-status-' + $t(appStateColor)">
            {{ $t(appStateMessage) }}
          </div>
          <div v-if="!wizardMode" class="AppHeader-instruction">
            {{ $t(appStateInstruction) }}
          </div>
        </div>

        <div :class="'offset-md-1 col-md-1 AppHeader-yubikey '+(yubikeys.yubikeys.length > 0 ? '' : 'AppHeader-yubikey-none')">
          <span v-if="yubikeys.active" >
            <img src="../assets/img/yubi.png" />
          </span>
        </div>

        <div v-if="!forcedWizardMode" class="col-md-1 AppHeader-menu">
          <div class="dropdown float-end">
            <button class="btn btn-cyan" type="button" id="dropdownMenu" data-bs-toggle="dropdown" aria-expanded="false">
              <img src="../assets/img/burger.png" alt="Menu" />
            </button>
            <ul class="dropdown-menu" aria-labelledby="dropdownMenu">
              <li v-if="analysingIN || analysingTRANSIT || analysingOUT">
                <span class="dropdown-item">🟠 {{ $t('header.menu.working') }}</span>
              </li>
              <li v-else>
                <span class="dropdown-item">🟢 {{ $t('header.menu.ready') }}</span>
              </li>
              <li>
                <button class="dropdown-item" type="button" @click="reload()">🔄 {{ $t('header.menu.reload') }}</button>
              </li>
              <li v-if="!wizardMode">
                <button class="dropdown-item" type="button" @click="$emit('openWizard', true)">{{ $t('header.menu.show_wizard') }}</button>
              </li>
              <li v-if="wizardMode">
                <button class="dropdown-item" type="button" @click="$emit('openWizard', false)">{{ $t('header.menu.close_wizard') }}</button>
              </li>
            </ul>
          </div>
        </div>

      </div>
    </div>
  </nav>
</template>

<script>
export default {
  name: "AppHeader",
  props: [
    "wizardMode",
    "forcedWizardMode",
    "analysingIN",
    "analysingOUT",
    "usb_in",
    "usb_out",
    "yubikeys",
    "filesOUT",
    "filesIN",
    "deamonStatus",
    "analysingTRANSIT",
  ],
  watch: {
    analysingIN() { this.updateStatus() },
    analysingOUT() { this.updateStatus() },
    usb_in() { this.updateStatus() },
    usb_out() { this.updateStatus() },
    filesOUT() { this.updateStatus() },
    filesIN() { this.updateStatus() },
    deamonStatus() { this.updateStatus() },
    analysingTRANSIT() { this.updateStatus() },
  },
  data() {
    return {
      previousAnalysingIN: false,
      appStateColor: 'header.app.state.starting.color',
      appStateMessage: 'header.app.state.starting.message',
      appStateInstruction: 'header.app.state.starting.instruction',
    };
  },
  methods: {
    created() {
    },
    reload:function(){
      window.location.reload();
    },
    updateStatus() {
      if (this.previousAnalysingIN === undefined) {
        this.previousAnalysingIN = false;
      }

      if (this.previousAnalysingIN === false && this.analysingIN) {
        this.previousAnalysingIN = true;
      }

      if (this.usb_in.length > 0 && this.analysingIN) {
        this.appStateColor = 'header.app.state.reading_device_content.color';
        this.appStateMessage = 'header.app.state.reading_device_content.message';
        this.appStateInstruction = 'header.app.state.reading_device_content.instruction';
        return;
      }

      // Vu qu'on n'est pas vraiment sur une machine d'état (3 démons indépendants), on va la simuler pour l'expérience utilisateur
      // Si les démons sont off, on ne va pas plus loin, on affiche une erreur
      if (!this.deamonStatus) {
        this.appStateColor = 'header.app.state.deamon_down.color';
        this.appStateMessage = 'header.app.state.deamon_down.message';
        this.appStateInstruction = 'header.app.state.deamon_down.instruction';
        return;
      }

      // L'analyse des fichiers de la clé d'entrée est finie
      if (this.usb_in.length > 0 && this.previousAnalysingIN === true && this.analysingIN === false) {
        this.appStateColor = 'header.app.state.transfer_complete.color';
        this.appStateMessage = 'header.app.state.transfer_complete.message';
        this.appStateInstruction = 'header.app.state.transfer_complete.instruction';
        this.previousAnalysingIN = false;
        return;
      }

      this.previousAnalysingIN = this.analysingIN;

      // L'utilisateur n'a pas la visibilité des stades de l'analyse (il peut le voir éventuellement sur le détail du guichet)
      // if (this.analysingIN || (this.usb_out.length > 0 && this.analysingOUT)) {
      // SNE: pas besoin d'ajouter this.usb_out.length dans les conditions. this.analysingIN et (this.analysingOUT suffisent
      if (this.analysingIN || this.analysingOUT) {
        this.appStateColor = 'header.app.state.analysing_files.color';
        this.appStateMessage = 'header.app.state.analysing_files.message';
        this.appStateInstruction = 'header.app.state.analysing_files.instruction';
        return;
      }

      // Si on n'analyse rien et qu'on a une clé IN et des fichiers OUT, c'est qu'on a fini le transfert et l'analyse
      // SNE: si on analyse rien, du coup this.analysingIN et this.analysingOUT sont à false :)
      if (this.filesOUT.length > 0 && this.usb_in.length > 0 && this.analysingIN === false && this.analysingOUT === false) {
        this.appStateColor = 'header.app.state.transferred_and_analysed.color';
        this.appStateMessage = 'header.app.state.transferred_and_analysed.message';
        this.appStateInstruction = 'header.app.state.transferred_and_analysed.instruction';
        return;
      }

      // Si on n'analyse rien et qu'on a une clé OUT et des fichiers OUT, on est en train de transférer les fichiers vers la clé
      // SNE: OK là ca fonctionne aussi effectivement avec la taille du tableau de fichier
      if (this.usb_out.length > 0 && this.filesOUT.length > 0) {
        this.appStateColor = 'header.app.state.writing_device_content.color';
        this.appStateMessage = 'header.app.state.writing_device_content.message';
        this.appStateInstruction = 'header.app.state.writing_device_content.instruction';
        return;
      }

      // Si on n'analyse rien et qu'on a une clé OUT et pas de fichiers OUT, on a fini de transférer les fichiers vers la clé
      // SNE: idem ici
      if (this.usb_out.length > 0 && this.filesOUT.length === 0) {
        this.appStateColor = 'header.app.state.transfer_complete.color';
        this.appStateMessage = 'header.app.state.transfer_complete.message';
        this.appStateInstruction = 'header.app.state.transfer_complete.instruction';
        return;
      }

      // Si on n'est pas dans les états précédents, c'est que l'app est prête à recevoir une clé
      this.appStateColor = 'header.app.state.ready.color';
      this.appStateMessage = 'header.app.state.ready.message';
      this.appStateInstruction = 'header.app.state.ready.instruction';
      return;
    },
  },
};
</script>

<style lang="scss">
@import "../assets/style/app.scss";

.AppHeader-navbar {
  background-color: $navy;
  height: 80px;
  @include media-breakpoint-down(lg) {
    height: 65px;
  }
}
.AppHeader-logo img {
  height: 35px;
  margin-top: 18px;
  margin-right: 20;
  @include media-breakpoint-down(lg) {
    height: 45px;
    margin-top: 10px;
  }
}
.AppHeader-status {
  text-align: center;
  border-radius: 0 0 5px 5px;
  padding: 2px;
  text-transform: uppercase;
  font-size: 0.9rem;
  @include media-breakpoint-down(lg) {
    font-size: 0.75rem;
  }
  &-off {
    display: none;
  }
  &-ok {
    color: $status-ok;
    background-color: $status-bg-ok;
  }
  &-working {
    color: $status-working;
    background-color: $status-bg-working;
  }
  &-inactive {
    color: $status-off;
    background-color: $status-bg-off;
  }
  &-danger {
    color: $status-danger;
    background-color: $status-bg-danger;
  }
}
.AppHeader-instruction {
  padding-top: 10px;
  text-align: center;
  font-size: 0.95em;
  color: $white;
}

.AppHeader-yubikey {
  span {
    margin-top: 20px;
    background-color: $status-bg-ok;
    border-radius: 5px;
    float: right;

    @include media-breakpoint-down(lg) {
      margin-top: 12px !important;
    }

    img {
      padding: 10px;
      height: 40px !important;
      width: auto !important;
    }
  }
  &.AppHeader-yubikey-none {
    span {
      background-color: $status-bg-danger;
    }
    img {
      opacity: 0.5;
    }
  }
}

.AppHeader-menu {
  margin-top: 20px !important;
  @include media-breakpoint-down(lg) {
    margin-top: 12px !important;
  }
  img {
    height: 25px;
    width: 25px;
  }
}

</style>
