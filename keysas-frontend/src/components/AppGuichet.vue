<template>
    <h2>
      {{ $t('guichet_'+type+'.is_'+(this.working ? 'working' : 'ready')) }}
    </h2>

    <!-- USB Key list -->
    <div :class="'AppGuichet-item AppGuichet-item-' + (this.usb.length > 0 ? 'active' : 'inactive') + ' AppGuichet-device AppGuichet-device-'+this.type">
      <div class="AppGuichet-item-head">
        <span class="check-icon" />
        <p>
          {{ $t('guichet_'+type+'.usb_device.'+(this.usb.length > 0 ? 'connected' : 'not_found')) }}
        </p>
      </div>
      <ul v-if="this.usb.length > 0">
        <li v-for="(device, index) in this.usb" v-bind:key="index"> {{ device }}</li>
      </ul>
    </div>

    <!-- Status Guichet IN -->
    <div v-if="this.type === 'IN'">
      <div v-if="this.working" class="AppGuichet-item AppGuichet-item-working AppGuichet-files">
        <div class="AppGuichet-item-head">
          <span class="working-icon" />
          <p>{{ $t('guichet_IN.tasks.analysing_files') }}</p>
        </div>
      </div>
      <div v-else-if="this.listInBackup.length === 0" class="AppGuichet-item AppGuichet-item-inactive AppGuichet-files">
        <div class="AppGuichet-item-head">
          <p>{{ $t('guichet_IN.files.not_found') }}</p>
        </div>
      </div>
      <div v-else class="AppGuichet-item AppGuichet-item-active AppGuichet-files">
        <div class="AppGuichet-item-head">
          <span class="check-icon" />
          <p>
            {{ $tc('guichet_IN.files.x_files_analysed', this.listInBackup.length) }}
          </p>
        </div>
      </div>
    </div>

    <!-- Status Guichet OUT -->
    <div v-if="this.type === 'OUT'">
      <div v-if="this.files.length === 0" class="AppGuichet-item AppGuichet-item-inactive AppGuichet-files">
        <div class="AppGuichet-item-head">
          <p>{{ $t('guichet_OUT.files.not_found') }}</p>
        </div>
      </div>
      <div v-else-if="this.usb.length > 0" class="AppGuichet-item AppGuichet-item-working AppGuichet-files">
        <div class="AppGuichet-item-head">
          <span class="working-icon" />
          <p >{{ $t('guichet_OUT.tasks.transferring_files') }}</p>
        </div>
      </div>
      <div v-else class="AppGuichet-item AppGuichet-item-active AppGuichet-files">
        <div class="AppGuichet-item-head">
          <span class="check-icon" />
          <p>
            {{ $tc('guichet_OUT.files.x_files_ready_for_transfer', this.listOutOK.length) }}
          </p>
        </div>
      </div>
    </div>

    <!-- List Detail visibility switchers -->
    <h5 v-if="this.type === 'IN' && this.listInBackup.length > 0" class="AppGuichet-switcher">
      <a @click="this.displayDetail = !this.displayDetail" :class="this.displayDetail ? 'AppGuichet-switcher-active' : null">
        {{ $t('guichet_IN.files.list.'+(this.displayDetail ? 'hide' : 'show')) }}
      </a>
    </h5>
    <h5 v-else-if="this.type === 'OUT' && (this.listOutOK.length > 0 || this.listOutError.length > 0)" class="AppGuichet-switcher">
      <a @click="this.displayErrors = false" :class="(this.displayErrors ? null : 'AppGuichet-switcher-active') + ' AppGuichet-switcher-first'">
        {{ $tc('guichet_OUT.files.x_files_verified_available', this.listOutOK.length) }}
      </a>
      <a @click="this.displayErrors = true" :class="this.displayErrors ? 'AppGuichet-switcher-active' : null">
        {{ $tc('guichet_OUT.files.x_files_refused', this.listOutError.length) }}
      </a>
    </h5>

    <!-- List Detail -->
    <ul v-if="this.type === 'IN' && this.listInBackup.length > 0 && this.displayDetail" class="AppGuichet-list list-group">
      <li class="list-group-item list-in" v-for="(file, index) in this.listInBackup" v-bind:key="index">{{ file.filename }}<span class="file-error">{{ file.error ? $t(file.error) : '' }}</span></li>
    </ul>
    <ul v-if="this.type === 'OUT' && this.listOutOK.length > 0 && !this.displayErrors" class="AppGuichet-list list-group">
      <li class="list-group-item list-out" v-for="(file, index) in this.listOutOK" v-bind:key="index">{{ file.filename }}<span class="file-error">{{ file.error ? $t(file.error) : '' }}</span></li>
    </ul>
    <ul v-if="this.type === 'OUT' && this.listOutError.length > 0 && this.displayErrors" class="AppGuichet-list list-group">
      <li class="list-group-item list-out-error" v-for="(file, index) in this.listOutError" v-bind:key="index">{{ file.filename }}<span class="file-error">{{ $t(file.error) }}</span></li>
    </ul>

    <!-- USB IN Help placeholder -->
    <div v-if="this.type === 'IN' && this.usb.length === 0 && this.listInBackup.length === 0" class="AppGuichet-plugMessage">
      <p>{{ $t('guichet_IN.usb_device.insert_placeholder') }}</p>
      <img src="../assets/img/big-top-arrow.png" />
    </div>
</template>

<script>
export default {
  name: "AppGuichet",
  props: [
    "type",
    "working",
    "usb",
    "files",
  ],
  data() {
    return {
      displayDetail: false,
      displayErrors: false,
      listInBackup: [],
      listOutOK: [],
      listOutError: [],
    }
  },
  emits: ['guichetInCleared', 'guichetOutCleared'],
  methods: {
    clearAllLists() {
      this.listInBackup = [];
      this.listOutOK = [];
      this.listOutError = [];
      return;
    },
    clearListIn() {
      this.listInBackup = [];
      return;
    }
  },
  watch: {
    files(val, oldVal) {
      let errorsMessages = {
        '.antivirus': 'guichet_OUT.files.error.reason.antivirus',
        '.forbidden': 'guichet_OUT.files.error.reason.forbidden',
        '.yara': 'guichet_OUT.files.error.reason.yara',
        '.toobig': 'guichet_OUT.files.error.reason.toobig',
        '.failed': 'guichet_OUT.files.error.reason.failed',
      };

      if(this.type === 'IN') {
        if(val.length === 0 && oldVal.length > 0) {
          setTimeout(() => {
            this.$emit('guichetInCleared');
          }, 5000);
          return;
        }

        val.forEach(element => {
          let failed = element.endsWith('.failed');
          let slicedElement = failed ? element.substring(0, element.indexOf('.failed')) : element;

          if(!this.listInBackup.map(x => x.filename).includes(slicedElement)) {
            this.listInBackup.push({
              filename: slicedElement,
              error: failed ? errorsMessages['.failed'] : null
            });
          }
        });
        return;
      }

      if(this.type === 'OUT') {
        if(val.length === 0 && oldVal.length > 0) {
          this.$emit('guichetOutCleared');
          return;
        }

        val.forEach(element => {
          if(element.endsWith('.sha256')) {
            return;
          }

          // handling Yara case
          if (element.endsWith('.yara')) {
            let slicedElement = element.substring(0, element.indexOf('.yara'));
            let list = val.includes(slicedElement) ? this.listOutOK : this.listOutError;
            if (!list.map(x => x.filename).includes(slicedElement)) {
              list.push({
                filename: slicedElement,
                error: errorsMessages['.yara']
              });
            }
            return;
          }

          let fileProcessed = false;
          Object.entries(errorsMessages).forEach(([key,message]) => {
            if(element.endsWith(key)) {
              let slicedElement = element.substring(0, element.indexOf(key));
              if(!this.listOutError.map(x => x.filename).includes(slicedElement)) {
                this.listOutError.push({
                  filename: slicedElement,
                  error: message
                });
              }
              fileProcessed = true;
            }
          })

          if (!fileProcessed && !this.listOutOK.map(x => x.filename).includes(element)) {
            this.listOutOK.push({
              filename: element,
              error: null,
            });
          }
        });
      }
    },
  }
}
</script>

<style lang="scss">
@import "../assets/style/app.scss";

.AppGuichet-item {
	padding: 20px;
	margin-top: 15px;
	border-radius: 5px;
	@include media-breakpoint-down(lg) {
		padding: 11px;
		margin-top: 10px;
	}

.AppGuichet-item-head {
	display: flex;
	align-items: center;
	justify-content: flex-start;

	& > .working-icon,
	& > .check-icon {
		margin-right: 13px;
		display: inline-block;
		min-width: 32px;
		min-height: 32px;
		flex-basis: 32px;
		background-color: white;
		border-radius: 16px;
		background-repeat: no-repeat;
		background-position: center;
	}
	& > .working-icon {
		background-image: url("../assets/img/hourglass.svg");
	}
	& > .check-icon {
		display: none;
		background-image: url("../assets/img/check.svg");
	}
}

& > p {
	display: inline-block;
	vertical-align: top;
	line-height: 1rem;
}

&-active {
	color: $status-ok;
	background-color: $status-bg-ok;
	ul {
		color: $status-ok-light;
	}
	.AppGuichet-item-head > .check-icon {
		display: inline-block;
	}
}
  &-working {
  	color: $status-working;
  	background-color: $status-bg-working;
  }
  &-inactive {
  	color: $status-off;
  	background-color: $status-bg-off;
  }

  p {
  	margin: 0;
  	font-size: 0.85rem;
  }
  ul {
  	font-size: 0.8rem;
  	list-style-type: none;
  	padding-top: 0.5rem;
  	padding-left: 0;
  	margin-bottom: 0;
  }
}

.AppGuichet-device {
	position: relative;
	overflow: hidden;

	&:before {
		content: " ";
		position: absolute;
		top: 0;
		left: 0;
		height: 100%;
		width: 100%;
		opacity: 0.15;
		background-repeat: no-repeat;
	}

	&-IN:before {
		background-position: 93% 110%;
		background-size: 25px auto;
		background-image: url("../assets/img/usbkey.svg");
		@include media-breakpoint-down(lg) {
			background-size: 20px auto;
		}
	}

	&-OUT:before {
		background-position: 95% 110%;
		background-size: 32px auto;
		background-image: url("../assets/img/usbkey-signed.svg");
		@include media-breakpoint-down(lg) {
			background-size: 25px auto;
		}
	}

	ul {
		margin-left: 45px;
		margin-top: -10px;
	}
}

.AppGuichet-files {
	position: relative;
	overflow: hidden;

	&:before {
		content: " ";
		position: absolute;
		top: 0;
		left: 0;
		height: 100%;
		width: 100%;
		opacity: 0.15;
		background-repeat: no-repeat;
		background-position: 95% 120%;
		background-size: 36px auto;
		background-image: url("../assets/img/document.svg");
		@include media-breakpoint-down(lg) {
			background-size: 25px auto;
		}
	}
}

.AppGuichet-switcher {
	margin: 18px 0 6px;
	@include media-breakpoint-down(lg) {
		margin: 10px 0 6px;
	}
	a {
		padding: 0 0 0 15px;
		font-weight: 400;
		color: $grey-medium;
		&:first-of-type {
			padding: 0 15px 0 0;
		}
		&.AppGuichet-switcher-first {
			border-right: 1px solid $grey-medium;
		}
		&.AppGuichet-switcher-active {
			font-weight: 700;
			color: $grey-dark;
		}
	}
}

.AppGuichet-list {
	margin-top: 10px;
	font-size: 0.75rem;
	overflow-y: scroll;
	max-height: 230px;
	border: 1px solid $grey-dark;
	@include media-breakpoint-down(lg) {
		max-height: 150px;
	}

	.list-out-error,
	.list-in,
	.list-out {
		display: flex;
		justify-content: space-between;

		.file-error {
			color: indianred;
			padding-left: 5px;
		}
	}
}

.AppGuichet-plugMessage {
	text-align: center;
	p {
		color: $grey-medium;
		font-size: 1.1rem;
		margin: 30px auto;
	}
	@include media-breakpoint-down(lg) {
		img {
			height: 60px;
		}
		p {
			font-size: 0.9rem;
		}
	}
}


</style>
