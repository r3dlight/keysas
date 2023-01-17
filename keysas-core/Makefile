PROJECT_NAME := "keysas-core"

.PHONY: all test audit clippy build install uninstall usbinstall usbuninstall help

all: test audit clippy build install

test: ## Run unittests
	@cargo test

audit:  ## Audit code and dependencies
	@cargo install cargo-audit
	@cargo audit

clippy:   ## Run clippy syntax checker
	@cargo clippy

build: ## Build the binary files
	@if [ ! -d "bin" ]; then mkdir bin; fi
	@cargo build --release
	@cp target/release/keysas-in bin/
	@cp target/release/keysas-transit bin/
	@cp target/release/keysas-out bin/
	@echo "build: Keysas-core is now compiled in bin directory !" 

clean: ## Remove previous build
	@if [ -d "bin" ]; then rm -fr bin; fi

install: ## Install Keyas on your GNU/Linux OS, you need to be sudo !
	@echo "****************************************************************************"
	@echo "*      You need to be root or a sudo user  : type sudo make install         *" 
	@echo "****************************************************************************"
	@if [ -x sh/install.sh ]; then ./sh/install.sh; fi


uninstall: ## Uninstall Keysas on your GNU/Linux OS, you need to be sudo !
	@echo "*************************************************************************" 
	@echo "*      You need to be root or a sudo user  : type sudo make uninstall   *"
	@echo "*************************************************************************" 
	@if [ -x sh/uninstall.sh ]; then ./sh/uninstall.sh; fi

help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

