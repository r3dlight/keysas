PROJECT_NAME := "keysas"
BUILD_DIR := ./bin
YARA_RULES := /usr/share/keysas/

.PHONY: all test audit clippy build install install-core install-yararules uninstall help

all: test audit clippy build install

test: ## Run unittests
	@cargo test

audit:  ## Audit code and dependencies
	@cargo install cargo-audit
	@cargo audit

clippy:   ## Run clippy syntax checker
	@cargo clippy

build: ## Build the binary files
	@if [ ! -d "bin" ]; then mkdir ${BUILD_DIR}; fi
	@cargo build --release
	@cp target/release/${PROJECT_NAME}-in ${BUILD_DIR}
	@cp target/release/${PROJECT_NAME}-transit ${BUILD_DIR}
	@cp target/release/${PROJECT_NAME}-out ${BUILD_DIR}
	@cp target/release/${PROJECT_NAME}-sign ${BUILD_DIR}
	@cp target/release/${PROJECT_NAME}-backend ${BUILD_DIR}
	@cp target/release/${PROJECT_NAME}-io ${BUILD_DIR}
	@cp target/release/${PROJECT_NAME}-fido ${BUILD_DIR}
	@if [ ! -d "./${PROJECT_NAME}-core/bin" ]; then mkdir ./${PROJECT_NAME}-core/bin; fi
	@cp target/release/${PROJECT_NAME}-in ./${PROJECT_NAME}-core/bin/
	@cp target/release/${PROJECT_NAME}-transit ./${PROJECT_NAME}-core/bin/
	@cp target/release/${PROJECT_NAME}-out ./${PROJECT_NAME}-core/bin/
	@if [ ! -d "./${PROJECT_NAME}-io/bin" ]; then mkdir ./${PROJECT_NAME}-io/bin; fi
	@cp target/release/${PROJECT_NAME}-io ./${PROJECT_NAME}-io/bin/
	@if [ ! -d "./${PROJECT_NAME}-backend/bin" ]; then mkdir ./${PROJECT_NAME}-backend/bin; fi
	@cp target/release/${PROJECT_NAME}-backend ./${PROJECT_NAME}-backend/bin/
	@echo "build: ${PROJECT_NAME} is now compiled in bin directory !" 

clean: ## Remove previous build
	@if [ -d "bin" ]; then rm -fr ${BUILD_DIR}; fi
	@if [ -d "./${PROJECT_NAME}-core/bin" ]; then rm -fr ./${PROJECT_NAME}-core/bin; fi
	@if [ -d "./${PROJECT_NAME}-io/bin" ]; then rm -fr ./${PROJECT_NAME}-io/bin; fi
	@if [ -d "./${PROJECT_NAME}-backend/bin" ]; then rm -fr ./${PROJECT_NAME}-backend/bin; fi
	@if [ -d "target" ]; then rm -fr target; fi
	@cargo clean

install: ## Install keysas on your GNU/Linux OS (You need to be sudo).
	@echo "****************************************************************************"
	@echo "*      You need to be root or a sudo user  : type sudo make install         *" 
	@echo "****************************************************************************"
	@if [ -x ./${PROJECT_NAME}-core/Makefile ]; then cd ./${PROJECT_NAME}-core && make install; fi
	@if [ -x ./${PROJECT_NAME}-io/Makefile ]; then cd ./${PROJECT_NAME}-io && make install; fi
	@if [ -x ./${PROJECT_NAME}-backend/Makefile ]; then cd ./${PROJECT_NAME}-backend && make install; fi
	@install -v -o root -g root -m 0500 bin/${PROJECT_NAME}-sign /usr/bin/
	@install -v -o root -g root -m 0500 bin/${PROJECT_NAME}-manage-yubikey /usr/bin/

install-core: ## Only install the keysas-core for a network gateway (You need to be sudo).
	@echo "****************************************************************************"
	@echo "*      You need to be root or a sudo user  : type sudo make install-core   *" 
	@echo "****************************************************************************"
	@if [ -x ./${PROJECT_NAME}-core/Makefile ]; then cd ./${PROJECT_NAME}-core && make install; fi

install-yararules: ## Install various Yara rules from the internet (You need to be sudo).
	@echo "****************************************************************************"
	@echo "*   You need to be root or a sudo user  : type sudo make install-yararules *" 
	@echo "****************************************************************************"
	@if [ -d ${YARA_RULES}/rules ]; then mv ${YARA_RULES}/rules ${YARA_RULES}/rules.save; fi
	@if [ -d ${YARA_RULES} ]; then cd ${YARA_RULES} && git clone --depth=1 https://github.com/Yara-Rules/rules.git; fi
	@if [ -d ${YARA_RULES} ]; then cd ${YARA_RULES}/rules && git clone --depth=1 https://github.com/reversinglabs/reversinglabs-yara-rules.git; fi
	@if [ -d ${YARA_RULES} ]; then cd ${YARA_RULES}/rules && git clone --depth=1 https://github.com/elastic/protections-artifacts.git; fi
	@if [ -d ${YARA_RULES} ]; then cd ${YARA_RULES}/rules && ./index_gen.sh; fi
	
uninstall: ## Uninstall Keysas on your GNU/Linux OS, you need to be sudo !
	@echo "*************************************************************************" 
	@echo "*      You need to be root or a sudo user  : type sudo make uninstall   *"
	@echo "*************************************************************************" 
	@if [ -x ./${PROJECT_NAME}-core/Makefile ]; then cd ./${PROJECT_NAME}-core && make uninstall; fi
	@if [ -x ./${PROJECT_NAME}-ui/Makefile ]; then cd ./${PROJECT_NAME}-ui && make uninstall; fi
	@rm /usr/bin/${PROJECT_NAME}-sign | true
	@rm /usr/bin/${PROJECT_NAME}-manage-yubikey | true

help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
