PROJECT_NAME := "Keysas-ui"

.PHONY: all install uninstall help

all: install


install: ## Install Keyas-ui on your GNU/Linux OS, you need to be sudo !
	@echo "****************************************************************************"
	@echo "*      You need to be root or a sudo user  : type sudo make install         *" 
	@echo "****************************************************************************"
	@if [ -x sh/install.sh ]; then ./sh/install.sh; fi


uninstall: ## Uninstall Keysas-ui on your GNU/Linux OS, you need to be sudo !
	@echo "*************************************************************************" 
	@echo "*      You need to be root or a sudo user  : type sudo make uninstall   *"
	@echo "*************************************************************************" 
	@if [ -x sh/uninstall.sh ]; then ./sh/uninstall.sh; fi

help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

