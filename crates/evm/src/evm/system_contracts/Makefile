.PHONY: help

help: ## Display this help message
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Set genesis from system contract source files
genesis:
	forge script script/GenesisGenerator.s.sol:GenesisGenerator --ffi

genesis-prod:
	forge script script/GenesisGenerator.s.sol:GenesisGenerator --ffi --sig "runProd()"