SHELL:=/bin/sh
.PHONY: all

app_name="kernelsnoop"

help: ## this help
	@awk 'BEGIN {FS = ":.*?## ";  printf "Usage:\n  make \033[36m<target> \033[0m\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*?## / {gsub("\\\\n",sprintf("\n%22c",""), $$2);printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

update-deps: ## Update dependencies
	go get -u ;\
	go mod tidy

go-generate: ## Run go generate
	go generate ./...

run: go-generate update-deps ## Run the application
	CGO_ENABLED=0 GOARCH=amd64 sudo go run main.go

build-run: go-generate update-deps ## Run the application
	CGO_ENABLED=0 GOARCH=amd64 go build && sudo ./ebpfw