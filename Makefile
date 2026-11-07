# oagentkit/guardx —— 与共享 CI(oagentkit/.github go-ci.yml)同口径的本地门禁载体(agentkit#138)
.PHONY: test test-race test-coverage lint fmt vet ci tidy first-party-dep help

## test: 运行所有单元测试
test:
	go test ./...

## test-race: 运行竞态检测测试
test-race:
	go test -race ./...

## test-coverage: 生成测试覆盖率报告
test-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

## lint: 运行 golangci-lint（需要先安装）
lint:
	golangci-lint run ./...

## fmt: 格式化所有 Go 文件
fmt:
	gofmt -s -w .
	goimports -w .

## vet: 运行 go vet
vet:
	go vet ./...

## first-party-dep: 零第三方依赖硬规则检查（go list -m all 仅允许本模块 + github.com/oekit/* 白名单，对应 AGENTS.md）
first-party-dep:
	@bad=$$(GOWORK=off go list -m all | grep -v -e '^github.com/oagentkit/guardx$$' -e '^github.com/oekit/' || true); \
	if [ -n "$$bad" ]; then \
		echo "零第三方依赖硬规则被违反：go list -m all 出现白名单之外的模块："; \
		echo "$$bad"; \
		exit 1; \
	fi; \
	echo "first-party-dep: OK（仅本模块 + github.com/oekit/* 第一方基座，零第三方依赖）"

## ci: 模拟 CI 流程（first-party-dep + fmt 检查 + vet + test-race），与共享 CI go-ci.yml 同口径
ci:
	@$(MAKE) --no-print-directory first-party-dep
	@test -z "$$(gofmt -l . | grep -v vendor | tee /dev/stderr)" || (echo "请运行 make fmt" && exit 1)
	go vet ./...
	go test -race -count=1 ./...

## tidy: 整理 go.mod
tidy:
	go mod tidy

## help: 显示帮助
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //'
