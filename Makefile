GO_BUILD = go build -o
EXECUTABLE = mpmserver
CGO = 0

.PHONY: build
build:
	CGO_ENABLED=$(CGO) $(GO_BUILD) $(EXECUTABLE) main.go

.PHONY: test
test:
	rm -rf server/db/ && go test ./server/... -race -v -timeout 5m

.PHONY: clean
clean:
	rm -rf db/
