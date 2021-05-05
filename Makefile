.PHONY: test
test:
	rm -rf server/db/ && go test ./server/... -race -v -timeout 5m

.PHONY: clean
clean:
	rm -rf db/
