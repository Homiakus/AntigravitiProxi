.PHONY: test vet build windows linux clean

test:
	go test ./...

vet:
	go vet ./...

build:
	go build -trimpath -o dist/antigraviti-proxi ./cmd/antigraviti-proxi

windows:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o dist/antigraviti-proxi-windows-amd64.exe ./cmd/antigraviti-proxi

linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o dist/antigraviti-proxi-linux-amd64 ./cmd/antigraviti-proxi

clean:
	rm -rf dist
