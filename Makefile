build:
	go build -o bin/scanner ./cmd/scanner

run:
	go run ./cmd/scanner

clean:
	rm -rf bin/
