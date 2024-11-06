docker run --rm -v "$PWD":/usr/src/myapp -w /usr/src/myapp -e GOOS=darwin golang:1.23 go build -v
