BINARY := "apoch"
LDFLAGS := "-s -w"

build:
	rm -f $(BINARY)
	go build -ldflags $(LDFLAGS)

clean:
	rm -rf apoch completions/
