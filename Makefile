.PHONY: gen-bpf gen-compile-commands
gen-bpf:
	go generate ./...

gen-compile-commands:
	@bear --force-wrapper -- make gen-bpf
