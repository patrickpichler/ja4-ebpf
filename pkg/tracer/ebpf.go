package tracer

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event -target arm64 tracer ./c/tracer.bpf.c -- -I../../c/headers -Wno-address-of-packed-member -O2 -fno-stack-protector
