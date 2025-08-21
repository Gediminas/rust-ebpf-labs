# PoC AF_XDP Kernel Network Bypass

PoC: Network packets redirection to AF_XDP to bypass kernel network stack; using [xdpilone](https://docs.rs/xdpilone)


## Build & Run

[Requirements](../#Requirements)

```sh
just run --iface lo  # Terminal-1
just traffic         # Terminal-2
```

## Dev

```sh
just run-dev         # Terminal-1
just traffic-dev     # Terminal-2
```
