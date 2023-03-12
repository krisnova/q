# q

A smol 🤏 static rust binary which can be used to surface kernel queueing and latency metrics.

### Building 

```bash
# Compile the eBPF probe, embed the probe into the binary, compile and install the static binary
make ebpf install
```

### Running

```bash 
sudo q
```