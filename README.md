# Q

A single rust binary which can be used to surface Kernel queue metrics. 

### Building 

```bash
# Compile the eBPF probe, embed the probe into the binary, and install the binary
make ebpf install
```

### Running

```bash 
sudo q
```