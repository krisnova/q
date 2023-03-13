# q

A smol 🤏 static rust binary which can be used to surface kernel queueing metrics with eBPF kprobes.

The easiest metrics to surface are anything found in the [sock](https://www.kernel.org/doc/html/v6.2/networking/kapi.html#c.sock) API.

The following 'accept queues' are currently instrumented.

 - [X] TCP/IPv4
 - [X] TCP/IPv6
 - [ ] UDP (Connectionless)
 - [ ] Unix domain

### Building 

```bash
# Compile the eBPF probe, embed the probe into the binary, compile and install the static binary
make ebpf install
```

### Running

```bash 
sudo q
```

### Observing The Linux Accept Queue

Execute the `dysfunctional-listen-not-accept-tcp-exec` server and send curl requests to `localhost:9064`.

Notice that the requests will accumulate in the accept queue even once the client has been killed. The only way to "flush" the queue is to terminate the server. I am currently unsure
if Linux provides another way to clean up these orphaned connections.

```bash 
[2023-03-13T04:50:35Z INFO  q] Success! Loaded eBPF probe into kernel
[2023-03-13T04:50:35Z INFO  q]  --> Attached: kprobe__tcp_conn_request
[2023-03-13T04:50:35Z INFO  q]  --> Attached: kprobe__inet_csk_accept
[2023-03-13T04:50:35Z INFO  q] Waiting for Ctrl-C...
[2023-03-13T04:50:44Z INFO  qprobe] AF_INET 'accept queue' qlen: 8, qmax: 4096, src address: 0.0.0.0, dest address: 0.0.0.0
[2023-03-13T04:50:48Z INFO  qprobe] AF_INET 'accept queue' qlen: 9, qmax: 4096, src address: 0.0.0.0, dest address: 0.0.0.0
[2023-03-13T04:50:50Z INFO  qprobe] AF_INET 'accept queue' qlen: 10, qmax: 4096, src address: 0.0.0.0, dest address: 0.0.0.0
[2023-03-13T04:50:51Z INFO  qprobe] AF_INET 'accept queue' qlen: 11, qmax: 4096, src address: 0.0.0.0, dest address: 0.0.0.0
```
