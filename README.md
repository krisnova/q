# snoopkit

Surface Linux networking metrics with eBPF

 - Small C server that just calls `listen()` and never accepts
 - Curl the server to "simulate and inbound request"
 - Report accept queue length at runtime with eBPF
   - Userspace program (snoopkit)
   - eBPF probe (instrument?)

