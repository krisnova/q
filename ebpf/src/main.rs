#![no_std]
#![no_main]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod binding;
use crate::binding::{sk_buff, sk_buff_head, sock, sock_common};
use aya_bpf::{helpers::bpf_probe_read_kernel, macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::info;

#[link_section = "license"]
#[used]
pub static LICENSE: [u8; 4] = *b"GPL\0";

// Taken from 6.2 headers /include/linux/socket.h
// https://github.com/torvalds/linux/blob/v6.2/include/linux/socket.h
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

// Areas to instrument:
// All of the implementation of this code can be found in /net/ipv4/*.c
// Most of the layer 3 IP code is in /net/ipv4/inet_connection_sock.c
// The layer 4 connection code is in /net/ipv4/tcp_input.c
// -----------------------------------------------------------------------
// [X] tcp_connect (outbound)          // example will be removed
// [ ] inet_csk_listen_start (inbound) // listen()                 layer 3
// [X] tcp_conn_request (inbound)      // New connection received  layer 4
// [X] inet_csk_accept (inbound)       // accept()                 layer 3
// -----------------------------------------------------------------------
//
// Also areas to consider:
//
// - https://github.com/torvalds/linux/blob/v6.2/net/ipv4/tcp_fastopen.c#L238
//     - Looks like this is specifically where children are added to TFO
// - https://github.com/torvalds/linux/blob/v6.2/net/ipv4/tcp_fastopen.c#L296
//     - Looks like this is a function that is used to check the length
//
// Outstanding Work:
//
// We need to read the qlen off the inet const struct sock *sk as seen in
// tcp_fastopen_queue_check()
//
// acceptq = &inet_csk(sk)->icsk_accept_queue->qlen
//
// and log this (just need to decide where)

// q_tcp_fastopen_queue_check
#[kprobe(name = "q_tcp_fastopen_queue_check")]
pub fn q_tcp_fastopen_queue_check(ctx: ProbeContext) -> u32 {
    // sock_common (tcp_connect)
    match try_tcp_fastopen_queue_check(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

fn try_tcp_fastopen_queue_check(ctx: ProbeContext) -> Result<u32, i64> {
    // let sock: *mut sock = ctx.arg(0).ok_or(1i64)?;
    // let sk_common = unsafe {
    //     bpf_probe_read_kernel(&(*sock).__sk_common as *const sock_common).map_err(|e| e)?
    // };
    // log_sock(ctx, sk_common);
    Ok(0)
}

// q_inet_csk_accept
//
// struct sock *sk, int flags, int *err, bool kern
//
// Research:
//
// Confirmed that this kprobe will execute when a client sends a HTTP
// request to a server that calls accept() after the server has begun listening
// for new connections. It is safe to assume that if this function has been
// executed an element has been removed from the corresponding "accept queue".
#[kprobe(name = "q_inet_csk_accept")]
pub fn q_inet_csk_accept(ctx: ProbeContext) -> u32 {
    // sock_common (tcp_connect)
    match try_inet_csk_accept(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

fn try_inet_csk_accept(ctx: ProbeContext) -> Result<u32, i64> {
    // arg 0 -> struct sock *sk
    // arg 1 -> int flags
    // arg 2 -> int *err
    // arg 3 -> bool kern
    let sock: *mut sock = ctx.arg(2).ok_or(1i64)?;
    let sk_common = unsafe {
        bpf_probe_read_kernel(&(*sock).__sk_common as *const sock_common).map_err(|e| e)?
    };
    let qlen =
        unsafe { bpf_probe_read_kernel(&(*sock).sk_ack_backlog as *const u32).map_err(|e| e)? };
    let _qmax =
        unsafe { bpf_probe_read_kernel(&(*sock).sk_max_ack_backlog as *const u32).map_err(|e| e)? };
    log_q(ctx, sk_common, qlen);
    Ok(0)
}

// q_tcp_conn_request
//
// int tcp_conn_request(struct request_sock_ops *rsk_ops,
//                      const struct tcp_request_sock_ops *af_ops,
//                      struct sock *sk, struct sk_buff *skb)
//
// Research:
//
// Confirmed that this kprobe will execute when a client sends a HTTP
// request to a server that calls listen() but has not yet accepted()
// a connection.
//
// This is the "entry point" for all new inbound connections "coming off the wire"
// in the Net Device subsystem (tcpdump and wireshark)
//
// According to (https://www.kernel.org/doc/html/v4.16/networking/kapi.html)
// the sock.sk_ack_backlog is the "current listen backlog" which the name
// corresponds to the TCP states we can expect to find connections in the accept
// queue.
#[kprobe(name = "q_tcp_conn_request")]
pub fn q_tcp_conn_request(ctx: ProbeContext) -> u32 {
    // sock_common (tcp_connect)
    match try_tcp_conn_request(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

fn try_tcp_conn_request(ctx: ProbeContext) -> Result<u32, i64> {
    // arg 0 -> struct request_sock_ops *rsk_ops
    // arg 1 -> const struct tcp_request_sock_ops *af_ops
    // arg 2 -> struct sock *sk
    // arg 3 -> struct sk_buff *skb
    let sock: *mut sock = ctx.arg(2).ok_or(1i64)?;
    let sk_common = unsafe {
        bpf_probe_read_kernel(&(*sock).__sk_common as *const sock_common).map_err(|e| e)?
    };
    let qlen =
        unsafe { bpf_probe_read_kernel(&(*sock).sk_ack_backlog as *const u32).map_err(|e| e)? };
    let _qmax =
        unsafe { bpf_probe_read_kernel(&(*sock).sk_max_ack_backlog as *const u32).map_err(|e| e)? };
    log_q(ctx, sk_common, qlen);
    Ok(0)
}

// Generic method to log a queue structure
//
// pub struct sk_buff {
//     pub __bindgen_anon_1: sk_buff__bindgen_ty_1,
//     pub __bindgen_anon_2: sk_buff__bindgen_ty_2,
//     pub __bindgen_anon_3: sk_buff__bindgen_ty_3,
//     pub cb: [::aya_bpf::cty::c_char; 48usize],
//     pub __bindgen_anon_4: sk_buff__bindgen_ty_4,
//     pub _nfct: ::aya_bpf::cty::c_ulong,
//     pub len: ::aya_bpf::cty::c_uint,
//     pub data_len: ::aya_bpf::cty::c_uint,
//     pub mac_len: __u16,
//     pub hdr_len: __u16,
//     pub queue_mapping: __u16,
//     pub __cloned_offset: __IncompleteArrayField<__u8>,
//     pub _bitfield_align_1: [u8; 0],
//     pub _bitfield_1: __BindgenBitfieldUnit<[u8; 1usize]>,
//     pub active_extensions: __u8,
//     pub __bindgen_anon_5: sk_buff__bindgen_ty_5,
//     pub tail: sk_buff_data_t,
//     pub end: sk_buff_data_t,
//     pub head: *mut ::aya_bpf::cty::c_uchar,
//     pub data: *mut ::aya_bpf::cty::c_uchar,
//     pub truesize: ::aya_bpf::cty::c_uint,
//     pub users: refcount_t,
//     pub extensions: *mut skb_ext,
// }
//
// pub struct sk_buff_head {
//     pub __bindgen_anon_1: sk_buff_head__bindgen_ty_1,
//     pub qlen: __u32,
//     pub lock: spinlock_t,
// }
//
fn log_q(ctx: ProbeContext, sk_common: sock_common, qlen: u32) {
    match sk_common.skc_family {
        AF_INET => {
            let src_addr =
                u32::from_be(unsafe { sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_rcv_saddr });
            let dest_addr: u32 =
                u32::from_be(unsafe { sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_daddr });
            info!(
                &ctx,
                "AF_INET queue qlen: {} src address: {:ipv4}, dest address: {:ipv4}",
                qlen,
                src_addr,
                dest_addr,
            );
        }
        AF_INET6 => {
            let src_addr = sk_common.skc_v6_rcv_saddr;
            let dest_addr = sk_common.skc_v6_daddr;
            info!(
                &ctx,
                "AF_INET queue qlen: {} src address: {:ipv4}, dest address: {:ipv4}",
                qlen,
                unsafe { src_addr.in6_u.u6_addr8 },
                unsafe { dest_addr.in6_u.u6_addr8 }
            );
        }
        0_u16..=1_u16 | 3_u16..=9_u16 | 11_u16..=u16::MAX => todo!(),
    }
}

// Generic method to log a common socket structure
fn log_sock(ctx: ProbeContext, sk_common: sock_common) {
    match sk_common.skc_family {
        AF_INET => {
            let src_addr =
                u32::from_be(unsafe { sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_rcv_saddr });
            let dest_addr: u32 =
                u32::from_be(unsafe { sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_daddr });
            info!(
                &ctx,
                "AF_INET sock src address: {:ipv4}, dest address: {:ipv4}", src_addr, dest_addr,
            );
        }
        AF_INET6 => {
            let src_addr = sk_common.skc_v6_rcv_saddr;
            let dest_addr = sk_common.skc_v6_daddr;
            info!(
                &ctx,
                "AF_INET6 sock src addr: {:ipv6}, dest addr: {:ipv6}",
                unsafe { src_addr.in6_u.u6_addr8 },
                unsafe { dest_addr.in6_u.u6_addr8 }
            );
        }
        0_u16..=1_u16 | 3_u16..=9_u16 | 11_u16..=u16::MAX => todo!(),
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

// q_tcp_connect
//
// Example kprobe to be removed or uncalled by 'q'
// Useful for quickly debugging the eBPF probe functionality
// as this is an --> outbound TCP connection from the host kernel.
#[kprobe(name = "q_tcp_connect")]
pub fn q_tcp_connect(ctx: ProbeContext) -> u32 {
    // sock_common (tcp_connect)
    match try_tcp_connect(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

fn try_tcp_connect(ctx: ProbeContext) -> Result<u32, i64> {
    // let sock: *mut sock = ctx.arg(0).ok_or(1i64)?;
    // let sk_common = unsafe {
    //     bpf_probe_read_kernel(&(*sock).__sk_common as *const sock_common).map_err(|e| e)?
    // };
    // log_sock(ctx, sk_common);
    Ok(0)
}
