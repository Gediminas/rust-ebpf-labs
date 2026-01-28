#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]

use crate::bpf_utils::read_unchecked;
use aya_ebpf::{
    bindings::xdp_action::{self, XDP_DROP, XDP_PASS},
    helpers,
    macros::{map, xdp},
    maps::RingBuf,
    programs::XdpContext,
};
use aya_log_ebpf::{debug, info};
use core::{mem, ptr};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

const RING_SIZE: u32 = 1 << 26; // 64 MB

#[map]
static RING: RingBuf = RingBuf::with_byte_size(RING_SIZE, 0);

#[xdp]
pub fn poc_xdp_ring(ctx: XdpContext) -> u32 {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = end - start;

    if len < 20 {
        return XDP_PASS;
    }

    // // FIXME EtherType is limited enum, which is UB when parsing packet, drop EthHdr (but works for now)
    // let eth: EthHdr = unsafe { read_unchecked(ctx.data()) };
    // if let EtherType::Ipv4 = eth.ether_type {
    // } else {
    //     return XDP_PASS;
    // }

    // let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    // let source = u32::from_be(unsafe { (*ipv4hdr).src_addr });

    // // Search for UDP only
    // match unsafe { (*ipv4hdr).proto } {
    //     IpProto::Udp => {}
    //     _ => return XDP_PASS,
    // }

    // let udphdr: *const UdpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
    // let src_port = unsafe { u16::from_be((*udphdr).source) };

    // if src_port != 53 {
    //     return XDP_PASS;
    // }

    // debug!(&ctx, "Dropping packet from source {:i}", source);

    // const U16_SIZE: usize = mem::size_of::<u16>();
    // const SIZE: usize = U16_SIZE + 1500;

    // match RING.reserve::<[u8; SIZE]>(0) {
    //     Some(mut event) => {
    //         let len = ctx.data_end() - ctx.data();

    //         // We check if packet len is greater than our reserved buffer size
    //         if aya_ebpf::check_bounds_signed(len as i64, 1, 1500) == false {
    //             event.discard(0);
    //             return XDP_DROP;
    //         }

    //         unsafe {
    //             // we first save into the buffer the packet length.
    //             // Useful on userspace to retrieve the correct amount of bytes and not some bytes not part of the packet.
    //             ptr::write_unaligned(event.as_mut_ptr() as *mut _, len as u16);

    //             // We copy the entire content of the packet to the buffer (L2 to L7)
    //             match helpers::bpf_xdp_load_bytes(
    //                 ctx.ctx,
    //                 0,
    //                 event.as_mut_ptr().byte_add(U16_SIZE) as *mut _,
    //                 len as u32,
    //             ) {
    //                 0 => event.submit(0),
    //                 _ => event.discard(0),
    //             }
    //         }
    //     }
    //     None => {
    //         info!(&ctx, "Cannot reserve space in ring buffer.");
    //     }
    // };

    XDP_DROP
}

unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(&*ptr)
}
