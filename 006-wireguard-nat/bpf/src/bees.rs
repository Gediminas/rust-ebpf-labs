// #![allow(unused_imports)]
// #![allow(unused_variables)]
// #![allow(dead_code)]

use aya_ebpf::{
    bindings::{BPF_F_RDONLY, xdp_action::XDP_PASS},
    macros::{map, xdp},
    maps::PerCpuArray,
    programs::XdpContext,
};
use aya_log_ebpf::error;
use poc_common::Stat;

#[map]
static STAT: PerCpuArray<Stat> = PerCpuArray::with_max_entries(1, BPF_F_RDONLY);

#[xdp]
pub fn poc_xdp(ctx: XdpContext) -> u32 {
    let Some(stat) = STAT.get_ptr_mut(0) else {
        error!(&ctx, "STAT failed");
        return XDP_PASS;
    };

    unsafe { (*stat).total_packets += 1 };

    // let len = ctx.data_end() - ctx.data();
    // Verifier safer perhaps:
    // if !aya_ebpf::check_bounds_signed(len as i64, 1, MAX_MTU as i64) {
    //     return XDP_PASS;
    // }

    XDP_PASS
}
