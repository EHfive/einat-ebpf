// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later

macro_rules! einat_obj_bytes {
    () => {
        include_bytes!(concat!(env!("OUT_DIR"), "/einat.bpf.o"))
    };
}

#[repr(C, align(32))]
struct Aligned<const N: usize>([u8; N]);
const EINAT_OBJ_LEN: usize = einat_obj_bytes!().len();
const EINAT_OBJ_ALIGNED: Aligned<EINAT_OBJ_LEN> = Aligned(*einat_obj_bytes!());

pub const fn einat_obj_data() -> &'static [u8] {
    &EINAT_OBJ_ALIGNED.0
}
