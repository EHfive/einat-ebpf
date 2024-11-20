// SPDX-FileCopyrightText: 2023 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later

#[macro_export]
macro_rules! derive_pod {
    (
        $( #[$attr:meta] )*
        $vis:vis struct $name:ident {
            $(
                $( #[$attr_f:meta] )?
                $vis_f:vis $field:ident : $typ:ty
            ),* $(,)*
        }
    ) => {
        $( #[$attr] )*
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, ::bytemuck::Zeroable, ::bytemuck::Pod)]
        $vis struct $name {
            $(
               $( #[$attr_f] )?
               $vis_f  $field : $typ,
            )*
        }

        /// # Safety
        /// Only impl aya::Pod for struct where bytemuck::Pod already applies,
        /// it's safe as the later is guarded by bytemuck's Pod derive
        #[cfg(feature = "aya")]
        unsafe impl ::aya::Pod for $name where $name: ::bytemuck::Pod {}
    };
}
