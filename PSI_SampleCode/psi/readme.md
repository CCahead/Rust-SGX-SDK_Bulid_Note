//https://stackoverflow.com/questions/57756927/rust-modules-confusion-when-there-is-main-rs-and-lib-rs
我的问题:在使用main.rs的时候，他无法use worker的包，显示冲突了？
error[E0432]: unresolved import `crate::worker`
 --> src/main.rs:1:12
  |
1 | use crate::worker::{PSI,Ctx};
  |            ^^^^^^
  |            |
  |            unresolved import
  |            help: a similar path exists: `psi::worker`

error: aborting due to previous error

For more information about this error, try `rustc --explain E0432`.
error: could not compile `psi`.

有两个crate: one for binary another for lib?