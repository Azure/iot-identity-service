use crate::{types, wrap_rc, Result};

pub trait Marshal<T> {
    fn marshal(&mut self, data: &T) -> Result<()>;
}

pub trait Unmarshal<T> {
    fn unmarshal(&mut self) -> Result<T>;
}

macro_rules! marshal {
    ($($ts:ident),*) => {
        $(
            impl Marshal<types::sys::$ts> for usize {
                fn marshal(&mut self, data: &types::sys::$ts) -> Result<()> {
                    let mut out = 0;
                    paste::paste! {
                        wrap_rc!(mu_sys::[< Tss2_MU_ $ts _Marshal >](
                            data,
                            std::ptr::null_mut(),
                            u64::MAX,
                            &mut out
                        ))?;
                    }
                    *self = out as _;
                    Ok(())
                }
            }

            impl Marshal<types::sys::$ts> for &mut [u8] {
                fn marshal(&mut self, data: &types::sys::$ts) -> Result<()> {
                    let mut index = 0;
                    paste::paste! {
                        wrap_rc!(mu_sys::[< Tss2_MU_ $ts _Marshal >](
                            data,
                            self.as_mut_ptr(),
                            self.len() as _,
                            &mut index
                        ))?
                    }

                    let buf = std::mem::take(self);
                    let (_, rest) = buf.split_at_mut(index as _);
                    let _ = std::mem::replace(self, rest);
                    Ok(())
                }
            }
        )*
    }
}

macro_rules! unmarshal {
    ($($ts:ident),*) => {
        $(
            impl Unmarshal<types::sys::$ts> for &[u8] {
                fn unmarshal(&mut self) -> Result<types::sys::$ts> {
                    let mut index = 0;
                    let mut out = std::mem::MaybeUninit::<types::sys::$ts>::zeroed();

                    paste::paste! {
                        wrap_rc!(mu_sys::[< Tss2_MU_ $ts _Unmarshal >](
                            self.as_ptr(),
                            self.len() as _,
                            &mut index,
                            out.as_mut_ptr()
                        ))?;
                    }

                    let (_, rest) = self.split_at(index as _);
                    let _ = std::mem::replace(self, rest);
                    Ok(unsafe { out.assume_init() })
                }
            }
        )*
    }
}

marshal! {
    TPM2B_PUBLIC
}

unmarshal! {
    TPM2B_ENCRYPTED_SECRET,
    TPM2B_ID_OBJECT,
    TPM2B_PRIVATE,
    TPM2B_PUBLIC
}

#[cfg(test)]
mod tests {}
