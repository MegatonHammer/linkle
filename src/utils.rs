use core::ops::{BitAnd, Not};
use num_traits::Num;
use std::io;

pub struct Hexstring<'a>(pub &'a [u8]);

impl<'a> core::fmt::Debug for Hexstring<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

#[macro_export]
macro_rules! impl_debug_deserialize_serialize_hexstring {
    ($for:ident) => {
        impl std::fmt::Debug for $for {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_tuple(stringify!($for))
                    .field(&$crate::utils::Hexstring(&self.0[..]))
                    .finish()
            }
        }

        impl std::fmt::Display for $for {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> std::fmt::Result {
                std::fmt::Debug::fmt(&$crate::utils::Hexstring(&self.0[..]), f)
            }
        }

        impl<'de> serde::Deserialize<'de> for $for {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct StrVisitor;
                impl<'de> serde::de::Visitor<'de> for StrVisitor {
                    type Value = $for;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        formatter.write_str("a character hexstring")
                    }

                    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        let mut value = [0; std::mem::size_of::<$for>()];
                        if s.len() != std::mem::size_of::<$for>() * 2 {
                            return Err(E::invalid_length(s.len(), &self));
                        }
                        for (idx, c) in s.bytes().enumerate() {
                            let c = match c {
                                b'a'..=b'z' => c - b'a' + 10,
                                b'A'..=b'Z' => c - b'A' + 10,
                                b'0'..=b'9' => c - b'0',
                                _ => {
                                    return Err(E::invalid_value(
                                        serde::de::Unexpected::Str(s),
                                        &self,
                                    ))
                                }
                            };
                            value[idx / 2] |= c << if idx % 2 == 0 { 4 } else { 0 }
                        }

                        Ok($for(value))
                    }
                }

                deserializer.deserialize_str(StrVisitor)
            }
        }

        impl serde::Serialize for $for {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.collect_str(self)
            }
        }
    };
}

pub fn align_down<T: Num + Not<Output = T> + BitAnd<Output = T> + Copy>(addr: T, align: T) -> T {
    addr & !(align - T::one())
}

pub fn align_up<T: Num + Not<Output = T> + BitAnd<Output = T> + Copy>(addr: T, align: T) -> T {
    align_down(addr + (align - T::one()), align)
}

// Why is this not a trait...
pub trait TryClone: Sized {
    fn try_clone(&self) -> io::Result<Self>;
}

impl TryClone for std::fs::File {
    fn try_clone(&self) -> io::Result<Self> {
        std::fs::File::try_clone(self)
    }
}

pub struct ReadRange<R> {
    inner: R,
    start_from: u64,
    size: u64,
    inner_pos: u64,
}

impl<R> ReadRange<R> {
    pub fn new(stream: R, start_from: u64, max_size: u64) -> ReadRange<R> {
        ReadRange {
            inner: stream,
            start_from,
            size: max_size,
            inner_pos: 0,
        }
    }

    #[allow(unused)]
    pub fn pos_in_stream(&self) -> u64 {
        self.start_from + self.inner_pos
    }
}

impl<R: io::Read> io::Read for ReadRange<R> {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        if self.size < self.inner_pos + buf.len() as u64 {
            // Avoid reading out of the section's bound.
            buf = &mut buf[..(self.size.saturating_sub(self.inner_pos)) as usize];
        }
        let read = self.inner.read(buf)?;
        self.inner_pos += read as u64;
        Ok(read)
    }
}

impl<R: io::Seek> io::Seek for ReadRange<R> {
    fn seek(&mut self, from: io::SeekFrom) -> io::Result<u64> {
        let new_inner_pos = match from {
            io::SeekFrom::Start(val) => val,
            io::SeekFrom::Current(val) => {
                if val < 0 {
                    if let Some(s) = self.inner_pos.checked_sub(-val as u64) {
                        s
                    } else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "Seek before position 0",
                        ));
                    }
                } else {
                    self.inner_pos + val as u64
                }
            }
            io::SeekFrom::End(val) => {
                if val < 0 {
                    if let Some(s) = self.size.checked_sub(-val as u64) {
                        s
                    } else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "Seek before position 0",
                        ));
                    }
                } else {
                    self.size + val as u64
                }
            }
        };

        let newpos = self
            .inner
            .seek(io::SeekFrom::Start(self.start_from + new_inner_pos))?;
        self.inner_pos = newpos - self.start_from;
        Ok(self.inner_pos)
    }
}
