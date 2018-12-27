use num_traits::Num;
use core::ops::{Not, BitAnd};
use std::io;

pub fn align_down<T: Num + Not<Output = T> + BitAnd<Output = T> + Copy>(addr: T, align: T) -> T
{
    addr & !(align - T::one())
}

pub fn align_up<T: Num + Not<Output = T> + BitAnd<Output = T> + Copy>(addr: T, align: T) -> T
{
    align_down(addr + (align - T::one()), align)
}

// Why is this not a trait...
pub trait TryClone: Sized {
    fn try_clone(&self) -> std::io::Result<Self>;
}

impl TryClone for std::fs::File {
    fn try_clone(&self) -> std::io::Result<Self> { std::fs::File::try_clone(&self) }
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
            start_from: start_from,
            size: max_size,
            inner_pos: 0
        }
    }

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
                        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Seek before position 0"));
                    }
                } else {
                    self.inner_pos + val as u64
                }
            },
            io::SeekFrom::End(val) => {
                if val < 0 {
                    if let Some(s) = self.size.checked_sub(-val as u64) {
                        s
                    } else {
                        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Seek before position 0"));
                    }
                } else {
                    self.size + val as u64
                }
            }
        };

        let newpos = self.inner.seek(io::SeekFrom::Start(self.start_from + new_inner_pos))?;
        self.inner_pos = newpos - self.start_from;
        Ok(self.inner_pos)
    }
}
