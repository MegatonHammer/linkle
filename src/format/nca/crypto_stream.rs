use crate::error::Error;
use crate::format::nca::{NcaCrypto, NcaSectionInfo};
use crate::utils::align_down;
use byteorder::{ByteOrder, BE};
use std::cmp::min;
use std::io;
use std::io::{Read, Seek, Write};

/// A wrapper around a Read/Seek stream, decrypting its contents based of an
/// NCA Section.
#[derive(Debug)]
pub struct CryptoStream<R> {
    pub(super) stream: R,
    // Hello borrowck my old friend. We need to keep the state separate from the
    // buffer, otherwise we get borrow problems.
    pub(super) state: CryptoStreamState,
    // Keep a 1-block large buffer of data in case of partial reads.
    pub(super) buffer: [u8; 0x10],
}

#[derive(Debug)]
pub struct CryptoStreamState {
    pub(super) offset: u64,
    pub(super) json: NcaSectionInfo,
}

impl<R: Seek> CryptoStream<R> {
    pub fn seek_aligned(&mut self, from: io::SeekFrom) -> io::Result<()> {
        let new_offset = match from {
            io::SeekFrom::Start(cur) => cur,
            io::SeekFrom::Current(val) => (self.state.offset as i64 + val) as u64,
            io::SeekFrom::End(val) => (self.state.json.size() as i64 + val) as u64,
        };
        if new_offset % 16 != 0 {
            panic!("Seek not aligned");
        }
        self.stream.seek(io::SeekFrom::Start(new_offset))?;
        self.state.offset = new_offset;
        Ok(())
    }
}

impl CryptoStreamState {
    fn get_ctr(&self) -> [u8; 0x10] {
        let offset = self.json.media_start_offset / 16 + self.offset / 16;
        let mut ctr = [0; 0x10];
        // Write section nonce in Big Endian.
        BE::write_u64(&mut ctr[..8], self.json.nonce);
        // Set ctr to offset / BLOCK_SIZE, in big endian.
        BE::write_u64(&mut ctr[8..], offset);
        ctr
    }

    fn decrypt(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        match self.json.crypto {
            NcaCrypto::None => {
                // Nothing to do.
                Ok(())
            }
            NcaCrypto::Ctr(key) => key.decrypt_ctr(buf, &self.get_ctr()),
            NcaCrypto::Bktr(_) => todo!(),
            NcaCrypto::Xts(_) => todo!(),
        }
    }

    fn encrypt(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        match self.json.crypto {
            NcaCrypto::None => {
                // Nothing to do.
                Ok(())
            }
            NcaCrypto::Ctr(key) => key.encrypt_ctr(buf, &self.get_ctr()),
            NcaCrypto::Bktr(_) => todo!(),
            NcaCrypto::Xts(_) => todo!(),
        }
    }
}

/// Read implementation for CryptoStream.
impl<R: Read> Read for CryptoStream<R> {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        let previous_leftovers = (self.state.offset % 16) as usize;
        let previous_leftovers_read = if previous_leftovers != 0 {
            // First, handle leftovers from a previous read call, so we go back
            // to a properly block-aligned read.
            let to = min(previous_leftovers + buf.len(), 16);
            let size = to - previous_leftovers;
            buf[..size].copy_from_slice(&self.buffer[previous_leftovers..to]);
            self.state.offset += size as u64;

            buf = &mut buf[size..];
            size
        } else {
            0
        };

        let read = self.stream.read(buf)?;
        buf = &mut buf[..read];

        // Decrypt all the non-leftover bytes.
        let len_no_leftovers = align_down(buf.len(), 16);
        self.state.decrypt(&mut buf[..len_no_leftovers]).unwrap();
        self.state.offset += len_no_leftovers as u64;
        let leftovers = buf.len() % 16;
        if leftovers != 0 {
            // We got some leftover, save them in the internal buffer, finish
            // reading it, decrypt it, and copy the part we want back.
            //
            // Why not delay decryption until we have a full block? Well, that's
            // because the read interface is **stupid**. If we ever return 0,
            // the file is assumed to be finished - instead of signaling "herp,
            // needs more bytes". So we play greedy.
            let from = align_down(buf.len(), 16);
            self.buffer[..leftovers].copy_from_slice(&buf[from..buf.len()]);
            self.stream.read_exact(&mut self.buffer[leftovers..])?;
            // TODO: Bubble up the error.
            self.state.decrypt(&mut self.buffer).unwrap();
            buf[from..].copy_from_slice(&self.buffer[..leftovers]);
            self.state.offset += leftovers as u64;
        }

        Ok(previous_leftovers_read + read)
    }
}

impl<W: Write + Seek> Write for CryptoStream<W> {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        let previous_leftovers = (self.state.offset % 16) as usize;
        let previous_leftovers_written = if previous_leftovers != 0 {
            // We need to do two things: Rewrite the block on disk with the
            // encrypted data, and update the leftover buffer with the decrypted
            // data.
            let to = min(previous_leftovers + buf.len(), 16);
            let size = to - previous_leftovers;
            self.buffer[previous_leftovers..to].copy_from_slice(&buf[..size]);

            // We are done handling this block. Write it to disk.
            // TODO: Bubble up the error.
            self.state.encrypt(&mut self.buffer).unwrap();
            self.stream.write_all(&self.buffer)?;
            self.state.decrypt(&mut self.buffer).unwrap();

            if to != 16 {
                self.stream.seek(io::SeekFrom::Current(-16))?;
            } else {
                self.buffer = [0; 16];
            }

            self.state.offset += size as u64;

            buf = &buf[size..];
            size
        } else {
            0
        };

        // Encrypt chunk by chunk
        for chunk in buf.chunks_exact(16) {
            self.buffer.copy_from_slice(chunk);
            self.state.encrypt(&mut self.buffer).unwrap();
            self.stream.write_all(&self.buffer)?;
            self.state.offset += 16
        }

        // Store all leftover bytes.
        let leftovers = buf.len() % 16;
        if leftovers != 0 {
            // We got some leftover, save them in the internal buffer so they can
            // be processed in a subsequent write. Note that this will not work
            // at all if you mix reads and writes...
            let from = align_down(buf.len(), 16);
            self.buffer = [0; 16];
            self.buffer[..leftovers].copy_from_slice(&buf[from..buf.len()]);
            self.state.encrypt(&mut self.buffer).unwrap();
            self.stream.write_all(&self.buffer)?;
            self.state.decrypt(&mut self.buffer).unwrap();
            self.stream.seek(io::SeekFrom::Current(-16))?;
            self.state.offset += leftovers as u64;
        }

        Ok(previous_leftovers_written + buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<Stream: Read + Write + Seek> Seek for CryptoStream<Stream> {
    fn seek(&mut self, from: io::SeekFrom) -> io::Result<u64> {
        self.state.offset = match from {
            io::SeekFrom::Start(cur) => cur,
            io::SeekFrom::Current(val) => (self.state.offset as i64 + val) as u64,
            io::SeekFrom::End(val) => (self.state.json.size() as i64 + val) as u64,
        };

        let aligned_offset = align_down(self.state.offset, 16);
        self.stream.seek(io::SeekFrom::Start(aligned_offset))?;
        if self.state.offset % 16 != 0 {
            self.stream.read_exact(&mut self.buffer)?;
            self.state.decrypt(&mut self.buffer).unwrap();
        }
        Ok(self.state.offset)
    }
}
