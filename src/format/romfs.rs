use std::mem;
use std::rc::{Rc, Weak};
use std::io::{self, Write, Cursor};
use std::fs::{self, File};
use std::cell::RefCell;
use std::path::PathBuf;
use byteorder::{WriteBytesExt, LE};

#[derive(Debug)]
struct RomFsDirEntCtx {
    system_path: PathBuf,
    name: String,
    entry_offset: u32,
    parent: Weak<RefCell<RomFsDirEntCtx>>,
    child: Vec<Rc<RefCell<RomFsDirEntCtx>>>,
    file: Vec<Rc<RefCell<RomFsFileEntCtx>>>,
}

#[derive(Debug)]
struct RomFsFileEntCtx {
    system_path: PathBuf,
    name: String,
    entry_offset: u32,
    offset: u64,
    size: u64,
    parent: Weak<RefCell<RomFsDirEntCtx>>,
}

#[repr(C)]
#[derive(Debug)]
struct RomFsDirEntryHdr {
    parent: u32,
    sibling: u32,
    child: u32,
    file: u32,
    hash: u32,
    name_size: u32
}

#[repr(C)]
#[derive(Debug)]
struct RomFsFileEntryHdr {
    parent: u32,
    sibling: u32,
    offset: u64,
    size: u64,
    hash: u32,
    name_size: u32
}

impl RomFsDirEntCtx {
    fn new(parent: Weak<RefCell<RomFsDirEntCtx>>, path: PathBuf) -> Rc<RefCell<RomFsDirEntCtx>> {
        Rc::new(RefCell::new(RomFsDirEntCtx {
            system_path: path.clone(),
            name: path.file_name().expect("Path to terminate properly").to_str().expect("Path to contain non-unicode chars").into(),
            entry_offset: 0,
            parent,
            child: vec![],
            file: vec![]
        }))
    }
}

/// A graph of directories, and various metadata associated to it.
#[derive(Debug)]
struct RomFsCtx {
    dirs: Vec<Rc<RefCell<RomFsDirEntCtx>>>,
    files: Vec<Rc<RefCell<RomFsFileEntCtx>>>,
    dir_table_size: u64,
    file_table_size: u64,
    file_partition_size: u64,
}

impl RomFsCtx {
    fn visit_dir(path: PathBuf) -> io::Result<RomFsCtx> {
        // Stack of directories to visit. We'll iterate over it. When finding
        // new directories, we'll push them to this stack, so that iteration may
        // continue. This avoids doing recursive functions (which runs the risk
        // of stack overflowing).
        let mut dirs = vec![];

        // First, let's create our root folder. We'll want the parent to be
        // itself, so let's first set it to an unbound Weak, and set it to itself
        // after creation.
        let root_folder = RomFsDirEntCtx::new(Weak::new(), path);
        {
            let mut root_folder_borrow = root_folder.borrow_mut();

            root_folder_borrow.parent = Rc::downgrade(&root_folder.clone());
            // The name is empty for the root dir.
            root_folder_borrow.name = String::from("");
        }

        // Let's build our context. This will be returned. It contains the graph
        // of files/directories, and some meta-information that will be used to
        // write the romfs file afterwards.
        let mut ctx = RomFsCtx {
            dirs: vec![],
            files: vec![],
            // We have the root dir already.
            dir_table_size: mem::size_of::<RomFsDirEntryHdr>() as u64, // Root Dir
            file_table_size: 0,
            file_partition_size: 0
        };

        // Let's start iterating.
        ctx.dirs.push(root_folder.clone());
        dirs.push(root_folder);

        while let Some(parent_dir) = dirs.pop() {
            let path = parent_dir.borrow().system_path.clone();

            let cur_dir_idx = ctx.dirs.len();

            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let file_type = entry.file_type()?;

                if file_type.is_dir() {
                    let new_dir = RomFsDirEntCtx::new(Rc::downgrade(&parent_dir), entry.path());

                    // We want to push this directory to the list of directories to
                    // traverse/discover, and to the child list of the parent dir.
                    ctx.dirs.push(new_dir.clone());
                    dirs.push(new_dir.clone());

                    parent_dir.borrow_mut().child.push(new_dir.clone());

                    // Update the context. We want to keep track of the number of directories, and
                    // the size of the dir_table.
                    ctx.dir_table_size += mem::size_of::<RomFsDirEntryHdr>() as u64 + align64(new_dir.borrow().name.len() as u64, 4);

                } else if file_type.is_file() {
                    let file = Rc::new(RefCell::new(RomFsFileEntCtx {
                        system_path: entry.path(),
                        name: entry.path().file_name().expect("Path to terminate properly").to_str().expect("Path to contain non-unicode chars").into(),
                        entry_offset: 0,
                        offset: 0,
                        size: entry.metadata()?.len(),
                        parent: Rc::downgrade(&parent_dir)
                    }));

                    ctx.files.push(file.clone());

                    parent_dir.borrow_mut().file.push(file.clone());

                    ctx.file_table_size += mem::size_of::<RomFsFileEntryHdr>() as u64 + align64(file.borrow().name.len() as u64, 4);

                } else if file_type.is_symlink() {
                    Err(io::Error::new(io::ErrorKind::Other, format!("Can't handle symlinks in romfs: {}", entry.path().to_string_lossy())))?;
                } else {
                    Err(io::Error::new(io::ErrorKind::Other, format!("Unknown file type at {}", entry.path().to_string_lossy())))?;
                }
            }
            parent_dir.borrow_mut().child.sort_by_key(|v| v.borrow().name.clone());
            parent_dir.borrow_mut().file.sort_by_key(|v| v.borrow().name.clone());
            ctx.dirs[cur_dir_idx..].sort_by_key(|v| v.borrow().name.clone());
        }

        ctx.files.sort_by_key(|v| v.borrow().system_path.to_string_lossy().into_owned());

        Ok(ctx)
    }
}

// From https://www.3dbrew.org/wiki/RomFS
// The size of the table is dependent on the number of entries in the relevant
// MetaData table (it's probably intended to always be the smallest prime number
// greater than or equal to the number of entries, but the implementation was
// lazy)
fn romfs_get_hash_table_count(mut num_entries: usize) -> usize {
    if num_entries < 3 {
        3
    } else if num_entries < 19 {
        num_entries | 1
    } else {
        while num_entries % 2 == 0 || num_entries % 3 == 0 ||
            num_entries % 5 == 0 || num_entries % 7 == 0 ||
            num_entries % 11 == 0 || num_entries % 13 == 0 ||
            num_entries % 17 == 0 {
            num_entries += 1;
        }
        num_entries
    }
}

fn align32(offset: u32, align: u32) -> u32 {
    let mask = !(align - 1);
    (offset + (align - 1)) & mask
}

fn align64(offset: u64, align: u64) -> u64 {
    let mask = !(align - 1);
    (offset + (align - 1)) & mask
}

fn calc_path_hash(parent: u32, path: &str) -> u32 {
    // Magic algorithm. This likely comes straight from RE'd come from nintendo.
    let mut hash = parent ^ 123456789;
    for c in path.as_bytes() {
        hash = (hash >> 5) | (hash << 27);
        hash ^= *c as u32;
    }
    hash
}

pub struct RomFs {
    folder: PathBuf
}

impl RomFs {
    pub fn from_directory(folder: &str) -> io::Result<RomFs> {
        Ok(RomFs {
            folder: PathBuf::from(folder)
        })
    }

    pub fn write(&self, to: &mut Write) -> io::Result<()> {
        println!("Visiting directories...");
        let mut romfs_ctx = RomFsCtx::visit_dir(self.folder.clone())?;

        const ROMFS_ENTRY_EMPTY: u32 = 0xFFFFFFFF;

        let mut dir_hash_table = vec![ROMFS_ENTRY_EMPTY; romfs_get_hash_table_count(romfs_ctx.dirs.len())];
        let mut file_hash_table = vec![ROMFS_ENTRY_EMPTY; romfs_get_hash_table_count(romfs_ctx.files.len())];

        let mut dir_table = vec![0u8; romfs_ctx.dir_table_size as usize];
        let mut file_table = vec![0u8; romfs_ctx.file_table_size as usize];

        println!("Calculating metadata...");

        // Calculate file offset and file partition size.
        let mut entry_offset = 0;
        for file in romfs_ctx.files.iter_mut() {
            // Files have to start aligned at 0x10. We do this at the start to
            // avoid useless padding after the last file.
            romfs_ctx.file_partition_size = align64(romfs_ctx.file_partition_size, 0x10);

            // Update the data section size and set the file offset in the data
            // section.
            file.borrow_mut().offset = romfs_ctx.file_partition_size;
            romfs_ctx.file_partition_size += file.borrow().size;

            // Set the file offset in the file table section.
            file.borrow_mut().entry_offset = entry_offset;
            entry_offset += mem::size_of::<RomFsFileEntryHdr>() as u32 + align32(file.borrow().name.len() as u32, 4);
        }

        // Calculate directory offsets.
        let mut entry_offset = 0;
        for dir in romfs_ctx.dirs.iter_mut() {
            dir.borrow_mut().entry_offset = entry_offset;
            entry_offset += mem::size_of::<RomFsDirEntryHdr>() as u32 + align32(dir.borrow().name.len() as u32, 4);
        }

        // Populate file tables
        for file in romfs_ctx.files.iter() {
            let orig_file = file;
            let file = file.borrow();
            let parent = file.parent.upgrade().unwrap();
            let parent = parent.borrow();
            let sibling = parent.file.windows(2).find(|window| Rc::ptr_eq(&window[0], orig_file)).map(|window| window[1].borrow().entry_offset);
            let hash = calc_path_hash(parent.entry_offset, &file.name);

            let mut cursor = Cursor::new(&mut file_table[file.entry_offset as usize..]);
            cursor.write_u32::<LE>(parent.entry_offset)?;
            cursor.write_u32::<LE>(sibling.unwrap_or(ROMFS_ENTRY_EMPTY))?;
            cursor.write_u64::<LE>(file.offset)?;
            cursor.write_u64::<LE>(file.size)?;
            cursor.write_u32::<LE>(file_hash_table[hash as usize % file_hash_table.len()])?;
            cursor.write_u32::<LE>(file.name.len() as u32)?;
            cursor.write_all(file.name.as_bytes())?;

            let cur_len = file_hash_table.len();
            file_hash_table[hash as usize % cur_len] = file.entry_offset;
        }

        // Populate dir tables
        for dir in romfs_ctx.dirs.iter() {
            let dir = dir.borrow();
            let parent = dir.parent.upgrade().unwrap();
            let parent = parent.borrow();
            let sibling = parent.child.windows(2).find(|window| window[0].borrow().system_path == dir.system_path).map(|window| window[1].borrow().entry_offset);
            let hash = calc_path_hash(parent.entry_offset, &dir.name);

            let mut cursor = Cursor::new(&mut dir_table[dir.entry_offset as usize..]);
            cursor.write_u32::<LE>(parent.entry_offset)?;
            cursor.write_u32::<LE>(sibling.unwrap_or(ROMFS_ENTRY_EMPTY))?;
            cursor.write_u32::<LE>(dir.child.first().map(|v| v.borrow().entry_offset).unwrap_or(ROMFS_ENTRY_EMPTY))?;
            cursor.write_u32::<LE>(dir.file.first().map(|v| v.borrow().entry_offset).unwrap_or(ROMFS_ENTRY_EMPTY))?;
            cursor.write_u32::<LE>(dir_hash_table[hash as usize % dir_hash_table.len()])?;
            cursor.write_u32::<LE>(dir.name.len() as u32)?;
            cursor.write_all(dir.name.as_bytes())?;

            let cur_len = dir_hash_table.len();
            dir_hash_table[hash as usize % cur_len] = dir.entry_offset;
        }

        // Write the header
        // TODO: why 0x200???
        const ROMFS_FILEPARTITION_OFS: u64 = 0x200;

        to.write_u64::<LE>(80)?; // Size of header

        let cur_ofs = align64(ROMFS_FILEPARTITION_OFS + romfs_ctx.file_partition_size, 4);
        to.write_u64::<LE>(cur_ofs)?; // dir_hash_table_ofs
        to.write_u64::<LE>((dir_hash_table.len() * mem::size_of::<u32>()) as u64)?; // dir_hash_table_size

        let cur_ofs = cur_ofs + (dir_hash_table.len() * mem::size_of::<u32>()) as u64;
        to.write_u64::<LE>(cur_ofs)?; // dir_table_ofs
        to.write_u64::<LE>(dir_table.len() as u64)?; // dir_table_size

        let cur_ofs = cur_ofs + dir_table.len() as u64;
        to.write_u64::<LE>(cur_ofs)?; // file_hash_table_ofs
        to.write_u64::<LE>((file_hash_table.len() * mem::size_of::<u32>()) as u64)?; // file_hash_table_size

        let cur_ofs = cur_ofs + (file_hash_table.len() * mem::size_of::<u32>()) as u64;
        to.write_u64::<LE>(cur_ofs)?; // file_table_ofs
        to.write_u64::<LE>(file_table.len() as u64)?; // file_table_size

        to.write_u64::<LE>(ROMFS_FILEPARTITION_OFS)?; // file_partition_ofs

        // Extend to 0x200 (we're currently at 0x50)
        to.write_all(&[0; 0x1B0])?;

        let mut cur_ofs = 0x200;

        for file in romfs_ctx.files.iter() {
            // Files have to start aligned at 0x10. We do this at the start to
            // avoid useless padding after the last file.
            let new_cur_ofs = align64(cur_ofs, 0x10);
            to.write_all(&vec![0; (new_cur_ofs - cur_ofs) as usize])?;
            cur_ofs = new_cur_ofs;

            println!("Writing {} to RomFS image...", file.borrow().system_path.to_string_lossy());
            assert_eq!(file.borrow().offset, cur_ofs - 0x200, "Wrong offset");

            let len = io::copy(&mut File::open(&file.borrow().system_path)?, to)?;
            assert_eq!(len, file.borrow().size, "File changed while building romfs");
            cur_ofs += file.borrow().size;
        }

        // Pad to 4.
        let new_cur_ofs = align64(cur_ofs, 4);
        to.write_all(&vec![0; (new_cur_ofs - cur_ofs) as usize])?;
        let cur_ofs = new_cur_ofs;

        // Write dir hash table
        assert_eq!(cur_ofs, align64(ROMFS_FILEPARTITION_OFS + romfs_ctx.file_partition_size, 4));
        for hash in dir_hash_table {
            to.write_u32::<LE>(hash)?;
        }
        to.write_all(&dir_table)?;
        for hash in file_hash_table {
            to.write_u32::<LE>(hash)?;
        }
        to.write_all(&file_table)?;
        Ok(())
    }
}
