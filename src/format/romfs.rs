use std::mem;
use std::rc::{Rc, Weak};
use std::io::{self, Write, Cursor};
use std::fs::{self, File};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use byteorder::{WriteBytesExt, LE};
use crate::error::Error;
use failure::Backtrace;

#[derive(Debug)]
struct RomFsDirEntCtx {
    // Only used in `RomFs::from_directory`
    system_path: PathBuf,
    name: String,
    entry_offset: u32,
    parent: Weak<RefCell<RomFsDirEntCtx>>,
    child: Vec<Rc<RefCell<RomFsDirEntCtx>>>,
    file: Vec<Rc<RefCell<RomFsFileEntCtx>>>,
}

impl RomFsDirEntCtx {
    fn internal_path(&self) -> String {
        let mut path = self.name.clone();
        let mut cur = self.parent.upgrade().unwrap();
        while cur.borrow().name != "" {
            path = cur.borrow().name.clone() + "/" + &path;
            let new_cur = cur.borrow().parent.upgrade().unwrap();
            cur = new_cur;
        }
        path
    }
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

impl RomFsFileEntCtx {
    fn internal_path(&self) -> String {
        let parent = self.parent.upgrade().unwrap();
        let parent_borrow = parent.borrow();
        parent_borrow.internal_path() + "/" + &self.name
    }
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
    #[allow(clippy::new_ret_no_self)]
    fn new(parent: Weak<RefCell<RomFsDirEntCtx>>, path: PathBuf) -> Rc<RefCell<RomFsDirEntCtx>> {
        let filename = path.file_name().expect("Path to terminate properly").to_str().expect("Path to contain non-unicode chars").into();
        Rc::new(RefCell::new(RomFsDirEntCtx {
            system_path: path,
            name: filename,
            entry_offset: 0,
            parent,
            child: vec![],
            file: vec![]
        }))
    }

    fn new_root() -> Rc<RefCell<RomFsDirEntCtx>> {
        // We'll want the parent to point to itself, so let's first
        // set it to an unbound Weak, and set it to itself
        // after creation.
        let root = Rc::new(RefCell::new(RomFsDirEntCtx {
            system_path: PathBuf::from(""),
            name: String::from(""),
            entry_offset: 0,
            parent: Weak::new(),
            child: vec![],
            file: vec![]
        }));
        let weak = Rc::downgrade(&root);
        root.borrow_mut().parent = weak;
        root
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
    let mut hash = parent ^ 123_456_789;
    for c in path.as_bytes() {
        hash = (hash >> 5) | (hash << 27);
        hash ^= u32::from(*c);
    }
    hash
}

// TODO: why 0x200???
const ROMFS_FILEPARTITION_OFS: u64 = 0x200;

/// A graph of directories, and various metadata associated to it.
#[derive(Debug)]
pub struct RomFs {
    dirs: Vec<Rc<RefCell<RomFsDirEntCtx>>>,
    files: Vec<Rc<RefCell<RomFsFileEntCtx>>>,
    dir_table_size: u64,
    file_table_size: u64,
    file_partition_size: u64,
}

#[allow(clippy::len_without_is_empty)]
impl RomFs {
    // Internal path
    pub fn push_file(&mut self, file_path: &Path, internal_path: &str) -> io::Result<()> {
        let mut parent = self.dirs[0].clone();

        let mut components = internal_path.split('/').peekable();
        while let Some(component) = components.next() {
            if components.peek().is_none() {
                let metadata = file_path.metadata()?;
                // Handling last component. Add the file.
                let file_to_add = Rc::new(RefCell::new(RomFsFileEntCtx {
                    system_path: PathBuf::from(file_path),
                    name: String::from(component),
                    entry_offset: 0,
                    offset: 0,
                    size: metadata.len(),
                    parent: Rc::downgrade(&parent),
                }));
                self.files.push(file_to_add.clone());
                parent.borrow_mut().file.push(file_to_add.clone());
                parent.borrow_mut().file.sort_by_key(|v| v.borrow().name.clone());

                self.file_table_size += mem::size_of::<RomFsFileEntryHdr>() as u64 + align64(file_to_add.borrow().name.len() as u64, 4);
            } else {
                // Handling a parent component. Find the directory, create if it doesn't exist.
                if component == "" {
                    continue;
                }
                let new_parent = if let Some(child) = parent.borrow().child.iter().find(|v| v.borrow().name == component) {
                    child.clone()
                } else {
                    // system_path is not used outside from_directory. It's okay if it doesn't
                    // point to something "safe" (or to anything at all)
                    let child = Rc::new(RefCell::new(RomFsDirEntCtx {
                        system_path: PathBuf::from(""),
                        name: String::from(component),
                        entry_offset: 0,
                        parent: Rc::downgrade(&parent),
                        child: vec![],
                        file: vec![]
                    }));
                    self.dirs.push(child.clone());
                    parent.borrow_mut().child.push(child.clone());
                    parent.borrow_mut().child.sort_by_key(|v| v.borrow().name.clone());

                    self.dir_table_size += mem::size_of::<RomFsDirEntryHdr>() as u64 + align64(child.borrow().name.len() as u64, 4);
                    child
                };
                parent = new_parent;
            }
        }
        self.files.sort_by_key(|v| v.borrow().internal_path());
        self.dirs.sort_by_key(|v| v.borrow().internal_path());
        self.calculate_offsets();
        Ok(())
    }

    pub fn empty() -> RomFs {
        // First, let's create our root folder.
        let root_folder = RomFsDirEntCtx::new_root();

        // And now, build the empty context, with just the root directory in it.
        let mut ctx = RomFs {
            dirs: vec![root_folder],
            files: vec![],
            // We have the root dir already.
            dir_table_size: mem::size_of::<RomFsDirEntryHdr>() as u64, // Root Dir
            file_table_size: 0,
            file_partition_size: 0,
        };

        ctx.calculate_offsets();

        ctx
    }

    pub fn from_directory(path: &Path) -> Result<RomFs, Error> {
        // Stack of directories to visit. We'll iterate over it. When finding
        // new directories, we'll push them to this stack, so that iteration may
        // continue. This avoids doing recursive functions (which runs the risk
        // of stack overflowing).
        let mut dirs = vec![];

        // Let's build our context. This will be returned. It contains the graph
        // of files/directories, and some meta-information that will be used to
        // write the romfs file afterwards.
        let mut ctx = RomFs::empty();

        // Set the system_path of the root directory.
        ctx.dirs[0].borrow_mut().system_path = PathBuf::from(path);

        // Let's start iterating with the root directory.
        dirs.push(ctx.dirs[0].clone());

        while let Some(parent_dir) = dirs.pop() {
            let path = parent_dir.borrow().system_path.clone();

            for entry in fs::read_dir(&path).map_err(|err| (err, &path))? {
                let entry = entry.map_err(|err| (err, &path))?;
                let file_type = entry.file_type().map_err(|err| (err, entry.path()))?;

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
                        size: entry.metadata().map_err(|err| (err, entry.path()))?.len(),
                        parent: Rc::downgrade(&parent_dir)
                    }));

                    ctx.files.push(file.clone());

                    parent_dir.borrow_mut().file.push(file.clone());

                    ctx.file_table_size += mem::size_of::<RomFsFileEntryHdr>() as u64 + align64(file.borrow().name.len() as u64, 4);

                } else if file_type.is_symlink() {
                    Err(Error::RomFsSymlink(entry.path(), Backtrace::new()))?;
                } else {
                    Err(Error::RomFsFiletype(entry.path(), Backtrace::new()))?;
                }
            }
            parent_dir.borrow_mut().child.sort_by_key(|v| v.borrow().name.clone());
            parent_dir.borrow_mut().file.sort_by_key(|v| v.borrow().name.clone());
        }

        ctx.files.sort_by_key(|v| v.borrow().internal_path());
        ctx.dirs.sort_by_key(|v| v.borrow().internal_path());

        ctx.calculate_offsets();

        Ok(ctx)
    }

    pub fn len(&self) -> usize {
        (align64(ROMFS_FILEPARTITION_OFS + self.file_partition_size, 4) +
            romfs_get_hash_table_count(self.dirs.len() * mem::size_of::<u32>())  as u64 +
            self.dir_table_size +
            romfs_get_hash_table_count(self.files.len() * mem::size_of::<u32>()) as u64 +
            self.file_table_size) as usize
    }

    fn calculate_offsets(&mut self) {
        // Calculate file offset and file partition size.
        let mut entry_offset = 0;
        self.file_partition_size = 0;
        for file in self.files.iter_mut() {
            // Files have to start aligned at 0x10. We do this at the start to
            // avoid useless padding after the last file.
            self.file_partition_size = align64(self.file_partition_size, 0x10);

            // Update the data section size and set the file offset in the data
            // section.
            file.borrow_mut().offset = self.file_partition_size;
            self.file_partition_size += file.borrow().size;

            // Set the file offset in the file table section.
            file.borrow_mut().entry_offset = entry_offset;
            entry_offset += mem::size_of::<RomFsFileEntryHdr>() as u32 + align32(file.borrow().name.len() as u32, 4);
        }

        // Calculate directory offsets.
        let mut entry_offset = 0;
        for dir in self.dirs.iter_mut() {
            dir.borrow_mut().entry_offset = entry_offset;
            entry_offset += mem::size_of::<RomFsDirEntryHdr>() as u32 + align32(dir.borrow().name.len() as u32, 4);
        }
    }


    pub fn write(&self, to: &mut dyn Write) -> io::Result<()> {
        const ROMFS_ENTRY_EMPTY: u32 = 0xFF_FF_FF_FF;

        let mut dir_hash_table = vec![ROMFS_ENTRY_EMPTY; romfs_get_hash_table_count(self.dirs.len())];
        let mut file_hash_table = vec![ROMFS_ENTRY_EMPTY; romfs_get_hash_table_count(self.files.len())];

        let mut dir_table = vec![0u8; self.dir_table_size as usize];
        let mut file_table = vec![0u8; self.file_table_size as usize];

        // Populate file tables
        for file in self.files.iter() {
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
        for dir in self.dirs.iter() {
            let dir = dir.borrow();
            let parent = dir.parent.upgrade().unwrap();
            let parent = parent.borrow();
            let sibling = parent.child.windows(2).find(|window| window[0].borrow().internal_path() == dir.internal_path()).map(|window| window[1].borrow().entry_offset);
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
        to.write_u64::<LE>(80)?; // Size of header

        let cur_ofs = align64(ROMFS_FILEPARTITION_OFS + self.file_partition_size, 4);
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

        for file in self.files.iter() {
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
        assert_eq!(cur_ofs, align64(ROMFS_FILEPARTITION_OFS + self.file_partition_size, 4));
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
