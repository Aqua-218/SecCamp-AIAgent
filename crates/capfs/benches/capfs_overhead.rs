//! Layered measurement of what capfs costs per filesystem operation.
//!
//! Four layers run the identical client-side workload so their differences
//! attribute the cost rather than merely reporting it:
//!
//! | Layer | What it measures |
//! |---|---|
//! | `native` | the backing filesystem with no capfs in the path |
//! | `passthrough` | the same FUSE transport and mount configuration with every capability check removed |
//! | `capfs` | the real [`CapabilityFilesystem`] mount |
//! | `kernel` | one in-process capability decision with no FUSE round trip |
//!
//! `capfs / native` is the overhead an application actually pays.
//! `passthrough / native` is the FUSE transport's share of it, and
//! `capfs / passthrough` is what capability enforcement itself adds.
//!
//! The passthrough control mounts through [`capfs::filesystem::mount_config`],
//! so it inherits the same thread count, ACL, and mount options, and it replies
//! to `OPEN` with the same `FOPEN_DIRECT_IO | FOPEN_NOFLUSH` and to attribute
//! replies with the same zero TTL. Only the capability work differs.
//!
//! `native` is ordinary buffered I/O, because that is what an application gets
//! when capfs is absent. Both FUSE layers bypass the page cache by construction,
//! so the reported ratios include that difference deliberately.
//!
//! Each benchmark builds and tears down its own mount. That keeps the
//! in-memory audit trail, which grows by one retained record per committed
//! effect, from spanning the whole run.

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        collections::BTreeMap,
        ffi::OsStr,
        fs::{self, File, OpenOptions},
        hint::black_box,
        io,
        num::NonZeroUsize,
        os::{
            fd::OwnedFd,
            unix::fs::{FileExt, MetadataExt},
        },
        path::{Path, PathBuf},
        sync::{
            Arc, Barrier, Mutex,
            atomic::{AtomicU64, Ordering},
        },
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    use authority_core::{
        capability::{
            AuthorityBody, AuthorityRequest, CapId, CapabilityRequest, IssuerId, SubjectId,
        },
        file::{FileAuthority, FileEffect, FileEffects, FileRequest},
        kernel::{CapabilityKernel, EffectExecution},
        path::{CanonicalPath, PathPattern},
        repository::RepoId,
        state::{CapabilityGrant, CapabilityState, StaticAuthorityEnvelope, Subject},
        time::{MonotonicTime, TimeWindow},
    };
    use capfs::{
        backing::{ImportedRepository, PreflightLimits},
        filesystem::{CapabilityFilesystem, MountAuthority, MountInstanceId, mount_config},
    };
    use criterion::{BenchmarkId, Criterion, Throughput};
    use fuser::{
        BackgroundSession, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags,
        Generation, INodeNo, KernelConfig, LockOwner, MountOption, OpenFlags, ReplyAttr, ReplyData,
        ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, WriteFlags,
    };
    use rustix::{
        fs::{Mode, OFlags, open},
        io::{pread, pwrite},
    };
    use tempfile::{TempDir, tempdir};

    /// Matches the adapter's own per-request bound so both FUSE layers agree.
    const MAX_IO_SIZE: u32 = 1024 * 1024;
    /// Matches the adapter's zero attribute TTL, which forces every stat to
    /// reach userspace instead of being served from the kernel's attribute
    /// cache.
    const ATTRIBUTE_TTL: Duration = Duration::ZERO;
    const NODE_GENERATION: Generation = Generation(0);

    /// Directory the capability is scoped to, below the repository root.
    const SCOPE: &str = "bench";
    /// Directory whose listing the `readdir` benchmark walks.
    const LISTING: &str = "listing";
    /// Entries in that directory, excluding `.` and `..`.
    const LISTING_ENTRIES: usize = 32;
    /// Transfer sizes swept by the read and write benchmarks.
    const TRANSFER_SIZES: [usize; 3] = [4 * 1024, 64 * 1024, 1024 * 1024];
    /// Client thread counts swept by the concurrency benchmark.
    const THREAD_COUNTS: [usize; 5] = [1, 2, 4, 8, 16];

    // ---------------------------------------------------------------- fixture

    /// Populates one backing tree shared by every layer's workload.
    fn populate(root: &Path) {
        let scope = root.join(SCOPE);
        fs::create_dir(&scope).expect("benchmark scope directory must be creatable");
        for size in TRANSFER_SIZES {
            fs::write(scope.join(read_target(size)), vec![0xA5_u8; size])
                .expect("benchmark read target must be writable");
        }
        fs::write(
            scope.join(WRITE_TARGET),
            vec![0x5A_u8; *TRANSFER_SIZES.last().expect("sizes must be non-empty")],
        )
        .expect("benchmark write target must be writable");
        let listing = scope.join(LISTING);
        fs::create_dir(&listing).expect("benchmark listing directory must be creatable");
        for index in 0..LISTING_ENTRIES {
            fs::write(listing.join(format!("entry-{index:03}")), b"")
                .expect("benchmark listing entry must be writable");
        }
    }

    /// Name of the pre-sized file read at one transfer size.
    fn read_target(size: usize) -> String {
        format!("read-{size}.bin")
    }

    /// Pre-sized file the write benchmark overwrites in place, so writes never
    /// extend the file and never take the truncate path.
    const WRITE_TARGET: &str = "write.bin";

    /// Bounds wide enough for the fixture, and no wider.
    fn preflight_limits() -> PreflightLimits {
        PreflightLimits::new(
            NonZeroUsize::new(128).expect("entry bound must be non-zero"),
            4,
        )
    }

    // ------------------------------------------------------------ passthrough

    /// One inode assignment table for the passthrough control.
    ///
    /// The control is deliberately the cheapest correct implementation: it
    /// keeps a path per inode and never forgets one, so a `LOOKUP` costs a map
    /// insert rather than a namespace transaction.
    #[derive(Debug)]
    struct Inodes {
        by_inode: BTreeMap<u64, PathBuf>,
        by_path: BTreeMap<PathBuf, u64>,
        next: u64,
    }

    impl Inodes {
        fn new(root: PathBuf) -> Self {
            Self {
                by_inode: BTreeMap::from([(1, root.clone())]),
                by_path: BTreeMap::from([(root, 1)]),
                next: 2,
            }
        }

        fn intern(&mut self, path: PathBuf) -> u64 {
            if let Some(inode) = self.by_path.get(&path) {
                return *inode;
            }
            let inode = self.next;
            self.next += 1;
            self.by_inode.insert(inode, path.clone());
            self.by_path.insert(path, inode);
            inode
        }

        fn path(&self, inode: u64) -> Option<&PathBuf> {
            self.by_inode.get(&inode)
        }
    }

    /// One snapshotted directory entry held by an open directory handle.
    #[derive(Debug)]
    struct Listing {
        inode: u64,
        kind: FileType,
        name: String,
    }

    /// A FUSE filesystem with capfs's mount configuration and none of its
    /// authorization, isolating what the FUSE transport alone costs.
    #[derive(Debug)]
    struct PassthroughFilesystem {
        inodes: Mutex<Inodes>,
        files: Mutex<BTreeMap<u64, OwnedFd>>,
        directories: Mutex<BTreeMap<u64, Vec<Listing>>>,
        next_handle: AtomicU64,
    }

    impl PassthroughFilesystem {
        fn new(root: &Path) -> Self {
            Self {
                inodes: Mutex::new(Inodes::new(root.to_path_buf())),
                files: Mutex::new(BTreeMap::new()),
                directories: Mutex::new(BTreeMap::new()),
                next_handle: AtomicU64::new(1),
            }
        }

        fn handle(&self) -> u64 {
            self.next_handle.fetch_add(1, Ordering::Relaxed)
        }

        fn path_of(&self, inode: INodeNo) -> Option<PathBuf> {
            self.inodes.lock().ok()?.path(inode.0).cloned()
        }
    }

    /// Converts backing metadata into the reply shape capfs also produces.
    fn attributes(inode: u64, metadata: &fs::Metadata) -> FileAttr {
        let kind = if metadata.is_dir() {
            FileType::Directory
        } else {
            FileType::RegularFile
        };
        FileAttr {
            ino: INodeNo(inode),
            size: metadata.size(),
            blocks: metadata.blocks(),
            atime: unix_time(metadata.atime(), metadata.atime_nsec()),
            mtime: unix_time(metadata.mtime(), metadata.mtime_nsec()),
            ctime: unix_time(metadata.ctime(), metadata.ctime_nsec()),
            crtime: UNIX_EPOCH,
            kind,
            perm: u16::try_from(metadata.mode() & 0o7777).unwrap_or(0),
            nlink: u32::try_from(metadata.nlink()).unwrap_or(1),
            uid: metadata.uid(),
            gid: metadata.gid(),
            rdev: 0,
            blksize: u32::try_from(metadata.blksize()).unwrap_or(4096),
            flags: 0,
        }
    }

    /// Forwards a backing error to the FUSE reply unchanged.
    fn errno(error: rustix::io::Errno) -> Errno {
        Errno::from(io::Error::from_raw_os_error(error.raw_os_error()))
    }

    fn unix_time(seconds: i64, nanoseconds: i64) -> SystemTime {
        let seconds = u64::try_from(seconds).unwrap_or(0);
        let nanoseconds = u32::try_from(nanoseconds).unwrap_or(0);
        UNIX_EPOCH + Duration::new(seconds, nanoseconds)
    }

    impl Filesystem for PassthroughFilesystem {
        fn init(&mut self, _request: &Request, config: &mut KernelConfig) -> io::Result<()> {
            config
                .set_max_write(MAX_IO_SIZE)
                .map(|_| ())
                .map_err(|limit| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("FUSE rejected the {MAX_IO_SIZE}-byte bound; maximum is {limit}"),
                    )
                })
        }

        fn lookup(&self, _request: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
            let Some(parent) = self.path_of(parent) else {
                reply.error(Errno::ENOENT);
                return;
            };
            let path = parent.join(name);
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                reply.error(Errno::ENOENT);
                return;
            };
            let Ok(mut inodes) = self.inodes.lock() else {
                reply.error(Errno::EIO);
                return;
            };
            let inode = inodes.intern(path);
            drop(inodes);
            reply.entry(
                &ATTRIBUTE_TTL,
                &attributes(inode, &metadata),
                NODE_GENERATION,
            );
        }

        fn getattr(
            &self,
            _request: &Request,
            inode: INodeNo,
            _handle: Option<FileHandle>,
            reply: ReplyAttr,
        ) {
            let Some(path) = self.path_of(inode) else {
                reply.error(Errno::ENOENT);
                return;
            };
            match fs::symlink_metadata(&path) {
                Ok(metadata) => reply.attr(&ATTRIBUTE_TTL, &attributes(inode.0, &metadata)),
                Err(_) => reply.error(Errno::ENOENT),
            }
        }

        fn open(&self, _request: &Request, inode: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
            let Some(path) = self.path_of(inode) else {
                reply.error(Errno::ENOENT);
                return;
            };
            let requested = OFlags::from_bits_retain(u32::try_from(flags.0).unwrap_or(0));
            let access = requested & (OFlags::WRONLY | OFlags::RDWR);
            let Ok(descriptor) = open(&path, access | OFlags::CLOEXEC, Mode::empty()) else {
                reply.error(Errno::EACCES);
                return;
            };
            let handle = self.handle();
            let Ok(mut files) = self.files.lock() else {
                reply.error(Errno::EIO);
                return;
            };
            files.insert(handle, descriptor);
            drop(files);
            reply.opened(
                FileHandle(handle),
                FopenFlags::FOPEN_DIRECT_IO | FopenFlags::FOPEN_NOFLUSH,
            );
        }

        fn read(
            &self,
            _request: &Request,
            _inode: INodeNo,
            handle: FileHandle,
            offset: u64,
            size: u32,
            _flags: OpenFlags,
            _lock_owner: Option<LockOwner>,
            reply: ReplyData,
        ) {
            let Ok(files) = self.files.lock() else {
                reply.error(Errno::EIO);
                return;
            };
            let Some(descriptor) = files.get(&handle.0) else {
                reply.error(Errno::EBADF);
                return;
            };
            let mut bytes = vec![0_u8; size as usize];
            match pread(descriptor, bytes.as_mut_slice(), offset) {
                Ok(count) => {
                    bytes.truncate(count);
                    drop(files);
                    reply.data(&bytes);
                }
                Err(error) => reply.error(errno(error)),
            }
        }

        fn write(
            &self,
            _request: &Request,
            _inode: INodeNo,
            handle: FileHandle,
            offset: u64,
            data: &[u8],
            _write_flags: WriteFlags,
            _flags: OpenFlags,
            _lock_owner: Option<LockOwner>,
            reply: ReplyWrite,
        ) {
            let Ok(files) = self.files.lock() else {
                reply.error(Errno::EIO);
                return;
            };
            let Some(descriptor) = files.get(&handle.0) else {
                reply.error(Errno::EBADF);
                return;
            };
            match pwrite(descriptor, data, offset) {
                Ok(count) => reply.written(u32::try_from(count).unwrap_or(0)),
                Err(error) => reply.error(errno(error)),
            }
        }

        fn release(
            &self,
            _request: &Request,
            _inode: INodeNo,
            handle: FileHandle,
            _flags: OpenFlags,
            _lock_owner: Option<LockOwner>,
            _flush: bool,
            reply: ReplyEmpty,
        ) {
            if let Ok(mut files) = self.files.lock() {
                files.remove(&handle.0);
            }
            reply.ok();
        }

        fn opendir(&self, _request: &Request, inode: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
            let Some(path) = self.path_of(inode) else {
                reply.error(Errno::ENOENT);
                return;
            };
            let Ok(entries) = fs::read_dir(&path) else {
                reply.error(Errno::ENOENT);
                return;
            };
            let mut listing = vec![
                Listing {
                    inode: inode.0,
                    kind: FileType::Directory,
                    name: ".".to_owned(),
                },
                Listing {
                    inode: inode.0,
                    kind: FileType::Directory,
                    name: "..".to_owned(),
                },
            ];
            let Ok(mut inodes) = self.inodes.lock() else {
                reply.error(Errno::EIO);
                return;
            };
            for entry in entries.flatten() {
                // `file_type` reads the dirent's own `d_type`. Asking the path
                // instead costs one `stat` per entry, which would make this
                // control more expensive than the layer it controls for.
                let kind = if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                    FileType::Directory
                } else {
                    FileType::RegularFile
                };
                let child = inodes.intern(entry.path());
                listing.push(Listing {
                    inode: child,
                    kind,
                    name: entry.file_name().to_string_lossy().into_owned(),
                });
            }
            drop(inodes);
            let handle = self.handle();
            let Ok(mut directories) = self.directories.lock() else {
                reply.error(Errno::EIO);
                return;
            };
            directories.insert(handle, listing);
            drop(directories);
            reply.opened(FileHandle(handle), FopenFlags::empty());
        }

        fn readdir(
            &self,
            _request: &Request,
            _inode: INodeNo,
            handle: FileHandle,
            offset: u64,
            mut reply: ReplyDirectory,
        ) {
            let Ok(directories) = self.directories.lock() else {
                reply.error(Errno::EIO);
                return;
            };
            let Some(listing) = directories.get(&handle.0) else {
                reply.error(Errno::EBADF);
                return;
            };
            let start = usize::try_from(offset).unwrap_or(usize::MAX);
            for (index, entry) in listing.iter().enumerate().skip(start) {
                let next = u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1);
                if reply.add(INodeNo(entry.inode), next, entry.kind, &entry.name) {
                    break;
                }
            }
            drop(directories);
            reply.ok();
        }

        fn releasedir(
            &self,
            _request: &Request,
            _inode: INodeNo,
            handle: FileHandle,
            _flags: OpenFlags,
            reply: ReplyEmpty,
        ) {
            if let Ok(mut directories) = self.directories.lock() {
                directories.remove(&handle.0);
            }
            reply.ok();
        }
    }

    // ------------------------------------------------------------ capability

    /// The effects every layer's workload needs, and nothing beyond them.
    fn benchmark_effects() -> FileEffects {
        FileEffects::from_effects([
            FileEffect::ReadData,
            FileEffect::WriteData,
            FileEffect::ListDirectory,
        ])
    }

    /// One kernel holding a subject and a capability scoped to [`SCOPE`].
    struct Authority {
        kernel: Arc<CapabilityKernel>,
        subject: SubjectId,
        capability: CapId,
        repository: RepoId,
    }

    impl Authority {
        fn new(label: &str) -> Self {
            let repository = RepoId::new("workspace");
            let subject = SubjectId::new(format!("{label}-subject"));
            let validity = TimeWindow::new(
                MonotonicTime::from_ticks(0),
                MonotonicTime::from_ticks(1000),
            )
            .expect("benchmark validity must be non-empty");
            let kernel = Arc::new(CapabilityKernel::new(CapabilityState::new(IssuerId::new(
                format!("{label}-session"),
            ))));
            kernel
                .register_subject(Subject::new(
                    subject.clone(),
                    StaticAuthorityEnvelope::new(
                        validity,
                        AuthorityBody::File(FileAuthority::new(
                            repository.clone(),
                            benchmark_effects(),
                            PathPattern::Prefix(CanonicalPath::root()),
                        )),
                    ),
                ))
                .expect("benchmark subject registration must succeed");
            let capability = kernel
                .issue_root(CapabilityGrant::new(
                    subject.clone(),
                    validity,
                    AuthorityBody::File(FileAuthority::new(
                        repository.clone(),
                        benchmark_effects(),
                        PathPattern::Prefix(
                            CanonicalPath::new([SCOPE]).expect("scope must be canonical"),
                        ),
                    )),
                ))
                .expect("benchmark capability issuance must succeed");
            Self {
                kernel,
                subject,
                capability,
                repository,
            }
        }

        /// Builds the request shape capfs constructs for one data effect.
        fn request(&self, effect: FileEffect, path: &CanonicalPath) -> CapabilityRequest {
            CapabilityRequest::new(
                CLOCK,
                AuthorityRequest::File(FileRequest::new(
                    self.repository.clone(),
                    effect,
                    path.clone(),
                )),
            )
        }
    }

    /// Fixed authorization time, inside every validity window used here.
    const CLOCK: MonotonicTime = MonotonicTime::from_ticks(5);

    // ----------------------------------------------------------- layer setup

    /// Which of the three client-visible layers a workload runs against.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Layer {
        Native,
        Passthrough,
        Capfs,
    }

    impl Layer {
        const fn name(self) -> &'static str {
            match self {
                Self::Native => "native",
                Self::Passthrough => "passthrough",
                Self::Capfs => "capfs",
            }
        }

        const fn needs_fuse(self) -> bool {
            !matches!(self, Self::Native)
        }
    }

    /// A populated tree reachable at [`Self::scope`], plus whatever mount is
    /// needed to reach it.
    ///
    /// Field order is the drop order: the session unmounts before the
    /// mountpoint directory is removed.
    struct Workspace {
        _session: Option<BackgroundSession>,
        _mountpoint: Option<TempDir>,
        _backing: TempDir,
        scope: PathBuf,
    }

    impl Workspace {
        fn new(layer: Layer, label: &str) -> Self {
            let backing = tempdir().expect("benchmark backing directory must be creatable");
            populate(backing.path());

            let (session, mountpoint) = match layer {
                Layer::Native => (None, None),
                Layer::Passthrough => {
                    let mountpoint = tempdir().expect("benchmark mountpoint must be creatable");
                    let mut config = mount_config();
                    for option in &mut config.mount_options {
                        match option {
                            MountOption::FSName(name) | MountOption::Subtype(name) => {
                                "capfs-passthrough".clone_into(name);
                            }
                            _ => {}
                        }
                    }
                    let session = fuser::spawn_mount(
                        PassthroughFilesystem::new(backing.path()),
                        mountpoint.path(),
                        &config,
                    )
                    .expect("passthrough mount must succeed");
                    (Some(session), Some(mountpoint))
                }
                Layer::Capfs => {
                    let mountpoint = tempdir().expect("benchmark mountpoint must be creatable");
                    let authority = Authority::new(label);
                    let imported = ImportedRepository::open(
                        authority.repository.clone(),
                        backing.path(),
                        preflight_limits(),
                    )
                    .expect("benchmark backing must pass preflight");
                    let filesystem = CapabilityFilesystem::new(
                        imported,
                        Arc::clone(&authority.kernel),
                        MountAuthority::new(
                            MountInstanceId::new(label),
                            authority.subject.clone(),
                            authority.capability.clone(),
                            authority.repository.clone(),
                        ),
                        Arc::new(CLOCK),
                    )
                    .expect("capability filesystem must initialize");
                    let session = capfs::filesystem::spawn_mount(filesystem, mountpoint.path())
                        .expect("capfs mount must succeed");
                    (Some(session), Some(mountpoint))
                }
            };

            let root = mountpoint.as_ref().map_or_else(
                || backing.path().to_path_buf(),
                |dir| dir.path().to_path_buf(),
            );

            Self {
                _session: session,
                _mountpoint: mountpoint,
                _backing: backing,
                scope: root.join(SCOPE),
            }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.scope.join(name)
        }
    }

    // ------------------------------------------------------------ benchmarks

    /// Layers to measure, dropping the FUSE-backed ones when `/dev/fuse` is
    /// unavailable rather than failing the run.
    fn layers() -> Vec<Layer> {
        let fuse = Path::new("/dev/fuse").exists();
        if !fuse {
            eprintln!("/dev/fuse is unavailable; measuring the native layer only");
        }
        [Layer::Native, Layer::Passthrough, Layer::Capfs]
            .into_iter()
            .filter(|layer| fuse || !layer.needs_fuse())
            .collect()
    }

    /// Positioned reads on an already-open descriptor, so each iteration is one
    /// `READ` and never a `LOOKUP` or `OPEN`.
    pub fn read(criterion: &mut Criterion) {
        let mut group = criterion.benchmark_group("read");
        for size in TRANSFER_SIZES {
            group.throughput(Throughput::Bytes(size as u64));
            for layer in layers() {
                let workspace = Workspace::new(layer, &format!("read-{}-{size}", layer.name()));
                let file = File::open(workspace.path(&read_target(size)))
                    .expect("benchmark read target must be openable");
                let mut buffer = vec![0_u8; size];
                group.bench_function(BenchmarkId::new(layer.name(), size), |bencher| {
                    bencher.iter(|| {
                        let count = file
                            .read_at(buffer.as_mut_slice(), 0)
                            .expect("benchmark read must succeed");
                        black_box(count);
                    });
                });
            }
        }
        group.finish();
    }

    /// Positioned writes over a pre-sized file, so no iteration extends it or
    /// takes the truncate path.
    pub fn write(criterion: &mut Criterion) {
        let mut group = criterion.benchmark_group("write");
        for size in TRANSFER_SIZES {
            group.throughput(Throughput::Bytes(size as u64));
            for layer in layers() {
                let workspace = Workspace::new(layer, &format!("write-{}-{size}", layer.name()));
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(workspace.path(WRITE_TARGET))
                    .expect("benchmark write target must be openable");
                let buffer = vec![0x3C_u8; size];
                group.bench_function(BenchmarkId::new(layer.name(), size), |bencher| {
                    bencher.iter(|| {
                        let count = file
                            .write_at(&buffer, 0)
                            .expect("benchmark write must succeed");
                        black_box(count);
                    });
                });
            }
        }
        group.finish();
    }

    /// One `stat` per iteration. With a zero attribute TTL this is a `LOOKUP`
    /// on every call, so it measures the metadata path rather than the kernel's
    /// attribute cache.
    pub fn stat(criterion: &mut Criterion) {
        let mut group = criterion.benchmark_group("stat");
        for layer in layers() {
            let workspace = Workspace::new(layer, &format!("stat-{}", layer.name()));
            let path = workspace.path(&read_target(TRANSFER_SIZES[0]));
            group.bench_function(layer.name(), |bencher| {
                bencher.iter(|| {
                    let metadata =
                        fs::symlink_metadata(&path).expect("benchmark stat must succeed");
                    black_box(metadata.len());
                });
            });
        }
        group.finish();
    }

    /// One open/close pair per iteration: `LOOKUP`, `OPEN`, then `RELEASE`.
    pub fn open_close(criterion: &mut Criterion) {
        let mut group = criterion.benchmark_group("open_close");
        for layer in layers() {
            let workspace = Workspace::new(layer, &format!("open-{}", layer.name()));
            let path = workspace.path(&read_target(TRANSFER_SIZES[0]));
            group.bench_function(layer.name(), |bencher| {
                bencher.iter(|| {
                    let file = File::open(&path).expect("benchmark open must succeed");
                    black_box(&file);
                    drop(file);
                });
            });
        }
        group.finish();
    }

    /// A full directory walk of [`LISTING_ENTRIES`] entries per iteration.
    pub fn readdir(criterion: &mut Criterion) {
        let mut group = criterion.benchmark_group("readdir");
        group.throughput(Throughput::Elements(LISTING_ENTRIES as u64));
        for layer in layers() {
            let workspace = Workspace::new(layer, &format!("readdir-{}", layer.name()));
            let path = workspace.path(LISTING);
            group.bench_function(layer.name(), |bencher| {
                bencher.iter(|| {
                    let count = fs::read_dir(&path)
                        .expect("benchmark listing must be readable")
                        .count();
                    black_box(count);
                });
            });
        }
        group.finish();
    }

    /// Per-operation wall clock as client threads are added.
    ///
    /// Every thread opens its own descriptor and reads its own 4 KiB, so the
    /// only thing they contend for is the mount. The reported time is one
    /// operation's share of wall clock: it falls as threads are added when the
    /// mount serves them in parallel, and stays flat when the mount serializes
    /// them.
    pub fn concurrent_read(criterion: &mut Criterion) {
        let mut group = criterion.benchmark_group("concurrent_read");
        let size = TRANSFER_SIZES[0];
        for threads in THREAD_COUNTS {
            for layer in layers() {
                let workspace =
                    Workspace::new(layer, &format!("concurrent-{}-{threads}", layer.name()));
                let path = workspace.path(&read_target(size));
                group.bench_function(BenchmarkId::new(layer.name(), threads), |bencher| {
                    bencher.iter_custom(|iterations| {
                        let per_thread = iterations.div_ceil(threads as u64).max(1);
                        // The extra party is this thread, so timing starts only
                        // once every worker has its descriptor open.
                        let barrier = Arc::new(Barrier::new(threads + 1));
                        let workers: Vec<_> = (0..threads)
                            .map(|_| {
                                let path = path.clone();
                                let barrier = Arc::clone(&barrier);
                                thread::spawn(move || {
                                    let file = File::open(&path)
                                        .expect("benchmark read target must be openable");
                                    let mut buffer = vec![0_u8; size];
                                    barrier.wait();
                                    for _ in 0..per_thread {
                                        let count = file
                                            .read_at(buffer.as_mut_slice(), 0)
                                            .expect("benchmark read must succeed");
                                        black_box(count);
                                    }
                                })
                            })
                            .collect();
                        barrier.wait();
                        let start = Instant::now();
                        for worker in workers {
                            worker.join().expect("benchmark worker must not panic");
                        }
                        let elapsed = start.elapsed();
                        // Workers run `per_thread * threads` operations, which
                        // rounding can push above `iterations`. Rescale so the
                        // figure criterion divides is the cost of exactly
                        // `iterations` operations.
                        let performed = per_thread * threads as u64;
                        let scaled = elapsed.as_nanos() * u128::from(iterations)
                            / u128::from(performed).max(1);
                        Duration::from_nanos(u64::try_from(scaled).unwrap_or(u64::MAX))
                    });
                });
            }
        }
        group.finish();
    }

    /// The capability decisions themselves, with no FUSE round trip.
    ///
    /// `commit` is the data path capfs takes for every `READ` and `WRITE`: it
    /// records an audit attempt, runs the effect under the state guard, and
    /// transitions the attempt to a committed effect. `observe` is the metadata
    /// path taken by `LOOKUP` and `GETATTR`, which inspects the live capability
    /// without recording an effect.
    ///
    /// `commit` retains one audit record per iteration, so each sample runs
    /// against a freshly built kernel and the trail cannot span the run.
    pub fn capability_check(criterion: &mut Criterion) {
        let mut group = criterion.benchmark_group("capability_check");
        let path = CanonicalPath::new([SCOPE, "read-4096.bin"]).expect("path must be canonical");

        group.bench_function("commit", |bencher| {
            bencher.iter_custom(|iterations| {
                let authority = Authority::new("capability-commit");
                let request = authority.request(FileEffect::ReadData, &path);
                let start = std::time::Instant::now();
                for _ in 0..iterations {
                    let outcome = authority.kernel.authorize_and_execute_classified(
                        &authority.subject,
                        &authority.capability,
                        &request,
                        |_| EffectExecution::<(), ()>::Committed {
                            value: (),
                            receipt: None,
                        },
                    );
                    black_box(outcome).expect("benchmark authorization must succeed");
                }
                start.elapsed()
            });
        });

        let authority = Authority::new("capability-observe");
        group.bench_function("observe", |bencher| {
            bencher.iter(|| {
                let outcome = authority.kernel.with_active_capability(
                    &authority.subject,
                    &authority.capability,
                    CLOCK,
                    |capability| {
                        Ok::<_, ()>(matches!(capability.authority(), AuthorityBody::File(_)))
                    },
                );
                black_box(outcome).expect("benchmark inspection must succeed");
            });
        });

        group.finish();
    }
}

#[cfg(target_os = "linux")]
fn main() {
    let mut criterion = criterion::Criterion::default().configure_from_args();
    linux::read(&mut criterion);
    linux::write(&mut criterion);
    linux::stat(&mut criterion);
    linux::open_close(&mut criterion);
    linux::readdir(&mut criterion);
    linux::concurrent_read(&mut criterion);
    linux::capability_check(&mut criterion);
    criterion.final_summary();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("capfs benchmarks require Linux FUSE support");
}
