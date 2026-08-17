#![no_main]

use authority_core::path::CanonicalPath;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let segments: Vec<&str> = text.split('/').take(64).collect();
    if let Ok(path) = CanonicalPath::new(segments) {
        let root = CanonicalPath::root();
        let _ = path.is_at_or_below(&root);
        let _ = path.parent();
        let _ = path.child("fuzz");
        let _ = path.rebase(&root, &root);
    }
});
