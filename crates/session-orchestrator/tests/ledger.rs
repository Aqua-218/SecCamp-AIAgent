//! Durable identity-ledger contract tests.

use std::{
    fs::{self, OpenOptions},
    io::{Seek, SeekFrom, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use session_orchestrator::{
    DurableIdentityLedger, IdentityKind, IdentityLedger, LedgerError, MAX_LEDGER_RECORDS,
};

fn ledger_path(test_name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock must be after the Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "session-orchestrator-{test_name}-{}-{nonce}.ledger",
        std::process::id()
    ))
}

fn remove(path: &PathBuf) {
    let _ = fs::remove_file(path);
    let mut lock = path.as_os_str().to_os_string();
    lock.push(".lock");
    let _ = fs::remove_file(lock);
}

#[test]
fn durable_ledger_recovers_all_committed_records_after_reopen() {
    let path = ledger_path("recovery");
    let first = [0x11; 16];
    let second = [0x22; 16];
    {
        let mut ledger = DurableIdentityLedger::open(&path).expect("ledger must open");
        ledger
            .reserve_batch(&[(IdentityKind::Session, first), (IdentityKind::Vm, second)])
            .expect("batch must sync");
        assert_eq!(ledger.committed_count(), 2);
    }
    let ledger = DurableIdentityLedger::open(&path).expect("ledger must recover");
    assert!(ledger.contains(first));
    assert!(ledger.contains(second));
    assert_eq!(ledger.committed_count(), 2);
    drop(ledger);
    remove(&path);
}

#[test]
fn corrupt_record_is_rejected() {
    let path = ledger_path("corrupt");
    {
        let ledger = DurableIdentityLedger::open(&path).expect("ledger must open");
        drop(ledger);
    }
    let mut file = OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("test ledger must be writable");
    file.seek(SeekFrom::Start(0)).expect("seek must work");
    file.write_all(b"X").expect("test corruption must write");
    file.sync_data().expect("test corruption must sync");
    let error = DurableIdentityLedger::open(&path).expect_err("corrupt header must fail");
    assert!(matches!(error, LedgerError::Corrupt { .. }));
    remove(&path);
}

#[test]
fn truncated_record_is_rejected() {
    let path = ledger_path("truncated");
    {
        let mut ledger = DurableIdentityLedger::open(&path).expect("ledger must open");
        ledger
            .reserve(IdentityKind::Session, [0x44; 16])
            .expect("record must be committed");
    }
    let file = OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("test ledger must be writable");
    let length = file.metadata().expect("metadata must work").len();
    file.set_len(length - 1).expect("test truncation must work");
    file.sync_data().expect("test truncation must sync");
    let error = DurableIdentityLedger::open(&path).expect_err("truncated header must fail");
    assert!(matches!(error, LedgerError::Truncated { .. }));
    remove(&path);
}

#[test]
fn duplicate_remains_rejected_after_reopen() {
    let path = ledger_path("duplicate");
    let identity = [0x33; 16];
    {
        let mut ledger = DurableIdentityLedger::open(&path).expect("ledger must open");
        ledger
            .reserve(IdentityKind::Capability, identity)
            .expect("first reservation must sync");
    }
    let mut reopened = DurableIdentityLedger::open(&path).expect("ledger must recover");
    let error = reopened
        .reserve(IdentityKind::Request, identity)
        .expect_err("duplicate must remain rejected");
    assert!(matches!(error, LedgerError::Duplicate { .. }));
    drop(reopened);
    remove(&path);
}

#[test]
fn second_owner_is_rejected_while_first_owner_is_alive() {
    let path = ledger_path("lock");
    let first = DurableIdentityLedger::open(&path).expect("first owner must open");
    let error = DurableIdentityLedger::open(&path).expect_err("second owner must be rejected");
    assert!(matches!(error, LedgerError::Locked { .. }));
    drop(first);
    remove(&path);
}

#[test]
fn record_count_limit_is_explicitly_bounded() {
    assert_eq!(MAX_LEDGER_RECORDS, 1_048_576);
}
