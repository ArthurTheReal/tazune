use crate::dns::{DnsRecord, QueryType, ResultCode};

use std::collections::HashMap;
use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

// Answers are kept at least MIN_TTL and at most MAX_TTL seconds, whatever their
// own TTL says. A TTL of 0 means "don't cache this" and is respected.
const MIN_TTL: u32 = 10;
const MAX_TTL: u32 = 86_400; // one day

// How long "this name doesn't exist" (NXDOMAIN) and "this name has no records of
// this type" (NODATA) are remembered. The proper value is the SOA record's
// minimum field (RFC 2308), but we don't parse SOA yet, so use a fixed value.
const NEGATIVE_TTL: u32 = 60;

type Key = (String, QueryType);

struct CacheEntry {
    rescode: ResultCode,
    answers: Vec<DnsRecord>,
    expires: Instant,
}

// What a cache hit gives back: ready to be copied into a response.
pub struct CachedResponse {
    pub rescode: ResultCode,
    pub answers: Vec<DnsRecord>,
}

// A cache of upstream answers, keyed by (name, query type). It is shared between
// all worker threads, so the map sits behind an RwLock: many threads can read
// (cache hits) at the same time, and only inserts need exclusive access.
//
// Locks are only ever held while touching the map, never while talking to the
// network, so a slow upstream can't block cache hits.
pub struct Cache {
    entries: RwLock<HashMap<Key, CacheEntry>>,
    max_entries: usize,
}

impl Cache {
    pub fn new(max_entries: usize) -> Cache {
        Cache {
            entries: RwLock::new(HashMap::new()),
            max_entries,
        }
    }

    pub fn get(&self, name: &str, qtype: QueryType) -> Option<CachedResponse> {
        self.get_at(name, qtype, Instant::now())
    }

    pub fn put(&self, name: &str, qtype: QueryType, rescode: ResultCode, answers: &[DnsRecord]) {
        self.put_at(name, qtype, rescode, answers, Instant::now())
    }

    fn get_at(&self, name: &str, qtype: QueryType, now: Instant) -> Option<CachedResponse> {
        let entries = self.read_lock();
        let entry = entries.get(&(name.to_string(), qtype))?;

        if entry.expires <= now {
            return None;
        }

        let remaining = ceil_secs(entry.expires.duration_since(now));
        let answers = entry
            .answers
            .iter()
            .map(|record| record.with_ttl(record.ttl().min(remaining)))
            .collect();

        Some(CachedResponse {
            rescode: entry.rescode,
            answers,
        })
    }

    fn put_at(&self, name: &str, qtype: QueryType, rescode: ResultCode, answers: &[DnsRecord], now: Instant) {
        if self.max_entries == 0 {
            return;
        }
        let Some(ttl) = cache_ttl(rescode, answers) else {
            return;
        };

        let key = (name.to_string(), qtype);
        let entry = CacheEntry {
            rescode,
            answers: answers.to_vec(),
            expires: now + Duration::from_secs(u64::from(ttl)),
        };

        let mut entries = self.write_lock();
        if entries.len() >= self.max_entries && !entries.contains_key(&key) {
            make_room(&mut entries, self.max_entries, now);
        }
        entries.insert(key, entry);
    }

    // The cache holds no invariants that a panicking thread could break halfway
    // (an insert either happened or it didn't), so if a thread panicked while
    // holding the lock we just carry on with the data instead of panicking too.
    fn read_lock(&self) -> RwLockReadGuard<'_, HashMap<Key, CacheEntry>> {
        self.entries.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write_lock(&self) -> RwLockWriteGuard<'_, HashMap<Key, CacheEntry>> {
        self.entries.write().unwrap_or_else(PoisonError::into_inner)
    }
}

// How long an answer may be cached, or None if it must not be.
fn cache_ttl(rescode: ResultCode, answers: &[DnsRecord]) -> Option<u32> {
    match rescode {
        ResultCode::NOERROR if !answers.is_empty() => {
            // The answer is only as fresh as its shortest-lived record.
            let shortest = answers.iter().map(DnsRecord::ttl).min()?;
            if shortest == 0 {
                None
            } else {
                Some(shortest.clamp(MIN_TTL, MAX_TTL))
            }
        }
        // NODATA (NOERROR with nothing in it) and NXDOMAIN: negative caching.
        ResultCode::NOERROR | ResultCode::NXDOMAIN => Some(NEGATIVE_TTL),
        // SERVFAIL, REFUSED and friends are often temporary, so retry upstream.
        _ => None,
    }
}

// Called with the write lock held when the cache is full. Drops expired entries
// first, and if that wasn't enough, the entry closest to expiring (it has the
// least time left to be useful). This scans the whole map, but only runs when
// the cache is full and a new name arrives.
fn make_room(entries: &mut HashMap<Key, CacheEntry>, max_entries: usize, now: Instant) {
    entries.retain(|_, entry| entry.expires > now);

    if entries.len() >= max_entries {
        let soonest = entries
            .iter()
            .min_by_key(|(_, entry)| entry.expires)
            .map(|(key, _)| key.clone());
        if let Some(key) = soonest {
            entries.remove(&key);
        }
    }
}

// Whole seconds, rounded up, so an entry with half a second left reports a TTL
// of 1 and not 0 (which clients read as "don't cache").
fn ceil_secs(duration: Duration) -> u32 {
    let secs = duration.as_secs() + u64::from(duration.subsec_nanos() > 0);
    secs.min(u64::from(u32::MAX)) as u32
}