//! The [`super::LiftCache`] as it was before its entries kept their index for the cache's
//! life (contiguous arrays, the dead entries at their front removed by moving the others
//! down and renumbering them), for the test that the cache behaves exactly as it did
//! (`cache_matches_old_cache`).

use super::{BlockDecoder, Memory, OpFacts, X86Lifter, reads_outside_pf, x87};
use super::{DEAD, FAILED, Meta, NO_NEXT, READS_PF, X87};
use crate::lift::LiftedInstruction;

const CACHE_RESERVE: usize = 2048;
const INDEX_PAGE: u64 = 1024;
const MAX_SPARE_PAGES: usize = 128;
const NO_INDEX: u32 = u32::MAX;

#[derive(Default)]
pub(super) struct OldCache {
    map: AddrIndex,
    pub(super) head: usize,
    pub(super) live: usize,
    pub(super) lifted: Vec<std::cell::OnceCell<LiftedInstruction>>,
    pub(super) decoded: Vec<iced_x86::Instruction>,
    is_64: bool,
    lazy: bool,
    pub(super) meta: Vec<Meta>,
    pub(super) addr: Vec<u64>,
    pub(super) sflags: Vec<u8>,
    pub(super) target: Vec<u64>,
    pub(super) special: Vec<u32>,
    kept: usize,
}

impl OldCache {
    pub(super) fn new(lazy: bool) -> Self {
        Self { lazy, ..Self::default() }
    }

    pub(super) fn trim(&mut self, start: u64, at: usize) {
        if self.live > at.max(2 * self.kept) {
            self.retain_from(start);
            self.kept = self.live;
        }
        let (len, cap) = (self.lifted.len(), self.lifted.capacity());
        if self.head > 0 && 4 * self.head >= len && 4 * (cap - len) < len {
            self.compact();
        }
    }

    pub(super) fn retain_from(&mut self, start: u64) {
        while self.head < self.lifted.len() {
            let p = self.head;
            if self.meta[p].flags & DEAD == 0 {
                if self.addr[p] >= start {
                    break;
                }
                self.lifted[p].take();
                self.meta[p] = Meta { next: NO_NEXT, len: 0, flags: DEAD };
                self.live -= 1;
            }
            self.head += 1;
        }
        if self.head > 0 && 2 * self.head >= self.lifted.len() {
            self.compact();
        }
    }

    fn compact(&mut self) {
        let h = self.head;
        self.lifted.drain(..h);
        self.decoded.drain(..h);
        self.meta.drain(..h);
        self.addr.drain(..h);
        self.sflags.drain(..h);
        self.target.drain(..h);
        self.head = 0;
        let h = u32::try_from(h).expect("lift cache index");
        let k = self.special.partition_point(|&i| i < h);
        self.special.drain(..k);
        for i in &mut self.special {
            *i -= h;
        }
        for m in &mut self.meta {
            m.next = if m.next == NO_NEXT || m.next < h { NO_NEXT } else { m.next - h };
        }
        self.map.shift_down(h);
    }

    fn reserve(&mut self, n: usize) {
        let n = (2 * n).max(CACHE_RESERVE);
        self.lifted.reserve(n);
        self.decoded.reserve(n);
        self.meta.reserve(n);
        self.addr.reserve(n);
        self.sflags.reserve(n);
        self.target.reserve(n);
    }

    /// The entry of `addr`, when one is held.
    pub(super) fn lookup(&mut self, addr: u64) -> Option<u32> {
        let i = *self.map.slot(addr);
        (i != NO_INDEX && self.meta[i as usize].flags & DEAD == 0).then_some(i)
    }

    /// The instruction at index `i`, lifted.
    pub(super) fn insn(&self, i: u32) -> &LiftedInstruction {
        self.lifted[i as usize].get_or_init(|| {
            X86Lifter { is_64: self.is_64, parity: false }
                .lift_decoded(self.decoded[i as usize], self.addr[i as usize], None)
                .expect("an instruction `decoded_facts` answers for lifts")
        })
    }

    pub(super) fn index_of<'m>(&mut self, lifter: &X86Lifter, memory: &'m Memory, addr: u64, block: &mut Option<BlockDecoder<'m>>) -> u32 {
        let i = *self.map.slot(addr);
        if i != NO_INDEX && self.meta[i as usize].flags & DEAD == 0 {
            return i;
        }
        if self.lifted.len() == self.lifted.capacity() {
            self.reserve(self.live);
        }
        let i = u32::try_from(self.lifted.len()).expect("lift cache index");
        assert!(i != NO_INDEX, "lift cache index");
        let decoded = lifter.decode_in_block(memory, addr, block);
        let lazy = match &decoded {
            Ok(insn) if self.lazy && !lifter.parity => X86Lifter::decoded_facts(insn).map(|f| (*insn, f)),
            _ => None,
        };
        let (flags, len, shape) = if let Some((insn, (sflags, target, reads_pf))) = lazy {
            self.is_64 = lifter.is_64;
            let len = u8::try_from(insn.len()).expect("an x86 instruction is at most 15 bytes");
            self.lifted.push(std::cell::OnceCell::new());
            self.decoded.push(insn);
            (if reads_pf { READS_PF } else { 0 }, len, crate::lift::InsnShape { address: addr, target, flags: sflags })
        } else {
            let mut facts = OpFacts::default();
            match decoded.and_then(|insn| lifter.lift_decoded_facts(insn, addr, None, &mut facts)) {
                Ok(insn) => {
                    let x87 = insn.mnemonic.x86_instruction().is_none_or(x87::is_x87);
                    let flags = if x87 { X87 } else { 0 } | if facts.reads_outside_pf { READS_PF } else { 0 };
                    let len = u8::try_from(insn.length).expect("an x86 instruction is at most 15 bytes");
                    let shape = crate::lift::InsnShape { address: addr, target: facts.target, flags: facts.flags };
                    debug_assert_eq!(facts.reads_outside_pf, reads_outside_pf(&insn));
                    self.lifted.push(std::cell::OnceCell::from(insn));
                    self.decoded.push(iced_x86::Instruction::default());
                    (flags, len, shape)
                }
                Err(_) => {
                    self.lifted.push(std::cell::OnceCell::new());
                    self.decoded.push(iced_x86::Instruction::default());
                    (FAILED, 0, crate::lift::InsnShape { address: addr, ..Default::default() })
                }
            }
        };
        self.meta.push(Meta { next: NO_NEXT, len, flags });
        self.addr.push(shape.address);
        self.sflags.push(shape.flags);
        self.target.push(shape.target);
        if shape.flags != 0 {
            self.special.push(i);
        }
        *self.map.slot(addr) = i;
        self.live += 1;
        i
    }

    /// The walk of `X86Lifter::walk_cached` (its indices, before the x87 / PF checks).
    pub(super) fn walk(&mut self, fast: &X86Lifter, memory: &Memory, start: u64, count: usize) -> Vec<u32> {
        let mut idxs: Vec<u32> = Vec::new();
        let mut addr = start;
        let mut prev: Option<u32> = None;
        let mut block = None;
        for _ in 0..count {
            let i = match prev.map(|p| self.meta[p as usize].next) {
                Some(i) if i != NO_NEXT => i,
                _ => {
                    let i = self.index_of(fast, memory, addr, &mut block);
                    if let Some(p) = prev {
                        self.meta[p as usize].next = i;
                    }
                    i
                }
            };
            let m = self.meta[i as usize];
            if m.flags & FAILED != 0 {
                break;
            }
            prev = Some(i);
            idxs.push(i);
            addr += u64::from(m.len);
        }
        idxs
    }
}

#[derive(Default)]
struct AddrIndex {
    pages: Vec<Box<[u32; INDEX_PAGE as usize]>>,
    by_page: rustc_hash::FxHashMap<u64, u32>,
    last: Option<(u64, u32)>,
    spare: Vec<Box<[u32; INDEX_PAGE as usize]>>,
}

impl AddrIndex {
    fn slot(&mut self, addr: u64) -> &mut u32 {
        let page = addr / INDEX_PAGE;
        let at = match self.last {
            Some((p, at)) if p == page => at,
            _ => self.page_of(page),
        };
        &mut self.pages[at as usize][(addr % INDEX_PAGE) as usize]
    }

    fn page_of(&mut self, page: u64) -> u32 {
        let next = u32::try_from(self.pages.len()).expect("lift cache pages");
        let at = *self.by_page.entry(page).or_insert(next);
        if at == next {
            let page = self.spare.pop().unwrap_or_else(|| Box::new([NO_INDEX; INDEX_PAGE as usize]));
            self.pages.push(page);
        }
        self.last = Some((page, at));
        at
    }

    fn shift_down(&mut self, h: u32) {
        let pages = std::mem::take(&mut self.pages);
        let mut kept: rustc_hash::FxHashMap<u32, u32> = rustc_hash::FxHashMap::default();
        for (at, mut page) in pages.into_iter().enumerate() {
            let mut any = false;
            for i in page.iter_mut() {
                *i = if *i == NO_INDEX || *i < h { NO_INDEX } else { *i - h };
                any |= *i != NO_INDEX;
            }
            if any {
                kept.insert(at as u32, self.pages.len() as u32);
                self.pages.push(page);
            } else if self.spare.len() < MAX_SPARE_PAGES {
                self.spare.push(page);
            }
        }
        self.by_page.retain(|_, at| match kept.get(at) {
            Some(&new) => {
                *at = new;
                true
            }
            None => false,
        });
        self.last = None;
    }
}
