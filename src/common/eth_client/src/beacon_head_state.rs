use std::prelude::v1::*;

use crate::{BeaconClient, BeaconSlot, HeadState};
use base::channel::Boardcast;
use base::thread::spawn;
use base::trace::Alive;
use eth_types::{BlockHeader, Withdrawal, SH256};

use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;

#[derive(Clone, Debug)]
pub struct BeaconHead {
    pub slot: u64,
    pub slot_time: u64,

    // NOTICE: this block may not match the slot number
    pub block: Arc<BlockHeader>,
    randao: Option<SH256>,
    withdrawal: Option<Vec<Withdrawal>>,
}

impl BeaconHead {
    pub fn is_eth1_match(&self) -> bool {
        self.block.timestamp.as_u64() == self.slot_time
    }

    pub fn ready_for_submit(&self) -> bool {
        self.randao.is_some() && self.withdrawal.is_some()
    }

    pub fn randao(&self) -> SH256 {
        match &self.randao {
            Some(randao) => randao.clone(),
            None => self.block.mix_hash,
        }
    }

    pub fn withdrawal(&self) -> Vec<Withdrawal> {
        match &self.withdrawal {
            Some(item) => item.clone(),
            None => vec![],
        }
    }

    pub fn thread_name(&self) -> String {
        let blk_number = if self.block.timestamp.as_u64() == self.slot_time {
            self.block.number.as_u64()
        } else {
            self.block.number.as_u64() + 1
        };
        format!("{}.{}", self.slot + 1, blk_number + 1)
    }
}

pub struct BeaconHeadState {
    head_state: HeadState,
    new_head_handle: Option<JoinHandle<()>>,
    head_bcast: Boardcast<BeaconHead>,

    randao_bcast: Boardcast<(u64, SH256)>,
    randao_handle: Option<JoinHandle<()>>,

    withdrawal_bcast: Boardcast<(u64, Vec<Withdrawal>)>,
    withdrawal_handle: Option<JoinHandle<()>>,
}

impl BeaconHeadState {
    pub fn new(
        alive: Alive,
        head_state: HeadState,
        beacon_slot: BeaconSlot,
        cl: Arc<BeaconClient>,
    ) -> Self {
        // let el = head_state.el();
        let head_bcast = Boardcast::new();
        let new_head_handle = Some(Self::new_head_task(
            alive.clone(),
            head_state.clone(),
            head_bcast.clone(),
            beacon_slot,
        ));
        let withdrawal_bcast = Boardcast::new();
        let withdrawal_handle = Some(Self::fetch_withdrawal_task(
            alive.clone(),
            cl.clone(),
            withdrawal_bcast.clone(),
            beacon_slot,
        ));
        let randao_bcast = Boardcast::new();
        let randao_handle = Some(Self::fetch_randao_task(
            alive.clone(),
            cl.clone(),
            randao_bcast.clone(),
            beacon_slot,
        ));
        Self {
            head_state,
            new_head_handle,
            head_bcast,
            randao_handle,
            randao_bcast,
            withdrawal_handle,
            withdrawal_bcast,
        }
    }

    fn fetch_randao_task(
        alive: Alive,
        cl: Arc<BeaconClient>,
        bcast: Boardcast<(u64, SH256)>,
        beacon_slot: BeaconSlot,
    ) -> JoinHandle<()> {
        spawn(format!("beacon-fetch-randao"), move || loop {
            if !alive.is_alive() {
                break;
            }
            let slot = beacon_slot.current();
            match cl.get_randao(slot) {
                Ok(randao) => {
                    bcast.boardcast((slot, randao.data.randao));
                }
                Err(err) => {
                    glog::error!("fetch randao[{}] fail: {:?}", slot, err);
                }
            }
            base::thread::sleep_ms(1000);
        })
    }

    fn fetch_withdrawal_task(
        alive: Alive,
        cl: Arc<BeaconClient>,
        bcast: Boardcast<(u64, Vec<Withdrawal>)>,
        beacon_slot: BeaconSlot,
    ) -> JoinHandle<()> {
        spawn(format!("beacon-fetch-withdrawal"), move || loop {
            if !alive.is_alive() {
                break;
            }
            let slot = beacon_slot.current();
            match cl.withdrawal(slot) {
                Ok(result) => {
                    bcast.boardcast((
                        slot,
                        result
                            .data
                            .withdrawals
                            .iter()
                            .map(|item| item.to_standard())
                            .collect(),
                    ));
                }
                Err(err) => {
                    glog::error!("fetch randao fail: {:?}", err);
                }
            }
            base::thread::sleep_ms(1000);
        })
    }

    fn new_head_task(
        alive: Alive,
        head_state: HeadState,
        bcast: Boardcast<BeaconHead>,
        beacon_slot: BeaconSlot,
    ) -> JoinHandle<()> {
        spawn(format!("beacon-new-head"), move || {
            let mut last_slot = None;
            loop {
                if !alive.is_alive() {
                    break;
                }
                let slot = beacon_slot.current();
                if Some(slot) == last_slot {
                    alive.sleep_to(beacon_slot.time(slot + 1));
                    continue;
                }
                bcast.boardcast(BeaconHead {
                    slot,
                    slot_time: beacon_slot.secs(slot),
                    block: head_state.get(),
                    randao: None,
                    withdrawal: None,
                });
                last_slot = Some(slot);
                base::thread::sleep_ms(100);
            }
            bcast.clean();
        })
    }

    pub fn subscribe(&self) -> mpsc::Receiver<BeaconHead> {
        self.head_bcast.new_subscriber()
    }

    pub fn refresh(&self, head: &mut BeaconHead) {
        if let Some((slot, randao)) = self.randao_bcast.get_latest() {
            if head.slot == slot {
                head.randao = Some(randao);
            }
        }
        if let Some((slot, withdrawals)) = self.withdrawal_bcast.get_latest() {
            if head.slot == slot {
                head.withdrawal = Some(withdrawals);
            }
        }
        let new_head = self.head_state.get();
        if new_head.timestamp.as_u64() == head.slot_time {
            head.block = new_head;
        }
    }
}

impl Drop for BeaconHeadState {
    fn drop(&mut self) {
        base::thread::join(&mut self.new_head_handle);
        base::thread::join(&mut self.randao_handle);
        base::thread::join(&mut self.withdrawal_handle);
    }
}
