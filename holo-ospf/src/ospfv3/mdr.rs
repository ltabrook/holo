//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use crate::northbound::configuration::MdrInterfaceCfg;
use crate::packet::lsa::{LsaHdrVersion, LsaKey};
use crate::version::Version;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MdrLevel {
    #[default]
    Other,
    Backup,
    Mdr,
}

impl MdrLevel {
    pub(crate) const fn is_dr_or_backup(self) -> bool {
        matches!(self, MdrLevel::Backup | MdrLevel::Mdr)
    }
}

#[derive(Debug)]
pub struct MdrInterfaceState<V: Version> {
    pub config: MdrInterfaceCfg,
    pub mdr_level: MdrLevel,
    pub parent: Option<Ipv4Addr>,
    pub backup_parent: Option<Ipv4Addr>,
    pub hello_sequence_number: u16,
    pub full_hello_count: u16,
    pub differential_hello_count: u16,
    pub mdr_neighbor_change: bool,
    pub backup_wait: BTreeMap<LsaKey<V::LsaType>, BTreeSet<Ipv4Addr>>,
    pub delayed_acks: BTreeMap<LsaKey<V::LsaType>, V::LsaHdr>,
}

impl<V> MdrInterfaceState<V>
where
    V: Version,
{
    pub(crate) fn new(config: &MdrInterfaceCfg) -> Self {
        Self {
            config: config.clone(),
            mdr_level: MdrLevel::Other,
            parent: None,
            backup_parent: None,
            hello_sequence_number: 0,
            full_hello_count: 0,
            differential_hello_count: 0,
            mdr_neighbor_change: false,
            backup_wait: Default::default(),
            delayed_acks: Default::default(),
        }
    }
}

#[derive(Debug)]
pub struct MdrNeighborState<V: Version> {
    pub remote_interface_id: Option<u32>,
    pub hello_sequence_number: u16,
    pub a_bit: bool,
    pub full_hello_received: bool,
    pub mdr_level: MdrLevel,
    pub parent: Option<Ipv4Addr>,
    pub backup_parent: Option<Ipv4Addr>,
    pub child: bool,
    pub dependent: bool,
    pub dependent_selector: bool,
    pub selected_advertised: bool,
    pub routable: bool,
    pub reverse_2way: bool,
    pub adjacency_desired: bool,
    pub bidirectional_neighbors: BTreeSet<Ipv4Addr>,
    pub dependent_neighbors: BTreeSet<Ipv4Addr>,
    pub selected_advertised_neighbors: BTreeSet<Ipv4Addr>,
    pub incoming_link_metric: Option<u16>,
    pub outgoing_link_metric: Option<u16>,
    pub link_metrics: BTreeMap<Ipv4Addr, u16>,
    pub acked_lsas: BTreeMap<LsaKey<V::LsaType>, V::LsaHdr>,
}

impl<V> Default for MdrNeighborState<V>
where
    V: Version,
{
    fn default() -> Self {
        Self {
            remote_interface_id: None,
            hello_sequence_number: 0,
            a_bit: false,
            full_hello_received: false,
            mdr_level: Default::default(),
            parent: None,
            backup_parent: None,
            child: false,
            dependent: false,
            dependent_selector: false,
            selected_advertised: false,
            routable: false,
            reverse_2way: false,
            adjacency_desired: false,
            bidirectional_neighbors: Default::default(),
            dependent_neighbors: Default::default(),
            selected_advertised_neighbors: Default::default(),
            incoming_link_metric: None,
            outgoing_link_metric: None,
            link_metrics: Default::default(),
            acked_lsas: Default::default(),
        }
    }
}
