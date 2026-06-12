//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, btree_map};
use std::net::Ipv4Addr;
use std::sync::Arc;

use chrono::Utc;

use crate::area::{Area, AreaType, BACKBONE_AREA_ID};
use crate::collections::{
    AreaIndex, AreaKey, Arena, InterfaceIndex, InterfaceKey, LsaEntryKey,
    LsdbIndex, LsdbKey, NeighborIndex, NeighborKey, lsdb_get, lsdb_get_mut,
    lsdb_index, lsdb_index_mut,
};
use crate::debug::{Debug, LsaFlushReason, SeqNoMismatchReason};
use crate::error::{Error, InterfaceCfgError};
use crate::flood::flood;
use crate::gr::GrExitReason;
use crate::instance::{InstanceArenas, InstanceUpView};
use crate::interface::{Interface, VirtualLinkKey, ism};
use crate::lsdb::{
    self, LsaEntry, LsaEntryFlags, LsaOriginateEvent, lsa_compare,
};
use crate::neighbor::{LastDbDesc, Neighbor, RxmtPacketType, nsm};
use crate::northbound::configuration::MdrLsaFullness;
use crate::northbound::notification;
use crate::ospfv3::mdr::MdrLevel;
use crate::packet::error::DecodeResult;
use crate::packet::iana::PacketType;
use crate::packet::lls::{MdrDdTlv, MdrHelloTlv, MdrMetricTlv};
use crate::packet::lsa::{
    Lsa, LsaBodyVersion, LsaHdrVersion, LsaKey, LsaScope, LsaTypeVersion,
};
use crate::packet::{
    DbDescFlags, DbDescVersion, HelloVersion, LsAckVersion, LsRequestVersion,
    LsUpdateVersion, OptionsVersion, Packet, PacketBase, PacketHdrVersion,
};
use crate::version::Version;
use crate::{gr, output, spf, tasks};

// ===== Interface FSM event =====

pub(crate) fn process_ism_event<V>(
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    area_key: AreaKey,
    iface_key: InterfaceKey,
    event: ism::Event,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Lookup area and interface.
    let (_, area) = arenas.areas.get_mut_by_key(&area_key)?;
    let (_iface_idx, iface) = area
        .interfaces
        .get_mut_by_key(&mut arenas.interfaces, &iface_key)?;

    // Invoke FSM event.
    iface.fsm(
        area,
        instance,
        &mut arenas.neighbors,
        &arenas.lsa_entries,
        event,
    );
    if iface.is_mdr_enabled() {
        iface.run_mdr_adjacency_reevaluation_if_pending(
            area,
            instance,
            &mut arenas.neighbors,
            &arenas.lsa_entries,
        );
        iface.run_mdr_lsa_reevaluation_if_pending(area, instance);
    }

    Ok(())
}

// ===== Neighbor FSM event =====

pub(crate) fn process_nsm_event<V>(
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    area_key: AreaKey,
    iface_key: InterfaceKey,
    nbr_key: NeighborKey,
    event: nsm::Event,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Lookup area, interface and neighbor.
    let (_, area) = arenas.areas.get_mut_by_key(&area_key)?;
    let (_, iface) = area
        .interfaces
        .get_mut_by_key(&mut arenas.interfaces, &iface_key)?;
    let (nbr_idx, nbr) = iface
        .state
        .neighbors
        .get_mut_by_key(&mut arenas.neighbors, &nbr_key)?;

    // Invoke FSM event.
    nbr.fsm(iface, area, instance, &arenas.lsa_entries, event);
    if nbr.state == nsm::State::Down {
        // Effectively delete the neighbor.
        iface.state.neighbors.delete(&mut arenas.neighbors, nbr_idx);

        // Synchronize interface's Hello Tx task (updated list of neighbors).
        iface.sync_hello_tx(area, instance);
    }
    if iface.is_mdr_enabled() {
        iface.run_mdr_selection_if_pending(
            area,
            instance,
            &mut arenas.neighbors,
        );
        iface.run_mdr_adjacency_reevaluation_if_pending(
            area,
            instance,
            &mut arenas.neighbors,
            &arenas.lsa_entries,
        );
        iface.run_mdr_lsa_reevaluation_if_pending(area, instance);
    }

    Ok(())
}

// ===== MDR Hello interval elapsed =====

pub(crate) fn process_hello_interval_elapsed<V>(
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    area_key: AreaKey,
    iface_key: InterfaceKey,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Lookup area and interface.
    let (_, area) = arenas.areas.get_mut_by_key(&area_key)?;
    let (_, iface) = area
        .interfaces
        .get_mut_by_key(&mut arenas.interfaces, &iface_key)?;

    iface.send_mdr_hello_interval_elapsed(
        area,
        instance,
        &arenas.lsa_entries,
        &mut arenas.neighbors,
    );
    if iface.is_mdr_enabled() {
        iface.run_mdr_lsa_reevaluation_if_pending(area, instance);
    }

    Ok(())
}

// ===== Network packet receipt =====

pub(crate) fn process_packet<V>(
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    area_key: AreaKey,
    iface_key: InterfaceKey,
    src: V::NetIpAddr,
    dst: V::NetIpAddr,
    packet: DecodeResult<Packet<V>>,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Lookup area and interface.
    let (area_idx, area) = arenas.areas.get_by_key(&area_key)?;
    let (iface_idx, iface) =
        area.interfaces.get_by_key(&arenas.interfaces, &iface_key)?;

    // Check if the packet was decoded successfully.
    let packet = match packet {
        Ok(packet) => packet,
        Err(error) => {
            notification::if_rx_bad_packet(instance, iface, src);
            return Err(Error::PacketDecodeError(error));
        }
    };
    let pkt_type = packet.hdr().pkt_type();

    // Ignore packets received on inoperational or passive interfaces.
    if iface.is_down() || iface.is_passive() {
        return Ok(());
    }

    // Check the packet's Area ID and determine the interface it should be
    // processed on. If the Area ID matches, the packet stays on the current
    // interface. Otherwise, if it is destined for the backbone, an attempt is
    // made to map it to a virtual link interface.
    let (area_idx, iface_idx) = process_packet_resolve_interface(
        area_idx,
        iface_idx,
        packet.hdr(),
        arenas,
    )
    .map_err(|error| {
        let iface = &mut arenas.interfaces[iface_idx];
        Error::InterfaceCfgError(iface.name.clone(), src, pkt_type, error)
    })?;
    let area = &mut arenas.areas[area_idx];
    let iface = &mut arenas.interfaces[iface_idx];
    if iface.is_virtual_link() && iface.is_down() {
        return Ok(());
    }

    // Validate IP destination address.
    V::validate_packet_dst(iface, dst)?;

    // Validate IP source address.
    V::validate_packet_src(iface, src)?;

    // OSPFv3: check for Instance ID mismatch.
    if !V::packet_instance_id_match(iface, packet.hdr()) {
        // Instance ID mismatches are expected in normal operation and do not
        // constitute an error.
        return Ok(());
    }

    // Perform authentication sequence number validation.
    let router_id = packet.hdr().router_id();
    if let Some(auth_seqno) = packet.hdr().auth_seqno()
        && let Some((_, nbr)) =
            V::get_neighbor(iface, &src, router_id, &mut arenas.neighbors)
    {
        // Discard the packet if its sequence number is lower than the recorded
        // sequence number in the sender's neighbor data structure.
        //
        // Sequence number checking is dependent on OSPF packet type in order to
        // account for packet prioritization as specified in RFC 4222.
        let nbr_auth_seqno = nbr.auth_seqno.entry(pkt_type).or_default();
        match auth_seqno.cmp(nbr_auth_seqno) {
            Ordering::Less => {
                return Err(Error::PacketAuthInvalidSeqno(src, auth_seqno));
            }
            Ordering::Equal if V::STRICT_AUTH_SEQNO_CHECK => {
                return Err(Error::PacketAuthInvalidSeqno(src, auth_seqno));
            }
            _ => {
                // Packet sequence number is valid.
            }
        }

        // Update neighbor's last received sequence number.
        *nbr_auth_seqno = auth_seqno;
    }

    // Log received packet.
    if iface.config.trace_opts.packets_resolved.load().rx(pkt_type) {
        Debug::<V>::PacketRx(iface, &src, &dst, &packet).log();
    }

    if let Packet::Hello(pkt) = packet {
        process_packet_hello(
            iface,
            area,
            instance,
            &mut arenas.neighbors,
            &arenas.lsa_entries,
            src,
            pkt,
        )
    } else {
        // Non-Hello packets not matching any active neighbor are discarded.
        let (nbr_idx, nbr) =
            V::get_neighbor(iface, &src, router_id, &mut arenas.neighbors)
                .ok_or(Error::UnknownNeighbor(src, router_id))?;

        match packet {
            Packet::Hello(_) => unreachable!(),
            Packet::DbDesc(pkt) => process_packet_dbdesc(
                nbr,
                iface,
                area,
                instance,
                &arenas.lsa_entries,
                src,
                pkt,
            ),
            Packet::LsRequest(pkt) => process_packet_lsreq(
                nbr,
                iface,
                area,
                instance,
                &arenas.lsa_entries,
                pkt,
            ),
            Packet::LsUpdate(pkt) => process_packet_lsupd(
                nbr_idx, iface_idx, area_idx, instance, arenas, src, pkt,
            ),
            Packet::LsAck(pkt) => process_packet_lsack(nbr, instance, pkt),
        }
    }
}

pub(crate) fn process_packet_resolve_interface<V>(
    area_idx: AreaIndex,
    iface_idx: InterfaceIndex,
    packet_hdr: &V::PacketHdr,
    arenas: &mut InstanceArenas<V>,
) -> Result<(AreaIndex, InterfaceIndex), InterfaceCfgError>
where
    V: Version,
{
    let is_abr = arenas.areas.is_abr(&arenas.interfaces);
    let area = &arenas.areas[area_idx];

    // Case 1 (RFC 2328 8.2): The Area ID in the packet header matches the
    // receiving interface's Area ID.
    if packet_hdr.area_id() == area.area_id {
        return Ok((area_idx, iface_idx));
    }

    // Case 2 (RFC 2328 8.2): The Area ID in the packet header is the backbone.
    // In this case, the packet may have come over a virtual link. The router
    // must be an ABR, the Router ID in the packet header must be the other end
    // of a configured virtual link, and the receiving interface must belong to
    // the virtual link's transit area.
    if packet_hdr.area_id() == BACKBONE_AREA_ID
        && is_abr
        && let Some((backbone_idx, backbone)) =
            arenas.areas.get_by_area_id(BACKBONE_AREA_ID)
    {
        let vlink_key = VirtualLinkKey {
            transit_area_id: area.area_id,
            router_id: packet_hdr.router_id(),
        };
        if let Some((vlink_idx, _)) = backbone
            .interfaces
            .get_by_vlink_key(&arenas.interfaces, &vlink_key)
        {
            return Ok((backbone_idx, vlink_idx));
        }
    }

    // Otherwise: Area ID mismatch.
    Err(InterfaceCfgError::AreaIdMismatch(
        packet_hdr.area_id(),
        area.area_id,
    ))
}

#[derive(Clone, Debug, Default)]
struct MdrHelloNeighborLists {
    down: Vec<Ipv4Addr>,
    init: Vec<Ipv4Addr>,
    dependent: Vec<Ipv4Addr>,
    selected_advertised: Vec<Ipv4Addr>,
    bidirectional: Vec<Ipv4Addr>,
}

impl MdrHelloNeighborLists {
    fn decode<V>(hello: &V::PacketHello, tlv: MdrHelloTlv) -> Option<Self>
    where
        V: Version,
    {
        let neighbors = hello.neighbor_list_ordered();
        let n1 = usize::from(tlv.n1);
        let n2 = usize::from(tlv.n2);
        let n3 = usize::from(tlv.n3);
        let n4 = usize::from(tlv.n4);
        let counted = n1.checked_add(n2)?.checked_add(n3)?.checked_add(n4)?;
        if counted > neighbors.len() {
            return None;
        }

        let down = neighbors[0..n1].to_vec();
        let init = neighbors[n1..n1 + n2].to_vec();
        let dependent = neighbors[n1 + n2..n1 + n2 + n3].to_vec();
        let selected_advertised = neighbors[n1 + n2 + n3..counted].to_vec();
        let bidirectional = neighbors[counted..].to_vec();

        Some(Self {
            down,
            init,
            dependent,
            selected_advertised,
            bidirectional,
        })
    }

    fn bidirectional_neighbor_ids(&self) -> Vec<Ipv4Addr> {
        self.dependent
            .iter()
            .chain(&self.selected_advertised)
            .chain(&self.bidirectional)
            .copied()
            .collect()
    }
}

fn mdr_level_from_hello(
    router_id: Ipv4Addr,
    dr: Option<Ipv4Addr>,
    bdr: Option<Ipv4Addr>,
) -> MdrLevel {
    if dr == Some(router_id) {
        MdrLevel::Mdr
    } else if bdr == Some(router_id) {
        MdrLevel::Backup
    } else {
        MdrLevel::Other
    }
}

fn mdr_metric_tlv_defaults_enabled<V>(iface: &Interface<V>) -> bool
where
    V: Version,
{
    iface.state.mdr.as_ref().is_some_and(|mdr| {
        matches!(
            mdr.config.lsa_fullness,
            MdrLsaFullness::MinCost | MdrLsaFullness::MinCost2Paths
        )
    })
}

fn mdr_reported_link_metrics(
    lists: &MdrHelloNeighborLists,
    metric_tlv: Option<&MdrMetricTlv>,
    default_when_absent: bool,
) -> BTreeMap<Ipv4Addr, u16> {
    let bidirectional_neighbors = lists.bidirectional_neighbor_ids();
    if bidirectional_neighbors.is_empty() {
        return BTreeMap::new();
    }

    let Some(metric_tlv) = metric_tlv else {
        return if default_when_absent {
            bidirectional_neighbors
                .into_iter()
                .map(|router_id| (router_id, 1))
                .collect()
        } else {
            BTreeMap::new()
        };
    };

    let mut metrics = bidirectional_neighbors
        .iter()
        .copied()
        .map(|router_id| (router_id, metric_tlv.default_metric))
        .collect::<BTreeMap<_, _>>();
    if metric_tlv.include_ids {
        for entry in &metric_tlv.metrics {
            if let Some(router_id) = entry.neighbor_id
                && metrics.contains_key(&router_id)
            {
                metrics.insert(router_id, entry.metric);
            }
        }
    } else {
        for (router_id, entry) in bidirectional_neighbors
            .into_iter()
            .zip(metric_tlv.metrics.iter())
        {
            metrics.insert(router_id, entry.metric);
        }
    }
    metrics
}

fn apply_mdr_full_hello<V>(
    nbr: &mut Neighbor<V>,
    local_router_id: Ipv4Addr,
    lists: &MdrHelloNeighborLists,
) -> bool
where
    V: Version,
{
    nbr.mdr.full_hello_received = true;
    nbr.mdr.dependent_neighbors =
        lists.dependent.iter().copied().collect::<BTreeSet<_>>();
    nbr.mdr.selected_advertised_neighbors = lists
        .selected_advertised
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    nbr.mdr.bidirectional_neighbors = lists
        .dependent
        .iter()
        .chain(&lists.selected_advertised)
        .chain(&lists.bidirectional)
        .copied()
        .collect::<BTreeSet<_>>();

    if lists.init.contains(&local_router_id) {
        nbr.mdr.reverse_2way = false;
        true
    } else if lists.dependent.contains(&local_router_id)
        || lists.selected_advertised.contains(&local_router_id)
        || lists.bidirectional.contains(&local_router_id)
    {
        nbr.mdr.reverse_2way = true;
        true
    } else {
        nbr.mdr.reverse_2way = false;
        false
    }
}

fn apply_mdr_differential_hello<V>(
    nbr: &mut Neighbor<V>,
    local_router_id: Ipv4Addr,
    lists: &MdrHelloNeighborLists,
    hello_repeat_count: u16,
    previous_hsn: u16,
    current_hsn: u16,
) -> bool
where
    V: Version,
{
    let mut twoway = false;
    let mut found_local = false;

    for router_id in lists.down.iter().chain(&lists.init) {
        if *router_id == local_router_id {
            found_local = true;
            twoway = lists.init.contains(router_id);
            nbr.mdr.reverse_2way = false;
        }
        nbr.mdr.dependent_neighbors.remove(router_id);
        nbr.mdr.selected_advertised_neighbors.remove(router_id);
        nbr.mdr.bidirectional_neighbors.remove(router_id);
    }

    for router_id in &lists.dependent {
        if *router_id == local_router_id {
            found_local = true;
            twoway = true;
            nbr.mdr.reverse_2way = true;
        }
        nbr.mdr.dependent_neighbors.insert(*router_id);
        nbr.mdr.bidirectional_neighbors.insert(*router_id);
        nbr.mdr.selected_advertised_neighbors.remove(router_id);
    }

    for router_id in &lists.selected_advertised {
        if *router_id == local_router_id {
            found_local = true;
            twoway = true;
            nbr.mdr.reverse_2way = true;
        }
        nbr.mdr.selected_advertised_neighbors.insert(*router_id);
        nbr.mdr.bidirectional_neighbors.insert(*router_id);
        nbr.mdr.dependent_neighbors.remove(router_id);
    }

    for router_id in &lists.bidirectional {
        if *router_id == local_router_id {
            found_local = true;
            twoway = true;
            nbr.mdr.reverse_2way = true;
        }
        nbr.mdr.bidirectional_neighbors.insert(*router_id);
        nbr.mdr.dependent_neighbors.remove(router_id);
        nbr.mdr.selected_advertised_neighbors.remove(router_id);
    }

    if !found_local && nbr.state >= nsm::State::TwoWay {
        let hello_delta = current_hsn.wrapping_sub(previous_hsn);
        if hello_delta <= hello_repeat_count {
            twoway = true;
        } else {
            nbr.mdr.reverse_2way = false;
        }
    }

    twoway
}

fn process_packet_mdr_hello<V>(
    iface: &mut Interface<V>,
    area: &Area<V>,
    instance: &mut InstanceUpView<'_, V>,
    lsa_entries: &Arena<LsaEntry<V>>,
    src: V::NetIpAddr,
    nbr: &mut Neighbor<V>,
    hello: &V::PacketHello,
) -> Result<(), Error<V>>
where
    V: Version,
{
    let Some(lls) = hello.lls().filter(|_| hello.options().l_bit()) else {
        return Ok(());
    };
    let Some(mdr_hello) = lls.mdr_hello else {
        return Ok(());
    };
    let Some(lists) = MdrHelloNeighborLists::decode::<V>(hello, mdr_hello)
    else {
        return Ok(());
    };
    if !mdr_hello.differential && mdr_hello.n1 != 0 {
        return Ok(());
    }

    let local_router_id = instance.state.router_id;
    let previous_hsn = nbr.mdr.hello_sequence_number;
    let prev_state = nbr.state;
    let prev_was_bidirectional = prev_state >= nsm::State::TwoWay;
    let prev_mdr_level = nbr.mdr.mdr_level;
    let prev_priority = nbr.priority;
    let prev_full_hello_received = nbr.mdr.full_hello_received;
    let prev_bns = nbr.mdr.bidirectional_neighbors.clone();
    let prev_sans = nbr.mdr.selected_advertised_neighbors.clone();
    let prev_link_metrics = nbr.mdr.link_metrics.clone();
    let prev_incoming_metric = nbr.mdr.incoming_link_metric;
    let prev_reverse_2way = nbr.mdr.reverse_2way;

    let dr = hello.dr().map(|dr| dr.get());
    let bdr = hello.bdr().map(|bdr| bdr.get());

    nbr.src = src;
    nbr.iface_id = hello.iface_id();
    nbr.priority = hello.priority();
    nbr.dr = hello.dr();
    nbr.bdr = hello.bdr();
    nbr.mdr.remote_interface_id = hello.iface_id();
    nbr.mdr.hello_sequence_number = mdr_hello.hello_sequence_number;
    nbr.mdr.a_bit = mdr_hello.adjacency_reduction_disabled;
    nbr.mdr.last_hello_differential = mdr_hello.differential;
    nbr.mdr.parent = dr;
    nbr.mdr.backup_parent = bdr;
    nbr.mdr.mdr_level = mdr_level_from_hello(nbr.router_id, dr, bdr);
    if nbr.mdr.mdr_level == MdrLevel::Other {
        nbr.mdr.dependent = false;
    }
    nbr.mdr.child = dr == Some(local_router_id) || bdr == Some(local_router_id);
    nbr.mdr.consecutive_hellos = if nbr.mdr.consecutive_hellos == 0 {
        1
    } else if mdr_hello.hello_sequence_number.wrapping_sub(previous_hsn) == 1 {
        nbr.mdr.consecutive_hellos.saturating_add(1)
    } else {
        1
    };

    let twoway = if mdr_hello.differential {
        let hello_repeat_count = iface
            .state
            .mdr
            .as_ref()
            .map(|mdr| mdr.config.full_hello_repeat_count.max(1))
            .unwrap_or(1);
        apply_mdr_differential_hello(
            nbr,
            local_router_id,
            &lists,
            hello_repeat_count,
            previous_hsn,
            mdr_hello.hello_sequence_number,
        )
    } else {
        apply_mdr_full_hello(nbr, local_router_id, &lists)
    };

    let default_metrics = mdr_metric_tlv_defaults_enabled(iface);
    nbr.mdr.link_metrics = mdr_reported_link_metrics(
        &lists,
        lls.mdr_metric.as_ref(),
        default_metrics,
    );
    nbr.mdr.incoming_link_metric =
        nbr.mdr.link_metrics.get(&local_router_id).copied();
    nbr.mdr.dependent_selector =
        nbr.mdr.dependent_neighbors.contains(&local_router_id);
    iface.refresh_mdr_backbone_state(nbr);

    let threshold = iface
        .state
        .mdr
        .as_ref()
        .map(|mdr| u16::from(mdr.config.consecutive_hello_threshold.max(1)))
        .unwrap_or(1);
    let hello_accepted = nbr.state != nsm::State::Down
        || nbr.mdr.consecutive_hellos >= threshold;
    if hello_accepted {
        nbr.fsm(iface, area, instance, lsa_entries, nsm::Event::HelloRcvd);
        if twoway {
            nbr.fsm(iface, area, instance, lsa_entries, nsm::Event::TwoWayRcvd);
        } else {
            nbr.fsm(iface, area, instance, lsa_entries, nsm::Event::OneWayRcvd);
        }
    }

    let is_bidirectional = nbr.state >= nsm::State::TwoWay;
    let mdr_neighbor_change = prev_was_bidirectional != is_bidirectional
        || (is_bidirectional
            && (prev_mdr_level != nbr.mdr.mdr_level
                || prev_priority != nbr.priority
                || prev_full_hello_received != nbr.mdr.full_hello_received
                || prev_bns != nbr.mdr.bidirectional_neighbors));
    if mdr_neighbor_change && let Some(mdr) = &mut iface.state.mdr {
        mdr.mdr_neighbor_change = true;
    }
    let lsa_relevant_change = prev_was_bidirectional != is_bidirectional
        || (is_bidirectional
            && (prev_mdr_level != nbr.mdr.mdr_level
                || prev_priority != nbr.priority
                || prev_full_hello_received != nbr.mdr.full_hello_received
                || prev_bns != nbr.mdr.bidirectional_neighbors
                || prev_sans != nbr.mdr.selected_advertised_neighbors
                || prev_link_metrics != nbr.mdr.link_metrics
                || prev_incoming_metric != nbr.mdr.incoming_link_metric
                || prev_reverse_2way != nbr.mdr.reverse_2way));
    if lsa_relevant_change && let Some(mdr) = &mut iface.state.mdr {
        mdr.lsa_reevaluation_pending = true;
    }

    Ok(())
}

fn mdr_router_id_from_tlv(value: Ipv4Addr) -> Option<Ipv4Addr> {
    (!value.is_unspecified()).then_some(value)
}

fn apply_mdr_dbdesc_tlv<V>(
    iface: &mut Interface<V>,
    instance: &InstanceUpView<'_, V>,
    nbr: &mut Neighbor<V>,
    mdr_dd: MdrDdTlv,
) -> (bool, bool)
where
    V: Version,
{
    let previous_level = nbr.mdr.mdr_level;
    let previous_child = nbr.mdr.child;
    let dr = mdr_router_id_from_tlv(mdr_dd.designated_router);
    let bdr = mdr_router_id_from_tlv(mdr_dd.backup_designated_router);

    nbr.mdr.parent = dr;
    nbr.mdr.backup_parent = bdr;
    nbr.mdr.mdr_level = if dr == Some(nbr.router_id) {
        MdrLevel::Mdr
    } else if bdr == Some(nbr.router_id) {
        MdrLevel::Backup
    } else {
        MdrLevel::Other
    };
    if nbr.mdr.mdr_level.is_dr_or_backup() {
        nbr.mdr.dependent_selector = true;
    } else {
        nbr.mdr.dependent = false;
    }
    nbr.mdr.child = dr == Some(instance.state.router_id)
        || bdr == Some(instance.state.router_id);
    iface.update_mdr_adjacency_desired(nbr);
    iface.refresh_mdr_backbone_state(nbr);

    (
        previous_level != nbr.mdr.mdr_level,
        !previous_child && nbr.mdr.child,
    )
}

fn process_packet_hello<V>(
    iface: &mut Interface<V>,
    area: &Area<V>,
    instance: &mut InstanceUpView<'_, V>,
    neighbors: &mut Arena<Neighbor<V>>,
    lsa_entries: &Arena<LsaEntry<V>>,
    src: V::NetIpAddr,
    hello: V::PacketHello,
) -> Result<(), Error<V>>
where
    V: Version,
{
    let protocol_input = &instance.tx.protocol_input;

    // Perform all the required sanity checks.
    process_packet_hello_sanity_checks(iface, area, instance, &hello).map_err(
        |error| {
            Error::InterfaceCfgError(
                iface.name.clone(),
                src,
                PacketType::Hello,
                error,
            )
        },
    )?;

    // Find or create new neighbor.
    let (_, nbr) =
        match V::get_neighbor(iface, &src, hello.router_id(), neighbors) {
            Some(value) => value,
            None => {
                // Create new neighbor.
                let (nbr_idx, nbr) = iface.state.neighbors.insert(
                    neighbors,
                    hello.router_id(),
                    src,
                );

                // Initialize neighbor values.
                nbr.iface_id = hello.iface_id();
                nbr.priority = hello.priority();
                if iface.is_broadcast_or_nbma() {
                    nbr.dr = hello.dr();
                    nbr.bdr = hello.bdr();
                }

                // Synchronize interface's Hello Tx task (updated list of
                // neighbors).
                iface.sync_hello_tx(area, instance);

                (nbr_idx, nbr)
            }
        };

    // Update neighbor's source address.
    //
    // For OSPFv2, this can only happen for point-to-point interfaces (for the
    // other interface types, an address change would prompt the creation of
    // a different neighbor entity).
    //
    // Once an address change occurs, the corresponding neighbor should
    // reoriginate its Router-LSA, so there's no need to reschedule SPF
    // manually in order to update the routing table.
    nbr.src = src;

    if iface.is_mdr_enabled() {
        let result = process_packet_mdr_hello(
            iface,
            area,
            instance,
            lsa_entries,
            src,
            nbr,
            &hello,
        );
        if result.is_ok() {
            iface.run_mdr_selection_if_pending(area, instance, neighbors);
            iface.run_mdr_adjacency_reevaluation_if_pending(
                area,
                instance,
                neighbors,
                lsa_entries,
            );
            iface.run_mdr_lsa_reevaluation_if_pending(area, instance);
        }
        return result;
    }

    // Trigger the HelloReceived event.
    nbr.fsm(iface, area, instance, lsa_entries, nsm::Event::HelloRcvd);

    // Trigger the 1-WayReceived or the 2-WayReceived event.
    if hello
        .neighbors()
        .iter()
        .any(|id| *id == instance.state.router_id)
    {
        nbr.fsm(iface, area, instance, lsa_entries, nsm::Event::TwoWayRcvd);
    } else {
        nbr.fsm(iface, area, instance, lsa_entries, nsm::Event::OneWayRcvd);

        // Update neighbor values.
        nbr.iface_id = hello.iface_id();
        if iface.is_broadcast_or_nbma() {
            nbr.priority = hello.priority();
            nbr.dr = hello.dr();
            nbr.bdr = hello.bdr();
        }

        return Ok(());
    }

    // Check for Interface ID change.
    if hello.iface_id() != nbr.iface_id {
        nbr.iface_id = hello.iface_id();

        // (Re)originate LSAs that might have been affected.
        instance.tx.protocol_input.lsa_orig_event(
            LsaOriginateEvent::NeighborInterfaceIdChange {
                area_id: area.id,
                iface_id: iface.id,
            },
        );
    }

    // Examine rest of the Hello Packet (ignore Point-to-MultiPoint interfaces
    // as per errata 4022 of RFC 2328).
    if iface.is_broadcast_or_nbma() {
        // Check for Router Priority change.
        if hello.priority() != nbr.priority {
            nbr.priority = hello.priority();
            protocol_input.ism_event(area.id, iface.id, ism::Event::NbrChange);
        }

        // Check for DR/BDR changes.
        let nbr_net_id = nbr.network_id();
        if iface.state.ism_state == ism::State::Waiting
            && ((hello.dr() == Some(nbr_net_id) && hello.bdr().is_none())
                || hello.bdr() == Some(nbr_net_id))
        {
            protocol_input.ism_event(area.id, iface.id, ism::Event::BackupSeen);
        }
        if (hello.dr() == Some(nbr_net_id) && nbr.dr != Some(nbr_net_id))
            || (hello.dr() != Some(nbr_net_id) && nbr.dr == Some(nbr_net_id))
            || (hello.bdr() == Some(nbr_net_id) && nbr.bdr != Some(nbr_net_id))
            || (hello.bdr() != Some(nbr_net_id) && nbr.bdr == Some(nbr_net_id))
        {
            protocol_input.ism_event(area.id, iface.id, ism::Event::NbrChange);
        }

        // Update neighbor's DR/BDR.
        nbr.dr = hello.dr();
        nbr.bdr = hello.bdr();
    }

    // Examine LLS data block if enabled and present in the packet.
    if iface.config.lls_enabled
        && hello.options().l_bit()
        && let Some(_lls) = hello.lls()
    {
        // TODO: Handle LLS data
    }

    Ok(())
}

fn process_packet_hello_sanity_checks<V>(
    iface: &Interface<V>,
    area: &Area<V>,
    instance: &InstanceUpView<'_, V>,
    hello: &V::PacketHello,
) -> Result<(), InterfaceCfgError>
where
    V: Version,
{
    // OSPF version-specific hello validation.
    V::validate_hello(iface, hello)?;

    // Check for HelloInterval mismatch.
    let expected_hello_interval = iface
        .state
        .mdr
        .as_ref()
        .map(|mdr| mdr.config.hello_interval)
        .unwrap_or(iface.config.hello_interval);
    if hello.hello_interval() != expected_hello_interval {
        return Err(InterfaceCfgError::HelloIntervalMismatch(
            hello.hello_interval(),
            expected_hello_interval,
        ));
    }

    // Check for RouterDeadInterval mismatch.
    let expected_dead_interval = iface
        .state
        .mdr
        .as_ref()
        .map(|mdr| u32::from(mdr.config.dead_interval))
        .unwrap_or(iface.config.dead_interval as u32);
    if hello.dead_interval() != expected_dead_interval {
        return Err(InterfaceCfgError::DeadIntervalMismatch(
            hello.dead_interval(),
            expected_dead_interval,
        ));
    }

    // Check for ExternalRoutingCapability mismatch.
    if hello.options().e_bit() && area.config.area_type != AreaType::Normal
        || !hello.options().e_bit() && area.config.area_type == AreaType::Normal
    {
        return Err(InterfaceCfgError::ExternalRoutingCapabilityMismatch(
            hello.options().e_bit(),
        ));
    }

    // Check for duplicate Router ID.
    if hello.router_id() == instance.state.router_id {
        return Err(InterfaceCfgError::DuplicateRouterId(hello.router_id()));
    }

    Ok(())
}

fn process_packet_dbdesc<V>(
    nbr: &mut Neighbor<V>,
    iface: &mut Interface<V>,
    area: &Area<V>,
    instance: &mut InstanceUpView<'_, V>,
    lsa_entries: &Arena<LsaEntry<V>>,
    src: V::NetIpAddr,
    dbdesc: V::PacketDbDesc,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // MTU mismatch check.
    if !iface.is_virtual_link()
        && !iface.config.mtu_ignore
        && dbdesc.mtu() > iface.system.mtu.unwrap()
    {
        return Err(Error::InterfaceCfgError(
            iface.name.clone(),
            src,
            PacketType::DbDesc,
            InterfaceCfgError::MtuMismatch(dbdesc.mtu()),
        ));
    }

    let mut mdr_adjok_due = false;
    if iface.is_mdr_enabled() {
        if dbdesc.options().l_bit()
            && let Some(mdr_dd) = dbdesc.lls().and_then(|lls| lls.mdr_dd)
        {
            let (level_changed, child_became_true) =
                apply_mdr_dbdesc_tlv(iface, instance, nbr, mdr_dd);
            mdr_adjok_due |= level_changed || child_became_true;
            if (level_changed || child_became_true)
                && let Some(mdr) = &mut iface.state.mdr
            {
                mdr.lsa_reevaluation_pending = true;
            }
        }

        let was_below_two_way = nbr.state < nsm::State::TwoWay;
        if nbr.state == nsm::State::Init {
            nbr.fsm(iface, area, instance, lsa_entries, nsm::Event::TwoWayRcvd);
        }
        if was_below_two_way && nbr.state >= nsm::State::TwoWay {
            mdr_adjok_due = true;
        }
        if mdr_adjok_due {
            iface.update_mdr_adjacency_desired(nbr);
            nbr.fsm(iface, area, instance, lsa_entries, nsm::Event::AdjOk);
        }
        iface.refresh_mdr_backbone_state(nbr);
        iface.run_mdr_lsa_reevaluation_if_pending(area, instance);
    }

    // Further processing depends on the neighbor's state.
    match nbr.state {
        nsm::State::Down | nsm::State::Attempt | nsm::State::TwoWay => {
            return Err(Error::DbDescReject(nbr.router_id, nbr.state));
        }
        nsm::State::Init | nsm::State::ExStart => {
            if nbr.state == nsm::State::Init {
                let event = nsm::Event::TwoWayRcvd;
                nbr.fsm(iface, area, instance, lsa_entries, event);
                if nbr.state != nsm::State::ExStart {
                    return Ok(());
                }
                // Fall through to the ExStart case.
            }

            if dbdesc
                .dd_flags()
                .contains(DbDescFlags::I | DbDescFlags::M | DbDescFlags::MS)
                && dbdesc.lsa_hdrs().is_empty()
                && dbdesc.router_id() > instance.state.router_id
            {
                // Set the master/slave bit to slave, and set the neighbor data
                // structure's DD sequence number to that specified by the
                // master.
                nbr.dd_flags.remove(DbDescFlags::MS);
                nbr.dd_seq_no = dbdesc.dd_seq_no();
            } else if !dbdesc
                .dd_flags()
                .intersects(DbDescFlags::I | DbDescFlags::MS)
                && dbdesc.dd_seq_no() == nbr.dd_seq_no
                && dbdesc.router_id() < instance.state.router_id
            {
                // In this case the router is Master.
            } else {
                // Ignore the packet.
                return Ok(());
            }

            nbr.options = Some(dbdesc.options());
            let event = nsm::Event::NegotiationDone;
            nbr.fsm(iface, area, instance, lsa_entries, event);
        }
        nsm::State::Exchange => {
            // Check for duplicate packet.
            if nbr.dbdesc_is_dup(&dbdesc) {
                // The slave needs to retransmit the last Database Description
                // packet that it had sent.
                if !nbr.dd_flags.contains(DbDescFlags::MS) {
                    output::rxmt_dbdesc(nbr, iface);
                }

                return Ok(());
            }

            // Sanity checks.
            let last_rcvd_dbdesc = nbr.last_rcvd_dbdesc.as_ref().unwrap();
            if dbdesc.dd_flags().contains(DbDescFlags::I)
                || dbdesc.dd_flags().contains(DbDescFlags::MS)
                    != last_rcvd_dbdesc.dd_flags.contains(DbDescFlags::MS)
            {
                let reason = SeqNoMismatchReason::InconsistentFlags;
                let event = nsm::Event::SeqNoMismatch(reason);
                nbr.fsm(iface, area, instance, lsa_entries, event);
                return Ok(());
            }
            if dbdesc.options().without_l_bit()
                != last_rcvd_dbdesc.options.without_l_bit()
            {
                let reason = SeqNoMismatchReason::InconsistentOptions;
                let event = nsm::Event::SeqNoMismatch(reason);
                nbr.fsm(iface, area, instance, lsa_entries, event);
                return Ok(());
            }
            if (nbr.dd_flags.contains(DbDescFlags::MS)
                && dbdesc.dd_seq_no() != nbr.dd_seq_no)
                || (!nbr.dd_flags.contains(DbDescFlags::MS)
                    && dbdesc.dd_seq_no() != nbr.dd_seq_no.wrapping_add(1))
            {
                let reason = SeqNoMismatchReason::InconsistentSeqNo;
                let event = nsm::Event::SeqNoMismatch(reason);
                nbr.fsm(iface, area, instance, lsa_entries, event);
                return Ok(());
            }
        }
        nsm::State::Loading | nsm::State::Full => {
            // Check for duplicate packet.
            if nbr.dbdesc_is_dup(&dbdesc) {
                // The slave must respond to duplicates by repeating the last
                // Database Description packet that it had sent.
                if !nbr.dd_flags.contains(DbDescFlags::MS) {
                    output::rxmt_dbdesc(nbr, iface);
                }

                return Ok(());
            }

            let reason = SeqNoMismatchReason::UnexpectedDbDesc;
            let event = nsm::Event::SeqNoMismatch(reason);
            nbr.fsm(iface, area, instance, lsa_entries, event);
            return Ok(());
        }
    }

    // If we got this far it means the packet was accepted. Stop the
    // retransmission interval in case it's active.
    nbr.rxmt_dbdesc_stop();

    // Now iterate over all LSA headers.
    for lsa_hdr in dbdesc.lsa_hdrs() {
        // Check if the LSA is valid for this area and neighbor.
        if !V::lsa_type_is_valid(
            Some(area.config.area_type),
            Some(iface.config.if_type),
            nbr.options,
            lsa_hdr.lsa_type(),
        ) {
            let reason = SeqNoMismatchReason::InvalidLsaType;
            let event = nsm::Event::SeqNoMismatch(reason);
            nbr.fsm(iface, area, instance, lsa_entries, event);
            return Ok(());
        }

        // RFC 5243 says:
        // "If the Database summary list contains an instance of the LSA that is
        // the same as or less recent than the listed LSA, the LSA is removed
        // from the Database summary list".
        let lsa_key = lsa_hdr.key();
        if let btree_map::Entry::Occupied(o) =
            nbr.lists.db_summary.entry(lsa_key)
        {
            let db_summ_lsa = o.get();
            if lsa_compare::<V>(&db_summ_lsa.hdr, lsa_hdr) != Ordering::Greater
            {
                o.remove();
            }
        }

        // Put the LSA on the Link state request list if it's not present on the
        // LSDB, or if the local copy is less recent than the received one.
        let lsdb = match lsa_hdr.lsa_type().scope() {
            LsaScope::Link => &iface.state.lsdb,
            LsaScope::Area => &area.state.lsdb,
            LsaScope::As => &instance.state.lsdb,
            LsaScope::Unknown => unreachable!(),
        };
        if let Some((_, lse)) = lsdb.get(lsa_entries, &lsa_key)
            && lsa_compare::<V>(&lse.data.hdr, lsa_hdr) != Ordering::Less
        {
            continue;
        }
        nbr.lists.ls_request.insert(lsa_key, *lsa_hdr);
    }

    // Start sending Link State Request packets.
    if !nbr.lists.ls_request.is_empty()
        && nbr.lists.ls_request_pending.is_empty()
    {
        output::send_lsreq(nbr, iface, area, instance);
    }

    // Further processing depends on whether the router is master or slave.
    let mut exchange_done = false;
    if nbr.dd_flags.contains(DbDescFlags::MS) {
        nbr.dd_seq_no = nbr.dd_seq_no.wrapping_add(1);

        if !nbr.dd_flags.contains(DbDescFlags::M)
            && !dbdesc.dd_flags().contains(DbDescFlags::M)
        {
            exchange_done = true;
        } else {
            output::send_dbdesc(nbr, iface, area, instance);
        }
    } else {
        nbr.dd_seq_no = dbdesc.dd_seq_no();

        output::send_dbdesc(nbr, iface, area, instance);

        if !nbr.dd_flags.contains(DbDescFlags::M)
            && !dbdesc.dd_flags().contains(DbDescFlags::M)
        {
            exchange_done = true;
        }
    }
    if exchange_done {
        nbr.fsm(iface, area, instance, lsa_entries, nsm::Event::ExchangeDone);

        // The slave must wait RouterDeadInterval seconds before freeing the
        // last Database Description packet. Reception of a Database Description
        // packet from the master after this interval will generate a
        // SeqNumberMismatch neighbor event.
        if !nbr.dd_flags.contains(DbDescFlags::MS) {
            let dbdesc_free_timer =
                tasks::dbdesc_free_timer(nbr, iface, area, instance);
            nbr.tasks.dbdesc_free_timer = Some(dbdesc_free_timer);
        }
    }

    // Examine LLS data block if enabled and present the packet.
    if iface.config.lls_enabled
        && dbdesc.options().l_bit()
        && let Some(_lls) = dbdesc.lls()
    {
        // TODO: Handle LLS data
    }

    // Save last received Database Description packet.
    nbr.last_rcvd_dbdesc = Some(LastDbDesc {
        options: dbdesc.options(),
        dd_flags: dbdesc.dd_flags(),
        dd_seq_no: dbdesc.dd_seq_no(),
    });

    Ok(())
}

fn process_packet_lsreq<V>(
    nbr: &mut Neighbor<V>,
    iface: &mut Interface<V>,
    area: &Area<V>,
    instance: &mut InstanceUpView<'_, V>,
    lsa_entries: &Arena<LsaEntry<V>>,
    ls_req: V::PacketLsRequest,
) -> Result<(), Error<V>>
where
    V: Version,
{
    if nbr.state < nsm::State::Exchange {
        if instance.config.trace_opts.flooding {
            Debug::<V>::PacketRxIgnore(nbr.router_id, &nbr.state).log();
        }
        return Ok(());
    }

    // Iterate over all request entries.
    for lsa_key in ls_req.entries() {
        // Locate LSA in the LSDB.
        let lsdb = match lsa_key.lsa_type.scope() {
            LsaScope::Link => &iface.state.lsdb,
            LsaScope::Area => &area.state.lsdb,
            LsaScope::As => &instance.state.lsdb,
            LsaScope::Unknown => {
                // OSPFv3: ignore requests for LSAs of unknown scope.
                continue;
            }
        };

        if let Some((_, lse)) = lsdb.get(lsa_entries, lsa_key) {
            // Copy LSA for transmission to the neighbor.
            let lsa = lse.data.clone();
            nbr.lists.ls_update.insert(*lsa_key, lsa);
        } else {
            // Something has gone wrong with the Database Exchange process.
            nbr.fsm(iface, area, instance, lsa_entries, nsm::Event::BadLsReq);
            return Ok(());
        }
    }

    // Schedule transmission of new LS Update.
    if !nbr.lists.ls_update.is_empty() {
        instance
            .tx
            .protocol_input
            .send_lsupd(area.id, iface.id, Some(nbr.id));
    }

    Ok(())
}

fn process_packet_lsupd<V>(
    nbr_idx: NeighborIndex,
    iface_idx: InterfaceIndex,
    area_idx: AreaIndex,
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    src: V::NetIpAddr,
    ls_upd: V::PacketLsUpdate,
) -> Result<(), Error<V>>
where
    V: Version,
{
    let nbr = &arenas.neighbors[nbr_idx];
    if nbr.state < nsm::State::Exchange {
        if instance.config.trace_opts.flooding {
            Debug::<V>::PacketRxIgnore(nbr.router_id, &nbr.state).log();
        }
        return Ok(());
    }

    // Process all LSAs contained in the packet.
    for lsa in ls_upd.into_lsas() {
        let stop = process_packet_lsupd_lsa(
            nbr_idx, iface_idx, area_idx, instance, arenas, src, lsa,
        );
        if stop {
            break;
        }
    }

    Ok(())
}

fn process_packet_lsupd_lsa<V>(
    nbr_idx: NeighborIndex,
    iface_idx: InterfaceIndex,
    area_idx: AreaIndex,
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    src: V::NetIpAddr,
    #[allow(unused_mut)] mut lsa: Lsa<V>,
) -> bool
where
    V: Version,
{
    let nbr = &arenas.neighbors[nbr_idx];
    let iface = &mut arenas.interfaces[iface_idx];
    let area = &arenas.areas[area_idx];

    // Generate raw data that might be missing for LSAs received in testing
    // mode.
    #[cfg(feature = "testing")]
    if lsa.raw.is_empty() {
        lsa.encode();
    }

    // (1) Validate the LSA (not only the checksum as specified by the RFC).
    if let Err(error) = lsa.validate() {
        // Send error notification.
        notification::if_rx_bad_lsa(instance, src, error);

        // Log why the LSA is being discarded.
        if instance.config.trace_opts.flooding {
            Debug::<V>::LsaDiscard(nbr.router_id, &lsa.hdr, &error).log();
        }

        // Examine the next LSA.
        return false;
    }

    // (2-3) Check if the LSA type is valid for this area and neighbor.
    if !V::lsa_type_is_valid(
        Some(area.config.area_type),
        Some(iface.config.if_type),
        nbr.options,
        lsa.hdr.lsa_type(),
    ) {
        // Examine the next LSA.
        return false;
    }

    // (5) Find the instance of this LSA that is currently contained in the
    // router's link state database.
    let lsdb_idx =
        V::lsdb_get_by_lsa_type(iface_idx, area_idx, lsa.hdr.lsa_type());
    let lsdb = match lsdb_idx {
        LsdbIndex::Link(_, _) => &iface.state.lsdb,
        LsdbIndex::Area(_) => &area.state.lsdb,
        LsdbIndex::As => &instance.state.lsdb,
    };
    let lsa_key = lsa.hdr.key();
    let lse = lsdb.get(&arenas.lsa_entries, &lsa_key).map(|(_, lse)| lse);

    // (4) If the LSA's LS age is equal to MaxAge, and there is currently no
    // instance of the LSA in the router's link state database, and none of
    // router's neighbors are in states Exchange or Loading.
    if lsa.hdr.is_maxage()
        && lse.is_none()
        && !arenas.neighbors.iter().any(|(_, nbr)| {
            matches!(nbr.state, nsm::State::Exchange | nsm::State::Loading)
        })
    {
        // Acknowledge the receipt of the LSA.
        output::send_lsack_direct(nbr, iface, area, instance, &lsa.hdr);

        // Examine the next LSA.
        return false;
    }

    // (5 cont.) There is no database copy, or the received LSA is more
    // recent than the database copy.
    let lsa_cmp = lse.map(|lse| lsa_compare::<V>(&lse.data.hdr, &lsa.hdr));
    if matches!(lsa_cmp, None | Some(Ordering::Less)) {
        // (5.a) MinLSArrival check.
        if let Some(lse) = lse
            && lsdb::lsa_min_arrival_check(lse)
        {
            // Log why the LSA is being discarded.
            if instance.config.trace_opts.flooding {
                Debug::<V>::LsaMinArrivalDiscard(nbr.router_id, &lsa.hdr).log();
            }

            // Examine the next LSA.
            return false;
        }

        // Move LSA into a reference-counting pointer.
        let lsa = Arc::new(lsa);

        // (5.b) Immediately flood the new LSA out some subset of the
        // router's interfaces.
        let src = Some((iface_idx, nbr_idx));
        let flooded_back = flood(
            instance,
            &arenas.areas,
            &mut arenas.interfaces,
            &mut arenas.neighbors,
            lsdb_idx,
            &lsa,
            src,
        );

        // (5.c) This step can be skipped since the LSA installation process
        // already takes care of removing the old copy from all Link state
        // retransmission lists.

        // (5.d) Install the new LSA in the link state database (replacing
        // the current database copy).
        let lse_idx = lsdb::install(instance, arenas, lsdb_idx, lsa);
        let lse = &mut arenas.lsa_entries[lse_idx];
        lse.flags.insert(LsaEntryFlags::RECEIVED);

        // Update statistics.
        instance.state.rx_lsa_count += 1;
        instance.state.discontinuity_time = Utc::now();

        // (5.e) Possibly acknowledge the receipt of the LSA by sending a
        // Link State Acknowledgment packet.
        let nbr = &mut arenas.neighbors[nbr_idx];
        let iface = &mut arenas.interfaces[iface_idx];
        let area = &arenas.areas[area_idx];
        let nbr_net_id = nbr.network_id();
        let nbr_router_id = nbr.router_id;
        if !flooded_back
            && (iface.state.ism_state != ism::State::Backup
                || iface.state.dr == Some(nbr_net_id))
        {
            // Enqueue delayed ack.
            iface.enqueue_delayed_ack(area, instance, &lse.data.hdr);
        }

        // Grace-LSA processing.
        if let Some((grace_period, reason, addr)) = lse.data.body.as_grace() {
            // For OSPFv2, on broadcast, NBMA and P2MP segments, the restarting
            // neighbor is identified by the IP interface address in the body of
            // the Grace-LSA.
            let nbr = match addr {
                Some(addr) => V::get_neighbor(
                    iface,
                    &addr,
                    nbr_router_id,
                    &mut arenas.neighbors,
                )
                .map(|(_, nbr)| nbr),
                None => Some(nbr),
            };

            if let Some(nbr) = nbr {
                gr::helper_process_grace_lsa(
                    nbr,
                    iface,
                    area,
                    &lse.data.hdr,
                    grace_period,
                    reason,
                    instance,
                );
            }
        }

        // (5.f) Check if this is a self-originated LSA.
        if lse.flags.contains(LsaEntryFlags::SELF_ORIGINATED) {
            if instance.config.trace_opts.flooding {
                Debug::<V>::LsaSelfOriginated(nbr_router_id, &lse.data.hdr)
                    .log();
            }

            // (Re)originate or flush self-originated LSA.
            let (lsdb_id, _) = lsdb_index(
                &instance.state.lsdb,
                &arenas.areas,
                &arenas.interfaces,
                lsdb_idx,
            );
            instance.tx.protocol_input.lsa_orig_event(
                LsaOriginateEvent::SelfOriginatedLsaRcvd {
                    lsdb_id,
                    lse_id: lse.id,
                },
            );
        }

        // Examine the next LSA.
        return false;
    }

    // (6 - errata 3974) Check if the received LSA is the same instance as
    // the database copy (i.e., neither one is more recent).
    let nbr = &mut arenas.neighbors[nbr_idx];
    let lse = lse.unwrap();
    if lsa_cmp == Some(Ordering::Equal) {
        // Check if this LSA can be handled as an implied acknowledgment.
        if let btree_map::Entry::Occupied(o) = nbr.lists.ls_rxmt.entry(lsa_key)
        {
            o.remove();
            nbr.rxmt_lsupd_stop_check();

            let nbr_net_id = nbr.network_id();
            if iface.state.ism_state == ism::State::Backup
                && iface.state.dr == Some(nbr_net_id)
            {
                // Enqueue delayed ack.
                iface.enqueue_delayed_ack(area, instance, &lsa.hdr);
            }
        } else {
            // Send direct ack.
            output::send_lsack_direct(nbr, iface, area, instance, &lsa.hdr);
        }

        // Examine the next LSA.
        return false;
    }

    // (7 - errata 3974) If there is an instance of the LSA on the sending
    // neighbor's Link state request list, an error has occurred in the
    // Database Exchange process.
    if nbr.lists.ls_request.contains_key(&lsa_key)
        || nbr.lists.ls_request_pending.contains_key(&lsa_key)
    {
        // Restart the Database Exchange process.
        nbr.fsm(
            iface,
            area,
            instance,
            &arenas.lsa_entries,
            nsm::Event::BadLsReq,
        );

        // Stop processing the Link State Update packet.
        return true;
    }

    // (8) The database copy is more recent.
    //
    // If the database copy has LS age equal to MaxAge and LS sequence
    // number equal to MaxSequenceNumber, simply discard the received LSA
    // without acknowledging it.
    if lse.data.hdr.is_maxage() && lse.data.hdr.seq_no() == lsdb::LSA_MAX_SEQ_NO
    {
        // Examine the next LSA.
        return false;
    }
    if !lsdb::lsa_min_arrival_check(lse) {
        // Send the database copy back to the sending neighbor, encapsulated
        // within a Link State Update Packet.
        nbr.lists.ls_update.insert(lsa_key, lse.data.clone());
        instance
            .tx
            .protocol_input
            .send_lsupd(area.id, iface.id, Some(nbr.id));
    } else {
        // Log why the LSA is being discarded.
        if instance.config.trace_opts.flooding {
            Debug::<V>::LsaMinArrivalDiscard(nbr.router_id, &lsa.hdr).log();
        }
    }

    // Examine the next LSA.
    false
}

fn process_packet_lsack<V>(
    nbr: &mut Neighbor<V>,
    instance: &InstanceUpView<'_, V>,
    ls_ack: V::PacketLsAck,
) -> Result<(), Error<V>>
where
    V: Version,
{
    if nbr.state < nsm::State::Exchange {
        if instance.config.trace_opts.flooding {
            Debug::<V>::PacketRxIgnore(nbr.router_id, &nbr.state).log();
        }
        return Ok(());
    }

    // Iterate over all LSA headers.
    for lsa_hdr in ls_ack.lsa_hdrs() {
        let lsa_key = lsa_hdr.key();
        if let btree_map::Entry::Occupied(o) = nbr.lists.ls_rxmt.entry(lsa_key)
        {
            let lsa = o.get();
            if lsa_compare::<V>(&lsa.hdr, lsa_hdr) == Ordering::Equal {
                o.remove();
                nbr.rxmt_lsupd_stop_check();
            } else if instance.config.trace_opts.flooding {
                Debug::<V>::QuestionableAck(nbr.router_id, lsa_hdr).log();
            }
        }
    }

    Ok(())
}

// ===== Free last sent/received Database Description packets =====

pub(crate) fn process_dbdesc_free<V>(
    _instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    area_key: AreaKey,
    iface_key: InterfaceKey,
    nbr_key: NeighborKey,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Lookup area, interface and neighbor.
    let (_, area) = arenas.areas.get_mut_by_key(&area_key)?;
    let (_iface_idx, iface) = area
        .interfaces
        .get_mut_by_key(&mut arenas.interfaces, &iface_key)?;
    let (_, nbr) = iface
        .state
        .neighbors
        .get_mut_by_key(&mut arenas.neighbors, &nbr_key)?;

    // Free last sent/received Database Description packets.
    nbr.tasks.dbdesc_free_timer = None;
    nbr.last_rcvd_dbdesc = None;
    nbr.last_sent_dbdesc = None;

    Ok(())
}

// ===== Request to send LS Update =====

pub(crate) fn process_send_lsupd<V>(
    instance: &InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    area_key: AreaKey,
    iface_key: InterfaceKey,
    nbr_key: Option<NeighborKey>,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Lookup area, interface and optional neighbor.
    let (_, area) = arenas.areas.get_mut_by_key(&area_key)?;
    let (_iface_idx, iface) = area
        .interfaces
        .get_mut_by_key(&mut arenas.interfaces, &iface_key)?;
    let nbr_idx = match &nbr_key {
        Some(nbr_key) => {
            let (nbr_idx, _) = iface
                .state
                .neighbors
                .get_mut_by_key(&mut arenas.neighbors, nbr_key)?;
            Some(nbr_idx)
        }
        None => None,
    };

    // Send LS Update.
    iface.state.tasks.ls_update_timer = None;
    output::send_lsupd(nbr_idx, iface, area, instance, &mut arenas.neighbors);

    Ok(())
}

// ===== Packet retransmission =====

pub(crate) fn process_packet_rxmt<V>(
    instance: &InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    area_key: AreaKey,
    iface_key: InterfaceKey,
    nbr_key: NeighborKey,
    packet_type: RxmtPacketType,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Lookup area, interface and optional neighbor.
    let (_, area) = arenas.areas.get_mut_by_key(&area_key)?;
    let (_iface_idx, iface) = area
        .interfaces
        .get_mut_by_key(&mut arenas.interfaces, &iface_key)?;
    let (_, nbr) = iface
        .state
        .neighbors
        .get_mut_by_key(&mut arenas.neighbors, &nbr_key)?;

    // Retransmit packet.
    match packet_type {
        RxmtPacketType::DbDesc => {
            output::rxmt_dbdesc(nbr, iface);
        }
        RxmtPacketType::LsRequest => {
            output::rxmt_lsreq(nbr, iface, area, instance);
        }
        RxmtPacketType::LsUpdate => {
            output::rxmt_lsupd(nbr, iface, area, instance);
        }
    }

    Ok(())
}

// ===== Delayed Ack timeout =====

pub(crate) fn process_delayed_ack_timeout<V>(
    instance: &InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    area_key: AreaKey,
    iface_key: InterfaceKey,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Lookup area and interface.
    let (_, area) = arenas.areas.get_mut_by_key(&area_key)?;
    let (_iface_idx, iface) = area
        .interfaces
        .get_mut_by_key(&mut arenas.interfaces, &iface_key)?;

    // Send delayed LS Ack.
    iface.state.tasks.ls_delayed_ack = None;
    output::send_lsack_delayed(iface, area, instance, &arenas.neighbors);

    Ok(())
}

// ===== LSA origination event =====

pub(crate) fn process_lsa_orig_event<V>(
    instance: &InstanceUpView<'_, V>,
    arenas: &InstanceArenas<V>,
    event: LsaOriginateEvent,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Check which LSAs need to be reoriginated or flushed.
    V::lsa_orig_event(instance, arenas, event)
}

// ===== LSA origination check =====

pub(crate) fn process_lsa_orig_check<V>(
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    lsdb_key: LsdbKey,
    options: Option<V::PacketOptions>,
    lsa_id: Ipv4Addr,
    lsa_body: V::LsaBody,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Lookup LSDB.
    let (lsdb_idx, _) = lsdb_get(
        &instance.state.lsdb,
        &arenas.areas,
        &arenas.interfaces,
        &lsdb_key,
    )?;

    // Attempt to originate LSA.
    lsdb::originate_check(
        instance, arenas, lsdb_idx, options, lsa_id, lsa_body,
    );

    Ok(())
}

// ===== LSA delayed origination timer =====

pub(crate) fn process_lsa_orig_delayed_timer<V>(
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    lsdb_key: LsdbKey,
    lsa_key: LsaKey<V::LsaType>,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Lookup LSDB.
    let (lsdb_idx, lsdb) = lsdb_get_mut(
        &mut instance.state.lsdb,
        &mut arenas.areas,
        &mut arenas.interfaces,
        &lsdb_key,
    )?;

    // Originate LSA.
    if let Some(ldo) = lsdb.delayed_orig.remove(&lsa_key) {
        lsdb::originate(instance, arenas, lsdb_idx, ldo.data);
    }

    Ok(())
}

// ===== LSA flush event =====

pub(crate) fn process_lsa_flush<V>(
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    lsdb_key: LsdbKey,
    lse_key: LsaEntryKey<V::LsaType>,
    reason: LsaFlushReason,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Lookup LSA entry and its corresponding LSDB.
    let (lsdb_idx, lsdb) = lsdb_get_mut(
        &mut instance.state.lsdb,
        &mut arenas.areas,
        &mut arenas.interfaces,
        &lsdb_key,
    )?;
    let (lse_idx, _) =
        lsdb.get_mut_by_key(&mut arenas.lsa_entries, &lse_key)?;

    // Flush LSA.
    lsdb::flush(instance, arenas, lsdb_idx, lse_idx, reason);

    Ok(())
}

// ===== LSA refresh event =====

pub(crate) fn process_lsa_refresh<V>(
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    lsdb_key: LsdbKey,
    lse_key: LsaEntryKey<V::LsaType>,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Lookup LSA entry and its corresponding LSDB.
    let (lsdb_idx, lsdb) = lsdb_get_mut(
        &mut instance.state.lsdb,
        &mut arenas.areas,
        &mut arenas.interfaces,
        &lsdb_key,
    )?;
    let (_, lse) = lsdb.get_by_key(&arenas.lsa_entries, &lse_key)?;

    assert!(lse.flags.contains(LsaEntryFlags::SELF_ORIGINATED));

    if instance.config.trace_opts.lsdb {
        Debug::<V>::LsaRefresh(&lse.data.hdr).log();
    }

    // Originate new instance of the LSA.
    let lsa = Lsa::new(
        0,
        lse.data.hdr.options(),
        lse.data.hdr.lsa_id(),
        lse.data.hdr.adv_rtr(),
        lse.data.hdr.seq_no() + 1,
        lse.data.body.clone(),
    );
    lsdb::originate(instance, arenas, lsdb_idx, lsa);

    Ok(())
}

// ===== LSDB MaxAge sweep timer =====

pub(crate) fn process_lsdb_maxage_sweep_interval<V>(
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    lsdb_key: LsdbKey,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Lookup LSDB.
    let (lsdb_idx, lsdb) = lsdb_get_mut(
        &mut instance.state.lsdb,
        &mut arenas.areas,
        &mut arenas.interfaces,
        &lsdb_key,
    )?;

    // Skip discarding MaxAge LSAs if any of the router's neighbors are in
    // states Exchange or Loading.
    if arenas.neighbors.iter().any(|(_, nbr)| {
        matches!(nbr.state, nsm::State::Exchange | nsm::State::Loading)
    }) {
        return Ok(());
    }

    // Get list of MaxAge LSAs that are no longer contained on any neighbor LS
    // retransmission lists.
    for lse_idx in lsdb
        .maxage_lsas
        .extract_if(|lse_idx| {
            let lse = &arenas.lsa_entries[*lse_idx];
            !arenas.neighbors.iter().any(|(_, nbr)| {
                nbr.lists
                    .ls_rxmt
                    .get(&lse.data.hdr.key())
                    .filter(|rxmt_lsa| Arc::ptr_eq(&lse.data, rxmt_lsa))
                    .is_some()
            })
        })
        .collect::<Vec<_>>()
    {
        let (_, lsdb) = lsdb_index_mut(
            &mut instance.state.lsdb,
            &mut arenas.areas,
            &mut arenas.interfaces,
            lsdb_idx,
        );
        let lse = &arenas.lsa_entries[lse_idx];

        // Delete or originate new instance of the LSA depending whether it's
        // wrapping its sequence number.
        if let Some(lsa) = lsdb.seqno_wrapping.remove(&lse.data.hdr.key()) {
            let lsa = Lsa::new(
                0,
                lsa.hdr.options(),
                lsa.hdr.lsa_id(),
                lsa.hdr.adv_rtr(),
                lsdb::LSA_INIT_SEQ_NO,
                lsa.body.clone(),
            );
            lsdb::originate(instance, arenas, lsdb_idx, lsa);
        } else {
            lsdb.delete(&mut arenas.lsa_entries, lse_idx);
        }
    }

    Ok(())
}

// ===== SPF run event =====

pub(crate) fn process_spf_delay_event<V>(
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    event: spf::fsm::Event,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Trigger SPF Delay FSM event.
    spf::fsm(event, instance, arenas)
}

// ===== Grace period timeout =====

pub(crate) fn process_grace_period_timeout<V>(
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    area_key: AreaKey,
    iface_key: InterfaceKey,
    nbr_key: NeighborKey,
) -> Result<(), Error<V>>
where
    V: Version,
{
    // Lookup area, interface and neighbor.
    let (_, area) = arenas.areas.get_mut_by_key(&area_key)?;
    let (_iface_idx, iface) = area
        .interfaces
        .get_mut_by_key(&mut arenas.interfaces, &iface_key)?;
    let (_, nbr) = iface
        .state
        .neighbors
        .get_mut_by_key(&mut arenas.neighbors, &nbr_key)?;

    if nbr.gr.is_some() {
        // Exit from the helper mode.
        gr::helper_exit(nbr, iface, area, GrExitReason::TimedOut, instance);

        // Delete the neighbor.
        instance.tx.protocol_input.nsm_event(
            area.id,
            iface.id,
            nbr.id,
            nsm::Event::InactivityTimer,
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::{Arc, OnceLock};

    use holo_protocol::{InstanceChannelsTx, InstanceShared, ProtocolInstance};
    use holo_utils::ibus;
    use holo_utils::southbound::InterfaceFlags;
    use holo_utils::yang::ContextExt;
    use holo_yang::YANG_CTX;
    use ipnetwork::Ipv6Network;
    use tokio::sync::mpsc;
    use yang5::context::Context;

    use super::*;
    use crate::area::BACKBONE_AREA_ID;
    use crate::collections::{AreaId, InterfaceId, NeighborIndex};
    use crate::instance::Instance;
    use crate::interface::InterfaceType;
    use crate::neighbor::NeighborNetId;
    use crate::ospfv3::packet::iana::Options;
    use crate::ospfv3::packet::{DbDesc, Hello, PacketHdr};
    use crate::packet::iana::PacketType;
    use crate::packet::lls::{
        LlsDbDescData, LlsHelloData, MdrDdTlv, MdrHelloTlv, MdrMetricEntry,
        MdrMetricTlv,
    };
    use crate::version::Ospfv3;

    static TEST_YANG_CTX: OnceLock<Arc<Context>> = OnceLock::new();

    fn ensure_yang_ctx() {
        TEST_YANG_CTX.get_or_init(|| {
            let mut yang_ctx = holo_yang::new_context();
            holo_yang::load_modules(
                &mut yang_ctx,
                &holo_yang::implemented_modules::ALL,
            );
            yang_ctx.cache_data_paths();
            let yang_ctx = Arc::new(yang_ctx);
            let _ = YANG_CTX.set(yang_ctx.clone());
            yang_ctx
        });
    }

    fn test_instance() -> Instance<Ospfv3> {
        ensure_yang_ctx();

        let (nb_tx, _nb_rx) = mpsc::unbounded_channel();
        let (ibus_tx, _ibus_rx) = ibus::ibus_channels();
        let (proto_tx, _proto_rx) =
            <Instance<Ospfv3> as ProtocolInstance>::protocol_input_channels();
        let (protocol_output_tx, _protocol_output_rx) = mpsc::channel(4);
        let channels_tx = InstanceChannelsTx::new(
            nb_tx,
            ibus_tx,
            proto_tx,
            protocol_output_tx,
        );
        let mut instance = <Instance<Ospfv3> as ProtocolInstance>::new(
            "test".into(),
            InstanceShared::default(),
            channels_tx,
        );
        instance.config.enabled = true;
        instance.config.router_id = Some(local_router_id());
        instance
    }

    fn add_test_interface(
        instance: &mut Instance<Ospfv3>,
        mdr_enabled: bool,
    ) -> (AreaId, InterfaceId) {
        let (_area_idx, area) = instance.arenas.areas.insert(BACKBONE_AREA_ID);
        let (_iface_idx, iface) = area.interfaces.insert(
            &mut instance.arenas.interfaces,
            "eth0".into(),
            None,
        );
        iface.system.ifindex = Some(1);
        iface.system.mtu = Some(1500);
        iface.system.flags.insert(InterfaceFlags::OPERATIVE);
        iface.system.linklocal_addr =
            Some("fe80::1/64".parse::<Ipv6Network>().unwrap());
        iface.config.enabled = true;
        iface.config.if_type = InterfaceType::Broadcast;
        iface.config.mdr.enabled = mdr_enabled;
        let area_id = area.id;
        let iface_id = iface.id;

        instance.update();

        (area_id, iface_id)
    }

    fn local_router_id() -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, 1)
    }

    fn router_id(octet: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, octet)
    }

    fn receive_hello(
        instance: &mut Instance<Ospfv3>,
        area_id: AreaId,
        iface_id: InterfaceId,
        hello: Hello,
    ) {
        let (mut instance_view, arenas) = instance.as_up().unwrap();
        process_packet(
            &mut instance_view,
            arenas,
            area_id.into(),
            iface_id.into(),
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 5),
            Ok(Packet::Hello(hello)),
        )
        .unwrap();
    }

    fn add_test_neighbor(
        instance: &mut Instance<Ospfv3>,
        area_id: AreaId,
        iface_id: InterfaceId,
        router_id: Ipv4Addr,
        state: nsm::State,
    ) -> NeighborIndex {
        let (_, area) = instance.arenas.areas.get_by_id(area_id).unwrap();
        let (iface_idx, _) = area
            .interfaces
            .get_by_id(&instance.arenas.interfaces, iface_id)
            .unwrap();
        let (nbr_idx, nbr) = instance.arenas.interfaces[iface_idx]
            .state
            .neighbors
            .insert(
                &mut instance.arenas.neighbors,
                router_id,
                Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
            );
        nbr.state = state;
        nbr_idx
    }

    fn receive_dbdesc(
        instance: &mut Instance<Ospfv3>,
        area_id: AreaId,
        iface_id: InterfaceId,
        dbdesc: DbDesc,
    ) {
        let (mut instance_view, arenas) = instance.as_up().unwrap();
        process_packet(
            &mut instance_view,
            arenas,
            area_id.into(),
            iface_id.into(),
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 5),
            Ok(Packet::DbDesc(dbdesc)),
        )
        .unwrap();
    }

    fn neighbor(
        instance: &Instance<Ospfv3>,
        area_id: AreaId,
        iface_id: InterfaceId,
        router_id: Ipv4Addr,
    ) -> &Neighbor<Ospfv3> {
        let (_, area) = instance.arenas.areas.get_by_id(area_id).unwrap();
        let (_, iface) = area
            .interfaces
            .get_by_id(&instance.arenas.interfaces, iface_id)
            .unwrap();
        iface
            .state
            .neighbors
            .get_by_router_id(&instance.arenas.neighbors, router_id)
            .unwrap()
            .1
    }

    fn iface<'a>(
        instance: &'a Instance<Ospfv3>,
        area_id: AreaId,
        iface_id: InterfaceId,
    ) -> &'a Interface<Ospfv3> {
        let (_, area) = instance.arenas.areas.get_by_id(area_id).unwrap();
        area.interfaces
            .get_by_id(&instance.arenas.interfaces, iface_id)
            .unwrap()
            .1
    }

    fn iface_mut<'a>(
        instance: &'a mut Instance<Ospfv3>,
        area_id: AreaId,
        iface_id: InterfaceId,
    ) -> &'a mut Interface<Ospfv3> {
        let (_, area) = instance.arenas.areas.get_by_id(area_id).unwrap();
        let (iface_idx, _) = area
            .interfaces
            .get_by_id(&instance.arenas.interfaces, iface_id)
            .unwrap();
        &mut instance.arenas.interfaces[iface_idx]
    }

    fn mdr_hello(
        router_id: Ipv4Addr,
        hsn: u16,
        differential: bool,
        dr: Option<Ipv4Addr>,
        bdr: Option<Ipv4Addr>,
        lists: MdrHelloNeighborLists,
        metric: Option<MdrMetricTlv>,
    ) -> Hello {
        let mut ordered_neighbors = Vec::new();
        ordered_neighbors.extend(lists.down.iter().copied());
        ordered_neighbors.extend(lists.init.iter().copied());
        ordered_neighbors.extend(lists.dependent.iter().copied());
        ordered_neighbors.extend(lists.selected_advertised.iter().copied());
        ordered_neighbors.extend(lists.bidirectional.iter().copied());
        Hello {
            hdr: PacketHdr {
                pkt_type: PacketType::Hello,
                router_id,
                area_id: BACKBONE_AREA_ID,
                instance_id: 0,
                auth_seqno: None,
            },
            iface_id: 11,
            priority: 7,
            options: Options::E | Options::L,
            hello_interval: 2,
            dead_interval: 6,
            dr: dr.map(NeighborNetId::from),
            bdr: bdr.map(NeighborNetId::from),
            neighbors: ordered_neighbors.iter().copied().collect(),
            neighbor_order: Some(ordered_neighbors),
            lls: Some(LlsHelloData {
                eof: None,
                mdr_hello: Some(MdrHelloTlv {
                    hello_sequence_number: hsn,
                    adjacency_reduction_disabled: false,
                    differential,
                    n1: lists.down.len() as u8,
                    n2: lists.init.len() as u8,
                    n3: lists.dependent.len() as u8,
                    n4: lists.selected_advertised.len() as u8,
                }),
                mdr_metric: metric,
                unknown_tlvs: Vec::new(),
            }),
        }
    }

    fn mdr_dbdesc(
        router_id: Ipv4Addr,
        options: Options,
        flags: DbDescFlags,
        dd_seq_no: u32,
        mdr_dd: Option<MdrDdTlv>,
    ) -> DbDesc {
        DbDesc {
            hdr: PacketHdr {
                pkt_type: PacketType::DbDesc,
                router_id,
                area_id: BACKBONE_AREA_ID,
                instance_id: 0,
                auth_seqno: None,
            },
            options,
            mtu: 1500,
            dd_flags: flags,
            dd_seq_no,
            lsa_hdrs: Vec::new(),
            lls: mdr_dd.map(|mdr_dd| LlsDbDescData {
                eof: None,
                mdr_dd: Some(mdr_dd),
                unknown_tlvs: Vec::new(),
            }),
        }
    }

    fn standard_hello(router_id: Ipv4Addr, neighbors: Vec<Ipv4Addr>) -> Hello {
        Hello {
            hdr: PacketHdr {
                pkt_type: PacketType::Hello,
                router_id,
                area_id: BACKBONE_AREA_ID,
                instance_id: 0,
                auth_seqno: None,
            },
            iface_id: 11,
            priority: 7,
            options: Options::E,
            hello_interval: 10,
            dead_interval: 40,
            dr: None,
            bdr: None,
            neighbors: neighbors.iter().copied().collect(),
            neighbor_order: Some(neighbors),
            lls: None,
        }
    }

    /// Validates RFC 5614 §4.2.1 and §4.2.3 — Full Hello Packet.
    ///
    /// A full MDR Hello replaces the peer-reported DNS/SANS/BNS sets, derives
    /// NSM 2-Way from the MDR lists, and drives the pending
    /// MDR-neighbor-change input through one selection pass.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/4.2.1.json,
    /// rfcs/parsed/chunks/5614/4.2.3.json
    #[tokio::test]
    async fn mdr_full_hello_updates_state_and_consumes_selection_change() {
        let mut instance = test_instance();
        let (area_id, iface_id) = add_test_interface(&mut instance, true);
        let remote = router_id(2);

        receive_hello(
            &mut instance,
            area_id,
            iface_id,
            mdr_hello(
                remote,
                10,
                false,
                Some(remote),
                Some(router_id(9)),
                MdrHelloNeighborLists {
                    dependent: vec![local_router_id(), router_id(3)],
                    selected_advertised: vec![router_id(4)],
                    bidirectional: vec![router_id(5)],
                    ..Default::default()
                },
                None,
            ),
        );

        let nbr = neighbor(&instance, area_id, iface_id, remote);
        assert_eq!(nbr.state, nsm::State::ExStart);
        assert_eq!(nbr.priority, 7);
        assert_eq!(nbr.mdr.remote_interface_id, Some(11));
        assert_eq!(nbr.mdr.hello_sequence_number, 10);
        assert!(nbr.mdr.full_hello_received);
        assert_eq!(nbr.mdr.mdr_level, MdrLevel::Mdr);
        assert_eq!(nbr.mdr.parent, Some(remote));
        assert_eq!(nbr.mdr.backup_parent, Some(router_id(9)));
        assert!(nbr.mdr.reverse_2way);
        assert!(nbr.mdr.dependent_selector);
        assert_eq!(
            nbr.mdr.dependent_neighbors,
            BTreeSet::from([local_router_id(), router_id(3)])
        );
        assert_eq!(
            nbr.mdr.selected_advertised_neighbors,
            BTreeSet::from([router_id(4)])
        );
        assert_eq!(
            nbr.mdr.bidirectional_neighbors,
            BTreeSet::from([
                local_router_id(),
                router_id(3),
                router_id(4),
                router_id(5),
            ])
        );
        assert_eq!(nbr.mdr.incoming_link_metric, Some(1));
        let mdr = iface(&instance, area_id, iface_id)
            .state
            .mdr
            .as_ref()
            .unwrap();
        assert!(!mdr.mdr_neighbor_change);
        assert_eq!(mdr.mdr_level, MdrLevel::Other);
        assert_eq!(mdr.parent, Some(remote));
        assert!(!mdr.adjacency_reevaluation_pending);
        assert!(!mdr.lsa_reevaluation_pending);
    }

    /// Validates RFC 5614 §4.2.2 — Differential Hello Packet.
    ///
    /// Differential Lists 1/2 remove IDs from DNS/SANS/BNS while Lists 3/4/5
    /// merge additions into the peer-reported neighbor sets.
    ///
    /// RFC chunk: rfcs/parsed/chunks/5614/4.2.2.json
    #[tokio::test]
    async fn mdr_differential_hello_merges_add_remove_lists() {
        let mut instance = test_instance();
        let (area_id, iface_id) = add_test_interface(&mut instance, true);
        let remote = router_id(2);

        receive_hello(
            &mut instance,
            area_id,
            iface_id,
            mdr_hello(
                remote,
                20,
                false,
                Some(remote),
                None,
                MdrHelloNeighborLists {
                    dependent: vec![local_router_id(), router_id(3)],
                    selected_advertised: vec![router_id(4)],
                    bidirectional: vec![router_id(5)],
                    ..Default::default()
                },
                None,
            ),
        );
        receive_hello(
            &mut instance,
            area_id,
            iface_id,
            mdr_hello(
                remote,
                21,
                true,
                Some(remote),
                None,
                MdrHelloNeighborLists {
                    down: vec![router_id(3), router_id(4)],
                    init: vec![local_router_id()],
                    dependent: vec![router_id(6)],
                    selected_advertised: vec![router_id(5)],
                    bidirectional: vec![router_id(7)],
                },
                None,
            ),
        );

        let nbr = neighbor(&instance, area_id, iface_id, remote);
        assert_eq!(nbr.state, nsm::State::ExStart);
        assert!(!nbr.mdr.reverse_2way);
        assert_eq!(nbr.mdr.hello_sequence_number, 21);
        assert!(nbr.mdr.last_hello_differential);
        assert_eq!(nbr.mdr.dependent_neighbors, BTreeSet::from([router_id(6)]));
        assert_eq!(
            nbr.mdr.selected_advertised_neighbors,
            BTreeSet::from([router_id(5)])
        );
        assert_eq!(
            nbr.mdr.bidirectional_neighbors,
            BTreeSet::from([router_id(5), router_id(6), router_id(7)])
        );
    }

    /// Validates RFC 5614 §4.2.2 — Differential Hello repeat window.
    ///
    /// If the local RID is absent from a differential Hello, 2-Way is retained
    /// only when the HSN gap is inside HelloRepeatCount; a larger gap drives
    /// 1-WayReceived and clears reverse-2-way.
    ///
    /// RFC chunk: rfcs/parsed/chunks/5614/4.2.2.json
    #[tokio::test]
    async fn mdr_differential_repeat_window_retains_then_expires() {
        let mut instance = test_instance();
        let (area_id, iface_id) = add_test_interface(&mut instance, true);
        let remote = router_id(2);

        receive_hello(
            &mut instance,
            area_id,
            iface_id,
            mdr_hello(
                remote,
                30,
                false,
                Some(remote),
                None,
                MdrHelloNeighborLists {
                    bidirectional: vec![local_router_id()],
                    ..Default::default()
                },
                None,
            ),
        );
        receive_hello(
            &mut instance,
            area_id,
            iface_id,
            mdr_hello(
                remote,
                33,
                true,
                Some(remote),
                None,
                MdrHelloNeighborLists::default(),
                None,
            ),
        );
        assert_eq!(
            neighbor(&instance, area_id, iface_id, remote).state,
            nsm::State::ExStart
        );

        receive_hello(
            &mut instance,
            area_id,
            iface_id,
            mdr_hello(
                remote,
                37,
                true,
                Some(remote),
                None,
                MdrHelloNeighborLists::default(),
                None,
            ),
        );

        let nbr = neighbor(&instance, area_id, iface_id, remote);
        assert_eq!(nbr.state, nsm::State::Init);
        assert!(!nbr.mdr.reverse_2way);
    }

    /// Validates RFC 5614 §4.3 — Neighbor Acceptance Condition.
    ///
    /// A configured consecutive-Hello threshold keeps a new MDR neighbor Down
    /// until the threshold is reached, then Holo's normal NSM events move the
    /// neighbor to 2-Way when the merged MDR lists contain the local RID.
    ///
    /// RFC chunk: rfcs/parsed/chunks/5614/4.3.json
    #[tokio::test]
    async fn mdr_acceptance_threshold_requires_consecutive_hellos() {
        let mut instance = test_instance();
        let (area_id, iface_id) = add_test_interface(&mut instance, true);
        let remote = router_id(2);
        {
            let iface = iface_mut(&mut instance, area_id, iface_id);
            iface.config.mdr.consecutive_hello_threshold = 2;
            iface
                .state
                .mdr
                .as_mut()
                .unwrap()
                .config
                .consecutive_hello_threshold = 2;
        }

        receive_hello(
            &mut instance,
            area_id,
            iface_id,
            mdr_hello(
                remote,
                1,
                false,
                Some(remote),
                None,
                MdrHelloNeighborLists {
                    bidirectional: vec![local_router_id()],
                    ..Default::default()
                },
                None,
            ),
        );
        assert_eq!(
            neighbor(&instance, area_id, iface_id, remote).state,
            nsm::State::Down
        );

        receive_hello(
            &mut instance,
            area_id,
            iface_id,
            mdr_hello(
                remote,
                2,
                false,
                Some(remote),
                None,
                MdrHelloNeighborLists {
                    bidirectional: vec![local_router_id()],
                    ..Default::default()
                },
                None,
            ),
        );

        let nbr = neighbor(&instance, area_id, iface_id, remote);
        assert_eq!(nbr.mdr.consecutive_hellos, 2);
        assert_eq!(nbr.state, nsm::State::ExStart);
    }

    /// Validates RFC 5614 §4.2.3 and Appendix A.2.5 — MDR Metric TLV.
    ///
    /// A received Metric TLV updates the per-link metric map and the incoming
    /// metric for the local RID from the peer-reported bidirectional list.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/4.2.3.json,
    /// rfcs/parsed/chunks/5614/a.2.5.json
    #[tokio::test]
    async fn mdr_metric_tlv_updates_incoming_metric() {
        let mut instance = test_instance();
        let (area_id, iface_id) = add_test_interface(&mut instance, true);
        let remote = router_id(2);

        receive_hello(
            &mut instance,
            area_id,
            iface_id,
            mdr_hello(
                remote,
                40,
                false,
                Some(remote),
                None,
                MdrHelloNeighborLists {
                    bidirectional: vec![local_router_id(), router_id(3)],
                    ..Default::default()
                },
                Some(MdrMetricTlv {
                    default_metric: 10,
                    include_ids: true,
                    metrics: vec![MdrMetricEntry {
                        neighbor_id: Some(local_router_id()),
                        metric: 25,
                    }],
                }),
            ),
        );

        let nbr = neighbor(&instance, area_id, iface_id, remote);
        assert_eq!(nbr.mdr.incoming_link_metric, Some(25));
        assert_eq!(nbr.mdr.link_metrics[&local_router_id()], 25);
        assert_eq!(nbr.mdr.link_metrics[&router_id(3)], 10);
    }

    /// Validates RFC 5614 §4.2.2 — NSM event from merged MDR state.
    ///
    /// A differential Hello whose flat wire list omits the local RID still
    /// drives TwoWayRcvd when the HSN gap is inside the repeat window.
    ///
    /// RFC chunk: rfcs/parsed/chunks/5614/4.2.2.json
    #[tokio::test]
    async fn mdr_nsm_uses_merged_state_not_flat_differential_list() {
        let mut instance = test_instance();
        let (area_id, iface_id) = add_test_interface(&mut instance, true);
        let remote = router_id(2);

        receive_hello(
            &mut instance,
            area_id,
            iface_id,
            mdr_hello(
                remote,
                50,
                false,
                Some(remote),
                None,
                MdrHelloNeighborLists {
                    bidirectional: vec![local_router_id()],
                    ..Default::default()
                },
                None,
            ),
        );
        receive_hello(
            &mut instance,
            area_id,
            iface_id,
            mdr_hello(
                remote,
                51,
                true,
                Some(remote),
                None,
                MdrHelloNeighborLists {
                    bidirectional: vec![router_id(3)],
                    ..Default::default()
                },
                None,
            ),
        );

        let nbr = neighbor(&instance, area_id, iface_id, remote);
        assert_eq!(nbr.state, nsm::State::ExStart);
        assert!(nbr.mdr.reverse_2way);
    }

    /// Validates RFC 5614 §4.2.2 — stale connectivity is removed.
    ///
    /// A missed differential beyond HelloRepeatCount removes stale BNS entries
    /// from List 1 and drives the neighbor back to 1-Way, preventing phantom
    /// two-hop connectivity.
    ///
    /// RFC chunk: rfcs/parsed/chunks/5614/4.2.2.json
    #[tokio::test]
    async fn mdr_phantom_connectivity_regression_removes_stale_bns() {
        let mut instance = test_instance();
        let (area_id, iface_id) = add_test_interface(&mut instance, true);
        let remote = router_id(2);

        receive_hello(
            &mut instance,
            area_id,
            iface_id,
            mdr_hello(
                remote,
                60,
                false,
                Some(remote),
                None,
                MdrHelloNeighborLists {
                    bidirectional: vec![local_router_id(), router_id(3)],
                    ..Default::default()
                },
                None,
            ),
        );
        receive_hello(
            &mut instance,
            area_id,
            iface_id,
            mdr_hello(
                remote,
                64,
                true,
                Some(remote),
                None,
                MdrHelloNeighborLists {
                    down: vec![router_id(3)],
                    ..Default::default()
                },
                None,
            ),
        );

        let nbr = neighbor(&instance, area_id, iface_id, remote);
        assert_eq!(nbr.state, nsm::State::Init);
        assert!(!nbr.mdr.bidirectional_neighbors.contains(&router_id(3)));
        assert!(!nbr.mdr.reverse_2way);
    }

    /// Validates RFC 5614 §7.5 — Receiving Database Description Packets.
    ///
    /// The MDR-DD TLV is processed before the neighbor-state DD match; a
    /// TwoWay neighbor whose TLV makes it a child is promoted to ExStart early
    /// enough to accept the same incoming DD packet.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/7.5.json,
    /// rfcs/parsed/chunks/5614/a.2.4.json
    #[tokio::test]
    async fn mdr_dbdesc_tlv_promotes_before_state_match() {
        let mut instance = test_instance();
        let (area_id, iface_id) = add_test_interface(&mut instance, true);
        let remote = router_id(2);
        add_test_neighbor(
            &mut instance,
            area_id,
            iface_id,
            remote,
            nsm::State::TwoWay,
        );
        {
            let iface = iface_mut(&mut instance, area_id, iface_id);
            let mdr = iface.state.mdr.as_mut().unwrap();
            mdr.mdr_level = MdrLevel::Mdr;
        }

        receive_dbdesc(
            &mut instance,
            area_id,
            iface_id,
            mdr_dbdesc(
                remote,
                Options::E | Options::L,
                DbDescFlags::I | DbDescFlags::M | DbDescFlags::MS,
                100,
                Some(MdrDdTlv {
                    designated_router: local_router_id(),
                    backup_designated_router: Ipv4Addr::UNSPECIFIED,
                }),
            ),
        );

        let nbr = neighbor(&instance, area_id, iface_id, remote);
        assert_eq!(nbr.state, nsm::State::Exchange);
        assert!(nbr.mdr.child);
        assert!(nbr.mdr.adjacency_desired);
        assert_eq!(nbr.dd_seq_no, 100);
    }

    /// Validates RFC 5614 §7.4 and §7.5 — MDR-DD exchange.
    ///
    /// A child-forming MDR-DD TLV on the initial DD starts adjacency, and the
    /// next accepted master DD completes an empty database exchange to Full
    /// without treating the ExStart-only L bit as an options mismatch.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/7.4.json,
    /// rfcs/parsed/chunks/5614/7.5.json,
    /// rfcs/parsed/chunks/5243/2.json
    #[tokio::test]
    async fn mdr_empty_dbdesc_exchange_reaches_full() {
        let mut instance = test_instance();
        let (area_id, iface_id) = add_test_interface(&mut instance, true);
        let remote = router_id(2);
        add_test_neighbor(
            &mut instance,
            area_id,
            iface_id,
            remote,
            nsm::State::TwoWay,
        );
        {
            let iface = iface_mut(&mut instance, area_id, iface_id);
            iface.state.mdr.as_mut().unwrap().mdr_level = MdrLevel::Mdr;
        }

        receive_dbdesc(
            &mut instance,
            area_id,
            iface_id,
            mdr_dbdesc(
                remote,
                Options::E | Options::L,
                DbDescFlags::I | DbDescFlags::M | DbDescFlags::MS,
                200,
                Some(MdrDdTlv {
                    designated_router: local_router_id(),
                    backup_designated_router: Ipv4Addr::UNSPECIFIED,
                }),
            ),
        );
        receive_dbdesc(
            &mut instance,
            area_id,
            iface_id,
            mdr_dbdesc(remote, Options::E, DbDescFlags::MS, 201, None),
        );

        let nbr = neighbor(&instance, area_id, iface_id, remote);
        assert_eq!(nbr.state, nsm::State::Full);
        assert!(nbr.lists.db_summary.is_empty());
        assert!(nbr.lists.ls_request.is_empty());
    }

    #[tokio::test]
    async fn non_mdr_hello_receive_still_uses_standard_flat_neighbor_list() {
        let mut instance = test_instance();
        let (area_id, iface_id) = add_test_interface(&mut instance, false);
        let remote = router_id(2);

        receive_hello(
            &mut instance,
            area_id,
            iface_id,
            standard_hello(remote, vec![local_router_id()]),
        );

        let nbr = neighbor(&instance, area_id, iface_id, remote);
        assert_eq!(nbr.state, nsm::State::TwoWay);
        assert!(iface(&instance, area_id, iface_id).state.mdr.is_none());
    }
}
