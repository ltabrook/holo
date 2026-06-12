//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::cmp::Ordering;
use std::collections::{BTreeSet, btree_map};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::area::Area;
use crate::collections::{
    Areas, Arena, InterfaceIndex, LsdbIndex, NeighborIndex,
};
use crate::instance::{InstanceArenas, InstanceUpView};
use crate::interface::{Interface, InterfaceType, ism};
use crate::lsdb;
use crate::neighbor::{Neighbor, nsm};
use crate::ospfv3::mdr::{BackupWaitEntry, MdrAckedLsa, MdrLevel};
use crate::packet::lsa::{Lsa, LsaHdrVersion};
use crate::tasks;
use crate::version::Version;

struct MdrFloodSource {
    nbr_idx: NeighborIndex,
    received_as_multicast: bool,
    source_is_mdr: bool,
    source_is_broadcast_relay: bool,
    source_bidirectional_routers: BTreeSet<Ipv4Addr>,
    reported_bidirectional_neighbors: BTreeSet<Ipv4Addr>,
}

// ===== global functions =====

pub(crate) fn flood<V>(
    instance: &mut InstanceUpView<'_, V>,
    areas: &Areas<V>,
    interfaces: &mut Arena<Interface<V>>,
    neighbors: &mut Arena<Neighbor<V>>,
    lsdb_idx: LsdbIndex,
    lsa: &Arc<Lsa<V>>,
    src: Option<(InterfaceIndex, NeighborIndex)>,
    received_as_multicast: bool,
) -> bool
where
    V: Version,
{
    clear_stale_mdr_backup_wait_for_lsa(instance, interfaces, lsa);

    // Iterate over eligible interfaces.
    //
    // For OSPFv3, the LSDB index already takes into consideration the U-bit of
    // the LSA, so there's no need to check it here.
    match lsdb_idx {
        LsdbIndex::Link(area_idx, iface_idx) => {
            let area = &areas[area_idx];
            flood_interface(
                iface_idx,
                area,
                instance,
                interfaces,
                neighbors,
                lsa,
                src,
                received_as_multicast,
            )
        }
        LsdbIndex::Area(area_idx) => {
            let area = &areas[area_idx];
            flood_area(
                area,
                instance,
                interfaces,
                neighbors,
                lsa,
                src,
                received_as_multicast,
            )
        }
        LsdbIndex::As => flood_as(
            instance,
            areas,
            interfaces,
            neighbors,
            lsa,
            src,
            received_as_multicast,
        ),
    }
}

// ===== helper functions =====

fn flood_interface<V>(
    iface_idx: InterfaceIndex,
    area: &Area<V>,
    instance: &mut InstanceUpView<'_, V>,
    interfaces: &mut Arena<Interface<V>>,
    neighbors: &mut Arena<Neighbor<V>>,
    lsa: &Arc<Lsa<V>>,
    src: Option<(InterfaceIndex, NeighborIndex)>,
    received_as_multicast: bool,
) -> bool
where
    V: Version,
{
    if interfaces[iface_idx].is_mdr_enabled() {
        return flood_interface_mdr(
            iface_idx,
            area,
            instance,
            interfaces,
            neighbors,
            lsa,
            src,
            received_as_multicast,
        );
    }

    let iface = &mut interfaces[iface_idx];
    let lsa_key = lsa.hdr.key();

    // Keep track that this LSA was flooded back out the receiving interface.
    // This information is relevant when deciding whether or not to send a
    // delayed ack later.
    let mut flooded_back = false;

    // 1) Each of the neighbors attached to this interface are examined.
    let mut rxmt_added = false;
    for nbr_idx in iface.state.neighbors.indexes() {
        let nbr = &mut neighbors[nbr_idx];

        // 1.a) Skip neighbors in a lesser state than Exchange.
        if nbr.state < nsm::State::Exchange {
            continue;
        }

        // Check if the LSA type is valid for this neighbor.
        if !V::lsa_type_is_valid(
            None,
            Some(iface.config.if_type),
            nbr.options,
            lsa.hdr.lsa_type(),
        ) {
            continue;
        }

        // 1.b) Handle adjacencies that are not full.
        if nbr.state != nsm::State::Full {
            use btree_map::Entry::Occupied;

            // Examine the Link state request list associated with this
            // adjacency.
            match (
                nbr.lists.ls_request.entry(lsa_key),
                nbr.lists.ls_request_pending.entry(lsa_key),
            ) {
                (Occupied(o), _) | (_, Occupied(o)) => {
                    let req = o.get();
                    let cmp = lsdb::lsa_compare::<V>(&lsa.hdr, req);
                    match cmp {
                        Ordering::Less => continue,
                        Ordering::Equal | Ordering::Greater => {
                            // Delete the LSA from the Link state request list.
                            o.remove();

                            // Check if the neighbor can transition to Full.
                            nbr.loading_done_check(iface, area, instance);

                            // Examine the next neighbor if the two copies are
                            // the same instance.
                            if cmp == Ordering::Equal {
                                continue;
                            }
                        }
                    }
                }
                _ => (),
            }
        }

        // 1.c) If the new LSA was received from this neighbor, examine the
        // next neighbor.
        if let Some((_, nbr_src_idx)) = src
            && nbr_src_idx == nbr_idx
        {
            continue;
        }

        // 1.d) Add LSA to the neighbor's rxmt list (or update the old version).
        nbr.lists.ls_rxmt.insert(lsa_key, lsa.clone());
        nbr.rxmt_lsupd_start_check(iface, area, instance);
        rxmt_added = true;
    }
    // 2) If in the previous step, the LSA was NOT added to any of the Link
    // state retransmission lists, there is no need to flood the LSA out the
    // interface and the next interface should be examined.
    if !rxmt_added {
        return flooded_back;
    }

    if let Some((iface_src_idx, nbr_src_idx)) = src
        && iface_src_idx == iface_idx
    {
        let nbr_src = &neighbors[nbr_src_idx];
        let nbr_src_net_id = nbr_src.network_id();

        // 3) If the new LSA was received on this interface, and it was
        // received from either the DR or the BDR, chances are
        // that all the neighbors have received the LSA already.
        // Therefore, examine the next interface.
        if iface.state.dr == Some(nbr_src_net_id)
            || iface.state.bdr == Some(nbr_src_net_id)
        {
            return flooded_back;
        }

        // 4) If the new LSA was received on this interface, and the
        // interface state is BDR, examine the next interface.
        if iface.state.ism_state == ism::State::Backup {
            return flooded_back;
        }

        flooded_back = true;
    }

    // Flood the LSA out the interface. Schedule the transmission as an attempt
    // to group more LSAs into the same message.
    iface.enqueue_ls_update(area, instance, lsa_key, lsa.clone());

    flooded_back
}

fn flood_interface_mdr<V>(
    iface_idx: InterfaceIndex,
    area: &Area<V>,
    instance: &mut InstanceUpView<'_, V>,
    interfaces: &mut Arena<Interface<V>>,
    neighbors: &mut Arena<Neighbor<V>>,
    lsa: &Arc<Lsa<V>>,
    src: Option<(InterfaceIndex, NeighborIndex)>,
    received_as_multicast: bool,
) -> bool
where
    V: Version,
{
    let lsa_key = lsa.hdr.key();
    let source =
        mdr_flood_source(interfaces, neighbors, src, received_as_multicast);
    let received_here =
        src.is_some_and(|(src_iface_idx, _)| src_iface_idx == iface_idx);
    let local_originated = src.is_none();
    let step6_local_outranks = (!received_here).then(|| {
        local_outranks_step6_covered_neighbors(
            instance,
            &interfaces[iface_idx],
            neighbors,
            source.as_ref(),
        )
    });

    let iface = &mut interfaces[iface_idx];
    let Some(mdr_snapshot) = iface.state.mdr.as_ref() else {
        return false;
    };
    let local_mdr_level = mdr_snapshot.mdr_level;
    let local_non_flooding_mdr = mdr_snapshot.non_flooding_mdr;
    let ack_cache_timeout = iface.config.mdr.ack_cache_timeout;
    let now = Instant::now();
    let nbr_indices = iface.state.neighbors.indexes().collect::<Vec<_>>();
    let mut uncovered_neighbors = BTreeSet::new();
    let mut covered_or_source_neighbors = BTreeSet::new();

    for nbr_idx in nbr_indices {
        let nbr = &mut neighbors[nbr_idx];

        if nbr.state < nsm::State::TwoWay {
            continue;
        }

        if !V::lsa_type_is_valid(
            None,
            Some(iface.config.if_type),
            nbr.options,
            lsa.hdr.lsa_type(),
        ) {
            continue;
        }

        if nbr.state >= nsm::State::Exchange && nbr.state != nsm::State::Full {
            use btree_map::Entry::Occupied;

            match (
                nbr.lists.ls_request.entry(lsa_key),
                nbr.lists.ls_request_pending.entry(lsa_key),
            ) {
                (Occupied(o), _) | (_, Occupied(o)) => {
                    let req = o.get();
                    let cmp = lsdb::lsa_compare::<V>(&lsa.hdr, req);
                    match cmp {
                        Ordering::Less => continue,
                        Ordering::Equal | Ordering::Greater => {
                            o.remove();
                            nbr.loading_done_check(iface, area, instance);
                            if cmp == Ordering::Equal {
                                continue;
                            }
                        }
                    }
                }
                _ => (),
            }
        }

        let received_from_neighbor = source
            .as_ref()
            .is_some_and(|source| source.nbr_idx == nbr_idx);
        let covered_by_source = source.as_ref().is_some_and(|source| {
            neighbor_covered_by_source(source, nbr.router_id)
        });
        mdr_prune_acked_lsa_for_newer_instance(nbr, &lsa.hdr);
        let acked_by_neighbor =
            mdr_neighbor_has_acked(nbr, ack_cache_timeout, &lsa.hdr, now);
        if received_from_neighbor || covered_by_source || acked_by_neighbor {
            covered_or_source_neighbors.insert(nbr.router_id);
        } else {
            uncovered_neighbors.insert(nbr.router_id);
        }

        if nbr.state < nsm::State::Exchange
            || received_from_neighbor
            || acked_by_neighbor
        {
            continue;
        }

        nbr.lists.ls_rxmt.insert(lsa_key, lsa.clone());
        nbr.rxmt_lsupd_start_check(iface, area, instance);
    }

    remove_mdr_backup_wait_neighbors(
        instance,
        interfaces,
        iface_idx,
        lsa_key,
        &covered_or_source_neighbors,
    );

    if uncovered_neighbors.is_empty() {
        return false;
    }

    let should_flood = if local_originated {
        true
    } else if received_here {
        match local_mdr_level {
            MdrLevel::Mdr => !local_non_flooding_mdr,
            MdrLevel::Backup => false,
            MdrLevel::Other => false,
        }
    } else if step6_local_outranks.unwrap_or(true) {
        true
    } else {
        false
    };
    let same_interface_backup_wait = received_here
        && (matches!(local_mdr_level, MdrLevel::Backup)
            || (local_mdr_level == MdrLevel::Mdr && local_non_flooding_mdr));
    let cross_interface_backup_wait =
        !received_here && !step6_local_outranks.unwrap_or(true);
    let should_backup_wait = !local_originated
        && (same_interface_backup_wait || cross_interface_backup_wait);

    if should_flood {
        let iface = &mut interfaces[iface_idx];
        iface.enqueue_ls_update(area, instance, lsa_key, lsa.clone());
        return received_here;
    }

    if should_backup_wait {
        let iface = &mut interfaces[iface_idx];
        add_mdr_backup_wait(
            instance,
            iface,
            lsa_key,
            lsa.clone(),
            uncovered_neighbors,
        );
    }

    false
}

fn mdr_flood_source<V>(
    interfaces: &Arena<Interface<V>>,
    neighbors: &Arena<Neighbor<V>>,
    src: Option<(InterfaceIndex, NeighborIndex)>,
    received_as_multicast: bool,
) -> Option<MdrFloodSource>
where
    V: Version,
{
    let (iface_idx, nbr_idx) = src?;
    let iface = &interfaces[iface_idx];
    let nbr = &neighbors[nbr_idx];
    let source_bidirectional_routers = iface
        .state
        .neighbors
        .iter(neighbors)
        .filter(|neighbor| neighbor.state >= nsm::State::TwoWay)
        .map(|neighbor| neighbor.router_id)
        .collect();
    let source_is_mdr = iface.is_mdr_enabled();
    let source_is_broadcast_relay = iface.config.if_type
        == InterfaceType::Broadcast
        && (iface.state.dr == Some(nbr.network_id())
            || iface.state.bdr == Some(nbr.network_id()));

    Some(MdrFloodSource {
        nbr_idx,
        received_as_multicast,
        source_is_mdr,
        source_is_broadcast_relay,
        source_bidirectional_routers,
        reported_bidirectional_neighbors: nbr
            .mdr
            .bidirectional_neighbors
            .clone(),
    })
}

fn neighbor_covered_by_source(
    source: &MdrFloodSource,
    candidate_router_id: Ipv4Addr,
) -> bool {
    if !source.received_as_multicast {
        return false;
    }
    if source.source_is_mdr {
        return source
            .reported_bidirectional_neighbors
            .contains(&candidate_router_id);
    }
    source.source_is_broadcast_relay
        && source
            .source_bidirectional_routers
            .contains(&candidate_router_id)
}

fn local_outranks_step6_covered_neighbors<V>(
    instance: &InstanceUpView<'_, V>,
    iface: &Interface<V>,
    neighbors: &Arena<Neighbor<V>>,
    source: Option<&MdrFloodSource>,
) -> bool
where
    V: Version,
{
    let Some(source) = source else {
        return true;
    };
    if !(source.source_is_mdr || source.source_is_broadcast_relay) {
        return true;
    }
    let Some(mdr) = iface.state.mdr.as_ref() else {
        return true;
    };
    iface
        .state
        .neighbors
        .iter(neighbors)
        .filter(|neighbor| {
            neighbor.state >= nsm::State::TwoWay
                && source
                    .source_bidirectional_routers
                    .contains(&neighbor.router_id)
                && neighbor_covered_by_source(source, neighbor.router_id)
        })
        .all(|neighbor| {
            mdr_rank_tuple(
                mdr.config.router_priority,
                mdr.mdr_level,
                instance.state.router_id,
            ) > mdr_rank_tuple(
                neighbor.priority,
                neighbor.mdr.mdr_level,
                neighbor.router_id,
            )
        })
}

fn mdr_rank_tuple(
    priority: u8,
    level: MdrLevel,
    router_id: Ipv4Addr,
) -> (u8, u8, Ipv4Addr) {
    let level = match level {
        MdrLevel::Other => 0,
        MdrLevel::Backup => 1,
        MdrLevel::Mdr => 2,
    };
    (priority, level, router_id)
}

pub(crate) fn mdr_prune_expired_acked_lsas<V>(
    nbr: &mut Neighbor<V>,
    ack_cache_timeout: Duration,
    now: Instant,
) where
    V: Version,
{
    nbr.mdr.acked_lsas.retain(|_, acked| {
        now.checked_duration_since(acked.received_at)
            .is_none_or(|age| age <= ack_cache_timeout)
    });
}

pub(crate) fn mdr_prune_acked_lsa_for_newer_instance<V>(
    nbr: &mut Neighbor<V>,
    lsa_hdr: &V::LsaHdr,
) where
    V: Version,
{
    let lsa_key = lsa_hdr.key();
    if nbr.mdr.acked_lsas.get(&lsa_key).is_some_and(|acked| {
        lsdb::lsa_compare::<V>(lsa_hdr, &acked.hdr) == Ordering::Greater
    }) {
        nbr.mdr.acked_lsas.remove(&lsa_key);
    }
}

pub(crate) fn mdr_store_acked_lsa<V>(
    nbr: &mut Neighbor<V>,
    ack_cache_timeout: Duration,
    lsa_hdr: &V::LsaHdr,
    now: Instant,
) where
    V: Version,
{
    mdr_prune_expired_acked_lsas(nbr, ack_cache_timeout, now);
    let lsa_key = lsa_hdr.key();
    if nbr.mdr.acked_lsas.get(&lsa_key).is_none_or(|acked| {
        lsdb::lsa_compare::<V>(lsa_hdr, &acked.hdr) == Ordering::Greater
    }) {
        nbr.mdr.acked_lsas.insert(
            lsa_key,
            MdrAckedLsa {
                hdr: *lsa_hdr,
                received_at: now,
            },
        );
    }
}

pub(crate) fn mdr_neighbor_has_acked<V>(
    nbr: &mut Neighbor<V>,
    ack_cache_timeout: Duration,
    lsa_hdr: &V::LsaHdr,
    now: Instant,
) -> bool
where
    V: Version,
{
    mdr_prune_expired_acked_lsas(nbr, ack_cache_timeout, now);
    nbr.mdr.acked_lsas.get(&lsa_hdr.key()).is_some_and(|acked| {
        lsdb::lsa_compare::<V>(&acked.hdr, lsa_hdr) != Ordering::Less
    })
}

pub(crate) fn remove_mdr_backup_wait_neighbor<V>(
    instance: &mut InstanceUpView<'_, V>,
    interfaces: &mut Arena<Interface<V>>,
    iface_idx: InterfaceIndex,
    lsa_key: crate::packet::lsa::LsaKey<V::LsaType>,
    router_id: Ipv4Addr,
) where
    V: Version,
{
    remove_mdr_backup_wait_neighbors(
        instance,
        interfaces,
        iface_idx,
        lsa_key,
        &BTreeSet::from([router_id]),
    );
}

fn add_mdr_backup_wait<V>(
    instance: &mut InstanceUpView<'_, V>,
    iface: &mut Interface<V>,
    lsa_key: crate::packet::lsa::LsaKey<V::LsaType>,
    lsa: Arc<Lsa<V>>,
    neighbors: BTreeSet<Ipv4Addr>,
) where
    V: Version,
{
    if neighbors.is_empty() {
        return;
    }
    let Some(mdr) = iface.state.mdr.as_mut() else {
        return;
    };

    let needs_timer =
        !instance.state.mdr_backup_wait_timers.contains_key(&lsa_key);
    let entry =
        mdr.backup_wait
            .entry(lsa_key)
            .or_insert_with(|| BackupWaitEntry {
                lsa: lsa.clone(),
                neighbors: BTreeSet::new(),
            });
    entry.lsa = lsa;
    entry.neighbors.extend(neighbors);

    if needs_timer {
        let task = tasks::mdr_backup_wait_timer(
            instance,
            lsa_key,
            iface.config.mdr.backup_wait_interval,
        );
        instance.state.mdr_backup_wait_timers.insert(lsa_key, task);
    }
}

fn remove_mdr_backup_wait_neighbors<V>(
    instance: &mut InstanceUpView<'_, V>,
    interfaces: &mut Arena<Interface<V>>,
    iface_idx: InterfaceIndex,
    lsa_key: crate::packet::lsa::LsaKey<V::LsaType>,
    neighbors_to_remove: &BTreeSet<Ipv4Addr>,
) where
    V: Version,
{
    if neighbors_to_remove.is_empty() {
        return;
    }
    let iface = &mut interfaces[iface_idx];
    let Some(mdr) = iface.state.mdr.as_mut() else {
        return;
    };
    let Some(entry) = mdr.backup_wait.get_mut(&lsa_key) else {
        return;
    };
    for router_id in neighbors_to_remove {
        entry.neighbors.remove(router_id);
    }
    if entry.neighbors.is_empty() {
        mdr.backup_wait.remove(&lsa_key);
    }
    remove_mdr_backup_wait_timer_if_unused(instance, interfaces, lsa_key);
}

fn clear_stale_mdr_backup_wait_for_lsa<V>(
    instance: &mut InstanceUpView<'_, V>,
    interfaces: &mut Arena<Interface<V>>,
    lsa: &Arc<Lsa<V>>,
) where
    V: Version,
{
    let lsa_key = lsa.hdr.key();
    let mut removed = false;
    for (_, iface) in interfaces.iter_mut() {
        let Some(mdr) = iface.state.mdr.as_mut() else {
            continue;
        };
        if mdr.backup_wait.get(&lsa_key).is_some_and(|entry| {
            lsdb::lsa_compare::<V>(&entry.lsa.hdr, &lsa.hdr) != Ordering::Equal
        }) {
            mdr.backup_wait.remove(&lsa_key);
            removed = true;
        }
    }
    if removed {
        remove_mdr_backup_wait_timer_if_unused(instance, interfaces, lsa_key);
    }
}

fn remove_mdr_backup_wait_timer_if_unused<V>(
    instance: &mut InstanceUpView<'_, V>,
    interfaces: &Arena<Interface<V>>,
    lsa_key: crate::packet::lsa::LsaKey<V::LsaType>,
) where
    V: Version,
{
    if !mdr_backup_wait_exists(interfaces, lsa_key) {
        instance.state.mdr_backup_wait_timers.remove(&lsa_key);
    }
}

fn mdr_backup_wait_exists<V>(
    interfaces: &Arena<Interface<V>>,
    lsa_key: crate::packet::lsa::LsaKey<V::LsaType>,
) -> bool
where
    V: Version,
{
    interfaces.iter().any(|(_, iface)| {
        iface
            .state
            .mdr
            .as_ref()
            .is_some_and(|mdr| mdr.backup_wait.contains_key(&lsa_key))
    })
}

pub(crate) fn expire_mdr_backup_wait<V>(
    instance: &mut InstanceUpView<'_, V>,
    arenas: &mut InstanceArenas<V>,
    lsa_key: crate::packet::lsa::LsaKey<V::LsaType>,
) -> Result<(), crate::error::Error<V>>
where
    V: Version,
{
    instance.state.mdr_backup_wait_timers.remove(&lsa_key);

    let area_ifaces = arenas
        .areas
        .indexes()
        .flat_map(|area_idx| {
            arenas.areas[area_idx]
                .interfaces
                .indexes()
                .map(move |iface_idx| (area_idx, iface_idx))
        })
        .collect::<Vec<_>>();

    for (area_idx, iface_idx) in area_ifaces {
        let Some(mut entry) = arenas.interfaces[iface_idx]
            .state
            .mdr
            .as_mut()
            .and_then(|mdr| mdr.backup_wait.remove(&lsa_key))
        else {
            continue;
        };

        let ack_cache_timeout =
            arenas.interfaces[iface_idx].config.mdr.ack_cache_timeout;
        let now = Instant::now();
        entry.neighbors = entry
            .neighbors
            .iter()
            .filter_map(|router_id| {
                let nbr_idx = arenas.interfaces[iface_idx]
                    .state
                    .neighbors
                    .get_by_router_id(&arenas.neighbors, *router_id)
                    .map(|(nbr_idx, _)| nbr_idx)?;
                let neighbor = &mut arenas.neighbors[nbr_idx];
                let still_needed = neighbor.state >= nsm::State::TwoWay
                    && !mdr_neighbor_has_acked(
                        neighbor,
                        ack_cache_timeout,
                        &entry.lsa.hdr,
                        now,
                    );
                still_needed.then_some(*router_id)
            })
            .collect();
        if entry.neighbors.is_empty() {
            continue;
        }

        let area = &arenas.areas[area_idx];
        let iface = &mut arenas.interfaces[iface_idx];
        iface.state.ls_ack_list.remove(&lsa_key);
        iface.enqueue_ls_update(area, instance, lsa_key, entry.lsa.clone());
    }

    Ok(())
}

fn flood_area<V>(
    area: &Area<V>,
    instance: &mut InstanceUpView<'_, V>,
    interfaces: &mut Arena<Interface<V>>,
    neighbors: &mut Arena<Neighbor<V>>,
    lsa: &Arc<Lsa<V>>,
    src: Option<(InterfaceIndex, NeighborIndex)>,
    received_as_multicast: bool,
) -> bool
where
    V: Version,
{
    let mut flooded_back = false;
    for iface_idx in area.interfaces.indexes() {
        flooded_back |= flood_interface(
            iface_idx,
            area,
            instance,
            interfaces,
            neighbors,
            lsa,
            src,
            received_as_multicast,
        );
    }

    flooded_back
}

fn flood_as<V>(
    instance: &mut InstanceUpView<'_, V>,
    areas: &Areas<V>,
    interfaces: &mut Arena<Interface<V>>,
    neighbors: &mut Arena<Neighbor<V>>,
    lsa: &Arc<Lsa<V>>,
    src: Option<(InterfaceIndex, NeighborIndex)>,
    received_as_multicast: bool,
) -> bool
where
    V: Version,
{
    let mut flooded_back = false;
    for area in areas
        .iter()
        // Check if the LSA type is valid for this area.
        .filter(|area| {
            V::lsa_type_is_valid(
                Some(area.config.area_type),
                None,
                None,
                lsa.hdr.lsa_type(),
            )
        })
    {
        flooded_back |= flood_area(
            area,
            instance,
            interfaces,
            neighbors,
            lsa,
            src,
            received_as_multicast,
        );
    }

    flooded_back
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
    use std::sync::OnceLock;
    use std::time::Duration;

    use holo_protocol::{InstanceChannelsTx, InstanceShared, ProtocolInstance};
    use holo_utils::ibus;
    use holo_utils::southbound::InterfaceFlags;
    use holo_utils::yang::ContextExt;
    use holo_yang::YANG_CTX;
    use ipnetwork::Ipv6Network;
    use tokio::sync::mpsc;
    use tokio::time::timeout;
    use yang5::context::Context;

    use super::*;
    use crate::area::BACKBONE_AREA_ID;
    use crate::collections::{AreaId, AreaIndex, InterfaceId};
    use crate::instance::Instance;
    use crate::network::{MulticastAddr, NetworkVersion};
    use crate::ospfv3::packet::iana::{LsaRouterFlags, Options};
    use crate::ospfv3::packet::lsa::{LsaBody, LsaRouter};
    use crate::packet::{LsUpdateVersion, Packet};
    use crate::tasks::messages::ProtocolOutputMsg;
    use crate::version::Ospfv3;
    use crate::{events, output};

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

    fn test_instance()
    -> (Instance<Ospfv3>, mpsc::Receiver<ProtocolOutputMsg<Ospfv3>>) {
        ensure_yang_ctx();

        let (nb_tx, _nb_rx) = mpsc::unbounded_channel();
        let (ibus_tx, _ibus_rx) = ibus::ibus_channels();
        let (proto_tx, _proto_rx) =
            <Instance<Ospfv3> as ProtocolInstance>::protocol_input_channels();
        let (protocol_output_tx, protocol_output_rx) = mpsc::channel(16);
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
        instance.config.router_id = Some(router_id(1));
        (instance, protocol_output_rx)
    }

    fn add_test_area(instance: &mut Instance<Ospfv3>) -> AreaIndex {
        instance.arenas.areas.insert(BACKBONE_AREA_ID).0
    }

    fn add_test_interface(
        instance: &mut Instance<Ospfv3>,
        area_idx: AreaIndex,
        name: &str,
        ifindex: u32,
        mdr_enabled: bool,
    ) -> (InterfaceIndex, AreaId, InterfaceId) {
        let area = &mut instance.arenas.areas[area_idx];
        let (iface_idx, iface) = area.interfaces.insert(
            &mut instance.arenas.interfaces,
            name.into(),
            None,
        );
        iface.system.ifindex = Some(ifindex);
        iface.system.mtu = Some(1500);
        iface.system.flags.insert(InterfaceFlags::OPERATIVE);
        iface.system.linklocal_addr =
            Some("fe80::1/64".parse::<Ipv6Network>().unwrap());
        iface.config.enabled = true;
        iface.config.if_type = InterfaceType::Broadcast;
        iface.config.mdr.enabled = mdr_enabled;
        iface.config.mdr.backup_wait_interval = Duration::from_millis(250);
        let area_id = area.id;
        let iface_id = iface.id;

        instance.update();
        if mdr_enabled {
            instance.arenas.interfaces[iface_idx].sync_mdr_state_from_config();
        }

        (iface_idx, area_id, iface_id)
    }

    fn add_neighbor(
        instance: &mut Instance<Ospfv3>,
        iface_idx: InterfaceIndex,
        router_id: Ipv4Addr,
        state: nsm::State,
        priority: u8,
        level: MdrLevel,
    ) -> NeighborIndex {
        let src = Ipv6Addr::new(
            0xfe80,
            0,
            0,
            0,
            0,
            0,
            0,
            u16::from(router_id.octets()[3]),
        );
        let (nbr_idx, nbr) = instance.arenas.interfaces[iface_idx]
            .state
            .neighbors
            .insert(&mut instance.arenas.neighbors, router_id, src);
        nbr.state = state;
        nbr.priority = priority;
        nbr.mdr.mdr_level = level;
        nbr_idx
    }

    fn router_id(octet: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, octet)
    }

    fn set_mdr_level(
        instance: &mut Instance<Ospfv3>,
        iface_idx: InterfaceIndex,
        level: MdrLevel,
    ) {
        let mdr = instance.arenas.interfaces[iface_idx]
            .state
            .mdr
            .as_mut()
            .expect("MDR state");
        mdr.mdr_level = level;
        mdr.non_flooding_mdr = false;
    }

    fn set_non_flooding_mdr(
        instance: &mut Instance<Ospfv3>,
        iface_idx: InterfaceIndex,
    ) {
        let mdr = instance.arenas.interfaces[iface_idx]
            .state
            .mdr
            .as_mut()
            .expect("MDR state");
        mdr.mdr_level = MdrLevel::Mdr;
        mdr.non_flooding_mdr = true;
    }

    fn area_lsa(seq_offset: u32, adv_router: Ipv4Addr) -> Arc<Lsa<Ospfv3>> {
        Arc::new(Lsa::new(
            0,
            Some(Options::V6 | Options::R),
            Ipv4Addr::UNSPECIFIED,
            adv_router,
            lsdb::LSA_INIT_SEQ_NO + seq_offset,
            LsaBody::Router(LsaRouter::new(
                false,
                LsaRouterFlags::empty(),
                Options::V6 | Options::R,
                vec![],
            )),
        ))
    }

    fn run_area_flood(
        instance: &mut Instance<Ospfv3>,
        area_idx: AreaIndex,
        lsa: &Arc<Lsa<Ospfv3>>,
        src: Option<(InterfaceIndex, NeighborIndex)>,
        received_as_multicast: bool,
    ) -> bool {
        let (mut instance_view, arenas) = instance.as_up().unwrap();
        flood(
            &mut instance_view,
            &arenas.areas,
            &mut arenas.interfaces,
            &mut arenas.neighbors,
            LsdbIndex::Area(area_idx),
            lsa,
            src,
            received_as_multicast,
        )
    }

    fn backup_wait_neighbors(
        instance: &Instance<Ospfv3>,
        iface_idx: InterfaceIndex,
        lsa: &Arc<Lsa<Ospfv3>>,
    ) -> BTreeSet<Ipv4Addr> {
        instance.arenas.interfaces[iface_idx]
            .state
            .mdr
            .as_ref()
            .and_then(|mdr| mdr.backup_wait.get(&lsa.hdr.key()))
            .map(|entry| entry.neighbors.clone())
            .unwrap_or_default()
    }

    fn backup_wait_timer_count(instance: &Instance<Ospfv3>) -> usize {
        instance
            .state
            .as_ref()
            .map(|state| state.mdr_backup_wait_timers.len())
            .unwrap_or_default()
    }

    /// Validates RFC 5614 §8.1 step 1(c), §8.1 step 2(c), and §8.4.
    ///
    /// The per-neighbor Acked-LSA cache records an acknowledged LSA instance,
    /// treats only same-or-newer cached instances as hits, expires by the
    /// configured retention interval, prunes older cached instances when a
    /// newer LSA is observed, and is naturally cleared with neighbor deletion.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/{8.1,8.4}.json
    #[tokio::test]
    async fn mdr_acked_lsa_cache_lifecycle_is_instance_aware() {
        let (mut instance, _rx) = test_instance();
        let area_idx = add_test_area(&mut instance);
        let (iface_idx, _, _) =
            add_test_interface(&mut instance, area_idx, "eth0", 1, true);
        let nbr_idx = add_neighbor(
            &mut instance,
            iface_idx,
            router_id(2),
            nsm::State::Full,
            1,
            MdrLevel::Mdr,
        );
        let timeout = instance.arenas.interfaces[iface_idx]
            .config
            .mdr
            .ack_cache_timeout;
        let now = Instant::now();
        let older = area_lsa(19, router_id(9));
        let lsa = area_lsa(20, router_id(9));
        let newer = area_lsa(21, router_id(9));

        {
            let nbr = &mut instance.arenas.neighbors[nbr_idx];
            mdr_store_acked_lsa(nbr, timeout, &lsa.hdr, now);
            assert!(mdr_neighbor_has_acked(nbr, timeout, &lsa.hdr, now));
            assert!(mdr_neighbor_has_acked(nbr, timeout, &older.hdr, now));
            assert!(!mdr_neighbor_has_acked(nbr, timeout, &newer.hdr, now));

            nbr.mdr
                .acked_lsas
                .get_mut(&lsa.hdr.key())
                .expect("cached ack")
                .received_at = now - timeout - Duration::from_secs(1);
            assert!(!mdr_neighbor_has_acked(nbr, timeout, &lsa.hdr, now));
            assert!(nbr.mdr.acked_lsas.is_empty());

            mdr_store_acked_lsa(nbr, timeout, &older.hdr, now);
            mdr_prune_acked_lsa_for_newer_instance(nbr, &newer.hdr);
            assert!(nbr.mdr.acked_lsas.is_empty());

            mdr_store_acked_lsa(nbr, timeout, &lsa.hdr, now);
            assert!(!nbr.mdr.acked_lsas.is_empty());
        }

        instance.arenas.interfaces[iface_idx]
            .state
            .neighbors
            .delete(&mut instance.arenas.neighbors, nbr_idx);
        assert!(
            instance.arenas.interfaces[iface_idx]
                .state
                .neighbors
                .get_by_router_id(&instance.arenas.neighbors, router_id(2))
                .is_none()
        );
    }

    /// Validates RFC 5614 §8.1 step 2(c) covered-neighbor suppression.
    ///
    /// A same-or-newer Acked-LSA cache hit prevents both relay and
    /// retransmission-list insertion for the covered neighbor; after the
    /// retention interval expires, the same flooding decision is no longer
    /// suppressed.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/{8.1,8.4}.json
    #[tokio::test]
    async fn mdr_acked_lsa_cache_suppresses_relay_only_until_expiry() {
        let (mut instance, _rx) = test_instance();
        let area_idx = add_test_area(&mut instance);
        let (iface_idx, _, _) =
            add_test_interface(&mut instance, area_idx, "eth0", 1, true);
        set_mdr_level(&mut instance, iface_idx, MdrLevel::Mdr);
        let src = add_neighbor(
            &mut instance,
            iface_idx,
            router_id(2),
            nsm::State::Full,
            1,
            MdrLevel::Other,
        );
        let target = add_neighbor(
            &mut instance,
            iface_idx,
            router_id(3),
            nsm::State::Full,
            1,
            MdrLevel::Other,
        );
        let lsa = area_lsa(22, router_id(2));
        let timeout = instance.arenas.interfaces[iface_idx]
            .config
            .mdr
            .ack_cache_timeout;
        let now = Instant::now();
        mdr_store_acked_lsa(
            &mut instance.arenas.neighbors[target],
            timeout,
            &lsa.hdr,
            now,
        );

        let flooded = run_area_flood(
            &mut instance,
            area_idx,
            &lsa,
            Some((iface_idx, src)),
            true,
        );

        assert!(!flooded);
        assert!(
            !instance.arenas.interfaces[iface_idx]
                .state
                .ls_update_list
                .contains_key(&lsa.hdr.key())
        );
        assert!(
            !instance.arenas.neighbors[target]
                .lists
                .ls_rxmt
                .contains_key(&lsa.hdr.key())
        );

        instance.arenas.neighbors[target]
            .mdr
            .acked_lsas
            .get_mut(&lsa.hdr.key())
            .expect("cached ack")
            .received_at = now - timeout - Duration::from_secs(1);
        let flooded = run_area_flood(
            &mut instance,
            area_idx,
            &lsa,
            Some((iface_idx, src)),
            true,
        );

        assert!(flooded);
        assert!(
            instance.arenas.interfaces[iface_idx]
                .state
                .ls_update_list
                .contains_key(&lsa.hdr.key())
        );
        assert!(
            instance.arenas.neighbors[target]
                .lists
                .ls_rxmt
                .contains_key(&lsa.hdr.key())
        );
    }

    async fn recv_lsupd(
        rx: &mut mpsc::Receiver<ProtocolOutputMsg<Ospfv3>>,
    ) -> crate::tasks::messages::output::NetTxPacketMsg<Ospfv3> {
        let msg = timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("timed out waiting for generated LSU")
            .expect("protocol output channel closed");
        let ProtocolOutputMsg::NetTxPacket(msg) = msg;
        let Packet::LsUpdate(_) = &msg.packet else {
            panic!("expected LS Update packet");
        };
        msg
    }

    /// Validates RFC 5614 §8.1 steps 2 and 5.
    ///
    /// A flooding MDR relays a multicast new LSA received on the same MANET
    /// interface when at least one bidirectional neighbor remains uncovered.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/{8.1,8.1.2}.json,
    /// rfcs/parsed/chunks/2328/13.3.json
    #[tokio::test]
    async fn mdr_flooding_mdr_relays_new_lsa() {
        let (mut instance, _rx) = test_instance();
        let area_idx = add_test_area(&mut instance);
        let (iface_idx, _, _) =
            add_test_interface(&mut instance, area_idx, "eth0", 1, true);
        set_mdr_level(&mut instance, iface_idx, MdrLevel::Mdr);
        let src = add_neighbor(
            &mut instance,
            iface_idx,
            router_id(2),
            nsm::State::Full,
            1,
            MdrLevel::Other,
        );
        let target = add_neighbor(
            &mut instance,
            iface_idx,
            router_id(3),
            nsm::State::Full,
            1,
            MdrLevel::Other,
        );
        let lsa = area_lsa(1, router_id(2));

        let flooded_back = run_area_flood(
            &mut instance,
            area_idx,
            &lsa,
            Some((iface_idx, src)),
            true,
        );

        assert!(flooded_back);
        assert!(
            instance.arenas.interfaces[iface_idx]
                .state
                .ls_update_list
                .contains_key(&lsa.hdr.key())
        );
        assert!(
            instance.arenas.neighbors[target]
                .lists
                .ls_rxmt
                .contains_key(&lsa.hdr.key())
        );
    }

    /// Validates RFC 5614 §8.1 step 3.
    ///
    /// An MDR Other does not relay a new LSA received on its MANET interface,
    /// while the standard retransmission list remains populated for adjacent
    /// uncovered neighbors.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/8.1.json,
    /// rfcs/parsed/chunks/2328/13.3.json
    #[tokio::test]
    async fn mdr_other_does_not_relay_same_interface_lsa() {
        let (mut instance, _rx) = test_instance();
        let area_idx = add_test_area(&mut instance);
        let (iface_idx, _, _) =
            add_test_interface(&mut instance, area_idx, "eth0", 1, true);
        set_mdr_level(&mut instance, iface_idx, MdrLevel::Other);
        let src = add_neighbor(
            &mut instance,
            iface_idx,
            router_id(2),
            nsm::State::Full,
            1,
            MdrLevel::Mdr,
        );
        let target = add_neighbor(
            &mut instance,
            iface_idx,
            router_id(3),
            nsm::State::Full,
            1,
            MdrLevel::Other,
        );
        let lsa = area_lsa(2, router_id(2));

        let flooded_back = run_area_flood(
            &mut instance,
            area_idx,
            &lsa,
            Some((iface_idx, src)),
            true,
        );

        assert!(!flooded_back);
        assert!(
            !instance.arenas.interfaces[iface_idx]
                .state
                .ls_update_list
                .contains_key(&lsa.hdr.key())
        );
        assert!(
            instance.arenas.neighbors[target]
                .lists
                .ls_rxmt
                .contains_key(&lsa.hdr.key())
        );
        assert!(backup_wait_neighbors(&instance, iface_idx, &lsa).is_empty());
    }

    /// Validates RFC 5614 §8.1 step 4 for Backup MDRs.
    ///
    /// A same-interface BMDR creates a BackupWait neighbor list instead of
    /// flooding immediately.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/{8.1,8.1.2}.json
    #[tokio::test]
    async fn mdr_backup_wait_for_same_interface_bmdr() {
        let (mut instance, _rx) = test_instance();
        let area_idx = add_test_area(&mut instance);
        let (iface_idx, _, _) =
            add_test_interface(&mut instance, area_idx, "eth0", 1, true);
        set_mdr_level(&mut instance, iface_idx, MdrLevel::Backup);
        let src = add_neighbor(
            &mut instance,
            iface_idx,
            router_id(2),
            nsm::State::Full,
            1,
            MdrLevel::Mdr,
        );
        add_neighbor(
            &mut instance,
            iface_idx,
            router_id(3),
            nsm::State::Full,
            1,
            MdrLevel::Other,
        );
        let lsa = area_lsa(3, router_id(2));

        run_area_flood(
            &mut instance,
            area_idx,
            &lsa,
            Some((iface_idx, src)),
            true,
        );

        assert_eq!(
            backup_wait_neighbors(&instance, iface_idx, &lsa),
            BTreeSet::from([router_id(3)])
        );
        assert_eq!(backup_wait_timer_count(&instance), 1);
        assert!(
            !instance.arenas.interfaces[iface_idx]
                .state
                .ls_update_list
                .contains_key(&lsa.hdr.key())
        );
    }

    /// Validates RFC 5614 §8.1 step 4 for non-flooding MDRs.
    ///
    /// A selected MDR marked non-flooding uses BackupWait, matching the NRL
    /// behavior and Rust oracle invariant.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/{8.1,8.1.2}.json
    #[tokio::test]
    async fn mdr_backup_wait_for_same_interface_non_flooding_mdr() {
        let (mut instance, _rx) = test_instance();
        let area_idx = add_test_area(&mut instance);
        let (iface_idx, _, _) =
            add_test_interface(&mut instance, area_idx, "eth0", 1, true);
        set_non_flooding_mdr(&mut instance, iface_idx);
        let src = add_neighbor(
            &mut instance,
            iface_idx,
            router_id(2),
            nsm::State::Full,
            1,
            MdrLevel::Mdr,
        );
        add_neighbor(
            &mut instance,
            iface_idx,
            router_id(3),
            nsm::State::Full,
            1,
            MdrLevel::Other,
        );
        let lsa = area_lsa(4, router_id(2));

        run_area_flood(
            &mut instance,
            area_idx,
            &lsa,
            Some((iface_idx, src)),
            true,
        );

        assert_eq!(
            backup_wait_neighbors(&instance, iface_idx, &lsa),
            BTreeSet::from([router_id(3)])
        );
        assert_eq!(backup_wait_timer_count(&instance), 1);
        assert!(
            !instance.arenas.interfaces[iface_idx]
                .state
                .ls_update_list
                .contains_key(&lsa.hdr.key())
        );
    }

    /// Validates RFC 5614 §8.1 step 2 covered-neighbor suppression.
    ///
    /// Covered-neighbor evidence from the multicast source suppresses relay
    /// without requiring Acked-LSA-cache state.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/8.1.json
    #[tokio::test]
    async fn mdr_covered_neighbor_suppresses_relay() {
        let (mut instance, _rx) = test_instance();
        let area_idx = add_test_area(&mut instance);
        let (iface_idx, _, _) =
            add_test_interface(&mut instance, area_idx, "eth0", 1, true);
        set_mdr_level(&mut instance, iface_idx, MdrLevel::Mdr);
        let src = add_neighbor(
            &mut instance,
            iface_idx,
            router_id(2),
            nsm::State::Full,
            1,
            MdrLevel::Mdr,
        );
        add_neighbor(
            &mut instance,
            iface_idx,
            router_id(3),
            nsm::State::Full,
            1,
            MdrLevel::Other,
        );
        instance.arenas.neighbors[src]
            .mdr
            .bidirectional_neighbors
            .insert(router_id(3));
        let lsa = area_lsa(5, router_id(2));

        let flooded_back = run_area_flood(
            &mut instance,
            area_idx,
            &lsa,
            Some((iface_idx, src)),
            true,
        );

        assert!(!flooded_back);
        assert!(
            !instance.arenas.interfaces[iface_idx]
                .state
                .ls_update_list
                .contains_key(&lsa.hdr.key())
        );
        assert!(backup_wait_neighbors(&instance, iface_idx, &lsa).is_empty());
    }

    /// Validates RFC 5614 §8.1.2 BackupWait expiry.
    ///
    /// Expiry floods when a listed neighbor remains bidirectional and has
    /// neither acknowledged through the Acked-LSA cache nor been removed by
    /// later covered-neighbor evidence.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/{8.1,8.1.2}.json
    #[tokio::test]
    async fn mdr_backup_wait_expiry_floods_when_still_needed() {
        let (mut instance, _rx) = test_instance();
        let area_idx = add_test_area(&mut instance);
        let (iface_idx, _, _) =
            add_test_interface(&mut instance, area_idx, "eth0", 1, true);
        set_mdr_level(&mut instance, iface_idx, MdrLevel::Backup);
        let src = add_neighbor(
            &mut instance,
            iface_idx,
            router_id(2),
            nsm::State::Full,
            1,
            MdrLevel::Mdr,
        );
        add_neighbor(
            &mut instance,
            iface_idx,
            router_id(3),
            nsm::State::Full,
            1,
            MdrLevel::Other,
        );
        let lsa = area_lsa(6, router_id(2));

        run_area_flood(
            &mut instance,
            area_idx,
            &lsa,
            Some((iface_idx, src)),
            true,
        );
        {
            let (mut instance_view, arenas) = instance.as_up().unwrap();
            expire_mdr_backup_wait(&mut instance_view, arenas, lsa.hdr.key())
                .unwrap();
        }

        assert!(backup_wait_neighbors(&instance, iface_idx, &lsa).is_empty());
        assert_eq!(backup_wait_timer_count(&instance), 0);
        assert!(
            instance.arenas.interfaces[iface_idx]
                .state
                .ls_update_list
                .contains_key(&lsa.hdr.key())
        );
    }

    /// Validates RFC 5614 §8.1.2 and §8.4 BackupWait interaction.
    ///
    /// A cached ACK from the pending neighbor before BackupWait expiry removes
    /// the need to flood on expiry; the pending list and per-LSA timer are
    /// cleared without enqueueing an LSU.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/{8.1.2,8.4}.json
    #[tokio::test]
    async fn mdr_backup_wait_ack_cache_before_expiry_cancels_flood() {
        let (mut instance, _rx) = test_instance();
        let area_idx = add_test_area(&mut instance);
        let (iface_idx, _, _) =
            add_test_interface(&mut instance, area_idx, "eth0", 1, true);
        set_mdr_level(&mut instance, iface_idx, MdrLevel::Backup);
        let src = add_neighbor(
            &mut instance,
            iface_idx,
            router_id(2),
            nsm::State::Full,
            1,
            MdrLevel::Mdr,
        );
        let target = add_neighbor(
            &mut instance,
            iface_idx,
            router_id(3),
            nsm::State::Full,
            1,
            MdrLevel::Other,
        );
        let lsa = area_lsa(23, router_id(2));

        run_area_flood(
            &mut instance,
            area_idx,
            &lsa,
            Some((iface_idx, src)),
            true,
        );
        assert_eq!(
            backup_wait_neighbors(&instance, iface_idx, &lsa),
            BTreeSet::from([router_id(3)])
        );

        let timeout = instance.arenas.interfaces[iface_idx]
            .config
            .mdr
            .ack_cache_timeout;
        mdr_store_acked_lsa(
            &mut instance.arenas.neighbors[target],
            timeout,
            &lsa.hdr,
            Instant::now(),
        );
        {
            let (mut instance_view, arenas) = instance.as_up().unwrap();
            expire_mdr_backup_wait(&mut instance_view, arenas, lsa.hdr.key())
                .unwrap();
        }

        assert!(backup_wait_neighbors(&instance, iface_idx, &lsa).is_empty());
        assert_eq!(backup_wait_timer_count(&instance), 0);
        assert!(
            !instance.arenas.interfaces[iface_idx]
                .state
                .ls_update_list
                .contains_key(&lsa.hdr.key())
        );
    }

    /// Validates RFC 5614 §8.1 BackupWait cancellation when coverage is later
    /// observed from a better relayer.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/8.1.json
    #[tokio::test]
    async fn mdr_backup_wait_cancels_when_neighbor_becomes_covered() {
        let (mut instance, _rx) = test_instance();
        let area_idx = add_test_area(&mut instance);
        let (iface_idx, _, _) =
            add_test_interface(&mut instance, area_idx, "eth0", 1, true);
        set_mdr_level(&mut instance, iface_idx, MdrLevel::Backup);
        let src = add_neighbor(
            &mut instance,
            iface_idx,
            router_id(2),
            nsm::State::Full,
            1,
            MdrLevel::Mdr,
        );
        add_neighbor(
            &mut instance,
            iface_idx,
            router_id(3),
            nsm::State::Full,
            1,
            MdrLevel::Other,
        );
        let lsa = area_lsa(7, router_id(2));

        run_area_flood(
            &mut instance,
            area_idx,
            &lsa,
            Some((iface_idx, src)),
            true,
        );
        instance.arenas.neighbors[src]
            .mdr
            .bidirectional_neighbors
            .insert(router_id(3));
        run_area_flood(
            &mut instance,
            area_idx,
            &lsa,
            Some((iface_idx, src)),
            true,
        );

        assert!(backup_wait_neighbors(&instance, iface_idx, &lsa).is_empty());
        assert_eq!(backup_wait_timer_count(&instance), 0);
        assert!(
            !instance.arenas.interfaces[iface_idx]
                .state
                .ls_update_list
                .contains_key(&lsa.hdr.key())
        );
    }

    /// Validates RFC 5614 §8.1 destination policy and §8.3 retransmission
    /// separation.
    ///
    /// MDR relays use AllSPFRouters multicast; retransmitted LSUs remain
    /// unicast to the neighbor.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/8.1.json,
    /// rfcs/parsed/chunks/5614/8.2.json
    #[tokio::test]
    async fn mdr_lsu_destination_policy_multicast_relay_unicast_retransmission()
    {
        let (mut instance, mut rx) = test_instance();
        let area_idx = add_test_area(&mut instance);
        let (iface_idx, _, _) =
            add_test_interface(&mut instance, area_idx, "eth0", 1, true);
        set_mdr_level(&mut instance, iface_idx, MdrLevel::Mdr);
        let src = add_neighbor(
            &mut instance,
            iface_idx,
            router_id(2),
            nsm::State::Full,
            1,
            MdrLevel::Other,
        );
        let target = add_neighbor(
            &mut instance,
            iface_idx,
            router_id(3),
            nsm::State::Full,
            1,
            MdrLevel::Other,
        );
        let lsa = area_lsa(8, router_id(2));

        run_area_flood(
            &mut instance,
            area_idx,
            &lsa,
            Some((iface_idx, src)),
            true,
        );
        {
            let (instance_view, arenas) = instance.as_up().unwrap();
            output::send_lsupd(
                None,
                &mut arenas.interfaces[iface_idx],
                &arenas.areas[area_idx],
                &instance_view,
                &mut arenas.neighbors,
            );
        }
        let relay = recv_lsupd(&mut rx).await;
        assert_eq!(relay.ifname, "eth0");
        assert_eq!(
            relay.dst.as_slice(),
            [*Ospfv3::multicast_addr(MulticastAddr::AllSpfRtrs)]
        );

        {
            let (instance_view, arenas) = instance.as_up().unwrap();
            output::rxmt_lsupd(
                &arenas.neighbors[target],
                &arenas.interfaces[iface_idx],
                &arenas.areas[area_idx],
                &instance_view,
            );
        }
        let retransmission = recv_lsupd(&mut rx).await;
        assert_eq!(
            retransmission.dst.as_slice(),
            [instance.arenas.neighbors[target].src]
        );
    }

    /// Validates RFC 5614 §8.1 step 6(b).
    ///
    /// An LSA received on another MANET interface creates BackupWait state on
    /// this outgoing MANET interface regardless of the local role when a common
    /// covered neighbor outranks the local router. The neighbor list is
    /// interface-local while the timer is per-LSA.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/{8.1,8.1.2}.json
    #[tokio::test]
    async fn mdr_cross_interface_step6b_backupwait_uses_one_timer_per_lsa() {
        let (mut instance, _rx) = test_instance();
        let area_idx = add_test_area(&mut instance);
        let (iface0_idx, _, _) =
            add_test_interface(&mut instance, area_idx, "eth0", 1, true);
        let (iface1_idx, _, _) =
            add_test_interface(&mut instance, area_idx, "eth1", 2, true);
        instance.arenas.interfaces[iface0_idx]
            .config
            .mdr
            .router_priority = 1;
        instance.arenas.interfaces[iface1_idx]
            .config
            .mdr
            .router_priority = 1;
        set_mdr_level(&mut instance, iface0_idx, MdrLevel::Other);
        set_mdr_level(&mut instance, iface1_idx, MdrLevel::Other);
        let src = add_neighbor(
            &mut instance,
            iface0_idx,
            router_id(2),
            nsm::State::Full,
            1,
            MdrLevel::Mdr,
        );
        add_neighbor(
            &mut instance,
            iface0_idx,
            router_id(4),
            nsm::State::Full,
            10,
            MdrLevel::Mdr,
        );
        add_neighbor(
            &mut instance,
            iface1_idx,
            router_id(4),
            nsm::State::Full,
            10,
            MdrLevel::Mdr,
        );
        add_neighbor(
            &mut instance,
            iface1_idx,
            router_id(5),
            nsm::State::Full,
            1,
            MdrLevel::Other,
        );
        instance.arenas.neighbors[src]
            .mdr
            .bidirectional_neighbors
            .insert(router_id(4));
        let lsa = area_lsa(9, router_id(2));

        run_area_flood(
            &mut instance,
            area_idx,
            &lsa,
            Some((iface0_idx, src)),
            true,
        );

        assert!(backup_wait_neighbors(&instance, iface0_idx, &lsa).is_empty());
        assert_eq!(
            backup_wait_neighbors(&instance, iface1_idx, &lsa),
            BTreeSet::from([router_id(5)])
        );
        assert_eq!(backup_wait_timer_count(&instance), 1);
    }

    /// Pins standard non-MDR flooding behavior while the MDR branch is added.
    ///
    /// RFC chunks: rfcs/parsed/chunks/2328/13.3.json
    #[tokio::test]
    async fn non_mdr_broadcast_flooding_still_enqueues_interface_lsu() {
        let (mut instance, _rx) = test_instance();
        let area_idx = add_test_area(&mut instance);
        let (iface_idx, _, _) =
            add_test_interface(&mut instance, area_idx, "eth0", 1, false);
        instance.arenas.interfaces[iface_idx].state.ism_state = ism::State::Dr;
        let src = add_neighbor(
            &mut instance,
            iface_idx,
            router_id(2),
            nsm::State::Full,
            1,
            MdrLevel::Other,
        );
        add_neighbor(
            &mut instance,
            iface_idx,
            router_id(3),
            nsm::State::Full,
            1,
            MdrLevel::Other,
        );
        let lsa = area_lsa(10, router_id(2));

        let flooded_back = run_area_flood(
            &mut instance,
            area_idx,
            &lsa,
            Some((iface_idx, src)),
            true,
        );

        assert!(flooded_back);
        assert!(
            instance.arenas.interfaces[iface_idx]
                .state
                .ls_update_list
                .contains_key(&lsa.hdr.key())
        );
    }
}
