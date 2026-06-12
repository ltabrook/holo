//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque, hash_map};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use holo_utils::bier::{
    BierCfgEvent, BierEncapId, BierEncapsulationType, BierInBiftId, BiftId,
};
use holo_utils::ip::{AddressFamily, IpAddrKind, IpNetworkKind};
use holo_utils::mpls::Label;
use holo_utils::sr::{IgpAlgoType, Sid, SidLastHopBehavior, SrCfgEvent};
use ipnetwork::IpNetwork;
use itertools::Itertools;

use crate::area::{
    Area, AreaType, AreaVersion, BACKBONE_AREA_ID, OptionsLocation,
};
use crate::collections::{
    AreaIndex, Arena, InterfaceIndex, LsaEntryId, LsdbId, LsdbIndex, lsdb_get,
};
use crate::debug::LsaFlushReason;
use crate::error::Error;
use crate::instance::{InstanceArenas, InstanceUpView};
use crate::interface::{Interface, InterfaceType, ism};
use crate::lsdb::{
    self, LsaEntry, LsaOriginateEvent, LsdbVersion, MAX_LINK_METRIC,
};
use crate::neighbor::{Neighbor, nsm};
use crate::northbound::configuration::{MdrAdjConnectivity, MdrLsaFullness};
use crate::ospfv3::packet::iana::{
    LsaFunctionCode, LsaRouterFlags, LsaRouterLinkType, Options, PrefixOptions,
};
use crate::ospfv3::packet::lsa::{
    LsaBody, LsaHdr, LsaInterAreaPrefix, LsaInterAreaRouter,
    LsaIntraAreaPrefix, LsaIntraAreaPrefixEntry, LsaLink, LsaLinkPrefix,
    LsaNetwork, LsaRouter, LsaRouterInfo, LsaRouterLink, LsaScopeCode, LsaType,
    PrefixSid,
};
use crate::packet::iana::RouterInfoCaps;
use crate::packet::lsa::{
    Lsa, LsaHdrVersion, LsaKey, LsaScope, LsaTypeVersion, PrefixSidVersion,
};
use crate::packet::tlv::{
    BierEncapSubStlv, BierStlv, DynamicHostnameTlv, NodeAdminTagTlv,
    PrefixSidFlags, RouterInfoCapsTlv, SidLabelRangeTlv, SrAlgoTlv,
    SrLocalBlockTlv,
};
use crate::route::{SummaryNet, SummaryNetFlags, SummaryRtr};
use crate::version::Ospfv3;

// ===== impl Ospfv3 =====

impl LsdbVersion<Self> for Ospfv3 {
    fn lsa_type_is_valid(
        area_type: Option<AreaType>,
        if_type: Option<InterfaceType>,
        _nbr_options: Option<Options>,
        lsa_type: LsaType,
    ) -> bool {
        // Reject LSAs of unknown (reserved) scope.
        if lsa_type.scope() == LsaScope::Unknown {
            return false;
        }

        // Reject AS-scoped LSAs over virtual links.
        if let Some(if_type) = if_type
            && if_type == InterfaceType::VirtualLink
            && lsa_type.scope() == LsaScope::As
        {
            return false;
        }

        // Reject AS-scoped and type-4 summary LSAs (as per errata 3746 of RFC
        // 2328) on stub/NSSA areas.
        if let Some(area_type) = area_type
            && area_type != AreaType::Normal
            && (lsa_type.scope() == LsaScope::As
                || lsa_type.function_code_normalized()
                    == Some(LsaFunctionCode::InterAreaRouter))
        {
            return false;
        }

        true
    }

    fn lsa_is_self_originated(
        lsa: &Lsa<Self>,
        router_id: Ipv4Addr,
        _interfaces: &Arena<Interface<Self>>,
    ) -> bool {
        // For IPv6, self-originated LSAs are those LSAs whose Advertising
        // Router is equal to the router's own Router ID.
        lsa.hdr.adv_rtr == router_id
    }

    fn lsa_orig_event(
        instance: &InstanceUpView<'_, Self>,
        arenas: &InstanceArenas<Self>,
        event: LsaOriginateEvent,
    ) -> Result<(), Error<Self>> {
        match event {
            LsaOriginateEvent::AreaStart { area_id } => {
                let (_, area) = arenas.areas.get_by_id(area_id)?;

                // Originate Router Information LSA(s).
                lsa_orig_router_info(area, instance);
            }
            LsaOriginateEvent::InterfaceStateChange { area_id, iface_id } => {
                // (Re)originate Router-LSA(s) in all areas since the ABR status
                // might have changed.
                for area in arenas.areas.iter() {
                    lsa_orig_router(area, instance, arenas);
                }

                // (Re)originate or flush Network-LSA.
                let (_, area) = arenas.areas.get_by_id(area_id)?;
                let (_, iface) =
                    area.interfaces.get_by_id(&arenas.interfaces, iface_id)?;
                if should_orig_network_lsa(iface, arenas) {
                    lsa_orig_network(iface, area, instance, arenas);
                } else {
                    lsa_flush_network(iface, area, instance, arenas);
                }

                // (Re)originate or flush Link-LSA.
                if iface.state.ism_state >= ism::State::Waiting {
                    lsa_orig_link(iface, area, instance);
                } else {
                    lsa_flush_link(iface, area, instance, arenas);
                }

                // (Re)originate Intra-area-prefix-LSA(s).
                lsa_orig_intra_area_prefix(area, instance, arenas);
            }
            LsaOriginateEvent::InterfaceDrChange { area_id, iface_id }
            | LsaOriginateEvent::GrHelperExit { area_id, iface_id } => {
                // (Re)originate Router-LSA(s).
                let (_, area) = arenas.areas.get_by_id(area_id)?;
                lsa_orig_router(area, instance, arenas);

                // (Re)originate or flush Network-LSA.
                let (_, iface) =
                    area.interfaces.get_by_id(&arenas.interfaces, iface_id)?;
                if should_orig_network_lsa(iface, arenas) {
                    lsa_orig_network(iface, area, instance, arenas);
                } else {
                    lsa_flush_network(iface, area, instance, arenas);
                }

                // (Re)originate Intra-area-prefix-LSA(s).
                lsa_orig_intra_area_prefix(area, instance, arenas);
            }
            LsaOriginateEvent::InterfaceAddrAddDel { area_id, iface_id } => {
                let (_, area) = arenas.areas.get_by_id(area_id)?;
                let (_, iface) =
                    area.interfaces.get_by_id(&arenas.interfaces, iface_id)?;

                // (Re)originate or flush Link-LSA.
                if iface.state.ism_state >= ism::State::Waiting {
                    lsa_orig_link(iface, area, instance);
                } else {
                    lsa_flush_link(iface, area, instance, arenas);
                }

                // (Re)originate Intra-area-prefix-LSA(s).
                lsa_orig_intra_area_prefix(area, instance, arenas);
            }
            LsaOriginateEvent::InterfaceCostChange { area_id } => {
                let (_, area) = arenas.areas.get_by_id(area_id)?;

                // (Re)originate Router-LSA(s).
                lsa_orig_router(area, instance, arenas);

                // (Re)originate Intra-area-prefix-LSA(s).
                lsa_orig_intra_area_prefix(area, instance, arenas);
            }
            LsaOriginateEvent::InterfaceFlagChange { area_id } => {
                let (_, area) = arenas.areas.get_by_id(area_id)?;

                // (Re)originate Intra-area-prefix-LSA(s).
                lsa_orig_intra_area_prefix(area, instance, arenas);
            }
            LsaOriginateEvent::NeighborToFromFull { area_id, iface_id } => {
                // (Re)originate Router-LSA(s).
                let (_, area) = arenas.areas.get_by_id(area_id)?;
                lsa_orig_router(area, instance, arenas);

                // (Re)originate Network-LSA.
                let (_, iface) =
                    area.interfaces.get_by_id(&arenas.interfaces, iface_id)?;
                if should_orig_network_lsa(iface, arenas) {
                    lsa_orig_network(iface, area, instance, arenas);
                } else {
                    lsa_flush_network(iface, area, instance, arenas);
                }

                // (Re)originate Intra-area-prefix-LSA(s).
                lsa_orig_intra_area_prefix(area, instance, arenas);

                // For virtual links, reoriginate the Router-LSA in the
                // associated transit area.
                if let Some(vlink_key) = &iface.vlink_key
                    && let Some((_, transit_area)) =
                        arenas.areas.get_by_area_id(vlink_key.transit_area_id)
                {
                    lsa_orig_router(transit_area, instance, arenas);
                }
            }
            LsaOriginateEvent::NeighborTwoWayOrHigherChange {
                area_id, ..
            } => {
                // (Re)originate Router-LSA(s).
                let (_, area) = arenas.areas.get_by_id(area_id)?;
                lsa_orig_router(area, instance, arenas);
            }

            LsaOriginateEvent::NeighborInterfaceIdChange {
                area_id, ..
            } => {
                // (Re)originate Router-LSA(s).
                let (_, area) = arenas.areas.get_by_id(area_id)?;
                lsa_orig_router(area, instance, arenas);
            }
            LsaOriginateEvent::VirtualLinkChange => {
                // (Re)originate Router-LSA in the backbone area.
                if let Some((_, backbone)) =
                    arenas.areas.get_by_area_id(BACKBONE_AREA_ID)
                {
                    lsa_orig_router(backbone, instance, arenas);
                }
            }
            LsaOriginateEvent::LinkLsaRcvd { area_id, iface_id } => {
                let (_, area) = arenas.areas.get_by_id(area_id)?;
                let (_, iface) =
                    area.interfaces.get_by_id(&arenas.interfaces, iface_id)?;
                if should_orig_network_lsa(iface, arenas) {
                    // (Re)originate Network-LSA.
                    lsa_orig_network(iface, area, instance, arenas);

                    // (Re)originate Intra-area-prefix-LSA(s).
                    lsa_orig_intra_area_prefix(area, instance, arenas);
                }
            }
            LsaOriginateEvent::SelfOriginatedLsaRcvd { lsdb_id, lse_id } => {
                // Check if the received self-originated LSA needs to be
                // reoriginated or flushed.
                process_self_originated_lsa(instance, arenas, lsdb_id, lse_id)?;
            }
            LsaOriginateEvent::StubRouterChange => {
                // (Re)originate Router-LSA(s) in all areas.
                for area in arenas.areas.iter() {
                    lsa_orig_router(area, instance, arenas);
                }
            }
            LsaOriginateEvent::GrHelperChange => {
                // (Re)originate Router Information LSA(s) in all areas.
                for area in arenas.areas.iter() {
                    lsa_orig_router_info(area, instance);
                }
            }
            LsaOriginateEvent::SrEnableChange => {
                // Reoriginate Router Information LSA(s) and
                // Intra-area-prefix-LSA(s) in all areas.
                for area in arenas.areas.iter() {
                    lsa_orig_router_info(area, instance);
                    lsa_orig_intra_area_prefix(area, instance, arenas);
                }
            }
            LsaOriginateEvent::SrCfgChange { change } => {
                match change {
                    SrCfgEvent::LabelRangeUpdate => {
                        // Reoriginate Router Information LSA(s) in all areas.
                        for area in arenas.areas.iter() {
                            lsa_orig_router_info(area, instance);
                        }
                    }
                    SrCfgEvent::PrefixSidUpdate(af) => {
                        if af == instance.state.af {
                            // (Re)originate Intra-area-prefix-LSA(s) in all
                            // areas.
                            for area in arenas.areas.iter() {
                                lsa_orig_intra_area_prefix(
                                    area, instance, arenas,
                                );
                            }
                        }
                    }
                }
            }
            LsaOriginateEvent::HostnameChange
            | LsaOriginateEvent::NodeTagsChange => {
                // (Re)originate Router-Info-LSA(s) in all areas.
                for area in arenas.areas.iter() {
                    lsa_orig_router_info(area, instance);
                }
            }
            LsaOriginateEvent::BierEnableChange => {
                // Reoriginate Intra-area-prefix-LSA(s) in all areas.
                for area in arenas.areas.iter() {
                    lsa_orig_intra_area_prefix(area, instance, arenas);
                }
            }
            LsaOriginateEvent::BierCfgChange { change } => match change {
                BierCfgEvent::EncapUpdate(af)
                | BierCfgEvent::SubDomainUpdate(af) => {
                    if af == instance.state.af {
                        for area in arenas.areas.iter() {
                            // Reoriginate Intra-area-prefix-LSA(s) in all areas.
                            lsa_orig_intra_area_prefix(area, instance, arenas);
                        }
                    }
                }
            },
        };

        Ok(())
    }

    fn lsa_orig_inter_area_network(
        area: &mut Area<Self>,
        instance: &InstanceUpView<'_, Self>,
        prefix: IpNetwork,
        lsa_id: Option<u32>,
        summary: &SummaryNet<Self>,
    ) -> u32 {
        let lsdb_id = LsdbId::Area(area.id);
        let extended_lsa = instance.config.extended_lsa;

        // Get LSA-ID.
        let lsa_id = lsa_id.unwrap_or_else(|| {
            area.state.version.next_type3_lsa_id += 1;
            area.state.version.next_type3_lsa_id
        });

        // Get SR Prefix-SIDs.
        let mut prefix_sids = BTreeMap::new();
        if let Some(mut prefix_sid) = summary.prefix_sid {
            // For non-connected prefixes, disable Prefix-SID PHP to ensure
            // end-to-end MPLS forwarding.
            if !summary.flags.contains(SummaryNetFlags::CONNECTED) {
                let flags = prefix_sid.flags_mut();
                flags.insert(PrefixSidFlags::NP);
                flags.remove(PrefixSidFlags::E);
            }

            prefix_sids.insert(IgpAlgoType::Spf, prefix_sid);
        }

        // (Re)originate Inter-Area-Network-LSA.
        let lsa_body = LsaBody::InterAreaPrefix(LsaInterAreaPrefix::new(
            extended_lsa,
            summary.metric,
            summary.prefix_options,
            prefix,
            prefix_sids,
        ));
        instance.tx.protocol_input.lsa_orig_check(
            lsdb_id,
            None,
            lsa_id.into(),
            lsa_body,
        );

        lsa_id
    }

    fn lsa_orig_inter_area_router(
        area: &mut Area<Self>,
        instance: &InstanceUpView<'_, Self>,
        router_id: Ipv4Addr,
        lsa_id: Option<u32>,
        summary: &SummaryRtr<Self>,
    ) -> u32 {
        let lsdb_id = LsdbId::Area(area.id);
        let extended_lsa = instance.config.extended_lsa;

        // Get LSA-ID.
        let lsa_id = lsa_id.unwrap_or_else(|| {
            area.state.version.next_type4_lsa_id += 1;
            area.state.version.next_type4_lsa_id
        });

        // (Re)originate Inter-Area-Router-LSA.
        let lsa_body = LsaBody::InterAreaRouter(LsaInterAreaRouter::new(
            extended_lsa,
            summary.options,
            summary.metric,
            router_id,
        ));
        instance.tx.protocol_input.lsa_orig_check(
            lsdb_id,
            None,
            lsa_id.into(),
            lsa_body,
        );

        lsa_id
    }

    fn lsdb_get_by_lsa_type(
        iface_idx: InterfaceIndex,
        area_idx: AreaIndex,
        lsa_type: LsaType,
    ) -> LsdbIndex {
        match lsa_type.scope() {
            LsaScope::Link => LsdbIndex::Link(area_idx, iface_idx),
            LsaScope::Area => {
                if lsa_type.function_code().is_none() && !lsa_type.u_bit() {
                    LsdbIndex::Link(area_idx, iface_idx)
                } else {
                    LsdbIndex::Area(area_idx)
                }
            }
            LsaScope::As => {
                if lsa_type.function_code().is_none() && !lsa_type.u_bit() {
                    LsdbIndex::Link(area_idx, iface_idx)
                } else {
                    LsdbIndex::As
                }
            }
            LsaScope::Unknown => {
                unreachable!();
            }
        }
    }

    fn lsdb_install(
        instance: &mut InstanceUpView<'_, Self>,
        arenas: &mut InstanceArenas<Self>,
        _lsdb_idx: LsdbIndex,
        lsdb_id: LsdbId,
        lsa: &Lsa<Self>,
    ) {
        // (Re)originate LSAs that might have been affected.
        if let LsdbId::Link(area_id, iface_id) = lsdb_id
            && lsa.hdr.lsa_type().function_code_normalized()
                == Some(LsaFunctionCode::Link)
        {
            instance.tx.protocol_input.lsa_orig_event(
                LsaOriginateEvent::LinkLsaRcvd { area_id, iface_id },
            );
        }
        if let LsdbId::Area(area_id) = lsdb_id
            && lsa.hdr.lsa_type().function_code_normalized()
                == Some(LsaFunctionCode::Router)
            && let Ok((_, area)) = arenas.areas.get_by_id(area_id)
        {
            for iface in area
                .interfaces
                .iter(&arenas.interfaces)
                .filter(|iface| iface.is_mdr_enabled())
            {
                instance.tx.protocol_input.lsa_orig_event(
                    LsaOriginateEvent::NeighborTwoWayOrHigherChange {
                        area_id,
                        iface_id: iface.id,
                    },
                );
            }
        }

        // Check for DynamicHostnameTlv
        if lsa.hdr.lsa_type.function_code_normalized()
            == Some(LsaFunctionCode::RouterInfo)
            && let LsaBody::RouterInfo(router_info) = &lsa.body
        {
            if let Some(hostname_tlv) = router_info.info_hostname.as_ref() {
                instance
                    .state
                    .hostnames
                    .insert(lsa.hdr.adv_rtr, hostname_tlv.hostname.clone());
            } else {
                instance.state.hostnames.remove(&lsa.hdr.adv_rtr);
            }
        }
    }
}

// ===== helper functions =====

fn lsa_orig_router(
    area: &Area<Ospfv3>,
    instance: &InstanceUpView<'_, Ospfv3>,
    arenas: &InstanceArenas<Ospfv3>,
) {
    let lsdb_id = LsdbId::Area(area.id);
    let extended_lsa = instance.config.extended_lsa;

    // Router-LSA's options.
    let options = Ospfv3::area_options(area, OptionsLocation::Lsa);

    // Router-LSA's flags.
    let mut flags = LsaRouterFlags::empty();
    if arenas.areas.is_abr(&arenas.interfaces) {
        flags.insert(LsaRouterFlags::B);
    }
    if lsdb::router_lsa_v_bit(area, arenas) {
        flags.insert(LsaRouterFlags::V);
    }

    // Router-LSA's links.
    let mut links = vec![];
    for iface in area
        .interfaces
        .iter(&arenas.interfaces)
        // Skip interfaces in the "Down" or "Loopback" states.
        .filter(|iface| {
            !matches!(
                iface.state.ism_state,
                ism::State::Down | ism::State::Loopback,
            )
        })
        // Skip interfaces without any full adjacencies.
        .filter(|iface| interface_has_full_neighbors(iface, arenas))
    {
        let ifindex = iface.system.ifindex.unwrap();

        // When stub-router is configured (RFC 6987), set the cost of all
        // links to MaxLinkMetric.
        let cost = if instance.config.stub_router {
            MAX_LINK_METRIC
        } else {
            iface.config.cost
        };

        if iface.is_mdr_enabled() {
            let advertised_neighbors = mdr_router_lsa_advertised_neighbors(
                iface,
                area,
                instance,
                &arenas.neighbors,
                &arenas.lsa_entries,
            );

            for nbr in iface
                .state
                .neighbors
                .iter(&arenas.neighbors)
                .filter(|nbr| advertised_neighbors.contains(&nbr.router_id))
            {
                let Some(nbr_iface_id) =
                    nbr.mdr.remote_interface_id.or(nbr.iface_id)
                else {
                    continue;
                };
                let link = LsaRouterLink::new(
                    LsaRouterLinkType::PointToPoint,
                    mdr_router_lsa_link_metric(nbr, cost),
                    ifindex,
                    nbr_iface_id,
                    nbr.router_id,
                    nbr.adj_sids.clone(),
                );
                links.push(link);
            }
            continue;
        }

        match iface.config.if_type {
            InterfaceType::PointToPoint | InterfaceType::PointToMultipoint => {
                // Add a Type-1 link (p2p) for each fully adjacent neighbor.
                for nbr in iface
                    .state
                    .neighbors
                    .iter(&arenas.neighbors)
                    .filter(|nbr| nbr.state == nsm::State::Full)
                {
                    let link = LsaRouterLink::new(
                        LsaRouterLinkType::PointToPoint,
                        cost,
                        ifindex,
                        nbr.iface_id.unwrap(),
                        nbr.router_id,
                        nbr.adj_sids.clone(),
                    );
                    links.push(link);
                }
            }
            InterfaceType::Broadcast | InterfaceType::NonBroadcast => {
                let (dr_router_id, dr_iface_id) = if iface.state.ism_state
                    == ism::State::Dr
                {
                    // The router itself is the DR.
                    (instance.state.router_id, ifindex)
                } else {
                    match iface.state.dr.and_then(|net_id| {
                        iface
                            .state
                            .neighbors
                            .get_by_net_id(&arenas.neighbors, net_id)
                            .filter(|(_, nbr)| nbr.state == nsm::State::Full)
                    }) {
                        Some((_, nbr)) => {
                            // The router is fully adjacent to the DR.
                            (nbr.router_id, nbr.iface_id.unwrap())
                        }
                        None => continue,
                    }
                };

                // Add a Type-2 (transit) link.
                let adj_sids = iface
                    .state
                    .neighbors
                    .iter(&arenas.neighbors)
                    .flat_map(|nbr| nbr.adj_sids.iter())
                    .copied()
                    .collect();
                let link = LsaRouterLink::new(
                    LsaRouterLinkType::TransitNetwork,
                    cost,
                    ifindex,
                    dr_iface_id,
                    dr_router_id,
                    adj_sids,
                );
                links.push(link);
            }
            InterfaceType::VirtualLink => {
                if let Some(nbr) =
                    iface.state.neighbors.iter(&arenas.neighbors).next()
                    && nbr.state == nsm::State::Full
                {
                    let vlink_state = iface.state.vlink.as_ref().unwrap();
                    let link = LsaRouterLink::new(
                        LsaRouterLinkType::VirtualLink,
                        vlink_state.cost as u16,
                        ifindex,
                        nbr.iface_id.unwrap(),
                        nbr.router_id,
                        Default::default(),
                    );
                    links.push(link);
                }
            }
        }
    }

    // Originate as many Router-LSAs as necessary.
    let mut lsa_id: u32 = 0;
    let mut originate_fn = |links| {
        let lsa_body = LsaBody::Router(LsaRouter::new(
            extended_lsa,
            flags,
            options,
            links,
        ));

        // (Re)originate Router-LSA.
        instance.tx.protocol_input.lsa_orig_check(
            lsdb_id,
            None,
            lsa_id.into(),
            lsa_body,
        );

        // Increment the LSA-ID.
        lsa_id += 1;
    };
    if links.is_empty() {
        originate_fn(links);
    } else {
        for links in links
            .into_iter()
            .chunks(
                (Lsa::<Ospfv3>::MAX_LENGTH
                    - LsaHdr::LENGTH as usize
                    - LsaRouter::BASE_LENGTH as usize)
                    / LsaRouterLink::max_length(extended_lsa),
            )
            .into_iter()
        {
            originate_fn(links.collect());
        }
    }

    // Flush self-originated Router-LSAs that are no longer needed.
    for (_, lse) in area
        .state
        .lsdb
        .iter_by_type_advrtr(
            &arenas.lsa_entries,
            LsaRouter::lsa_type(extended_lsa),
            instance.state.router_id,
        )
        .filter(|(_, lse)| lse.data.hdr.lsa_id >= Ipv4Addr::from(lsa_id))
    {
        lsa_flush(instance, lsdb_id, lse.id);
    }
}

fn interface_has_full_neighbors(
    iface: &Interface<Ospfv3>,
    arenas: &InstanceArenas<Ospfv3>,
) -> bool {
    iface
        .state
        .neighbors
        .iter(&arenas.neighbors)
        .any(|nbr| nbr.state == nsm::State::Full)
}

#[derive(Default)]
struct MdrNeighborLsaState {
    selected_advertised: BTreeSet<Ipv4Addr>,
    routable: BTreeSet<Ipv4Addr>,
}

pub(crate) fn mdr_refresh_interface_lsa_state(
    iface: &mut Interface<Ospfv3>,
    area: &Area<Ospfv3>,
    instance: &InstanceUpView<'_, Ospfv3>,
    lsa_entries: &Arena<LsaEntry<Ospfv3>>,
    neighbors: &mut Arena<Neighbor<Ospfv3>>,
) -> bool {
    if !iface.is_mdr_enabled() {
        return false;
    }

    let lsa_state =
        mdr_neighbor_lsa_state(iface, area, instance, neighbors, lsa_entries);
    let mut changed = false;
    for nbr_idx in iface.state.neighbors.indexes().collect::<Vec<_>>() {
        let nbr = &mut neighbors[nbr_idx];
        let selected = lsa_state.selected_advertised.contains(&nbr.router_id);
        let routable = lsa_state.routable.contains(&nbr.router_id);
        if nbr.mdr.selected_advertised != selected {
            nbr.mdr.selected_advertised = selected;
            changed = true;
        }
        if nbr.mdr.routable != routable {
            nbr.mdr.routable = routable;
            changed = true;
        }
    }

    if changed && let Some(mdr) = &mut iface.state.mdr {
        mdr.lsa_reevaluation_pending = true;
    }
    changed
}

fn mdr_router_lsa_advertised_neighbors(
    iface: &Interface<Ospfv3>,
    area: &Area<Ospfv3>,
    instance: &InstanceUpView<'_, Ospfv3>,
    neighbors: &Arena<Neighbor<Ospfv3>>,
    lsa_entries: &Arena<LsaEntry<Ospfv3>>,
) -> BTreeSet<Ipv4Addr> {
    let Some(mdr) = &iface.state.mdr else {
        return BTreeSet::new();
    };
    if mdr.config.lsa_fullness == MdrLsaFullness::SingleHopFull {
        return mdr_rfc7038_single_hop_full_advertised_neighbors(
            iface,
            area,
            instance,
            neighbors,
            lsa_entries,
        );
    }

    let local_router_id = instance.state.router_id;
    let lsa_state =
        mdr_neighbor_lsa_state(iface, area, instance, neighbors, lsa_entries);
    iface
        .state
        .neighbors
        .iter(neighbors)
        .filter(|nbr| {
            mdr_router_lsa_should_advertise_neighbor(
                iface,
                nbr,
                &lsa_state,
                local_router_id,
            )
        })
        .map(|nbr| nbr.router_id)
        .collect()
}

fn mdr_neighbor_lsa_state(
    iface: &Interface<Ospfv3>,
    area: &Area<Ospfv3>,
    instance: &InstanceUpView<'_, Ospfv3>,
    neighbors: &Arena<Neighbor<Ospfv3>>,
    lsa_entries: &Arena<LsaEntry<Ospfv3>>,
) -> MdrNeighborLsaState {
    MdrNeighborLsaState {
        selected_advertised: mdr_selected_advertised_neighbors(
            iface, instance, neighbors,
        ),
        routable: mdr_routable_neighbors(
            iface,
            area,
            instance,
            neighbors,
            lsa_entries,
        ),
    }
}

fn mdr_effective_lsa_fullness(
    iface: &Interface<Ospfv3>,
) -> Option<MdrLsaFullness> {
    let mdr = iface.state.mdr.as_ref()?;
    Some(match mdr.config.lsa_fullness {
        MdrLsaFullness::MdrFull if mdr.mdr_level.is_dr_or_backup() => {
            MdrLsaFullness::Full
        }
        MdrLsaFullness::MdrFull => MdrLsaFullness::Minimal,
        fullness => fullness,
    })
}

fn mdr_selected_advertised_neighbors(
    iface: &Interface<Ospfv3>,
    instance: &InstanceUpView<'_, Ospfv3>,
    neighbors: &Arena<Neighbor<Ospfv3>>,
) -> BTreeSet<Ipv4Addr> {
    match mdr_effective_lsa_fullness(iface) {
        Some(MdrLsaFullness::Minimal) => BTreeSet::new(),
        Some(MdrLsaFullness::MinCost) => {
            mdr_min_cost_selected_advertised_neighbors(
                iface, instance, neighbors, 1,
            )
        }
        Some(MdrLsaFullness::MinCost2Paths) => {
            mdr_min_cost_selected_advertised_neighbors(
                iface, instance, neighbors, 2,
            )
        }
        Some(MdrLsaFullness::Full | MdrLsaFullness::SingleHopFull) => iface
            .state
            .neighbors
            .iter(neighbors)
            .filter(|nbr| nbr.state >= nsm::State::TwoWay && !nbr.mdr.backbone)
            .map(|nbr| nbr.router_id)
            .collect(),
        Some(MdrLsaFullness::MdrFull) | None => BTreeSet::new(),
    }
}

fn mdr_routable_neighbors(
    iface: &Interface<Ospfv3>,
    area: &Area<Ospfv3>,
    instance: &InstanceUpView<'_, Ospfv3>,
    neighbors: &Arena<Neighbor<Ospfv3>>,
    lsa_entries: &Arena<LsaEntry<Ospfv3>>,
) -> BTreeSet<Ipv4Addr> {
    let Some(mdr) = &iface.state.mdr else {
        return BTreeSet::new();
    };
    if mdr.config.adj_connectivity == MdrAdjConnectivity::Full
        || mdr.config.lsa_fullness == MdrLsaFullness::SingleHopFull
        || instance.state.router_id.is_unspecified()
    {
        return BTreeSet::new();
    }

    let candidate_neighbors = iface
        .state
        .neighbors
        .iter(neighbors)
        .filter(|nbr| nbr.state >= nsm::State::TwoWay && nbr.mdr.reverse_2way)
        .map(|nbr| nbr.router_id)
        .collect::<BTreeSet<_>>();
    let full_neighbors = iface
        .state
        .neighbors
        .iter(neighbors)
        .filter(|nbr| nbr.state == nsm::State::Full)
        .map(|nbr| nbr.router_id)
        .collect::<BTreeSet<_>>();

    let mut routable = BTreeSet::new();
    for _ in 0..2 {
        let mut root_neighbors = full_neighbors.clone();
        root_neighbors.extend(routable.iter().copied());

        let reachable = mdr_root_reachable_router_ids(
            area,
            lsa_entries,
            instance.config.extended_lsa,
            &root_neighbors,
        );
        let updated = candidate_neighbors
            .iter()
            .copied()
            .filter(|router_id| reachable.contains(router_id))
            .collect::<BTreeSet<_>>();
        if updated == routable {
            break;
        }
        routable = updated;
    }

    routable
}

fn mdr_root_reachable_router_ids(
    area: &Area<Ospfv3>,
    lsa_entries: &Arena<LsaEntry<Ospfv3>>,
    extended_lsa: bool,
    root_neighbors: &BTreeSet<Ipv4Addr>,
) -> BTreeSet<Ipv4Addr> {
    let mut link_graph = BTreeMap::<Ipv4Addr, BTreeSet<Ipv4Addr>>::new();
    for (_, lse) in area
        .state
        .lsdb
        .iter_by_type(lsa_entries, LsaRouter::lsa_type(extended_lsa))
    {
        let LsaBody::Router(router) = &lse.data.body else {
            continue;
        };
        let router_links = link_graph.entry(lse.data.hdr.adv_rtr).or_default();
        router_links.extend(
            router
                .links
                .iter()
                .filter(|link| {
                    link.link_type == LsaRouterLinkType::PointToPoint
                })
                .map(|link| link.nbr_router_id),
        );
    }

    let mut reachable = root_neighbors.clone();
    let mut queue = root_neighbors.iter().copied().collect::<VecDeque<_>>();
    while let Some(current) = queue.pop_front() {
        let Some(router_links) = link_graph.get(&current) else {
            continue;
        };
        for neighbor_id in router_links {
            if reachable.contains(neighbor_id) {
                continue;
            }
            let Some(reverse_links) = link_graph.get(neighbor_id) else {
                continue;
            };
            if !reverse_links.contains(&current) {
                continue;
            }
            reachable.insert(*neighbor_id);
            queue.push_back(*neighbor_id);
        }
    }

    reachable
}

fn mdr_router_lsa_should_advertise_neighbor(
    iface: &Interface<Ospfv3>,
    nbr: &Neighbor<Ospfv3>,
    lsa_state: &MdrNeighborLsaState,
    local_router_id: Ipv4Addr,
) -> bool {
    if nbr.state < nsm::State::TwoWay {
        return false;
    }

    let selected_by_local =
        lsa_state.selected_advertised.contains(&nbr.router_id);
    let selected_by_neighbor = nbr
        .mdr
        .selected_advertised_neighbors
        .contains(&local_router_id);
    let backbone = nbr.mdr.backbone;

    if iface.state.mdr.as_ref().is_some_and(|mdr| {
        mdr.config.adj_connectivity == MdrAdjConnectivity::Full
    }) {
        return nbr.state == nsm::State::Full
            && (selected_by_local || selected_by_neighbor || backbone);
    }

    if nbr.state == nsm::State::Full {
        return true;
    }
    lsa_state.routable.contains(&nbr.router_id)
        && (selected_by_local || selected_by_neighbor || backbone)
}

fn mdr_rfc7038_single_hop_full_advertised_neighbors(
    iface: &Interface<Ospfv3>,
    area: &Area<Ospfv3>,
    instance: &InstanceUpView<'_, Ospfv3>,
    neighbors: &Arena<Neighbor<Ospfv3>>,
    lsa_entries: &Arena<LsaEntry<Ospfv3>>,
) -> BTreeSet<Ipv4Addr> {
    let mut advertised = iface
        .state
        .neighbors
        .iter(neighbors)
        .filter(|nbr| nbr.state == nsm::State::Full)
        .map(|nbr| nbr.router_id)
        .collect::<BTreeSet<_>>();
    let Some(mdr) = iface.state.mdr.as_ref() else {
        return advertised;
    };
    if mdr.mdr_level == crate::ospfv3::mdr::MdrLevel::Mdr {
        return advertised;
    }

    let Some(mdr_router_id) = mdr.parent else {
        return advertised;
    };
    let Some((_, mdr_nbr)) = iface
        .state
        .neighbors
        .get_by_router_id(neighbors, mdr_router_id)
    else {
        return advertised;
    };
    if mdr_nbr.state != nsm::State::Full {
        return advertised;
    }

    let mdr_links = mdr_router_lsa_linked_neighbors(
        area,
        lsa_entries,
        instance.config.extended_lsa,
        mdr_router_id,
    );
    advertised.extend(
        iface
            .state
            .neighbors
            .iter(neighbors)
            .filter(|nbr| nbr.state >= nsm::State::TwoWay)
            .filter(|nbr| mdr_links.contains(&nbr.router_id))
            .map(|nbr| nbr.router_id),
    );
    advertised
}

fn mdr_router_lsa_linked_neighbors(
    area: &Area<Ospfv3>,
    lsa_entries: &Arena<LsaEntry<Ospfv3>>,
    extended_lsa: bool,
    adv_router: Ipv4Addr,
) -> BTreeSet<Ipv4Addr> {
    area.state
        .lsdb
        .iter_by_type_advrtr(
            lsa_entries,
            LsaRouter::lsa_type(extended_lsa),
            adv_router,
        )
        .filter_map(|(_, lse)| match &lse.data.body {
            LsaBody::Router(router) => Some(router),
            _ => None,
        })
        .flat_map(|router| router.links.iter())
        .filter(|link| link.link_type == LsaRouterLinkType::PointToPoint)
        .map(|link| link.nbr_router_id)
        .collect()
}

fn mdr_min_cost_selected_advertised_neighbors(
    iface: &Interface<Ospfv3>,
    instance: &InstanceUpView<'_, Ospfv3>,
    neighbors: &Arena<Neighbor<Ospfv3>>,
    required_relay_count: usize,
) -> BTreeSet<Ipv4Addr> {
    let local_router_id = instance.state.router_id;
    if local_router_id.is_unspecified() {
        return BTreeSet::new();
    }

    let neighbor_ids = mdr_bidirectional_neighbor_ids(iface, neighbors);
    if neighbor_ids.is_empty() {
        return BTreeSet::new();
    }
    let connectivity =
        mdr_neighbor_connectivity_matrix(iface, neighbors, &neighbor_ids);
    let (adjacency, san) =
        mdr_neighbor_adj_san_matrices(iface, neighbors, &neighbor_ids);
    let prior_selected = iface
        .state
        .neighbors
        .iter(neighbors)
        .filter(|nbr| nbr.mdr.selected_advertised)
        .map(|nbr| nbr.router_id)
        .collect::<BTreeSet<_>>();
    let mut selected = BTreeSet::new();

    for (j_index, j_router_id) in neighbor_ids.iter().copied().enumerate() {
        let Some((_, neighbor_j)) = iface
            .state
            .neighbors
            .get_by_router_id(neighbors, j_router_id)
        else {
            continue;
        };
        if neighbor_j.mdr.backbone {
            continue;
        }

        let cost_i_j = u32::from(mdr_outgoing_metric(neighbor_j));
        let mut should_select = false;
        for (k_index, k_router_id) in neighbor_ids.iter().copied().enumerate() {
            if j_index == k_index {
                continue;
            }
            let Some((_, neighbor_k)) = iface
                .state
                .neighbors
                .get_by_router_id(neighbors, k_router_id)
            else {
                continue;
            };
            if neighbor_k.state < nsm::State::TwoWay {
                continue;
            }

            let cost_k_j = if connectivity[k_index][j_index] {
                u32::from(mdr_neighbor_reported_metric(neighbor_k, j_router_id))
            } else {
                u32::MAX
            };
            let local_path_cost =
                u32::from(mdr_incoming_metric(local_router_id, neighbor_k))
                    .saturating_add(cost_i_j);
            if cost_k_j <= local_path_cost {
                continue;
            }
            let relay_count = mdr_acceptable_min_cost_relay_count(
                iface,
                neighbors,
                &neighbor_ids,
                &connectivity,
                &adjacency,
                &san,
                &prior_selected,
                local_router_id,
                j_index,
                k_index,
            );
            if relay_count < required_relay_count {
                should_select = true;
                break;
            }
        }

        if should_select {
            selected.insert(j_router_id);
        }
    }

    selected
}

#[expect(clippy::too_many_arguments)]
fn mdr_acceptable_min_cost_relay_count(
    iface: &Interface<Ospfv3>,
    neighbors: &Arena<Neighbor<Ospfv3>>,
    neighbor_ids: &[Ipv4Addr],
    connectivity: &[Vec<bool>],
    adjacency: &[Vec<bool>],
    san: &[Vec<bool>],
    prior_selected: &BTreeSet<Ipv4Addr>,
    local_router_id: Ipv4Addr,
    j_index: usize,
    k_index: usize,
) -> usize {
    let j_router_id = neighbor_ids[j_index];
    let k_router_id = neighbor_ids[k_index];
    let Some((_, neighbor_j)) = iface
        .state
        .neighbors
        .get_by_router_id(neighbors, j_router_id)
    else {
        return 0;
    };
    let Some((_, neighbor_k)) = iface
        .state
        .neighbors
        .get_by_router_id(neighbors, k_router_id)
    else {
        return 0;
    };

    let selected_by_j = neighbor_j
        .mdr
        .selected_advertised_neighbors
        .contains(&local_router_id);
    let selected_by_local = prior_selected.contains(&j_router_id);
    let local_path_cost =
        u32::from(mdr_incoming_metric(local_router_id, neighbor_k))
            .saturating_add(u32::from(mdr_outgoing_metric(neighbor_j)));

    neighbor_ids
        .iter()
        .copied()
        .enumerate()
        .filter(|(u_index, u_router_id)| {
            if *u_index == j_index || *u_index == k_index {
                return false;
            }
            let Some((_, neighbor_u)) = iface
                .state
                .neighbors
                .get_by_router_id(neighbors, *u_router_id)
            else {
                return false;
            };
            if neighbor_u.state < nsm::State::TwoWay
                || !connectivity[*u_index][j_index]
                || !connectivity[*u_index][k_index]
            {
                return false;
            }

            let relay_cost = u32::from(mdr_neighbor_reported_metric(
                neighbor_k,
                *u_router_id,
            ))
            .saturating_add(u32::from(
                mdr_neighbor_reported_metric(neighbor_u, j_router_id),
            ));
            relay_cost < local_path_cost
                || (relay_cost == local_path_cost
                    && (adjacency[*u_index][j_index]
                        || mdr_sidcds_lexicographic(
                            u8::from(san[j_index][*u_index]),
                            u8::from(selected_by_j),
                            u8::from(san[*u_index][j_index]),
                            u8::from(selected_by_local),
                            *u_router_id,
                            local_router_id,
                        )))
        })
        .count()
}

fn mdr_bidirectional_neighbor_ids(
    iface: &Interface<Ospfv3>,
    neighbors: &Arena<Neighbor<Ospfv3>>,
) -> Vec<Ipv4Addr> {
    iface
        .state
        .neighbors
        .iter(neighbors)
        .filter(|nbr| nbr.state >= nsm::State::TwoWay)
        .map(|nbr| nbr.router_id)
        .sorted()
        .collect()
}

fn mdr_neighbor_connectivity_matrix(
    iface: &Interface<Ospfv3>,
    neighbors: &Arena<Neighbor<Ospfv3>>,
    neighbor_ids: &[Ipv4Addr],
) -> Vec<Vec<bool>> {
    let mut connectivity =
        vec![vec![false; neighbor_ids.len()]; neighbor_ids.len()];
    for (left_index, left_router_id) in neighbor_ids.iter().copied().enumerate()
    {
        for (right_index, right_router_id) in neighbor_ids
            .iter()
            .copied()
            .enumerate()
            .skip(left_index + 1)
        {
            let Some((_, left)) = iface
                .state
                .neighbors
                .get_by_router_id(neighbors, left_router_id)
            else {
                continue;
            };
            let Some((_, right)) = iface
                .state
                .neighbors
                .get_by_router_id(neighbors, right_router_id)
            else {
                continue;
            };
            let left_reports_right =
                left.mdr.bidirectional_neighbors.contains(&right.router_id);
            let right_reports_left =
                right.mdr.bidirectional_neighbors.contains(&left.router_id);
            let linked = match (
                left.mdr.full_hello_received,
                right.mdr.full_hello_received,
            ) {
                (true, true) => left_reports_right && right_reports_left,
                (true, false) => left_reports_right,
                (false, true) => right_reports_left,
                (false, false) => false,
            };
            connectivity[left_index][right_index] = linked;
            connectivity[right_index][left_index] = linked;
        }
    }
    connectivity
}

fn mdr_neighbor_adj_san_matrices(
    iface: &Interface<Ospfv3>,
    neighbors: &Arena<Neighbor<Ospfv3>>,
    neighbor_ids: &[Ipv4Addr],
) -> (Vec<Vec<bool>>, Vec<Vec<bool>>) {
    let mut adjacency =
        vec![vec![false; neighbor_ids.len()]; neighbor_ids.len()];
    let mut san = vec![vec![false; neighbor_ids.len()]; neighbor_ids.len()];

    for (left_index, left_router_id) in neighbor_ids.iter().copied().enumerate()
    {
        let Some((_, left)) = iface
            .state
            .neighbors
            .get_by_router_id(neighbors, left_router_id)
        else {
            continue;
        };
        for (right_index, right_router_id) in
            neighbor_ids.iter().copied().enumerate()
        {
            if left
                .mdr
                .selected_advertised_neighbors
                .contains(&right_router_id)
            {
                san[left_index][right_index] = true;
            }
            if left_index >= right_index {
                continue;
            }

            let Some((_, right)) = iface
                .state
                .neighbors
                .get_by_router_id(neighbors, right_router_id)
            else {
                continue;
            };
            if mdr_neighbor_pair_has_adjacency(left, right) {
                adjacency[left_index][right_index] = true;
                adjacency[right_index][left_index] = true;
            }
        }
    }

    (adjacency, san)
}

fn mdr_neighbor_pair_has_adjacency(
    left: &Neighbor<Ospfv3>,
    right: &Neighbor<Ospfv3>,
) -> bool {
    mdr_neighbor_pair_reports_adjacency(left, right)
        || mdr_neighbor_pair_reports_adjacency(right, left)
}

fn mdr_neighbor_pair_reports_adjacency(
    reporting: &Neighbor<Ospfv3>,
    candidate: &Neighbor<Ospfv3>,
) -> bool {
    (reporting.mdr.mdr_level.is_dr_or_backup()
        && candidate.mdr.mdr_level.is_dr_or_backup()
        && reporting
            .mdr
            .dependent_neighbors
            .contains(&candidate.router_id))
        || (candidate.mdr.mdr_level.is_dr_or_backup()
            && (reporting.mdr.parent == Some(candidate.router_id)
                || reporting.mdr.backup_parent == Some(candidate.router_id)))
}

fn mdr_outgoing_metric(nbr: &Neighbor<Ospfv3>) -> u16 {
    nbr.mdr.outgoing_link_metric.unwrap_or(1)
}

fn mdr_incoming_metric(
    local_router_id: Ipv4Addr,
    nbr: &Neighbor<Ospfv3>,
) -> u16 {
    nbr.mdr
        .incoming_link_metric
        .or_else(|| nbr.mdr.link_metrics.get(&local_router_id).copied())
        .unwrap_or(1)
}

fn mdr_neighbor_reported_metric(
    nbr: &Neighbor<Ospfv3>,
    router_id: Ipv4Addr,
) -> u16 {
    nbr.mdr.link_metrics.get(&router_id).copied().unwrap_or(1)
}

fn mdr_sidcds_lexicographic(
    left_priority: u8,
    right_priority: u8,
    left_level: u8,
    right_level: u8,
    left_router_id: Ipv4Addr,
    right_router_id: Ipv4Addr,
) -> bool {
    left_priority > right_priority
        || (left_priority == right_priority
            && (left_level > right_level
                || (left_level == right_level
                    && left_router_id > right_router_id)))
}

fn mdr_router_lsa_link_metric(nbr: &Neighbor<Ospfv3>, iface_cost: u16) -> u16 {
    nbr.mdr.outgoing_link_metric.unwrap_or(iface_cost)
}

fn should_orig_network_lsa(
    iface: &Interface<Ospfv3>,
    arenas: &InstanceArenas<Ospfv3>,
) -> bool {
    !iface.is_mdr_enabled()
        && iface.state.ism_state == ism::State::Dr
        && interface_has_full_neighbors(iface, arenas)
}

fn lsa_orig_network(
    iface: &Interface<Ospfv3>,
    area: &Area<Ospfv3>,
    instance: &InstanceUpView<'_, Ospfv3>,
    arenas: &InstanceArenas<Ospfv3>,
) {
    let lsdb_id = LsdbId::Area(area.id);
    let extended_lsa = instance.config.extended_lsa;

    // Network-LSA's options.
    let options = Ospfv3::area_options(area, OptionsLocation::Lsa);

    // An IPv6 network-LSA's Link State ID is set to the Interface ID of the
    // Designated Router on the link.
    let lsa_id = Ipv4Addr::from(iface.system.ifindex.unwrap());

    // Network-LSA's attached routers.
    let myself = instance.state.router_id;
    let nbrs = iface
        .state
        .neighbors
        .iter(&arenas.neighbors)
        .filter(|nbr| nbr.state == nsm::State::Full)
        .map(|nbr| nbr.router_id);
    let attached_rtrs = std::iter::once(myself).chain(nbrs).collect();

    // (Re)originate Network-LSA.
    let lsa_body =
        LsaBody::Network(LsaNetwork::new(extended_lsa, options, attached_rtrs));
    instance
        .tx
        .protocol_input
        .lsa_orig_check(lsdb_id, None, lsa_id, lsa_body);
}

fn lsa_flush_network(
    iface: &Interface<Ospfv3>,
    area: &Area<Ospfv3>,
    instance: &InstanceUpView<'_, Ospfv3>,
    arenas: &InstanceArenas<Ospfv3>,
) {
    let lsdb_id = LsdbId::Area(area.id);
    let extended_lsa = instance.config.extended_lsa;

    let adv_rtr = instance.state.router_id;
    let lsa_id = Ipv4Addr::from(iface.system.ifindex.unwrap());
    let lsa_key =
        LsaKey::new(LsaNetwork::lsa_type(extended_lsa), adv_rtr, lsa_id);
    if let Some((_, lse)) = area.state.lsdb.get(&arenas.lsa_entries, &lsa_key) {
        lsa_flush(instance, lsdb_id, lse.id);
    }
}

fn lsa_orig_link(
    iface: &Interface<Ospfv3>,
    area: &Area<Ospfv3>,
    instance: &InstanceUpView<'_, Ospfv3>,
) {
    // Link-LSAs SHOULD NOT be originated for virtual links.
    if iface.is_virtual_link() {
        return;
    }

    let lsdb_id = LsdbId::Link(area.id, iface.id);
    let extended_lsa = instance.config.extended_lsa;

    // Link-LSA's options.
    let options = Ospfv3::area_options(area, OptionsLocation::Lsa);

    // The Link State ID is set to the router's Interface ID on Link L.
    let lsa_id = Ipv4Addr::from(iface.system.ifindex.unwrap());

    // Link-LSA's prefixes.
    let prefixes = iface
        .system
        .addr_list
        .iter()
        // Filter by address family.
        .filter(|addr| addr.address_family() == instance.state.af)
        // Filter out IPv6 link-local addresses.
        .filter(|addr| {
            if let IpAddr::V6(addr) = addr.ip() {
                !addr.is_unicast_link_local()
            } else {
                true
            }
        })
        .map(|addr| addr.apply_mask())
        .map(|addr| LsaLinkPrefix::new(PrefixOptions::empty(), addr))
        .collect();

    // Select link-local address.
    //
    // When routing for the IPv4 address-family, select the primary IPv4 address
    // of the interface.
    let linklocal = match instance.state.af {
        AddressFamily::Ipv4 => iface.system.addr_list.first().unwrap().ip(),
        AddressFamily::Ipv6 => iface.system.linklocal_addr.unwrap().ip().into(),
    };

    // (Re)originate Link-LSA.
    let lsa_body = LsaBody::Link(LsaLink::new(
        extended_lsa,
        iface.config.priority,
        options,
        linklocal,
        prefixes,
    ));
    instance
        .tx
        .protocol_input
        .lsa_orig_check(lsdb_id, None, lsa_id, lsa_body);
}

fn lsa_flush_link(
    iface: &Interface<Ospfv3>,
    area: &Area<Ospfv3>,
    instance: &InstanceUpView<'_, Ospfv3>,
    arenas: &InstanceArenas<Ospfv3>,
) {
    // Link-LSAs SHOULD NOT be originated for virtual links.
    if iface.is_virtual_link() {
        return;
    }

    let lsdb_id = LsdbId::Link(area.id, iface.id);
    let extended_lsa = instance.config.extended_lsa;

    let adv_rtr = instance.state.router_id;
    let lsa_id = Ipv4Addr::from(iface.system.ifindex.unwrap());
    let lsa_key = LsaKey::new(LsaLink::lsa_type(extended_lsa), adv_rtr, lsa_id);
    if let Some((_, lse)) = iface.state.lsdb.get(&arenas.lsa_entries, &lsa_key)
    {
        lsa_flush(instance, lsdb_id, lse.id);
    }
}

fn lsa_orig_intra_area_prefix(
    area: &Area<Ospfv3>,
    instance: &InstanceUpView<'_, Ospfv3>,
    arenas: &InstanceArenas<Ospfv3>,
) {
    let sr_config = &instance.shared.sr_config;
    let bier_config = &instance.shared.bier_config;
    let lsdb_id = LsdbId::Area(area.id);
    let extended_lsa = instance.config.extended_lsa;
    let adv_rtr = instance.state.router_id;
    let mut adv_list = vec![];

    // Router's attached stub links and looped-back interfaces.
    let mut prefixes = vec![];
    for (iface, prefix) in area
        .interfaces
        .iter(&arenas.interfaces)
        // Skip interfaces in the "Down" state.
        .filter(|iface| !iface.is_down())
        // Skip interfaces reported as transit networks in the Router-LSA.
        .filter(|iface| {
            !((!iface.is_mdr_enabled()
                && iface.state.ism_state == ism::State::Dr
                && iface
                    .state
                    .neighbors
                    .iter(&arenas.neighbors)
                    .any(|nbr| nbr.state == nsm::State::Full))
                || (!iface.is_mdr_enabled()
                    && iface
                        .state
                        .dr
                        .and_then(|net_id| {
                            iface
                                .state
                                .neighbors
                                .get_by_net_id(&arenas.neighbors, net_id)
                                .filter(|(_, nbr)| {
                                    nbr.state == nsm::State::Full
                                })
                        })
                        .is_some()))
        })
        // Get all interface addresses.
        .flat_map(|iface| {
            iface
                .system
                .addr_list
                .iter()
                .map(move |addr| (iface, addr.apply_mask()))
        })
        // Filter by address family.
        .filter(|(_, addr)| addr.address_family() == instance.state.af)
        // Filter out IPv6 link-local addresses.
        .filter(|(_, addr)| {
            if let IpAddr::V6(addr) = addr.ip() {
                !addr.is_unicast_link_local()
            } else {
                true
            }
        })
    {
        let mut entry = if iface.state.ism_state == ism::State::Loopback
            || iface.config.if_type == InterfaceType::PointToMultipoint
        {
            // If the interface type is point-to-multipoint or the interface is
            // in the state Loopback, the global scope IPv6 addresses associated
            // with the interface (if any) are copied into the
            // intra-area-prefix-LSA with the PrefixOptions LA-bit set, the
            // PrefixLength set to 128, and the metric set to 0.
            let mut prefix_options = PrefixOptions::LA;
            if iface.config.node_flag
                && iface.state.ism_state == ism::State::Loopback
            {
                prefix_options.insert(PrefixOptions::N);
            }
            let plen = instance.state.af.max_prefixlen();
            let prefix = IpNetwork::new(prefix.ip(), plen).unwrap();
            LsaIntraAreaPrefixEntry::new(prefix_options, prefix, 0)
        } else {
            // Otherwise, the list of global prefixes configured in RTX for the
            // link are copied into the intra-area-prefix-LSA by specifying the
            // PrefixLength, PrefixOptions, and Address Prefix fields. The
            // Metric field for each of these prefixes is set to the interface's
            // output cost.
            LsaIntraAreaPrefixEntry::new(
                PrefixOptions::empty(),
                prefix,
                iface.config.cost,
            )
        };

        // Add Prefix-SID Sub-TLV.
        if instance.config.sr_enabled
            && let Some(prefix_sid) =
                sr_config.prefix_sids.get(&(prefix, IgpAlgoType::Spf))
        {
            let mut flags = PrefixSidFlags::empty();
            match prefix_sid.last_hop {
                SidLastHopBehavior::ExpNull => {
                    flags.insert(PrefixSidFlags::NP);
                    flags.insert(PrefixSidFlags::E);
                }
                SidLastHopBehavior::NoPhp => {
                    flags.insert(PrefixSidFlags::NP);
                }
                SidLastHopBehavior::Php => (),
            }
            let algo = IgpAlgoType::Spf;
            let sid = Sid::Index(prefix_sid.index);
            entry
                .prefix_sids
                .insert(algo, PrefixSid::new(flags, algo, sid));
        }

        // Add BIER Sub-TLV(s) if BIER is enabled and allowed to advertise
        if instance.config.bier.enabled && instance.config.bier.advertise {
            bier_config
                .sd_cfg
                .iter()
                // Search for subdomain configuration(s) for current prefix
                .filter(|((_, af), sd_cfg)| {
                    af == &AddressFamily::Ipv6 && sd_cfg.bfr_prefix == prefix
                })
                .for_each(|((sd_id, _), sd_cfg)| {
                    let mut bier = BierStlv::new(
                        *sd_id,
                        sd_cfg.mt_id,
                        sd_cfg.bfr_id,
                        sd_cfg.bar,
                        sd_cfg.ipa,
                    );

                    // BIER prefix has configured encap ?
                    bier.encaps = sd_cfg
                        .encap
                        .iter()
                        .filter_map(|((bsl, encap_type), encap)| {
                            match encap_type {
                                BierEncapsulationType::Mpls => {
                                    // TODO: where is the label defined?
                                    Some(BierEncapId::Mpls(Label::new(0)))
                                }
                                _ => match encap.in_bift_id {
                                    BierInBiftId::Base(id) => Some(id),
                                    BierInBiftId::Encoding(true) => Some(0),
                                    _ => None,
                                }
                                .map(|id| {
                                    BierEncapId::NonMpls(BiftId::new(id))
                                }),
                            }
                            .map(|id| {
                                BierEncapSubStlv::new(encap.max_si, id, *bsl)
                            })
                        })
                        .collect::<Vec<BierEncapSubStlv>>();

                    entry.bier.push(bier);
                });
        }

        prefixes.push(entry);
    }
    // If RTX has one or more virtual links configured through the area, it
    // includes one of its global scope IPv6 interface addresses in the LSA
    // (if it hasn't already), setting the LA-bit in the PrefixOptions field,
    // the PrefixLength to 128, and the Metric to 0.
    if !area.is_backbone()
        && let Some((_, backbone)) =
            arenas.areas.get_by_area_id(BACKBONE_AREA_ID)
        && backbone.interfaces.iter(&arenas.interfaces).any(|iface| {
            iface.vlink_key.as_ref().is_some_and(|vlink_key| {
                vlink_key.transit_area_id == area.area_id
            })
        })
        && !prefixes
            .iter()
            .any(|entry| entry.options.contains(PrefixOptions::LA))
    {
        // Select a global IPv6 address, preferring one from an interface
        // in the transit area and falling back to any other global address.
        if let Some(addr) = area
            .interfaces
            .iter(&arenas.interfaces)
            .chain(arenas.interfaces.iter().map(|(_, iface)| iface))
            .flat_map(|iface| iface.system.addr_list.iter())
            .filter_map(|addr| Ipv6Addr::get(addr.ip()))
            .find(|addr| !addr.is_unicast_link_local())
        {
            let plen = instance.state.af.max_prefixlen();
            let prefix = IpNetwork::new(addr.into(), plen).unwrap();
            let prefix_options = PrefixOptions::LA;
            let entry = LsaIntraAreaPrefixEntry::new(prefix_options, prefix, 0);
            prefixes.push(entry);
        }
    }
    let ref_lsa = LsaKey::new(
        LsaRouter::lsa_type(extended_lsa),
        adv_rtr,
        Ipv4Addr::from(0),
    );
    adv_list.push((ref_lsa, prefixes));

    // Designated Router's attached links.
    for iface in area
        .interfaces
        .iter(&arenas.interfaces)
        // MANET/MDR interfaces suppress Network-LSA origination, so their
        // prefixes stay router-referenced instead of network-referenced.
        .filter(|iface| !iface.is_mdr_enabled())
        // Skip non-DR interfaces.
        .filter(|iface| iface.state.ism_state == ism::State::Dr)
    {
        let mut prefixes = HashMap::new();
        for prefix in iface
            .state
            .lsdb
            // Get all interface Link-LSAs.
            .iter_by_type(&arenas.lsa_entries, LsaLink::lsa_type(extended_lsa))
            .map(|(_, lse)| &lse.data)
            // Check if the link-LSA's Advertising Router is fully adjacent to
            // the DR and the Link State ID matches the neighbor's interface ID.
            .filter(|lsa| {
                iface
                    .state
                    .neighbors
                    .get_by_router_id(&arenas.neighbors, lsa.hdr.adv_rtr)
                    .filter(|(_, nbr)| nbr.state == nsm::State::Full)
                    .filter(|(_, nbr)| {
                        lsa.hdr.lsa_id == Ipv4Addr::from(nbr.iface_id.unwrap())
                    })
                    .is_some()
            })
            // Get all Link-LSA prefixes.
            .flat_map(|lsa| {
                let link_lsa = lsa.body.as_link().unwrap();
                link_lsa.prefixes.iter().cloned()
            })
            // Filter out prefixes with the NU/LA options.
            .filter(|prefix| {
                !prefix
                    .options
                    .intersects(PrefixOptions::NU | PrefixOptions::LA)
            })
            // Filter out IPv6 link-local addresses.
            .filter(|prefix| {
                if let IpAddr::V6(addr) = prefix.value.ip() {
                    !addr.is_unicast_link_local()
                } else {
                    true
                }
            })
        {
            match prefixes.entry(prefix.value) {
                hash_map::Entry::Occupied(mut o) => {
                    // PrefixOptions fields should be logically OR'ed together.
                    *o.get_mut() |= prefix.options;
                }
                hash_map::Entry::Vacant(v) => {
                    v.insert(prefix.options);
                }
            }
        }

        let ref_lsa = LsaKey::new(
            LsaNetwork::lsa_type(extended_lsa),
            adv_rtr,
            Ipv4Addr::from(iface.system.ifindex.unwrap()),
        );
        let prefixes = prefixes
            .into_iter()
            // The Metric field for all prefixes is set to 0.
            .map(|(prefix, prefix_options)| {
                LsaIntraAreaPrefixEntry::new(prefix_options, prefix, 0)
            })
            .collect();
        adv_list.push((ref_lsa, prefixes));
    }

    // Originate as many Intra-Area-Prefix-LSAs as necessary.
    let mut lsa_id: u32 = 0;
    let mut originate_fn = |ref_lsa: LsaKey<LsaType>, prefixes| {
        let lsa_body = LsaBody::IntraAreaPrefix(LsaIntraAreaPrefix::new(
            extended_lsa,
            ref_lsa.lsa_type,
            ref_lsa.lsa_id,
            ref_lsa.adv_rtr,
            prefixes,
        ));

        // (Re)originate Intra-Area-Prefix-LSA.
        instance.tx.protocol_input.lsa_orig_check(
            lsdb_id,
            None,
            lsa_id.into(),
            lsa_body,
        );

        // Increment the LSA-ID.
        lsa_id += 1;
    };
    for (ref_lsa, prefixes) in adv_list {
        for prefixes in prefixes
            .into_iter()
            .chunks(
                (Lsa::<Ospfv3>::MAX_LENGTH
                    - LsaHdr::LENGTH as usize
                    - LsaIntraAreaPrefix::BASE_LENGTH as usize)
                    / LsaIntraAreaPrefixEntry::max_length(extended_lsa),
            )
            .into_iter()
        {
            originate_fn(ref_lsa, prefixes.collect());
        }
    }

    // Flush self-originated Intra-Area-Prefix-LSAs that are no longer needed.
    for (_, lse) in area
        .state
        .lsdb
        .iter_by_type_advrtr(
            &arenas.lsa_entries,
            LsaIntraAreaPrefix::lsa_type(extended_lsa),
            adv_rtr,
        )
        .filter(|(_, lse)| lse.data.hdr.lsa_id >= Ipv4Addr::from(lsa_id))
    {
        lsa_flush(instance, lsdb_id, lse.id);
    }
}

fn lsa_orig_router_info(
    area: &Area<Ospfv3>,
    instance: &InstanceUpView<'_, Ospfv3>,
) {
    let sr_config = &instance.shared.sr_config;
    let lsdb_id = LsdbId::Area(area.id);
    let lsa_id = Ipv4Addr::from(0);

    let mut sr_algo = None;
    let mut srgb = vec![];
    let mut srlb = vec![];
    let mut node_tags = vec![];
    if instance.config.sr_enabled {
        // Fill in supported SR algorithms.
        sr_algo = Some(SrAlgoTlv::new([IgpAlgoType::Spf].into()));

        // Fill in local SRGB.
        for range in &sr_config.srgb {
            let first = Sid::Label(Label::new(range.lower_bound));
            let range = range.upper_bound - range.lower_bound + 1;
            srgb.push(SidLabelRangeTlv::new(first, range));
        }

        // Fill in local SRLB.
        for range in &sr_config.srlb {
            let first = Sid::Label(Label::new(range.lower_bound));
            let range = range.upper_bound - range.lower_bound + 1;
            srlb.push(SrLocalBlockTlv::new(first, range));
        }
    }

    // Fill in node tags.
    if !instance.config.node_tags.is_empty() {
        node_tags.push(NodeAdminTagTlv::new(instance.config.node_tags.clone()));
    }

    // (Re)originate Router Information LSA.
    let scope = LsaScopeCode::Area;
    let mut info_caps = RouterInfoCaps::STUB_ROUTER;
    if instance.config.gr.helper_enabled {
        info_caps.insert(RouterInfoCaps::GR_HELPER);
    }
    let lsa_body = LsaBody::RouterInfo(LsaRouterInfo {
        scope,
        info_caps: Some(RouterInfoCapsTlv::new(info_caps)),
        func_caps: None,
        sr_algo,
        srgb,
        srlb,
        msds: None,
        srms_pref: None,
        info_hostname: instance
            .shared
            .hostname
            .as_ref()
            .map(|hostname| DynamicHostnameTlv::new(hostname.to_string())),
        node_tags,
        unknown_tlvs: vec![],
    });
    instance
        .tx
        .protocol_input
        .lsa_orig_check(lsdb_id, None, lsa_id, lsa_body);
}

fn process_self_originated_lsa(
    instance: &InstanceUpView<'_, Ospfv3>,
    arenas: &InstanceArenas<Ospfv3>,
    lsdb_id: LsdbId,
    lse_id: LsaEntryId,
) -> Result<(), Error<Ospfv3>> {
    let mut flush = false;

    // Lookup LSDB and LSA entry.
    let (lsdb_idx, lsdb) = lsdb_get(
        &instance.state.lsdb,
        &arenas.areas,
        &arenas.interfaces,
        &lsdb_id.into(),
    )?;
    let (_, lse) = lsdb.get_by_id(&arenas.lsa_entries, lse_id)?;
    let lsa = &lse.data;

    // Check LSA type.
    match lsa.hdr.lsa_type.function_code() {
        Some(LsaFunctionCode::Router) => {
            let area_idx = lsdb_idx.into_area().unwrap();
            let area = &arenas.areas[area_idx];

            // Reoriginate Router-LSA.
            lsa_orig_router(area, instance, arenas);
        }
        Some(LsaFunctionCode::Network) => {
            let area_idx = lsdb_idx.into_area().unwrap();
            let area = &arenas.areas[area_idx];

            // Check if the router is still the DR for the network.
            if let Some(iface) = area
                .interfaces
                .iter(&arenas.interfaces)
                .find(|iface| {
                    iface.system.ifindex == Some(u32::from(lsa.hdr.lsa_id) as _)
                })
                .filter(|iface| iface.state.ism_state == ism::State::Dr)
            {
                // Reoriginate Network-LSA.
                lsa_orig_network(iface, area, instance, arenas);
            } else {
                // Flush Network-LSA.
                flush = true;
            }
        }
        Some(
            LsaFunctionCode::InterAreaPrefix | LsaFunctionCode::InterAreaRouter,
        ) => {
            // Do nothing. These LSAs will be either reoriginated or flushed
            // once SPF runs and the routing table is computed.
        }
        Some(LsaFunctionCode::AsExternal) => {
            // Flush AS-External-LSA (redistribution of local routes isn't
            // supported at the moment).
            flush = true;
        }
        Some(LsaFunctionCode::Link) => {
            let (area_idx, iface_idx) = lsdb_idx.into_link().unwrap();
            let area = &arenas.areas[area_idx];
            let iface = &arenas.interfaces[iface_idx];

            if iface.state.ism_state >= ism::State::Waiting {
                // Reoriginate Link-LSA.
                lsa_orig_link(iface, area, instance);
            } else {
                // Flush Link-LSA.
                flush = true;
            }
        }
        Some(LsaFunctionCode::IntraAreaPrefix) => {
            let area_idx = lsdb_idx.into_area().unwrap();
            let area = &arenas.areas[area_idx];

            // Reoriginate Intra-area-prefix-LSA(s).
            lsa_orig_intra_area_prefix(area, instance, arenas);
        }
        Some(LsaFunctionCode::RouterInfo) => {
            // Flush Router-Information-LSA.
            flush = true;
        }
        _ => {
            // Flush unknown LSA.
            flush = true;
        }
    }

    if flush {
        // Effetively flush the received self-originated LSA.
        lsa_flush(instance, lsdb_id, lse_id);
    }

    Ok(())
}

fn lsa_flush(
    instance: &InstanceUpView<'_, Ospfv3>,
    lsdb_id: LsdbId,
    lse_id: LsaEntryId,
) {
    instance.tx.protocol_input.lsa_flush(
        lsdb_id,
        lse_id,
        LsaFlushReason::PrematureAging,
    );
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::{Arc, OnceLock};

    use holo_protocol::{InstanceChannelsTx, InstanceShared, ProtocolInstance};
    use holo_utils::ibus;
    use holo_utils::southbound::InterfaceFlags;
    use holo_utils::yang::ContextExt;
    use holo_yang::YANG_CTX;
    use ipnetwork::{IpNetwork, Ipv6Network};
    use tokio::sync::mpsc;
    use yang5::context::Context;

    use super::*;
    use crate::area::BACKBONE_AREA_ID;
    use crate::collections::{AreaId, AreaIndex, InterfaceId, InterfaceIndex};
    use crate::instance::{Instance, ProtocolInputChannelsRx};
    use crate::ospfv3::mdr::MdrLevel;
    use crate::tasks::messages::input::LsaOrigEventMsg;

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

    fn local_router_id() -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, 1)
    }

    fn router_id(octet: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, octet)
    }

    fn test_instance_with_input()
    -> (Instance<Ospfv3>, ProtocolInputChannelsRx<Ospfv3>) {
        ensure_yang_ctx();

        let (nb_tx, _nb_rx) = mpsc::unbounded_channel();
        let (ibus_tx, _ibus_rx) = ibus::ibus_channels();
        let (proto_tx, proto_rx) =
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
        (instance, proto_rx)
    }

    fn add_test_interface(
        instance: &mut Instance<Ospfv3>,
        mdr_enabled: bool,
    ) -> (AreaIndex, InterfaceIndex, AreaId, InterfaceId) {
        let (area_idx, area) = instance.arenas.areas.insert(BACKBONE_AREA_ID);
        let (iface_idx, iface) = area.interfaces.insert(
            &mut instance.arenas.interfaces,
            "eth0".into(),
            None,
        );
        iface.system.ifindex = Some(1);
        iface.system.mtu = Some(1500);
        iface.system.flags.insert(InterfaceFlags::OPERATIVE);
        iface.system.linklocal_addr =
            Some("fe80::1/64".parse::<Ipv6Network>().unwrap());
        iface.system.addr_list.insert(IpNetwork::V6(
            "2001:db8:1::1/64".parse::<Ipv6Network>().unwrap(),
        ));
        iface.config.enabled = true;
        iface.config.if_type = InterfaceType::Broadcast;
        iface.config.cost = 7;
        iface.config.mdr.enabled = mdr_enabled;
        let area_id = area.id;
        let iface_id = iface.id;

        instance.update();

        (area_idx, iface_idx, area_id, iface_id)
    }

    fn add_neighbor(
        instance: &mut Instance<Ospfv3>,
        iface_idx: InterfaceIndex,
        router_id: Ipv4Addr,
        iface_id: u32,
        state: nsm::State,
    ) {
        let (_, nbr) = instance.arenas.interfaces[iface_idx]
            .state
            .neighbors
            .insert(
                &mut instance.arenas.neighbors,
                router_id,
                Ipv6Addr::LOCALHOST,
            );
        nbr.state = state;
        nbr.iface_id = Some(iface_id);
        nbr.mdr.remote_interface_id = Some(iface_id);
    }

    fn set_lsa_fullness(
        instance: &mut Instance<Ospfv3>,
        iface_idx: InterfaceIndex,
        fullness: MdrLsaFullness,
    ) {
        let iface = &mut instance.arenas.interfaces[iface_idx];
        iface.config.mdr.lsa_fullness = fullness;
        iface.sync_mdr_state_from_config();
    }

    fn set_mdr_level(
        instance: &mut Instance<Ospfv3>,
        iface_idx: InterfaceIndex,
        level: MdrLevel,
    ) {
        instance.arenas.interfaces[iface_idx]
            .state
            .mdr
            .as_mut()
            .unwrap()
            .mdr_level = level;
    }

    fn set_neighbor_routable_quality(
        instance: &mut Instance<Ospfv3>,
        iface_idx: InterfaceIndex,
        router_id: Ipv4Addr,
    ) {
        let nbr_idx = instance.arenas.interfaces[iface_idx]
            .state
            .neighbors
            .get_by_router_id(&instance.arenas.neighbors, router_id)
            .map(|(nbr_idx, _)| nbr_idx)
            .expect("test neighbor");
        let nbr = &mut instance.arenas.neighbors[nbr_idx];
        nbr.mdr.reverse_2way = true;
    }

    fn set_neighbor_backbone(
        instance: &mut Instance<Ospfv3>,
        iface_idx: InterfaceIndex,
        router_id: Ipv4Addr,
        backbone: bool,
    ) {
        let nbr_idx = instance.arenas.interfaces[iface_idx]
            .state
            .neighbors
            .get_by_router_id(&instance.arenas.neighbors, router_id)
            .map(|(nbr_idx, _)| nbr_idx)
            .expect("test neighbor");
        let nbr = &mut instance.arenas.neighbors[nbr_idx];
        nbr.mdr.backbone = backbone;
    }

    fn connect_reported_bns(
        instance: &mut Instance<Ospfv3>,
        iface_idx: InterfaceIndex,
        left: Ipv4Addr,
        right: Ipv4Addr,
    ) {
        let left_idx = instance.arenas.interfaces[iface_idx]
            .state
            .neighbors
            .get_by_router_id(&instance.arenas.neighbors, left)
            .map(|(nbr_idx, _)| nbr_idx)
            .expect("left test neighbor");
        let left_nbr = &mut instance.arenas.neighbors[left_idx];
        left_nbr.mdr.full_hello_received = true;
        left_nbr.mdr.bidirectional_neighbors.insert(right);

        let right_idx = instance.arenas.interfaces[iface_idx]
            .state
            .neighbors
            .get_by_router_id(&instance.arenas.neighbors, right)
            .map(|(nbr_idx, _)| nbr_idx)
            .expect("right test neighbor");
        let right_nbr = &mut instance.arenas.neighbors[right_idx];
        right_nbr.mdr.full_hello_received = true;
        right_nbr.mdr.bidirectional_neighbors.insert(left);
    }

    fn set_reported_metric(
        instance: &mut Instance<Ospfv3>,
        iface_idx: InterfaceIndex,
        reporter: Ipv4Addr,
        target: Ipv4Addr,
        metric: u16,
    ) {
        let nbr_idx = instance.arenas.interfaces[iface_idx]
            .state
            .neighbors
            .get_by_router_id(&instance.arenas.neighbors, reporter)
            .map(|(nbr_idx, _)| nbr_idx)
            .expect("reporting test neighbor");
        let nbr = &mut instance.arenas.neighbors[nbr_idx];
        nbr.mdr.link_metrics.insert(target, metric);
        if target == local_router_id() {
            nbr.mdr.incoming_link_metric = Some(metric);
        }
    }

    fn set_outgoing_metric(
        instance: &mut Instance<Ospfv3>,
        iface_idx: InterfaceIndex,
        router_id: Ipv4Addr,
        metric: u16,
    ) {
        let nbr_idx = instance.arenas.interfaces[iface_idx]
            .state
            .neighbors
            .get_by_router_id(&instance.arenas.neighbors, router_id)
            .map(|(nbr_idx, _)| nbr_idx)
            .expect("test neighbor");
        let nbr = &mut instance.arenas.neighbors[nbr_idx];
        nbr.mdr.outgoing_link_metric = Some(metric);
    }

    fn install_router_lsa(
        instance: &mut Instance<Ospfv3>,
        area_idx: AreaIndex,
        adv_router: Ipv4Addr,
        links_to: &[Ipv4Addr],
    ) {
        let links = links_to
            .iter()
            .copied()
            .map(|nbr_router_id| {
                LsaRouterLink::new(
                    LsaRouterLinkType::PointToPoint,
                    1,
                    1,
                    u32::from(nbr_router_id.octets()[3]),
                    nbr_router_id,
                    Default::default(),
                )
            })
            .collect();
        let body = LsaBody::Router(LsaRouter::new(
            false,
            LsaRouterFlags::empty(),
            Options::empty(),
            links,
        ));
        let lsa = Arc::new(Lsa::new(
            0,
            Some(Options::empty()),
            Ipv4Addr::UNSPECIFIED,
            adv_router,
            0x80000001,
            body,
        ));
        let (mut instance_view, arenas) = instance.as_up().unwrap();
        lsdb::install(
            &mut instance_view,
            arenas,
            LsdbIndex::Area(area_idx),
            lsa,
        );
    }

    fn refresh_mdr_lsa_state(
        instance: &mut Instance<Ospfv3>,
        area_idx: AreaIndex,
        iface_idx: InterfaceIndex,
    ) -> bool {
        let (instance_view, arenas) = instance.as_up().unwrap();
        let area = &arenas.areas[area_idx];
        let iface = &mut arenas.interfaces[iface_idx];
        mdr_refresh_interface_lsa_state(
            iface,
            area,
            &instance_view,
            &arenas.lsa_entries,
            &mut arenas.neighbors,
        )
    }

    fn originate_router_lsa(
        instance: &mut Instance<Ospfv3>,
        rx: &mut ProtocolInputChannelsRx<Ospfv3>,
        area_idx: AreaIndex,
    ) -> LsaRouter {
        {
            let (instance_view, arenas) = instance.as_up().unwrap();
            let area = &arenas.areas[area_idx];
            lsa_orig_router(area, &instance_view, &*arenas);
        }

        let msg = rx
            .lsa_orig_check
            .try_recv()
            .expect("Router-LSA origination check");
        let LsaBody::Router(router) = msg.lsa_body else {
            panic!("expected Router-LSA body");
        };
        router
    }

    fn router_link_ids(router: &LsaRouter) -> BTreeSet<Ipv4Addr> {
        router.links.iter().map(|link| link.nbr_router_id).collect()
    }

    fn collect_lsa_orig_bodies(
        rx: &mut ProtocolInputChannelsRx<Ospfv3>,
    ) -> Vec<LsaBody> {
        let mut bodies = Vec::new();
        while let Ok(msg) = rx.lsa_orig_check.try_recv() {
            bodies.push(msg.lsa_body);
        }
        bodies
    }

    fn drain_lsa_orig_events(rx: &mut ProtocolInputChannelsRx<Ospfv3>) {
        while rx.lsa_orig_event.try_recv().is_ok() {}
    }

    fn originate_event_bodies(
        instance: &mut Instance<Ospfv3>,
        rx: &mut ProtocolInputChannelsRx<Ospfv3>,
        event: LsaOriginateEvent,
    ) -> Vec<LsaBody> {
        {
            let (instance_view, arenas) = instance.as_up().unwrap();
            Ospfv3::lsa_orig_event(&instance_view, &*arenas, event).unwrap();
        }
        collect_lsa_orig_bodies(rx)
    }

    fn has_lsa_body<F>(bodies: &[LsaBody], pred: F) -> bool
    where
        F: Fn(&LsaBody) -> bool,
    {
        bodies.iter().any(pred)
    }

    /// Validates RFC 5614 §9.4 — Originating Router-LSAs.
    ///
    /// Session 13a implements the mandatory floor: every Full MANET neighbor
    /// is advertised as a point-to-point Router-LSA link. Non-Full routable
    /// and SANS expansion remains session 13b scope.
    ///
    /// RFC chunk: rfcs/parsed/chunks/5614/9.4.json
    #[tokio::test]
    async fn mdr_router_lsa_advertises_full_neighbor_floor() {
        let (mut instance, mut rx) = test_instance_with_input();
        let (area_idx, iface_idx, _area_id, _iface_id) =
            add_test_interface(&mut instance, true);
        add_neighbor(
            &mut instance,
            iface_idx,
            router_id(2),
            22,
            nsm::State::Full,
        );
        add_neighbor(
            &mut instance,
            iface_idx,
            router_id(3),
            33,
            nsm::State::TwoWay,
        );
        instance.arenas.neighbors.iter_mut().for_each(|(_, nbr)| {
            if nbr.router_id == router_id(2) {
                nbr.mdr.outgoing_link_metric = Some(25);
            } else {
                nbr.mdr.backbone = true;
                nbr.mdr.selected_advertised = true;
            }
        });

        {
            let (instance_view, arenas) = instance.as_up().unwrap();
            let area = &arenas.areas[area_idx];
            lsa_orig_router(area, &instance_view, &*arenas);
        }

        let msg = rx
            .lsa_orig_check
            .try_recv()
            .expect("Router-LSA origination check");
        let LsaBody::Router(router) = msg.lsa_body else {
            panic!("expected Router-LSA body");
        };
        assert_eq!(router.links.len(), 1);
        let link = &router.links[0];
        assert_eq!(link.link_type, LsaRouterLinkType::PointToPoint);
        assert_eq!(link.metric, 25);
        assert_eq!(link.iface_id, 1);
        assert_eq!(link.nbr_iface_id, 22);
        assert_eq!(link.nbr_router_id, router_id(2));
        assert!(rx.lsa_orig_check.try_recv().is_err());
    }

    /// Validates RFC 5614 §9.2 and §9.4 — minimal Router-LSA set.
    ///
    /// Minimal mode keeps the Full-neighbor floor and adds only routable
    /// backbone neighbors.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/{9.2,9.4,10}.json
    #[tokio::test]
    async fn mdr_minimal_router_lsa_advertised_set() {
        let (mut instance, mut rx) = test_instance_with_input();
        let (area_idx, iface_idx, _area_id, _iface_id) =
            add_test_interface(&mut instance, true);
        set_lsa_fullness(&mut instance, iface_idx, MdrLsaFullness::Minimal);
        add_neighbor(
            &mut instance,
            iface_idx,
            router_id(2),
            22,
            nsm::State::Full,
        );
        add_neighbor(
            &mut instance,
            iface_idx,
            router_id(3),
            33,
            nsm::State::TwoWay,
        );
        add_neighbor(
            &mut instance,
            iface_idx,
            router_id(4),
            44,
            nsm::State::TwoWay,
        );
        set_neighbor_routable_quality(&mut instance, iface_idx, router_id(3));
        set_neighbor_routable_quality(&mut instance, iface_idx, router_id(4));
        set_neighbor_backbone(&mut instance, iface_idx, router_id(3), true);
        install_router_lsa(
            &mut instance,
            area_idx,
            router_id(2),
            &[router_id(3)],
        );
        install_router_lsa(
            &mut instance,
            area_idx,
            router_id(3),
            &[router_id(2)],
        );
        install_router_lsa(
            &mut instance,
            area_idx,
            router_id(4),
            &[router_id(2)],
        );
        refresh_mdr_lsa_state(&mut instance, area_idx, iface_idx);

        let router = originate_router_lsa(&mut instance, &mut rx, area_idx);

        assert_eq!(
            router_link_ids(&router),
            BTreeSet::from([router_id(2), router_id(3)])
        );
    }

    /// Validates RFC 5614 §9.3 and §9.4 — full Router-LSA set.
    ///
    /// Full mode selects every bidirectional non-backbone neighbor for SANS,
    /// but §9.4 still limits non-Full advertisements to routable neighbors.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/{9.3,9.4,10}.json
    #[tokio::test]
    async fn mdr_full_router_lsa_advertised_set() {
        let (mut instance, mut rx) = test_instance_with_input();
        let (area_idx, iface_idx, _area_id, _iface_id) =
            add_test_interface(&mut instance, true);
        set_lsa_fullness(&mut instance, iface_idx, MdrLsaFullness::Full);
        add_neighbor(
            &mut instance,
            iface_idx,
            router_id(2),
            22,
            nsm::State::Full,
        );
        add_neighbor(
            &mut instance,
            iface_idx,
            router_id(3),
            33,
            nsm::State::TwoWay,
        );
        add_neighbor(
            &mut instance,
            iface_idx,
            router_id(4),
            44,
            nsm::State::TwoWay,
        );
        set_neighbor_routable_quality(&mut instance, iface_idx, router_id(3));
        set_neighbor_routable_quality(&mut instance, iface_idx, router_id(4));
        install_router_lsa(
            &mut instance,
            area_idx,
            router_id(2),
            &[router_id(3)],
        );
        install_router_lsa(
            &mut instance,
            area_idx,
            router_id(3),
            &[router_id(2)],
        );
        refresh_mdr_lsa_state(&mut instance, area_idx, iface_idx);

        let router = originate_router_lsa(&mut instance, &mut rx, area_idx);

        assert_eq!(
            router_link_ids(&router),
            BTreeSet::from([router_id(2), router_id(3)])
        );
        let (_, nbr3) = instance.arenas.interfaces[iface_idx]
            .state
            .neighbors
            .get_by_router_id(&instance.arenas.neighbors, router_id(3))
            .unwrap();
        let (_, nbr4) = instance.arenas.interfaces[iface_idx]
            .state
            .neighbors
            .get_by_router_id(&instance.arenas.neighbors, router_id(4))
            .unwrap();
        assert!(nbr3.mdr.selected_advertised);
        assert!(nbr4.mdr.selected_advertised);
        assert!(nbr3.mdr.routable);
        assert!(!nbr4.mdr.routable);
    }

    /// Validates RFC 5614 §9.4 condition 2 — peer SANS symmetry.
    ///
    /// RFC chunk: rfcs/parsed/chunks/5614/9.4.json
    #[tokio::test]
    async fn mdr_router_lsa_includes_peer_sans_symmetry_neighbor() {
        let (mut instance, mut rx) = test_instance_with_input();
        let (area_idx, iface_idx, _area_id, _iface_id) =
            add_test_interface(&mut instance, true);
        set_lsa_fullness(&mut instance, iface_idx, MdrLsaFullness::Minimal);
        add_neighbor(
            &mut instance,
            iface_idx,
            router_id(2),
            22,
            nsm::State::Full,
        );
        add_neighbor(
            &mut instance,
            iface_idx,
            router_id(3),
            33,
            nsm::State::TwoWay,
        );
        set_neighbor_routable_quality(&mut instance, iface_idx, router_id(3));
        let (nbr3_idx, _) = instance.arenas.interfaces[iface_idx]
            .state
            .neighbors
            .get_by_router_id(&instance.arenas.neighbors, router_id(3))
            .unwrap();
        instance.arenas.neighbors[nbr3_idx]
            .mdr
            .selected_advertised_neighbors
            .insert(local_router_id());
        install_router_lsa(
            &mut instance,
            area_idx,
            router_id(2),
            &[router_id(3)],
        );
        install_router_lsa(
            &mut instance,
            area_idx,
            router_id(3),
            &[router_id(2)],
        );
        refresh_mdr_lsa_state(&mut instance, area_idx, iface_idx);

        let router = originate_router_lsa(&mut instance, &mut rx, area_idx);

        assert_eq!(
            router_link_ids(&router),
            BTreeSet::from([router_id(2), router_id(3)])
        );
    }

    /// Validates RFC 5614 §9.2 and §9.4 condition 3 — backbone inclusion.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/{9.2,9.4}.json
    #[tokio::test]
    async fn mdr_router_lsa_includes_backbone_neighbor() {
        let (mut instance, mut rx) = test_instance_with_input();
        let (area_idx, iface_idx, _area_id, _iface_id) =
            add_test_interface(&mut instance, true);
        set_lsa_fullness(&mut instance, iface_idx, MdrLsaFullness::Minimal);
        add_neighbor(
            &mut instance,
            iface_idx,
            router_id(2),
            22,
            nsm::State::Full,
        );
        add_neighbor(
            &mut instance,
            iface_idx,
            router_id(3),
            33,
            nsm::State::TwoWay,
        );
        set_neighbor_routable_quality(&mut instance, iface_idx, router_id(3));
        set_neighbor_backbone(&mut instance, iface_idx, router_id(3), true);
        install_router_lsa(
            &mut instance,
            area_idx,
            router_id(2),
            &[router_id(3)],
        );
        install_router_lsa(
            &mut instance,
            area_idx,
            router_id(3),
            &[router_id(2)],
        );
        refresh_mdr_lsa_state(&mut instance, area_idx, iface_idx);

        let router = originate_router_lsa(&mut instance, &mut rx, area_idx);

        assert_eq!(
            router_link_ids(&router),
            BTreeSet::from([router_id(2), router_id(3)])
        );
    }

    /// Validates RFC 5614 §9.3 — `LSAFullness = 3` role-dependent behavior.
    ///
    /// Holo follows the Rust oracle adaptation: MDR and BMDR interfaces use
    /// full advertised-neighbor selection, while Other interfaces use minimal
    /// selection.
    ///
    /// RFC chunk: rfcs/parsed/chunks/5614/9.3.json
    #[tokio::test]
    async fn mdr_full_behavior_depends_on_local_role() {
        async fn run_case(level: MdrLevel) -> BTreeSet<Ipv4Addr> {
            let (mut instance, mut rx) = test_instance_with_input();
            let (area_idx, iface_idx, _area_id, _iface_id) =
                add_test_interface(&mut instance, true);
            set_lsa_fullness(&mut instance, iface_idx, MdrLsaFullness::MdrFull);
            set_mdr_level(&mut instance, iface_idx, level);
            add_neighbor(
                &mut instance,
                iface_idx,
                router_id(2),
                22,
                nsm::State::Full,
            );
            add_neighbor(
                &mut instance,
                iface_idx,
                router_id(3),
                33,
                nsm::State::TwoWay,
            );
            set_neighbor_routable_quality(
                &mut instance,
                iface_idx,
                router_id(3),
            );
            install_router_lsa(
                &mut instance,
                area_idx,
                router_id(2),
                &[router_id(3)],
            );
            install_router_lsa(
                &mut instance,
                area_idx,
                router_id(3),
                &[router_id(2)],
            );
            refresh_mdr_lsa_state(&mut instance, area_idx, iface_idx);
            router_link_ids(&originate_router_lsa(
                &mut instance,
                &mut rx,
                area_idx,
            ))
        }

        assert_eq!(
            run_case(MdrLevel::Mdr).await,
            BTreeSet::from([router_id(2), router_id(3)])
        );
        assert_eq!(
            run_case(MdrLevel::Backup).await,
            BTreeSet::from([router_id(2), router_id(3)])
        );
        assert_eq!(
            run_case(MdrLevel::Other).await,
            BTreeSet::from([router_id(2)])
        );
    }

    /// Validates RFC 5614 Appendix C — metric-driven min-cost SANS.
    ///
    /// The target neighbor is selected only when the peer-reported direct
    /// cost is greater than the local two-hop path through this router.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/{9.3,c}.json
    #[tokio::test]
    async fn mdr_min_cost_sans_uses_reported_metrics() {
        let (mut instance, _rx) = test_instance_with_input();
        let (area_idx, iface_idx, _area_id, _iface_id) =
            add_test_interface(&mut instance, true);
        set_lsa_fullness(&mut instance, iface_idx, MdrLsaFullness::MinCost);
        for octet in [2, 3] {
            add_neighbor(
                &mut instance,
                iface_idx,
                router_id(octet),
                u32::from(octet),
                nsm::State::TwoWay,
            );
            set_neighbor_routable_quality(
                &mut instance,
                iface_idx,
                router_id(octet),
            );
        }
        set_neighbor_backbone(&mut instance, iface_idx, router_id(3), true);
        connect_reported_bns(
            &mut instance,
            iface_idx,
            router_id(2),
            router_id(3),
        );
        set_outgoing_metric(&mut instance, iface_idx, router_id(2), 3);
        set_reported_metric(
            &mut instance,
            iface_idx,
            router_id(3),
            local_router_id(),
            2,
        );
        set_reported_metric(
            &mut instance,
            iface_idx,
            router_id(3),
            router_id(2),
            12,
        );

        refresh_mdr_lsa_state(&mut instance, area_idx, iface_idx);
        let (_, nbr2) = instance.arenas.interfaces[iface_idx]
            .state
            .neighbors
            .get_by_router_id(&instance.arenas.neighbors, router_id(2))
            .unwrap();
        assert!(nbr2.mdr.selected_advertised);

        set_reported_metric(
            &mut instance,
            iface_idx,
            router_id(3),
            router_id(2),
            4,
        );
        refresh_mdr_lsa_state(&mut instance, area_idx, iface_idx);
        let (_, nbr2) = instance.arenas.interfaces[iface_idx]
            .state
            .neighbors
            .get_by_router_id(&instance.arenas.neighbors, router_id(2))
            .unwrap();
        assert!(!nbr2.mdr.selected_advertised);
    }

    /// Validates the local `LSAFullness = 2` adaptation.
    ///
    /// Holo matches the Rust oracle: a direct SANS edge is omitted only when
    /// at least two distinct acceptable relays exist.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/{9.3,c}.json
    #[tokio::test]
    async fn mdr_min_cost_2paths_requires_two_acceptable_relays() {
        let (mut instance, _rx) = test_instance_with_input();
        let (area_idx, iface_idx, _area_id, _iface_id) =
            add_test_interface(&mut instance, true);
        set_lsa_fullness(
            &mut instance,
            iface_idx,
            MdrLsaFullness::MinCost2Paths,
        );
        for octet in [2, 3, 4, 5] {
            add_neighbor(
                &mut instance,
                iface_idx,
                router_id(octet),
                u32::from(octet),
                nsm::State::TwoWay,
            );
            set_neighbor_routable_quality(
                &mut instance,
                iface_idx,
                router_id(octet),
            );
        }
        for octet in [3, 4, 5] {
            set_neighbor_backbone(
                &mut instance,
                iface_idx,
                router_id(octet),
                true,
            );
        }
        connect_reported_bns(
            &mut instance,
            iface_idx,
            router_id(2),
            router_id(3),
        );
        connect_reported_bns(
            &mut instance,
            iface_idx,
            router_id(2),
            router_id(4),
        );
        connect_reported_bns(
            &mut instance,
            iface_idx,
            router_id(3),
            router_id(4),
        );
        set_outgoing_metric(&mut instance, iface_idx, router_id(2), 3);
        set_reported_metric(
            &mut instance,
            iface_idx,
            router_id(3),
            local_router_id(),
            2,
        );
        set_reported_metric(
            &mut instance,
            iface_idx,
            router_id(3),
            router_id(2),
            9,
        );
        set_reported_metric(
            &mut instance,
            iface_idx,
            router_id(3),
            router_id(4),
            2,
        );
        set_reported_metric(
            &mut instance,
            iface_idx,
            router_id(4),
            router_id(2),
            2,
        );

        refresh_mdr_lsa_state(&mut instance, area_idx, iface_idx);
        let (_, nbr2) = instance.arenas.interfaces[iface_idx]
            .state
            .neighbors
            .get_by_router_id(&instance.arenas.neighbors, router_id(2))
            .unwrap();
        assert!(nbr2.mdr.selected_advertised);

        connect_reported_bns(
            &mut instance,
            iface_idx,
            router_id(2),
            router_id(5),
        );
        connect_reported_bns(
            &mut instance,
            iface_idx,
            router_id(3),
            router_id(5),
        );
        set_reported_metric(
            &mut instance,
            iface_idx,
            router_id(3),
            router_id(5),
            2,
        );
        set_reported_metric(
            &mut instance,
            iface_idx,
            router_id(5),
            router_id(2),
            2,
        );
        refresh_mdr_lsa_state(&mut instance, area_idx, iface_idx);
        let (_, nbr2) = instance.arenas.interfaces[iface_idx]
            .state
            .neighbors
            .get_by_router_id(&instance.arenas.neighbors, router_id(2))
            .unwrap();
        assert!(!nbr2.mdr.selected_advertised);
    }

    /// Validates RFC 5614 §9.1/§10 routable-neighbor walk and scheduling.
    ///
    /// Installed Router-LSAs make a 2-Way neighbor reachable through a Full
    /// root neighbor. Refreshing MDR LSA state updates `routable`, and the
    /// pending flag drains through the existing LSA origination event queue.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/{9.1,9.4,10}.json
    #[tokio::test]
    async fn mdr_routable_walk_change_queues_lsa_reevaluation() {
        let (mut instance, mut rx) = test_instance_with_input();
        let (area_idx, iface_idx, area_id, iface_id) =
            add_test_interface(&mut instance, true);
        drain_lsa_orig_events(&mut rx);
        add_neighbor(
            &mut instance,
            iface_idx,
            router_id(2),
            22,
            nsm::State::Full,
        );
        add_neighbor(
            &mut instance,
            iface_idx,
            router_id(3),
            33,
            nsm::State::TwoWay,
        );
        set_neighbor_routable_quality(&mut instance, iface_idx, router_id(3));
        install_router_lsa(
            &mut instance,
            area_idx,
            router_id(2),
            &[router_id(3)],
        );
        install_router_lsa(
            &mut instance,
            area_idx,
            router_id(3),
            &[router_id(2)],
        );
        drain_lsa_orig_events(&mut rx);

        assert!(refresh_mdr_lsa_state(&mut instance, area_idx, iface_idx));
        let (_, nbr3) = instance.arenas.interfaces[iface_idx]
            .state
            .neighbors
            .get_by_router_id(&instance.arenas.neighbors, router_id(3))
            .unwrap();
        assert!(nbr3.mdr.routable);

        {
            let (instance_view, arenas) = instance.as_up().unwrap();
            let area = &arenas.areas[area_idx];
            let iface = &mut arenas.interfaces[iface_idx];
            iface.run_mdr_lsa_reevaluation_if_pending(area, &instance_view);
        }
        let LsaOrigEventMsg { event } = rx
            .lsa_orig_event
            .try_recv()
            .expect("queued LSA origination event");
        assert!(matches!(
            event,
            LsaOriginateEvent::NeighborTwoWayOrHigherChange {
                area_id: queued_area_id,
                iface_id: queued_iface_id,
            } if queued_area_id == area_id && queued_iface_id == iface_id
        ));
        assert!(rx.lsa_orig_check.try_recv().is_err());
    }

    /// Validates RFC 7038 §3 — explicit value-5 behavior.
    ///
    /// `single-hop-full` is not an alias for RFC 5614 full-topology mode: a
    /// non-MDR includes a bidirectional non-Full neighbor only when it is Full
    /// with the MDR and the MDR's installed Router-LSA links to that neighbor.
    /// Routable-neighbor state remains empty for this value-5 procedure.
    ///
    /// RFC chunk: rfcs/parsed/chunks/7038/3.json
    #[tokio::test]
    async fn mdr_rfc7038_value5_single_hop_full_behavior() {
        let (mut instance, mut rx) = test_instance_with_input();
        let (area_idx, iface_idx, _area_id, _iface_id) =
            add_test_interface(&mut instance, true);
        set_lsa_fullness(
            &mut instance,
            iface_idx,
            MdrLsaFullness::SingleHopFull,
        );
        set_mdr_level(&mut instance, iface_idx, MdrLevel::Other);
        instance.arenas.interfaces[iface_idx]
            .state
            .mdr
            .as_mut()
            .unwrap()
            .parent = Some(router_id(2));
        add_neighbor(
            &mut instance,
            iface_idx,
            router_id(2),
            22,
            nsm::State::Full,
        );
        add_neighbor(
            &mut instance,
            iface_idx,
            router_id(3),
            33,
            nsm::State::TwoWay,
        );
        install_router_lsa(
            &mut instance,
            area_idx,
            router_id(2),
            &[router_id(3)],
        );
        refresh_mdr_lsa_state(&mut instance, area_idx, iface_idx);

        let router = originate_router_lsa(&mut instance, &mut rx, area_idx);

        assert_eq!(
            router_link_ids(&router),
            BTreeSet::from([router_id(2), router_id(3)])
        );
        let (_, nbr3) = instance.arenas.interfaces[iface_idx]
            .state
            .neighbors
            .get_by_router_id(&instance.arenas.neighbors, router_id(3))
            .unwrap();
        assert!(nbr3.mdr.selected_advertised);
        assert!(!nbr3.mdr.routable);
    }

    /// Validates RFC 5614 §9.4 with RFC 5340 §4.4.3.8/§4.4.3.9.
    ///
    /// MANET/MDR interfaces suppress Network-LSA origination, but retain
    /// Holo's native Link-LSA and router-referenced Intra-Area-Prefix-LSA
    /// origination.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/9.4.json,
    /// rfcs/parsed/chunks/5340/4.4.3.8.json,
    /// rfcs/parsed/chunks/5340/4.4.3.9.json,
    /// rfcs/parsed/chunks/5838/2.3.json
    #[tokio::test]
    async fn mdr_suppresses_network_lsa_but_retains_link_and_prefix_lsas() {
        let (mut instance, mut rx) = test_instance_with_input();
        let (_area_idx, iface_idx, area_id, iface_id) =
            add_test_interface(&mut instance, true);
        instance.arenas.interfaces[iface_idx].state.ism_state = ism::State::Dr;
        add_neighbor(
            &mut instance,
            iface_idx,
            router_id(2),
            22,
            nsm::State::Full,
        );

        let bodies = originate_event_bodies(
            &mut instance,
            &mut rx,
            LsaOriginateEvent::InterfaceStateChange { area_id, iface_id },
        );

        assert!(!has_lsa_body(&bodies, |body| {
            matches!(body, LsaBody::Network(_))
        }));
        let link_lsa = bodies
            .iter()
            .find_map(|body| match body {
                LsaBody::Link(lsa) => Some(lsa),
                _ => None,
            })
            .expect("Link-LSA retained");
        let expected_prefix: IpNetwork =
            "2001:db8:1::/64".parse::<Ipv6Network>().unwrap().into();
        assert!(
            link_lsa
                .prefixes
                .iter()
                .any(|prefix| prefix.value == expected_prefix)
        );

        let intra_prefix = bodies
            .iter()
            .find_map(|body| match body {
                LsaBody::IntraAreaPrefix(lsa) => Some(lsa),
                _ => None,
            })
            .expect("Intra-Area-Prefix-LSA retained");
        assert_eq!(intra_prefix.ref_lsa_type, LsaRouter::lsa_type(false));
        assert_eq!(intra_prefix.ref_lsa_id, Ipv4Addr::UNSPECIFIED);
        assert_eq!(intra_prefix.ref_adv_rtr, local_router_id());
        assert!(
            intra_prefix
                .prefixes
                .iter()
                .any(|prefix| prefix.value == expected_prefix)
        );
    }

    /// Validates the non-MDR regression surface for RFC 5340 §4.4.3.3-style
    /// Network-LSA origination: a broadcast DR with a Full neighbor still
    /// originates a Network-LSA.
    #[tokio::test]
    async fn non_mdr_dr_interface_still_originates_network_lsa() {
        let (mut instance, mut rx) = test_instance_with_input();
        let (_area_idx, iface_idx, area_id, iface_id) =
            add_test_interface(&mut instance, false);
        instance.arenas.interfaces[iface_idx].state.ism_state = ism::State::Dr;
        add_neighbor(
            &mut instance,
            iface_idx,
            router_id(2),
            22,
            nsm::State::Full,
        );

        let bodies = originate_event_bodies(
            &mut instance,
            &mut rx,
            LsaOriginateEvent::InterfaceStateChange { area_id, iface_id },
        );

        assert!(has_lsa_body(&bodies, |body| {
            matches!(body, LsaBody::Network(_))
        }));
    }

    /// Validates RFC 5614 §9.4 scheduling guidance.
    ///
    /// MANET advertised/backbone changes drain through Holo's existing
    /// `LsaOriginateEvent` scheduling path; they do not call Router-LSA
    /// origination directly.
    ///
    /// RFC chunk: rfcs/parsed/chunks/5614/9.4.json
    #[tokio::test]
    async fn mdr_lsa_reevaluation_uses_existing_origination_event() {
        let (mut instance, mut rx) = test_instance_with_input();
        let (area_idx, iface_idx, area_id, iface_id) =
            add_test_interface(&mut instance, true);
        drain_lsa_orig_events(&mut rx);

        {
            let (instance_view, arenas) = instance.as_up().unwrap();
            let area = &arenas.areas[area_idx];
            let iface = &mut arenas.interfaces[iface_idx];
            iface.state.mdr.as_mut().unwrap().lsa_reevaluation_pending = true;
            iface.run_mdr_lsa_reevaluation_if_pending(area, &instance_view);
        }

        let LsaOrigEventMsg { event } = rx
            .lsa_orig_event
            .try_recv()
            .expect("queued LSA origination event");
        assert!(matches!(
            event,
            LsaOriginateEvent::NeighborTwoWayOrHigherChange {
                area_id: queued_area_id,
                iface_id: queued_iface_id,
            } if queued_area_id == area_id && queued_iface_id == iface_id
        ));
        assert!(rx.lsa_orig_check.try_recv().is_err());
        assert!(
            !instance.arenas.interfaces[iface_idx]
                .state
                .mdr
                .as_ref()
                .unwrap()
                .lsa_reevaluation_pending
        );
    }
}
