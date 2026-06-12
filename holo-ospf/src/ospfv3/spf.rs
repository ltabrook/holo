//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use enum_as_inner::EnumAsInner;
use holo_utils::ip::AddressFamily;

use crate::area::Area;
use crate::collections::{Areas, Arena, Lsdb};
use crate::error::Error;
use crate::instance::InstanceUpView;
use crate::interface::Interface;
use crate::lsdb::LsaEntry;
use crate::neighbor::{Neighbor, nsm};
use crate::northbound::configuration::{MdrAdjConnectivity, MdrLsaFullness};
use crate::ospfv3::packet::iana::{
    LsaFunctionCode, LsaRouterFlags, LsaRouterLinkType, Options, PrefixOptions,
};
use crate::ospfv3::packet::lsa::{
    LsaAsExternal, LsaAsExternalFlags, LsaInterAreaPrefix, LsaInterAreaRouter,
    LsaIntraAreaPrefix, LsaLink, LsaNetwork, LsaRouter, LsaRouterInfo,
    LsaRouterLink, LsaScopeCode, LsaType,
};
use crate::packet::lsa::{Lsa, LsaHdrVersion, LsaKey};
use crate::route::{Nexthop, NexthopKey, Nexthops};
use crate::spf::{
    SpfComputation, SpfExternalNetwork, SpfInterAreaNetwork,
    SpfInterAreaRouter, SpfIntraAreaNetwork, SpfLink, SpfPartialComputation,
    SpfRouterInfo, SpfTriggerLsa, SpfVersion, Vertex, VertexIdVersion,
    VertexLsaVersion,
};
use crate::version::Ospfv3;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum VertexId {
    Network { router_id: Ipv4Addr, iface_id: u32 },
    Router { router_id: Ipv4Addr },
}

#[derive(Debug, Eq, PartialEq, EnumAsInner)]
pub enum VertexLsa {
    Network(Arc<Lsa<Ospfv3>>),
    Router(Vec<Arc<Lsa<Ospfv3>>>),
}

// ===== impl VertexId =====

impl VertexIdVersion for VertexId {
    fn new_root(router_id: Ipv4Addr) -> Self {
        VertexId::Router { router_id }
    }
}

// ===== impl VertexLsa =====

impl VertexLsaVersion<Ospfv3> for VertexLsa {
    fn is_router(&self) -> bool {
        matches!(self, VertexLsa::Router(_))
    }

    fn router_id(&self) -> Ipv4Addr {
        let lsa = self.as_router().unwrap().iter().next().unwrap();
        lsa.hdr.adv_rtr
    }

    fn router_options(&self) -> Options {
        let lsa = self.as_router().unwrap().iter().next().unwrap();
        let lsa_body = lsa.body.as_router().unwrap();
        lsa_body.options
    }

    fn router_flags(&self) -> LsaRouterFlags {
        let lsa = self.as_router().unwrap().iter().next().unwrap();
        let lsa_body = lsa.body.as_router().unwrap();
        lsa_body.flags
    }

    fn origin(&self) -> LsaKey<LsaType> {
        let lsa = match self {
            VertexLsa::Network(lsa) => lsa,
            VertexLsa::Router(lsas) => lsas.iter().next().unwrap(),
        };
        lsa.hdr.key()
    }
}

// ===== impl Ospfv3 =====

impl SpfVersion<Self> for Ospfv3 {
    type VertexId = VertexId;
    type VertexLsa = VertexLsa;

    fn spf_computation_type(
        trigger_lsas: &[SpfTriggerLsa<Self>],
    ) -> SpfComputation<Self> {
        // Router-LSA and Network-LSA changes represent topological changes,
        // hence a full SPF run is required to recompute the SPT.
        //
        // Link-LSA and Router Information LSA changes don't strictly require a
        // full SPF run, but doing so greatly simplify things (e.g. no need to
        // keep track of which routes are affected by which SRGBs).
        if trigger_lsas.iter().map(|tlsa| &tlsa.new).any(|lsa| {
            matches!(
                lsa.hdr.lsa_type.function_code_normalized(),
                Some(
                    LsaFunctionCode::Router
                        | LsaFunctionCode::Network
                        | LsaFunctionCode::Link
                        | LsaFunctionCode::RouterInfo
                )
            )
        }) {
            return SpfComputation::Full;
        }

        // Check Intra-Area-Prefix LSA changes.
        //
        // For that to work, for each changed Intra-Area-Prefix LSA, we merge
        // the prefixes from the old and new version of the LSA.
        let intra = trigger_lsas
            .iter()
            .flat_map(|tlsa| std::iter::once(&tlsa.new).chain(tlsa.old.iter()))
            .filter_map(|lsa| lsa.body.as_intra_area_prefix())
            .flat_map(|lsa_body| {
                lsa_body.prefixes.iter().map(move |prefix| prefix.value)
            })
            .collect();

        // Check Inter-Area-Prefix LSA changes.
        let inter_network = trigger_lsas
            .iter()
            .map(|tlsa| &tlsa.new)
            .filter_map(|lsa| lsa.body.as_inter_area_prefix())
            .map(|lsa_body| lsa_body.prefix)
            .collect();

        // Check Inter-Area-Router LSA changes.
        let inter_router = trigger_lsas
            .iter()
            .map(|tlsa| &tlsa.new)
            .filter_map(|lsa| lsa.body.as_inter_area_router())
            .map(|lsa_body| lsa_body.router_id)
            .collect::<BTreeSet<_>>();

        // Check AS-External LSA changes.
        let external = trigger_lsas
            .iter()
            .map(|tlsa| &tlsa.new)
            .filter_map(|lsa| lsa.body.as_as_external())
            .map(|lsa_body| lsa_body.prefix)
            .collect();

        SpfComputation::Partial(SpfPartialComputation {
            intra,
            inter_network,
            inter_router,
            external,
        })
    }

    fn calc_nexthops(
        area: &Area<Self>,
        parent: &Vertex<Self>,
        parent_link: Option<(usize, &LsaRouterLink)>,
        dest_id: VertexId,
        dest_lsa: &VertexLsa,
        interfaces: &Arena<Interface<Self>>,
        _neighbors: &Arena<Neighbor<Self>>,
        extended_lsa: bool,
        lsa_entries: &Arena<LsaEntry<Self>>,
    ) -> Result<Nexthops<IpAddr>, Error<Self>> {
        let mut nexthops = Nexthops::new();

        match &parent.lsa {
            // The parent vertex is the root.
            VertexLsa::Router(_parent_lsa) => {
                // The destination is either a directly connected network or
                // directly connected router.
                // The outgoing interface in this case is simply the OSPF
                // interface connecting to the destination network/router.
                let (_, parent_link) = parent_link.unwrap();

                // Get nexthop interface.
                let (iface_idx, iface) = area
                    .interfaces
                    .get_by_ifindex(interfaces, parent_link.iface_id as _)
                    .ok_or(Error::SpfNexthopCalcError(dest_id))?;

                // If the interface is a virtual link, do not resolve the
                // nexthop here. Virtual link nexthops are handled later,
                // as specified in RFC 2328 section 16.3.
                if iface.is_virtual_link() {
                    return Ok(nexthops);
                }

                match dest_lsa {
                    VertexLsa::Router(dest_lsa) => {
                        let nexthop_addr = calc_nexthop_lladdr(
                            iface,
                            parent_link.nbr_router_id,
                            parent_link.nbr_iface_id,
                            extended_lsa,
                            lsa_entries,
                        )
                        .ok_or(Error::SpfNexthopCalcError(dest_id))?;
                        let nbr_router_id =
                            dest_lsa.iter().next().unwrap().hdr.adv_rtr;

                        // Add nexthop.
                        nexthops.insert(
                            NexthopKey::new(iface_idx, Some(nexthop_addr)),
                            Nexthop::new(
                                iface_idx,
                                Some(nexthop_addr),
                                Some(nbr_router_id),
                            ),
                        );
                    }
                    VertexLsa::Network(_lsa) => {
                        // Add nexthop.
                        nexthops.insert(
                            NexthopKey::new(iface_idx, None),
                            Nexthop::new(iface_idx, None, None),
                        );
                    }
                }
            }
            // The parent vertex is a network that directly connects the
            // calculating router to the destination router.
            VertexLsa::Network(parent_lsa) => {
                // The list of next hops is then determined by examining the
                // destination's router-LSA. For each link in the router-LSA
                // that points back to the parent network, the link's Link
                // Data field provides the IP address of a next hop router.
                let dest_lsa = dest_lsa.as_router().unwrap();
                let dest_link = dest_lsa
                    .iter()
                    .map(|dest_lsa| dest_lsa.body.as_router().unwrap())
                    .flat_map(|dest_lsa_body| dest_lsa_body.links.iter())
                    .find(|dest_link| {
                        dest_link.nbr_router_id == parent_lsa.hdr.adv_rtr
                            && Ipv4Addr::from(dest_link.nbr_iface_id)
                                == parent_lsa.hdr.lsa_id
                    })
                    .ok_or(Error::SpfNexthopCalcError(dest_id))?;

                // Inherit outgoing interface from the parent network.
                let iface_idx = parent
                    .nexthops
                    .values()
                    .next()
                    .ok_or(Error::SpfNexthopCalcError(dest_id))?
                    .iface_idx;
                let iface = &interfaces[iface_idx];

                // Get nexthop address.
                let nbr_router_id = dest_lsa.iter().next().unwrap().hdr.adv_rtr;
                let nexthop_addr = calc_nexthop_lladdr(
                    iface,
                    nbr_router_id,
                    dest_link.iface_id,
                    extended_lsa,
                    lsa_entries,
                )
                .ok_or(Error::SpfNexthopCalcError(dest_id))?;

                // Add nexthop.
                nexthops.insert(
                    NexthopKey::new(iface_idx, Some(nexthop_addr)),
                    Nexthop::new(
                        iface_idx,
                        Some(nexthop_addr),
                        Some(nbr_router_id),
                    ),
                );
            }
        }

        Ok(nexthops)
    }

    fn root_neighbor_vertices(
        af: AddressFamily,
        area: &Area<Self>,
        _instance: &InstanceUpView<'_, Self>,
        interfaces: &Arena<Interface<Self>>,
        neighbors: &Arena<Neighbor<Self>>,
        extended_lsa: bool,
        lsa_entries: &Arena<LsaEntry<Self>>,
    ) -> Vec<Vertex<Self>> {
        let mut candidates = Vec::new();

        for iface_idx in area.interfaces.indexes() {
            let iface = &interfaces[iface_idx];
            let Some(mdr) = iface.state.mdr.as_ref() else {
                continue;
            };
            if !iface.is_mdr_enabled()
                || (mdr.config.adj_connectivity == MdrAdjConnectivity::Full
                    && mdr.config.lsa_fullness == MdrLsaFullness::Full)
            {
                continue;
            }

            for nbr in iface.state.neighbors.iter(neighbors) {
                if nbr.state < nsm::State::TwoWay
                    || !(nbr.state == nsm::State::Full || nbr.mdr.routable)
                {
                    continue;
                }
                let Some(remote_iface_id) =
                    nbr.mdr.remote_interface_id.or(nbr.iface_id)
                else {
                    continue;
                };
                let dest_id = VertexId::Router {
                    router_id: nbr.router_id,
                };
                let Some(dest_lsa) = Ospfv3::vertex_lsa_find(
                    af,
                    dest_id,
                    area,
                    extended_lsa,
                    lsa_entries,
                ) else {
                    continue;
                };
                let Some(nexthop_addr) = calc_nexthop_lladdr(
                    iface,
                    nbr.router_id,
                    remote_iface_id,
                    extended_lsa,
                    lsa_entries,
                ) else {
                    continue;
                };

                let mut vertex = Vertex::new(
                    dest_id,
                    dest_lsa,
                    u32::from(
                        nbr.mdr
                            .outgoing_link_metric
                            .unwrap_or(iface.config.cost),
                    ),
                    1,
                );
                vertex.nexthops.insert(
                    NexthopKey::new(iface_idx, Some(nexthop_addr)),
                    Nexthop::new(
                        iface_idx,
                        Some(nexthop_addr),
                        Some(nbr.router_id),
                    ),
                );
                candidates.push(vertex);
            }
        }

        candidates
    }

    fn post_full_spf_rib_update(
        instance: &mut InstanceUpView<'_, Self>,
        areas: &Areas<Self>,
        interfaces: &mut Arena<Interface<Self>>,
        neighbors: &mut Arena<Neighbor<Self>>,
        lsa_entries: &Arena<LsaEntry<Self>>,
    ) -> bool {
        let mut routable_changed = false;

        for area_idx in areas.indexes().collect::<Vec<_>>() {
            let area = &areas[area_idx];
            for iface_idx in area.interfaces.indexes().collect::<Vec<_>>() {
                let iface = &mut interfaces[iface_idx];
                routable_changed |=
                    crate::ospfv3::lsdb::mdr_refresh_interface_lsa_state_after_spf(
                        iface,
                        area,
                        instance,
                        lsa_entries,
                        neighbors,
                    );
            }
        }

        routable_changed
    }

    fn vertex_lsa_find(
        af: AddressFamily,
        id: VertexId,
        area: &Area<Self>,
        extended_lsa: bool,
        lsa_entries: &Arena<LsaEntry<Self>>,
    ) -> Option<VertexLsa> {
        match id {
            VertexId::Network {
                router_id,
                iface_id,
            } => {
                // Network-LSAs are always standalone.
                let lsa_key = LsaKey::new(
                    LsaNetwork::lsa_type(extended_lsa),
                    router_id,
                    Ipv4Addr::from(iface_id),
                );
                area.state
                    .lsdb
                    .get(lsa_entries, &lsa_key)
                    .map(|(_, lse)| &lse.data)
                    .filter(|lsa| !lsa.hdr.is_maxage())
                    .cloned()
                    .map(VertexLsa::Network)
            }
            VertexId::Router { router_id } => {
                // RFC 5340 - Section 4.8.1:
                // "All router-LSAs with the Advertising Router set to V's OSPF
                // Router ID MUST be processed as an aggregate, treating them as
                // fragments of a single large router-LSA".
                let lsas = area
                    .state
                    .lsdb
                    .iter_by_type_advrtr(
                        lsa_entries,
                        LsaRouter::lsa_type(extended_lsa),
                        router_id,
                    )
                    .map(|(_, lse)| &lse.data)
                    .filter(|lsa| !lsa.hdr.is_maxage())
                    .filter(|lsa| {
                        let lsa_body = lsa.body.as_router().unwrap();

                        // Ensure the R and V6 bits are set (except for AFs
                        // other than IPv6 unicast).
                        lsa_body.options.contains(Options::R)
                            && (af != AddressFamily::Ipv6
                                || lsa_body.options.contains(Options::V6))
                    })
                    .cloned()
                    .collect::<Vec<_>>();

                if !lsas.is_empty() {
                    Some(VertexLsa::Router(lsas))
                } else {
                    None
                }
            }
        }
    }

    fn vertex_lsa_links<'a>(
        vertex_lsa: &'a VertexLsa,
        af: AddressFamily,
        area: &'a Area<Ospfv3>,
        extended_lsa: bool,
        lsa_entries: &'a Arena<LsaEntry<Ospfv3>>,
    ) -> Box<dyn Iterator<Item = SpfLink<'a, Ospfv3>> + 'a> {
        match vertex_lsa {
            VertexLsa::Network(lsa) => {
                let lsa_body = lsa.body.as_network().unwrap();
                let iter = lsa_body.attached_rtrs.iter().filter_map(
                    move |router_id| {
                        let link_vid = VertexId::Router {
                            router_id: *router_id,
                        };
                        Ospfv3::vertex_lsa_find(
                            af,
                            link_vid,
                            area,
                            extended_lsa,
                            lsa_entries,
                        )
                        .map(|link_vlsa| {
                            SpfLink::new(None, link_vid, link_vlsa, 0)
                        })
                    },
                );
                Box::new(iter)
            }
            VertexLsa::Router(lsas) => {
                let iter = lsas
                    .iter()
                    .map(|lsa| lsa.body.as_router().unwrap())
                    .flat_map(|lsa| lsa.links.iter())
                    .map(|link| match link.link_type {
                        LsaRouterLinkType::PointToPoint
                        | LsaRouterLinkType::VirtualLink => {
                            let link_vid = VertexId::Router {
                                router_id: link.nbr_router_id,
                            };
                            (link, link_vid, link.metric)
                        }
                        LsaRouterLinkType::TransitNetwork => {
                            let link_vid = VertexId::Network {
                                router_id: link.nbr_router_id,
                                iface_id: link.nbr_iface_id,
                            };
                            (link, link_vid, link.metric)
                        }
                    })
                    .enumerate()
                    .filter_map(move |(link_pos, (link, link_vid, cost))| {
                        Ospfv3::vertex_lsa_find(
                            af,
                            link_vid,
                            area,
                            extended_lsa,
                            lsa_entries,
                        )
                        .map(|link_vlsa| {
                            SpfLink::new(
                                Some((link_pos, link)),
                                link_vid,
                                link_vlsa,
                                cost,
                            )
                        })
                    });
                Box::new(iter)
            }
        }
    }

    fn intra_area_networks<'a>(
        area: &'a Area<Self>,
        extended_lsa: bool,
        lsa_entries: &'a Arena<LsaEntry<Self>>,
    ) -> impl Iterator<Item = SpfIntraAreaNetwork<'a, Self>> + 'a {
        // Instead of examining the stub links within router-LSAs, the list of
        // the area's intra-area-prefix-LSAs is examined.
        area.state
            .lsdb
            .iter_by_type(
                lsa_entries,
                LsaIntraAreaPrefix::lsa_type(extended_lsa),
            )
            .map(|(_, lse)| &lse.data)
            .filter(|lsa| !lsa.hdr.is_maxage())
            .filter_map(move |lsa| {
                // Find SPT vertex corresponding to referenced LSA.
                let lsa_body = lsa.body.as_intra_area_prefix().unwrap();
                if lsa_body.ref_lsa_type == LsaRouter::lsa_type(extended_lsa) {
                    if lsa_body.ref_lsa_id != Ipv4Addr::UNSPECIFIED {
                        return None;
                    }
                    let vid = VertexId::Router {
                        router_id: lsa_body.ref_adv_rtr,
                    };
                    area.state.spt.get(&vid)
                } else if lsa_body.ref_lsa_type
                    == LsaNetwork::lsa_type(extended_lsa)
                {
                    let vid = VertexId::Network {
                        router_id: lsa_body.ref_adv_rtr,
                        iface_id: lsa_body.ref_lsa_id.into(),
                    };
                    area.state.spt.get(&vid)
                } else {
                    None
                }
                .map(|vertex| (vertex, &lsa_body.prefixes))
            })
            .flat_map(|(vertex, prefixes)| {
                prefixes
                    .iter()
                    // A prefix advertisement whose NU-bit is set SHOULD NOT be
                    // included in the routing calculation.
                    .filter(|prefix| {
                        !prefix.options.contains(PrefixOptions::NU)
                    })
                    .cloned()
                    .map(move |prefix| SpfIntraAreaNetwork {
                        vertex,
                        prefix: prefix.value,
                        prefix_options: prefix.options,
                        metric: prefix.metric,
                        prefix_sids: prefix.prefix_sids,
                        bier: prefix.bier,
                    })
            })
    }

    fn inter_area_networks<'a>(
        area: &'a Area<Self>,
        extended_lsa: bool,
        lsa_entries: &'a Arena<LsaEntry<Self>>,
    ) -> impl Iterator<Item = SpfInterAreaNetwork<Self>> + 'a {
        area.state
            .lsdb
            .iter_by_type(
                lsa_entries,
                LsaInterAreaPrefix::lsa_type(extended_lsa),
            )
            .map(|(_, lse)| &lse.data)
            .filter(|lsa| !lsa.hdr.is_maxage())
            .filter_map(|lsa| {
                let lsa_body = lsa.body.as_inter_area_prefix().unwrap();
                (!lsa_body.prefix_options.contains(PrefixOptions::NU))
                    .then_some(SpfInterAreaNetwork {
                        adv_rtr: lsa.hdr.adv_rtr,
                        prefix: lsa_body.prefix,
                        prefix_options: lsa_body.prefix_options,
                        metric: lsa_body.metric,
                        prefix_sids: lsa_body.prefix_sids.clone(),
                    })
            })
    }

    fn inter_area_routers<'a>(
        lsdb: &'a Lsdb<Self>,
        extended_lsa: bool,
        lsa_entries: &'a Arena<LsaEntry<Self>>,
    ) -> impl Iterator<Item = SpfInterAreaRouter<Self>> + 'a {
        lsdb.iter_by_type(
            lsa_entries,
            LsaInterAreaRouter::lsa_type(extended_lsa),
        )
        .map(|(_, lse)| &lse.data)
        .filter(|lsa| !lsa.hdr.is_maxage())
        .map(|lsa| {
            let lsa_body = lsa.body.as_inter_area_router().unwrap();
            SpfInterAreaRouter {
                adv_rtr: lsa.hdr.adv_rtr,
                router_id: lsa_body.router_id,
                options: lsa_body.options,
                flags: LsaRouterFlags::E,
                metric: lsa_body.metric,
            }
        })
    }

    fn external_networks<'a>(
        lsdb: &'a Lsdb<Self>,
        extended_lsa: bool,
        lsa_entries: &'a Arena<LsaEntry<Self>>,
    ) -> impl Iterator<Item = SpfExternalNetwork<Self>> + 'a {
        lsdb.iter_by_type(lsa_entries, LsaAsExternal::lsa_type(extended_lsa))
            .map(|(_, lse)| &lse.data)
            .filter(|lsa| !lsa.hdr.is_maxage())
            .filter_map(|lsa| {
                let lsa_body = lsa.body.as_as_external().unwrap();
                (!lsa_body.prefix_options.contains(PrefixOptions::NU))
                    .then_some(SpfExternalNetwork {
                        adv_rtr: lsa.hdr.adv_rtr,
                        e_bit: lsa_body.flags.contains(LsaAsExternalFlags::E),
                        prefix: lsa_body.prefix,
                        prefix_options: lsa_body.prefix_options,
                        metric: lsa_body.metric,
                        fwd_addr: lsa_body.fwd_addr,
                        tag: lsa_body.tag,
                    })
            })
    }

    fn area_router_information<'a>(
        lsdb: &'a Lsdb<Self>,
        router_id: Ipv4Addr,
        lsa_entries: &'a Arena<LsaEntry<Self>>,
    ) -> SpfRouterInfo<'a> {
        let mut ri_agg = SpfRouterInfo::default();

        for ri_lsa in lsdb
            .iter_by_type_advrtr(
                lsa_entries,
                LsaRouterInfo::lsa_type_scope(LsaScopeCode::Area),
                router_id,
            )
            .map(|(_, lse)| &lse.data)
            .filter(|lsa| !lsa.hdr.is_maxage())
            .filter_map(|lsa| lsa.body.as_router_info())
        {
            if let Some(sr_algo) = &ri_lsa.sr_algo {
                // When multiple SR-Algorithm TLVs are received from a given
                // router, the receiver MUST use the first occurrence of the TLV
                // in the Router Information Opaque LSA.
                //
                // If the SR-Algorithm TLV appears in multiple RI Opaque LSAs
                // that have the same flooding scope, the SR-Algorithm TLV in RI
                // Opaque LSA with the numerically smallest Instance ID MUST be
                // used and subsequent instances of the SR-Algorithm TLV MUST be
                // ignored.
                ri_agg.sr_algo.get_or_insert(sr_algo);
            }

            // Multiple occurrences of the SID/Label Range TLV MAY be advertised
            // in order to advertise multiple ranges.
            ri_agg.srgb.extend(&ri_lsa.srgb);
        }

        ri_agg
    }
}

// ===== helper functions =====

fn calc_nexthop_lladdr(
    iface: &Interface<Ospfv3>,
    nbr_router_id: Ipv4Addr,
    nbr_iface_id: u32,
    extended_lsa: bool,
    lsa_entries: &Arena<LsaEntry<Ospfv3>>,
) -> Option<IpAddr> {
    let lsa_key = LsaKey::new(
        LsaLink::lsa_type(extended_lsa),
        nbr_router_id,
        Ipv4Addr::from(nbr_iface_id),
    );
    iface
        .state
        .lsdb
        .get(lsa_entries, &lsa_key)
        .map(|(_, lse)| &lse.data)
        .filter(|lsa| !lsa.hdr.is_maxage())
        .map(|lsa| lsa.body.as_link().unwrap().linklocal)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
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
    use crate::collections::{AreaIndex, InterfaceIndex, LsdbIndex};
    use crate::instance::Instance;
    use crate::interface::InterfaceType;
    use crate::lsdb::{self, LSA_INIT_SEQ_NO, LSA_MAX_AGE};
    use crate::neighbor::nsm;
    use crate::ospfv3::packet::lsa::{LsaBody, LsaIntraAreaPrefixEntry};
    use crate::packet::lsa::LsaTypeVersion;
    use crate::route::PathType;
    use crate::version::Version;

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

    fn linklocal(octet: u8) -> IpAddr {
        IpAddr::V6(
            format!("fe80::{octet}")
                .parse()
                .expect("test link-local address"),
        )
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

    fn add_mdr_interface(
        instance: &mut Instance<Ospfv3>,
    ) -> (AreaIndex, InterfaceIndex) {
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
        iface.config.enabled = true;
        iface.config.if_type = InterfaceType::Broadcast;
        iface.config.cost = 7;
        iface.config.mdr.enabled = true;

        instance.update();

        (area_idx, iface_idx)
    }

    fn add_mdr_neighbor(
        instance: &mut Instance<Ospfv3>,
        iface_idx: InterfaceIndex,
        router_id: Ipv4Addr,
        remote_iface_id: u32,
        state: nsm::State,
        outgoing_metric: u16,
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
        nbr.iface_id = Some(remote_iface_id);
        nbr.mdr.remote_interface_id = Some(remote_iface_id);
        nbr.mdr.reverse_2way = state >= nsm::State::TwoWay;
        nbr.mdr.outgoing_link_metric = Some(outgoing_metric);
    }

    fn ospfv3_options() -> Options {
        Options::R | Options::V6
    }

    fn install_lsa(
        instance: &mut Instance<Ospfv3>,
        lsdb_idx: LsdbIndex,
        lsa: Lsa<Ospfv3>,
    ) {
        let (mut instance_view, arenas) = instance.as_up().unwrap();
        lsdb::install(&mut instance_view, arenas, lsdb_idx, Arc::new(lsa));
    }

    fn install_router_lsa(
        instance: &mut Instance<Ospfv3>,
        area_idx: AreaIndex,
        adv_router: Ipv4Addr,
        links: &[(u16, u32, Ipv4Addr)],
    ) {
        let links = links
            .iter()
            .copied()
            .map(|(metric, nbr_iface_id, nbr_router_id)| {
                LsaRouterLink::new(
                    LsaRouterLinkType::PointToPoint,
                    metric,
                    1,
                    nbr_iface_id,
                    nbr_router_id,
                    Default::default(),
                )
            })
            .collect();
        let lsa = Lsa::new(
            0,
            Some(ospfv3_options()),
            Ipv4Addr::UNSPECIFIED,
            adv_router,
            LSA_INIT_SEQ_NO,
            LsaBody::Router(LsaRouter::new(
                false,
                LsaRouterFlags::empty(),
                ospfv3_options(),
                links,
            )),
        );
        install_lsa(instance, LsdbIndex::Area(area_idx), lsa);
    }

    fn install_link_lsa(
        instance: &mut Instance<Ospfv3>,
        area_idx: AreaIndex,
        iface_idx: InterfaceIndex,
        adv_router: Ipv4Addr,
        remote_iface_id: u32,
        next_hop: IpAddr,
    ) {
        let lsa = Lsa::new(
            0,
            Some(ospfv3_options()),
            Ipv4Addr::from(remote_iface_id),
            adv_router,
            LSA_INIT_SEQ_NO,
            LsaBody::Link(LsaLink::new(
                false,
                1,
                ospfv3_options(),
                next_hop,
                Vec::new(),
            )),
        );
        install_lsa(instance, LsdbIndex::Link(area_idx, iface_idx), lsa);
    }

    fn install_prefix_lsa(
        instance: &mut Instance<Ospfv3>,
        area_idx: AreaIndex,
        adv_router: Ipv4Addr,
        prefix: &str,
        metric: u16,
    ) {
        let lsa = Lsa::new(
            0,
            Some(ospfv3_options()),
            Ipv4Addr::UNSPECIFIED,
            adv_router,
            LSA_INIT_SEQ_NO,
            LsaBody::IntraAreaPrefix(LsaIntraAreaPrefix::new(
                false,
                LsaRouter::lsa_type(false),
                Ipv4Addr::UNSPECIFIED,
                adv_router,
                vec![LsaIntraAreaPrefixEntry::new(
                    PrefixOptions::empty(),
                    prefix.parse().expect("test prefix"),
                    metric,
                )],
            )),
        );
        install_lsa(instance, LsdbIndex::Area(area_idx), lsa);
    }

    fn install_maxage_prefix_lsa(
        instance: &mut Instance<Ospfv3>,
        area_idx: AreaIndex,
        adv_router: Ipv4Addr,
        prefix: &str,
    ) {
        let lsa = Lsa::new(
            LSA_MAX_AGE,
            Some(ospfv3_options()),
            Ipv4Addr::UNSPECIFIED,
            adv_router,
            LSA_INIT_SEQ_NO + 1,
            LsaBody::IntraAreaPrefix(LsaIntraAreaPrefix::new(
                false,
                LsaRouter::lsa_type(false),
                Ipv4Addr::UNSPECIFIED,
                adv_router,
                vec![LsaIntraAreaPrefixEntry::new(
                    PrefixOptions::empty(),
                    prefix.parse().expect("test prefix"),
                    0,
                )],
            )),
        );
        install_lsa(instance, LsdbIndex::Area(area_idx), lsa);
    }

    fn run_full_spf(instance: &mut Instance<Ospfv3>) {
        let (mut instance_view, arenas) = instance.as_up().unwrap();
        crate::spf::fsm(
            crate::spf::fsm::Event::ConfigChange,
            &mut instance_view,
            arenas,
        )
        .expect("SPF run");
    }

    fn assert_route(
        instance: &Instance<Ospfv3>,
        prefix: &str,
        expected_next_hop: IpAddr,
        expected_metric: u32,
    ) {
        let prefix = prefix.parse::<IpNetwork>().expect("test prefix");
        let state = instance.state.as_ref().expect("instance up");
        let route = state.rib.get(&prefix).expect("route installed");
        assert_eq!(route.path_type, PathType::IntraArea);
        assert_eq!(route.metric, expected_metric);
        let nexthops = route.nexthops.values().collect::<Vec<_>>();
        assert_eq!(nexthops.len(), 1);
        let nexthop = nexthops[0];
        assert_eq!(nexthop.addr, Some(expected_next_hop));
    }

    fn assert_no_route(instance: &Instance<Ospfv3>, prefix: &str) {
        let prefix = prefix.parse::<IpNetwork>().expect("test prefix");
        let state = instance.state.as_ref().expect("instance up");
        assert!(!state.rib.contains_key(&prefix));
    }

    fn set_neighbor_state(
        instance: &mut Instance<Ospfv3>,
        iface_idx: InterfaceIndex,
        router_id: Ipv4Addr,
        state: nsm::State,
    ) {
        let nbr_idx = instance.arenas.interfaces[iface_idx]
            .state
            .neighbors
            .get_by_router_id(&instance.arenas.neighbors, router_id)
            .map(|(nbr_idx, _)| nbr_idx)
            .expect("test neighbor");
        let nbr = &mut instance.arenas.neighbors[nbr_idx];
        nbr.state = state;
        nbr.mdr.reverse_2way = state >= nsm::State::TwoWay;
        if state < nsm::State::TwoWay {
            nbr.mdr.routable = false;
        }
    }

    fn neighbor_is_routable(
        instance: &Instance<Ospfv3>,
        iface_idx: InterfaceIndex,
        router_id: Ipv4Addr,
    ) -> bool {
        instance.arenas.interfaces[iface_idx]
            .state
            .neighbors
            .get_by_router_id(&instance.arenas.neighbors, router_id)
            .map(|(_, nbr)| nbr.mdr.routable)
            .expect("test neighbor")
    }

    /// Validates RFC 5614 §10 dummy-root handling and RFC 5340 §4.8.2
    /// Link-LSA next-hop resolution for a direct MDR root neighbor.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/10.json,
    /// rfcs/parsed/chunks/5340/{4.8.1,4.8.2,4.8.3}.json
    #[tokio::test]
    async fn mdr_two_node_route_install_uses_link_lsa_next_hop_and_metric() {
        let mut instance = test_instance();
        let (area_idx, iface_idx) = add_mdr_interface(&mut instance);
        let nbr_b = router_id(2);

        add_mdr_neighbor(
            &mut instance,
            iface_idx,
            nbr_b,
            2,
            nsm::State::Full,
            5,
        );
        install_router_lsa(&mut instance, area_idx, local_router_id(), &[]);
        install_router_lsa(&mut instance, area_idx, nbr_b, &[]);
        install_link_lsa(
            &mut instance,
            area_idx,
            iface_idx,
            nbr_b,
            2,
            linklocal(2),
        );
        install_prefix_lsa(
            &mut instance,
            area_idx,
            nbr_b,
            "2001:db8:2::/128",
            0,
        );

        run_full_spf(&mut instance);

        assert_route(&instance, "2001:db8:2::/128", linklocal(2), 5);
    }

    /// Validates that a multi-hop MDR Router-LSA chain inherits the root
    /// neighbor next hop while accumulating Router-LSA point-to-point metrics.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/10.json,
    /// rfcs/parsed/chunks/2328/{16,16.1}.json
    #[tokio::test]
    async fn mdr_line_topology_installs_remote_prefix_with_root_neighbor_next_hop()
     {
        let mut instance = test_instance();
        let (area_idx, iface_idx) = add_mdr_interface(&mut instance);
        let nbr_b = router_id(2);
        let remote_c = router_id(3);

        add_mdr_neighbor(
            &mut instance,
            iface_idx,
            nbr_b,
            2,
            nsm::State::Full,
            5,
        );
        install_router_lsa(&mut instance, area_idx, local_router_id(), &[]);
        install_router_lsa(&mut instance, area_idx, nbr_b, &[(3, 3, remote_c)]);
        install_router_lsa(&mut instance, area_idx, remote_c, &[(3, 2, nbr_b)]);
        install_link_lsa(
            &mut instance,
            area_idx,
            iface_idx,
            nbr_b,
            2,
            linklocal(2),
        );
        install_prefix_lsa(
            &mut instance,
            area_idx,
            remote_c,
            "2001:db8:3::/128",
            4,
        );

        run_full_spf(&mut instance);

        assert_route(&instance, "2001:db8:3::/128", linklocal(2), 12);
    }

    /// Validates a triangle MDR topology with two root neighbors. The lower
    /// direct root metric wins even though the routers also describe each
    /// other through Router-LSAs.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/10.json,
    /// rfcs/parsed/chunks/2328/16.1.json
    #[tokio::test]
    async fn mdr_triangle_topology_prefers_direct_root_neighbor_metric() {
        let mut instance = test_instance();
        let (area_idx, iface_idx) = add_mdr_interface(&mut instance);
        let nbr_b = router_id(2);
        let nbr_c = router_id(3);

        add_mdr_neighbor(
            &mut instance,
            iface_idx,
            nbr_b,
            2,
            nsm::State::Full,
            5,
        );
        add_mdr_neighbor(
            &mut instance,
            iface_idx,
            nbr_c,
            3,
            nsm::State::Full,
            2,
        );
        install_router_lsa(&mut instance, area_idx, local_router_id(), &[]);
        install_router_lsa(&mut instance, area_idx, nbr_b, &[(5, 3, nbr_c)]);
        install_router_lsa(&mut instance, area_idx, nbr_c, &[(5, 2, nbr_b)]);
        install_link_lsa(
            &mut instance,
            area_idx,
            iface_idx,
            nbr_b,
            2,
            linklocal(2),
        );
        install_link_lsa(
            &mut instance,
            area_idx,
            iface_idx,
            nbr_c,
            3,
            linklocal(3),
        );
        install_prefix_lsa(
            &mut instance,
            area_idx,
            nbr_b,
            "2001:db8:2::/128",
            0,
        );
        install_prefix_lsa(
            &mut instance,
            area_idx,
            nbr_c,
            "2001:db8:3::/128",
            0,
        );

        run_full_spf(&mut instance);

        assert_route(&instance, "2001:db8:2::/128", linklocal(2), 5);
        assert_route(&instance, "2001:db8:3::/128", linklocal(3), 2);
    }

    /// Validates a square topology where a backup side of the square provides
    /// the lower-cost path to the remote router.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/10.json,
    /// rfcs/parsed/chunks/2328/16.1.json
    #[tokio::test]
    async fn mdr_square_with_backup_topology_uses_best_available_side() {
        let mut instance = test_instance();
        let (area_idx, iface_idx) = add_mdr_interface(&mut instance);
        let nbr_b = router_id(2);
        let nbr_c = router_id(3);
        let remote_d = router_id(4);

        add_mdr_neighbor(
            &mut instance,
            iface_idx,
            nbr_b,
            2,
            nsm::State::Full,
            1,
        );
        add_mdr_neighbor(
            &mut instance,
            iface_idx,
            nbr_c,
            3,
            nsm::State::Full,
            4,
        );
        install_router_lsa(&mut instance, area_idx, local_router_id(), &[]);
        install_router_lsa(&mut instance, area_idx, nbr_b, &[(5, 4, remote_d)]);
        install_router_lsa(&mut instance, area_idx, nbr_c, &[(1, 4, remote_d)]);
        install_router_lsa(
            &mut instance,
            area_idx,
            remote_d,
            &[(5, 2, nbr_b), (1, 3, nbr_c)],
        );
        install_link_lsa(
            &mut instance,
            area_idx,
            iface_idx,
            nbr_b,
            2,
            linklocal(2),
        );
        install_link_lsa(
            &mut instance,
            area_idx,
            iface_idx,
            nbr_c,
            3,
            linklocal(3),
        );
        install_prefix_lsa(
            &mut instance,
            area_idx,
            remote_d,
            "2001:db8:4::/128",
            0,
        );

        run_full_spf(&mut instance);

        assert_route(&instance, "2001:db8:4::/128", linklocal(3), 5);
    }

    /// Validates that total Router-LSA path metric, not only direct root cost,
    /// selects the next hop for a remote prefix.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/10.json,
    /// rfcs/parsed/chunks/5340/4.8.3.json
    #[tokio::test]
    async fn mdr_metric_preferred_relay_uses_total_router_lsa_cost() {
        let mut instance = test_instance();
        let (area_idx, iface_idx) = add_mdr_interface(&mut instance);
        let nbr_b = router_id(2);
        let nbr_c = router_id(3);
        let remote_d = router_id(4);

        add_mdr_neighbor(
            &mut instance,
            iface_idx,
            nbr_b,
            2,
            nsm::State::Full,
            10,
        );
        add_mdr_neighbor(
            &mut instance,
            iface_idx,
            nbr_c,
            3,
            nsm::State::Full,
            1,
        );
        install_router_lsa(&mut instance, area_idx, local_router_id(), &[]);
        install_router_lsa(&mut instance, area_idx, nbr_b, &[(1, 4, remote_d)]);
        install_router_lsa(
            &mut instance,
            area_idx,
            nbr_c,
            &[(20, 4, remote_d)],
        );
        install_router_lsa(
            &mut instance,
            area_idx,
            remote_d,
            &[(1, 2, nbr_b), (20, 3, nbr_c)],
        );
        install_link_lsa(
            &mut instance,
            area_idx,
            iface_idx,
            nbr_b,
            2,
            linklocal(2),
        );
        install_link_lsa(
            &mut instance,
            area_idx,
            iface_idx,
            nbr_c,
            3,
            linklocal(3),
        );
        install_prefix_lsa(
            &mut instance,
            area_idx,
            remote_d,
            "2001:db8:44::/128",
            0,
        );

        run_full_spf(&mut instance);

        assert_route(&instance, "2001:db8:44::/128", linklocal(2), 11);
    }

    /// Validates route withdrawal and reinstallation through the native full
    /// SPF/RIB path when the root neighbor is lost and later restored.
    ///
    /// RFC chunks: rfcs/parsed/chunks/2328/16.json,
    /// rfcs/parsed/chunks/5614/10.json
    #[tokio::test]
    async fn mdr_partition_withdraws_and_heal_reinstalls_route() {
        let mut instance = test_instance();
        let (area_idx, iface_idx) = add_mdr_interface(&mut instance);
        let nbr_b = router_id(2);
        let remote_c = router_id(3);

        add_mdr_neighbor(
            &mut instance,
            iface_idx,
            nbr_b,
            2,
            nsm::State::Full,
            5,
        );
        install_router_lsa(&mut instance, area_idx, local_router_id(), &[]);
        install_router_lsa(&mut instance, area_idx, nbr_b, &[(3, 3, remote_c)]);
        install_router_lsa(&mut instance, area_idx, remote_c, &[(3, 2, nbr_b)]);
        install_link_lsa(
            &mut instance,
            area_idx,
            iface_idx,
            nbr_b,
            2,
            linklocal(2),
        );
        install_prefix_lsa(
            &mut instance,
            area_idx,
            remote_c,
            "2001:db8:30::/128",
            0,
        );

        run_full_spf(&mut instance);
        assert_route(&instance, "2001:db8:30::/128", linklocal(2), 8);

        set_neighbor_state(&mut instance, iface_idx, nbr_b, nsm::State::Down);
        run_full_spf(&mut instance);
        assert_no_route(&instance, "2001:db8:30::/128");

        set_neighbor_state(&mut instance, iface_idx, nbr_b, nsm::State::Full);
        run_full_spf(&mut instance);
        assert_route(&instance, "2001:db8:30::/128", linklocal(2), 8);
    }

    /// Validates RFC 5614 §10's two-calculation rule: a non-Full neighbor can
    /// become routable after the first SPF/RIB calculation without any LSA body
    /// delta, and the immediate second calculation uses it as a root next hop.
    ///
    /// RFC chunk: rfcs/parsed/chunks/5614/10.json
    #[tokio::test]
    async fn mdr_routable_set_change_without_lsa_delta_runs_second_calculation()
    {
        let mut instance = test_instance();
        let (area_idx, iface_idx) = add_mdr_interface(&mut instance);
        let nbr_b = router_id(2);
        let nbr_c = router_id(3);

        add_mdr_neighbor(
            &mut instance,
            iface_idx,
            nbr_b,
            2,
            nsm::State::Full,
            10,
        );
        add_mdr_neighbor(
            &mut instance,
            iface_idx,
            nbr_c,
            3,
            nsm::State::TwoWay,
            2,
        );
        install_router_lsa(&mut instance, area_idx, local_router_id(), &[]);
        install_router_lsa(&mut instance, area_idx, nbr_b, &[(1, 3, nbr_c)]);
        install_router_lsa(&mut instance, area_idx, nbr_c, &[(1, 2, nbr_b)]);
        install_link_lsa(
            &mut instance,
            area_idx,
            iface_idx,
            nbr_b,
            2,
            linklocal(2),
        );
        install_link_lsa(
            &mut instance,
            area_idx,
            iface_idx,
            nbr_c,
            3,
            linklocal(3),
        );
        install_prefix_lsa(
            &mut instance,
            area_idx,
            nbr_c,
            "2001:db8:33::/128",
            0,
        );

        assert!(!neighbor_is_routable(&instance, iface_idx, nbr_c));
        run_full_spf(&mut instance);

        assert!(neighbor_is_routable(&instance, iface_idx, nbr_c));
        assert_eq!(instance.arenas.areas[area_idx].state.spf_run_count, 2);
        assert_route(&instance, "2001:db8:33::/128", linklocal(3), 2);
    }

    /// Validates that a MaxAge router-referenced prefix LSA withdrawal is
    /// removed through the same native full SPF/RIB path.
    ///
    /// RFC chunk: rfcs/parsed/chunks/2328/16.json
    #[tokio::test]
    async fn mdr_maxage_prefix_lsa_withdraws_installed_route() {
        let mut instance = test_instance();
        let (area_idx, iface_idx) = add_mdr_interface(&mut instance);
        let nbr_b = router_id(2);

        add_mdr_neighbor(
            &mut instance,
            iface_idx,
            nbr_b,
            2,
            nsm::State::Full,
            5,
        );
        install_router_lsa(&mut instance, area_idx, local_router_id(), &[]);
        install_router_lsa(&mut instance, area_idx, nbr_b, &[]);
        install_link_lsa(
            &mut instance,
            area_idx,
            iface_idx,
            nbr_b,
            2,
            linklocal(2),
        );
        install_prefix_lsa(
            &mut instance,
            area_idx,
            nbr_b,
            "2001:db8:22::/128",
            0,
        );

        run_full_spf(&mut instance);
        assert_route(&instance, "2001:db8:22::/128", linklocal(2), 5);

        install_maxage_prefix_lsa(
            &mut instance,
            area_idx,
            nbr_b,
            "2001:db8:22::/128",
        );
        run_full_spf(&mut instance);

        assert_no_route(&instance, "2001:db8:22::/128");
    }
}
