//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use holo_utils::ip::{AddressFamily, Ipv6AddrExt};
use holo_utils::southbound::InterfaceFlags;

use crate::area::{Area, AreaVersion, OptionsLocation};
use crate::collections::{Arena, NeighborIndex};
use crate::debug::InterfaceInactiveReason;
use crate::error::{Error, InterfaceCfgError};
use crate::instance::InstanceUpView;
use crate::interface::{self, Interface, InterfaceSys, InterfaceVersion};
use crate::lsdb::LsaEntry;
use crate::neighbor::{Neighbor, NeighborNetId, nsm};
use crate::network::{MulticastAddr, NetworkVersion};
use crate::northbound::configuration::{MdrAdjConnectivity, MdrLsaFullness};
use crate::ospfv3;
use crate::ospfv3::lsdb::mdr_refresh_interface_lsa_state;
use crate::ospfv3::mdr::{MdrHelloListType, MdrLevel};
use crate::ospfv3::packet::iana::Options;
use crate::ospfv3::packet::{Hello, PacketHdr};
use crate::packet::Packet;
use crate::packet::auth::AuthMethod;
use crate::packet::iana::PacketType;
use crate::packet::lls::{
    LlsHelloData, MdrHelloTlv, MdrMetricEntry, MdrMetricTlv,
};
use crate::version::Ospfv3;

#[derive(Default)]
struct MdrHelloNeighborLists {
    down: Vec<Ipv4Addr>,
    init: Vec<Ipv4Addr>,
    dependent: Vec<Ipv4Addr>,
    selected_advertised: Vec<Ipv4Addr>,
    bidirectional: Vec<Ipv4Addr>,
}

impl MdrHelloNeighborLists {
    fn push(&mut self, list_type: MdrHelloListType, router_id: Ipv4Addr) {
        match list_type {
            MdrHelloListType::Down => self.down.push(router_id),
            MdrHelloListType::Init => self.init.push(router_id),
            MdrHelloListType::Dependent => self.dependent.push(router_id),
            MdrHelloListType::SelectedAdvertised => {
                self.selected_advertised.push(router_id);
            }
            MdrHelloListType::Bidirectional => {
                self.bidirectional.push(router_id);
            }
        }
    }

    fn ordered(&self) -> Vec<Ipv4Addr> {
        let mut neighbors = Vec::with_capacity(
            self.down.len()
                + self.init.len()
                + self.dependent.len()
                + self.selected_advertised.len()
                + self.bidirectional.len(),
        );
        neighbors.extend(self.down.iter().copied());
        neighbors.extend(self.init.iter().copied());
        neighbors.extend(self.dependent.iter().copied());
        neighbors.extend(self.selected_advertised.iter().copied());
        neighbors.extend(self.bidirectional.iter().copied());
        neighbors
    }

    fn bidirectional_neighbors(&self) -> Vec<Ipv4Addr> {
        let mut neighbors = Vec::with_capacity(
            self.dependent.len()
                + self.selected_advertised.len()
                + self.bidirectional.len(),
        );
        neighbors.extend(self.dependent.iter().copied());
        neighbors.extend(self.selected_advertised.iter().copied());
        neighbors.extend(self.bidirectional.iter().copied());
        neighbors
    }
}

fn mdr_neighbor_is_bidirectional(nbr: &Neighbor<Ospfv3>) -> bool {
    nbr.state >= nsm::State::TwoWay
}

fn mdr_hello_list_type(nbr: &Neighbor<Ospfv3>) -> Option<MdrHelloListType> {
    match nbr.state {
        nsm::State::Down => Some(MdrHelloListType::Down),
        nsm::State::Init => Some(MdrHelloListType::Init),
        _ if nbr.mdr.dependent => Some(MdrHelloListType::Dependent),
        _ if nbr.mdr.selected_advertised => {
            Some(MdrHelloListType::SelectedAdvertised)
        }
        _ if mdr_neighbor_is_bidirectional(nbr) => {
            Some(MdrHelloListType::Bidirectional)
        }
        _ => None,
    }
}

fn mdr_hello_should_include_differential(
    nbr: &Neighbor<Ospfv3>,
    interface_hsn: u16,
    hello_repeat_count: u16,
) -> bool {
    if hello_repeat_count <= 1 {
        return true;
    }

    interface_hsn.wrapping_sub(nbr.mdr.hello_changed_hsn) < hello_repeat_count
        || (mdr_neighbor_is_bidirectional(nbr) && !nbr.mdr.reverse_2way)
}

fn mdr_effective_outgoing_metric(nbr: &Neighbor<Ospfv3>) -> u16 {
    nbr.mdr.outgoing_link_metric.unwrap_or(1)
}

fn build_mdr_metric_tlv(
    iface: &Interface<Ospfv3>,
    lists: &MdrHelloNeighborLists,
    neighbors: &Arena<Neighbor<Ospfv3>>,
) -> Option<MdrMetricTlv> {
    let mdr = iface.state.mdr.as_ref()?;
    if !mdr.config.metric_tlv_enabled
        || !matches!(
            mdr.config.lsa_fullness,
            MdrLsaFullness::MinCost | MdrLsaFullness::MinCost2Paths
        )
    {
        return None;
    }

    let mut metrics = lists
        .bidirectional_neighbors()
        .into_iter()
        .filter_map(|router_id| {
            let (_, nbr) = iface
                .state
                .neighbors
                .get_by_router_id(neighbors, router_id)?;
            Some((router_id, mdr_effective_outgoing_metric(nbr)))
        })
        .collect::<Vec<_>>();
    if metrics.is_empty() || metrics.iter().all(|(_, metric)| *metric == 1) {
        return None;
    }

    metrics.sort_by_key(|(router_id, _)| *router_id);
    let mut frequencies = BTreeMap::<u16, usize>::new();
    for (_, metric) in &metrics {
        *frequencies.entry(*metric).or_default() += 1;
    }
    let default_metric = frequencies
        .into_iter()
        .max_by(|(left_metric, left_count), (right_metric, right_count)| {
            left_count
                .cmp(right_count)
                .then_with(|| right_metric.cmp(left_metric))
        })
        .map_or(1, |(metric, _)| metric);

    Some(MdrMetricTlv {
        default_metric,
        include_ids: true,
        metrics: metrics
            .into_iter()
            .filter_map(|(router_id, metric)| {
                (metric != default_metric).then_some(MdrMetricEntry {
                    neighbor_id: Some(router_id),
                    metric,
                })
            })
            .collect(),
    })
}

// ===== impl Ospfv3 =====

impl InterfaceVersion<Self> for Ospfv3 {
    fn is_ready(
        af: AddressFamily,
        iface: &Interface<Self>,
    ) -> Result<(), InterfaceInactiveReason> {
        interface::is_ready_common(iface)?;

        if !iface.system.flags.contains(InterfaceFlags::LOOPBACK)
            && iface.system.linklocal_addr.is_none()
        {
            return Err(InterfaceInactiveReason::MissingLinkLocalAddress);
        }

        if af == AddressFamily::Ipv4
            && !iface.system.addr_list.iter().any(|addr| addr.is_ipv4())
        {
            return Err(InterfaceInactiveReason::MissingIpv4Address);
        }

        Ok(())
    }

    fn src_addr(iface_sys: &InterfaceSys<Self>) -> Ipv6Addr {
        iface_sys.linklocal_addr.unwrap().ip()
    }

    fn generate_hello(
        iface: &Interface<Self>,
        area: &Area<Self>,
        instance: &InstanceUpView<'_, Self>,
    ) -> Packet<Self> {
        let hdr = PacketHdr {
            pkt_type: PacketType::Hello,
            router_id: instance.state.router_id,
            area_id: area.area_id,
            instance_id: iface.config.instance_id.resolved,
            auth_seqno: None,
        };

        let lls = if iface.config.lls_enabled {
            // TODO: Get LLS configuration.
            None
        } else {
            None
        };

        Packet::Hello(Hello {
            hdr,
            iface_id: iface.system.ifindex.unwrap(),
            priority: iface.config.priority,
            options: Self::area_options(
                area,
                OptionsLocation::new_packet(
                    PacketType::Hello,
                    iface.state.auth.load().is_some(),
                    lls.is_some(),
                ),
            ),
            hello_interval: iface.config.hello_interval,
            dead_interval: iface.config.dead_interval,
            dr: iface.state.dr,
            bdr: iface.state.bdr,
            neighbors: iface.state.neighbors.router_ids().collect(),
            neighbor_order: None,
            lls,
        })
    }

    fn generate_mdr_hello(
        iface: &mut Interface<Self>,
        area: &Area<Self>,
        instance: &InstanceUpView<'_, Self>,
        lsa_entries: &Arena<LsaEntry<Self>>,
        neighbors: &mut Arena<Neighbor<Self>>,
    ) -> Packet<Self> {
        mdr_refresh_interface_lsa_state(
            iface,
            area,
            instance,
            lsa_entries,
            neighbors,
        );

        let Some(mdr) = iface.state.mdr.as_mut() else {
            return Self::generate_hello(iface, area, instance);
        };

        let neighbor_indexes =
            iface.state.neighbors.indexes().collect::<Vec<_>>();
        let hello_sequence_number = mdr.hello_sequence_number;
        let is_differential = mdr.next_hello_is_differential();
        let hello_repeat_count = mdr.config.full_hello_repeat_count.max(1);
        let adjacency_reduction_disabled =
            mdr.config.adj_connectivity == MdrAdjConnectivity::Full;
        let dr = match mdr.mdr_level {
            MdrLevel::Mdr => Some(instance.state.router_id),
            MdrLevel::Backup | MdrLevel::Other => mdr.parent,
        };
        let bdr = match mdr.mdr_level {
            MdrLevel::Backup => Some(instance.state.router_id),
            MdrLevel::Mdr | MdrLevel::Other => mdr.backup_parent,
        };
        let priority = mdr.config.router_priority;
        let hello_interval = mdr.config.hello_interval;
        let dead_interval = mdr.config.dead_interval;

        let mut lists = MdrHelloNeighborLists::default();
        for nbr_idx in neighbor_indexes {
            let nbr = &mut neighbors[nbr_idx];
            let Some(list_type) = mdr_hello_list_type(nbr) else {
                nbr.mdr.hello_list_type = None;
                nbr.mdr.hello_advertised_metric = None;
                continue;
            };

            let metric = mdr_neighbor_is_bidirectional(nbr)
                .then(|| mdr_effective_outgoing_metric(nbr));
            if nbr.mdr.hello_list_type != Some(list_type)
                || nbr.mdr.hello_advertised_metric != metric
            {
                nbr.mdr.hello_changed_hsn = hello_sequence_number;
                nbr.mdr.hello_list_type = Some(list_type);
                nbr.mdr.hello_advertised_metric = metric;
            }

            if !is_differential && list_type == MdrHelloListType::Down {
                continue;
            }
            if is_differential
                && !mdr_hello_should_include_differential(
                    nbr,
                    hello_sequence_number,
                    hello_repeat_count,
                )
            {
                continue;
            }

            lists.push(list_type, nbr.router_id);
        }

        let metric_tlv = build_mdr_metric_tlv(iface, &lists, neighbors);
        let lls = Some(LlsHelloData {
            eof: None,
            mdr_hello: Some(MdrHelloTlv {
                hello_sequence_number,
                adjacency_reduction_disabled,
                differential: is_differential,
                n1: lists.down.len().min(usize::from(u8::MAX)) as u8,
                n2: lists.init.len().min(usize::from(u8::MAX)) as u8,
                n3: lists.dependent.len().min(usize::from(u8::MAX)) as u8,
                n4: lists.selected_advertised.len().min(usize::from(u8::MAX))
                    as u8,
            }),
            mdr_metric: metric_tlv,
            unknown_tlvs: Vec::new(),
        });

        let ordered_neighbors = lists.ordered();
        let mut options = Self::area_options(
            area,
            OptionsLocation::new_packet(
                PacketType::Hello,
                iface.state.auth.load().is_some(),
                lls.is_some(),
            ),
        );
        // Session-04 MDR oracle fixtures pin the base RFC 5614 Hello option
        // set. RFC 5838 AF-specific MDR behavior remains later-session scope.
        options.remove(Options::AF);
        let packet = Packet::Hello(Hello {
            hdr: PacketHdr {
                pkt_type: PacketType::Hello,
                router_id: instance.state.router_id,
                area_id: area.area_id,
                instance_id: iface.config.instance_id.resolved,
                auth_seqno: None,
            },
            iface_id: iface.system.ifindex.unwrap(),
            priority,
            options,
            hello_interval,
            dead_interval,
            dr: dr.map(NeighborNetId::from),
            bdr: bdr.map(NeighborNetId::from),
            neighbors: ordered_neighbors.iter().copied().collect(),
            neighbor_order: Some(ordered_neighbors),
            lls,
        });

        iface
            .state
            .mdr
            .as_mut()
            .expect("MDR state exists while generating MDR Hello")
            .mark_hello_generated();

        packet
    }

    fn validate_packet_dst(
        iface: &Interface<Self>,
        dst: Ipv6Addr,
    ) -> Result<(), Error<Self>> {
        // Accept only unicast packets on virtual links.
        if iface.is_virtual_link() {
            if dst.is_multicast() {
                return Err(Error::InvalidDstAddr(dst));
            } else {
                return Ok(());
            }
        }

        // Check if the destination matches one of the interface unicast
        // addresses.
        if iface.system.addr_list.iter().any(|addr| addr.ip() == dst) {
            return Ok(());
        }

        // Check if the destination matches AllSPFRouters.
        if dst == *Self::multicast_addr(MulticastAddr::AllSpfRtrs) {
            return Ok(());
        }

        // Packets whose IP destination is AllDRouters should only be accepted
        // if the state of the receiving interface is DR or Backup.
        if dst == *Self::multicast_addr(MulticastAddr::AllDrRtrs)
            && iface.is_dr_or_backup()
        {
            return Ok(());
        }

        Err(Error::InvalidDstAddr(dst))
    }

    fn validate_packet_src(
        _iface: &Interface<Self>,
        src: Ipv6Addr,
    ) -> Result<(), Error<Self>> {
        if !src.is_usable() {
            return Err(Error::InvalidSrcAddr(src));
        }

        Ok(())
    }

    fn packet_instance_id_match(
        iface: &Interface<Self>,
        packet_hdr: &ospfv3::packet::PacketHdr,
    ) -> bool {
        let iface_instance_id = iface.config.instance_id.resolved;
        packet_hdr.instance_id == iface_instance_id
    }

    fn validate_hello(
        _iface: &Interface<Self>,
        hello: &ospfv3::packet::Hello,
    ) -> Result<(), InterfaceCfgError> {
        // Validate the setting of the AF-bit.
        if hello.hdr.instance_id >= 32 && !hello.options.contains(Options::AF) {
            return Err(InterfaceCfgError::AfBitClear);
        }

        Ok(())
    }

    fn max_packet_size(iface: &Interface<Self>) -> u16 {
        const VIRTUAL_LINK_MTU: u16 = 1280;
        const IPV6_HDR_SIZE: u16 = 40;

        let mtu = if iface.is_virtual_link() {
            VIRTUAL_LINK_MTU
        } else {
            iface.system.mtu.unwrap()
        };

        let mut max = mtu - IPV6_HDR_SIZE;

        // Reserve space for the authentication trailer when authentication is
        // enabled.
        let auth_guard = iface.state.auth.load();
        if let Some(auth) = auth_guard.as_ref() {
            max -= ospfv3::packet::AUTH_TRAILER_HDR_SIZE;
            match auth {
                AuthMethod::ManualKey(key) => {
                    max -= key.algo.digest_size() as u16
                }
                AuthMethod::Keychain(keychain) => {
                    max -= keychain.max_digest_size as u16
                }
            }
        }

        max
    }

    fn get_neighbor<'a>(
        iface: &mut Interface<Self>,
        _src: &Ipv6Addr,
        router_id: Ipv4Addr,
        neighbors: &'a mut Arena<Neighbor<Self>>,
    ) -> Option<(NeighborIndex, &'a mut Neighbor<Self>)> {
        // In OSPF for IPv6, neighboring routers on a given link are always
        // identified by their OSPF Router ID.
        iface
            .state
            .neighbors
            .get_mut_by_router_id(neighbors, router_id)
    }
}
