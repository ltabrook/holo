//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, LazyLock as Lazy};
use std::time::Duration;

use arc_swap::ArcSwap;
use enum_as_inner::EnumAsInner;
use holo_northbound::configuration::{
    Callbacks, CallbacksBuilder, InheritableConfig, Provider,
    ValidationCallbacks, ValidationCallbacksBuilder,
};
use holo_utils::bfd;
use holo_utils::crypto::CryptoAlgo;
use holo_utils::ip::{AddressFamily, IpAddrKind, IpNetworkKind};
use holo_utils::protocol::Protocol;
use holo_utils::yang::DataNodeRefExt;
use holo_yang::{ToYang, TryFromYang};
use yang5::data::{Data, DataNodeRef};

use crate::area::{self, AreaType, BACKBONE_AREA_ID};
use crate::collections::{AreaIndex, InterfaceIndex};
use crate::debug::InterfaceInactiveReason;
use crate::instance::Instance;
use crate::interface::{InterfaceType, VirtualLinkKey, ism};
use crate::lsdb::LsaOriginateEvent;
use crate::neighbor::nsm;
use crate::northbound::yang_gen::ospf;
use crate::packet::iana::PacketType;
use crate::route::RouteNetFlags;
use crate::version::{Ospfv2, Ospfv3, Version};
use crate::{gr, ibus, spf, sr, tasks};

#[derive(Debug, EnumAsInner)]
pub enum ListEntry<V: Version> {
    None,
    NodeTag(u32),
    TraceOption(InstanceTraceOption),
    Area(AreaIndex),
    AreaRange(AreaIndex, V::IpNetwork),
    Interface(AreaIndex, InterfaceIndex),
    StaticNbr(InterfaceIndex, V::NetIpAddr),
    InterfaceTraceOption(InterfaceIndex, InterfaceTraceOption),
}

#[derive(Debug)]
pub enum Resource {}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Event {
    InstanceReset,
    InstanceUpdate,
    InstanceIdUpdate,
    AreaCreate(AreaIndex),
    AreaDelete(AreaIndex),
    AreaTypeChange(AreaIndex),
    AreaSyncHelloTx(AreaIndex),
    InterfaceUpdate(AreaIndex, InterfaceIndex),
    InterfaceDelete(AreaIndex, InterfaceIndex),
    InterfaceReset(AreaIndex, InterfaceIndex),
    InterfaceResetHelloInterval(AreaIndex, InterfaceIndex),
    InterfaceResetDeadInterval(AreaIndex, InterfaceIndex),
    InterfacePriorityChange(AreaIndex, InterfaceIndex),
    InterfaceCostChange(AreaIndex),
    InterfaceFlagChange(AreaIndex),
    InterfaceSyncHelloTx(AreaIndex, InterfaceIndex),
    InterfaceMdrConfigChange(AreaIndex, InterfaceIndex),
    InterfaceUpdateAuth(AreaIndex, InterfaceIndex),
    InterfaceBfdChange(InterfaceIndex),
    InterfaceUpdateTraceOptions(InterfaceIndex),
    InterfaceIbusSub(String),
    StubRouterChange,
    GrHelperChange,
    SrEnableChange(bool),
    RerunSpf,
    UpdateVirtualLinks,
    UpdateSummaries,
    ReinstallRoutes,
    BierEnableChange(bool),
    NodeTagsChange,
    UpdateTraceOptions,
}

pub static VALIDATION_CALLBACKS_OSPFV2: Lazy<ValidationCallbacks> =
    Lazy::new(load_validation_callbacks_ospfv2);
pub static VALIDATION_CALLBACKS_OSPFV3: Lazy<ValidationCallbacks> =
    Lazy::new(load_validation_callbacks_ospfv3);
pub static CALLBACKS_OSPFV2: Lazy<Callbacks<Instance<Ospfv2>>> =
    Lazy::new(load_callbacks_ospfv2);
pub static CALLBACKS_OSPFV3: Lazy<Callbacks<Instance<Ospfv3>>> =
    Lazy::new(load_callbacks_ospfv3);

// ===== configuration structs =====

#[derive(Debug)]
pub struct InstanceCfg {
    pub af: Option<AddressFamily>,
    pub enabled: bool,
    pub router_id: Option<Ipv4Addr>,
    pub preference: Preference,
    pub gr: InstanceGrCfg,
    pub max_paths: u16,
    pub spf_initial_delay: u32,
    pub spf_short_delay: u32,
    pub spf_long_delay: u32,
    pub spf_hold_down: u32,
    pub spf_time_to_learn: u32,
    pub stub_router: bool,
    pub node_tags: BTreeSet<u32>,
    pub extended_lsa: bool,
    pub sr_enabled: bool,
    pub instance_id: u8,
    pub bier: BierOspfCfg,
    pub trace_opts: InstanceTraceOptions,
}

#[derive(Debug)]
pub struct BierOspfCfg {
    pub mt_id: u8,
    pub enabled: bool,
    pub advertise: bool,
    pub receive: bool,
}

#[derive(Debug)]
pub struct Preference {
    pub intra_area: u8,
    pub inter_area: u8,
    pub external: u8,
}

#[derive(Debug)]
pub struct InstanceGrCfg {
    pub helper_enabled: bool,
    pub helper_strict_lsa_checking: bool,
}

#[derive(Clone, Copy, Debug)]
pub enum InstanceTraceOption {
    Flooding,
    GracefulRestart,
    InternalBus,
    Lsdb,
    Neighbor,
    PacketsAll,
    PacketsHello,
    PacketsDbDesc,
    PacketsLsUpdate,
    PacketsLsRequest,
    PacketsLsAck,
    Spf,
}

#[derive(Debug, Default)]
pub struct InstanceTraceOptions {
    pub flooding: bool,
    pub gr: bool,
    pub ibus: bool,
    pub lsdb: bool,
    pub neighbor: bool,
    pub packets: TraceOptionPacket,
    pub spf: bool,
}

#[derive(Debug)]
pub struct AreaCfg {
    pub area_type: AreaType,
    pub summary: bool,
    pub default_cost: u32,
}

#[derive(Debug)]
pub struct RangeCfg {
    pub advertise: bool,
    pub cost: Option<u32>,
}

#[derive(Debug)]
pub struct InterfaceCfg<V: Version> {
    pub instance_id: InheritableConfig<u8>,
    pub if_type: InterfaceType,
    pub passive: bool,
    pub priority: u8,
    pub hello_interval: u16,
    pub dead_interval: u16,
    pub retransmit_interval: u16,
    pub transmit_delay: u16,
    pub enabled: bool,
    pub cost: u16,
    pub mtu_ignore: bool,
    pub node_flag: bool,
    pub anycast_flag: bool,
    pub static_nbrs: BTreeMap<V::NetIpAddr, StaticNbr>,
    pub auth_keychain: Option<String>,
    pub auth_keyid: Option<u32>,
    pub auth_key: Option<String>,
    pub auth_algo: Option<CryptoAlgo>,
    pub bfd_enabled: bool,
    pub bfd_params: bfd::ClientCfg,
    pub trace_opts: InterfaceTraceOptions,
    pub lls_enabled: bool,
    pub mdr: MdrInterfaceCfg,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MdrInterfaceCfg {
    pub enabled: bool,
    pub hello_interval: u16,
    pub dead_interval: u16,
    pub retransmit_interval: u16,
    pub router_priority: u8,
    pub adj_connectivity: MdrAdjConnectivity,
    pub lsa_fullness: MdrLsaFullness,
    pub mdr_constraint: u8,
    pub backup_wait_interval: Duration,
    pub ack_interval: Duration,
    pub ack_cache_timeout: Duration,
    pub two_hop_refresh: u16,
    pub full_hello_repeat_count: u16,
    pub consecutive_hello_threshold: u8,
    pub metric_tlv_enabled: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MdrAdjConnectivity {
    Full,
    Uniconnected,
    Biconnected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MdrLsaFullness {
    Minimal,
    MinCost,
    MinCost2Paths,
    MdrFull,
    Full,
    SingleHopFull,
}

fn mdr_duration_from_yang(value: &str) -> Duration {
    let (secs, millis) = value.split_once('.').unwrap_or((value, ""));
    let secs = secs.parse::<u64>().unwrap();
    let mut digits = 0;
    let mut millis = millis.chars().take(3).fold(0u64, |acc, c| {
        digits += 1;
        acc * 10 + c.to_digit(10).unwrap() as u64
    });

    for _ in digits..3 {
        millis *= 10;
    }

    Duration::from_secs(secs) + Duration::from_millis(millis)
}

fn mdr_adj_connectivity_from_dnode(
    dnode: &DataNodeRef<'_>,
) -> MdrAdjConnectivity {
    let value = dnode.get_string();
    MdrAdjConnectivity::try_from_yang(&value).unwrap()
}

fn mdr_lsa_fullness_from_dnode(dnode: &DataNodeRef<'_>) -> MdrLsaFullness {
    let value = dnode.get_string();
    MdrLsaFullness::try_from_yang(&value).unwrap()
}

fn queue_mdr_config_change(
    event_queue: &mut BTreeSet<Event>,
    area_idx: AreaIndex,
    iface_idx: InterfaceIndex,
) {
    event_queue.insert(Event::InterfaceMdrConfigChange(area_idx, iface_idx));
}

fn get_mdr_bool(dnode: &DataNodeRef<'_>, path: &str, default: bool) -> bool {
    dnode.get_bool_relative(path).unwrap_or(default)
}

fn get_mdr_u16(dnode: &DataNodeRef<'_>, path: &str, default: u16) -> u16 {
    dnode.get_u16_relative(path).unwrap_or(default)
}

fn get_mdr_string(
    dnode: &DataNodeRef<'_>,
    path: &str,
    default: &'static str,
) -> String {
    dnode
        .get_string_relative(path)
        .unwrap_or_else(|| default.into())
}

fn validate_mdr_interface_config(
    dnode: &DataNodeRef<'_>,
) -> Result<(), String> {
    use ospf::areas::area::interfaces::interface::mdr;

    let enabled = get_mdr_bool(dnode, "./enabled", mdr::enabled::DFLT);
    let passive = get_mdr_bool(
        dnode,
        "../passive",
        ospf::areas::area::interfaces::interface::passive::DFLT,
    );
    if enabled && passive {
        return Err("OSPF-MDR can't be enabled on a passive interface".into());
    }

    let adj_connectivity = get_mdr_string(
        dnode,
        "./adj-connectivity",
        mdr::adj_connectivity::DFLT,
    );
    let adj_connectivity =
        MdrAdjConnectivity::try_from_yang(&adj_connectivity).unwrap();
    let lsa_fullness =
        get_mdr_string(dnode, "./lsa-fullness", mdr::lsa_fullness::DFLT);
    let lsa_fullness = MdrLsaFullness::try_from_yang(&lsa_fullness).unwrap();
    if adj_connectivity == MdrAdjConnectivity::Full
        && matches!(
            lsa_fullness,
            MdrLsaFullness::Minimal | MdrLsaFullness::MdrFull
        )
    {
        return Err("RFC 5614 Section 3.2 requires LSAFullness min-cost, \
             min-cost-2-paths, full, or single-hop-full when \
             AdjConnectivity is full"
            .into());
    }

    let retransmit_interval = get_mdr_u16(
        dnode,
        "./retransmit-interval",
        mdr::retransmit_interval::DFLT,
    );
    let ack_interval =
        get_mdr_string(dnode, "./ack-interval", mdr::ack_interval::DFLT);
    let ack_interval = mdr_duration_from_yang(&ack_interval);
    if ack_interval >= Duration::from_secs(retransmit_interval.into()) {
        return Err(
            "RFC 5614 Section 3.2 requires AckInterval to be less than \
             RxmtInterval"
                .into(),
        );
    }

    Ok(())
}

#[derive(Debug)]
pub struct StaticNbr {
    pub cost: Option<u16>,
    pub poll_interval: u16,
    pub priority: u8,
}

#[derive(Clone, Copy, Debug)]
pub enum InterfaceTraceOption {
    PacketsAll,
    PacketsHello,
    PacketsDbDesc,
    PacketsLsUpdate,
    PacketsLsRequest,
    PacketsLsAck,
}

#[derive(Debug, Default)]
pub struct InterfaceTraceOptions {
    pub packets: TraceOptionPacket,
    pub packets_resolved: Arc<ArcSwap<TraceOptionPacketResolved>>,
}

#[derive(Debug, Default)]
pub struct TraceOptionPacket {
    pub all: Option<TraceOptionPacketType>,
    pub hello: Option<TraceOptionPacketType>,
    pub dbdesc: Option<TraceOptionPacketType>,
    pub lsreq: Option<TraceOptionPacketType>,
    pub lsupd: Option<TraceOptionPacketType>,
    pub lsack: Option<TraceOptionPacketType>,
}

#[derive(Clone, Copy, Debug)]
pub struct TraceOptionPacketResolved {
    pub hello: TraceOptionPacketType,
    pub dbdesc: TraceOptionPacketType,
    pub lsreq: TraceOptionPacketType,
    pub lsupd: TraceOptionPacketType,
    pub lsack: TraceOptionPacketType,
}

#[derive(Clone, Copy, Debug)]
pub struct TraceOptionPacketType {
    pub tx: bool,
    pub rx: bool,
}

// ===== callbacks =====

fn load_callbacks<V>() -> Callbacks<Instance<V>>
where
    V: Version,
{
    CallbacksBuilder::<Instance<V>>::default()
        .path(ospf::address_family::PATH)
        .modify_apply(|instance, args| {
            let af = args.dnode.get_af();
            instance.config.af = Some(af);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceReset);
        })
        .delete_apply(|instance, args| {
            instance.config.af = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceReset);
        })
        .path(ospf::enabled::PATH)
        .modify_apply(|instance, args| {
            let enabled = args.dnode.get_bool();
            instance.config.enabled = enabled;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceUpdate);
        })
        .path(ospf::explicit_router_id::PATH)
        .modify_apply(|instance, args| {
            let router_id = args.dnode.get_ipv4();
            let old_router_id = instance.get_router_id();
            instance.config.router_id = Some(router_id);

            // NOTE: apply the new Router-ID immediately.
            if instance.get_router_id() != old_router_id {
                let event_queue = args.event_queue;
                event_queue.insert(Event::InstanceReset);
                event_queue.insert(Event::InstanceUpdate);
            }
        })
        .delete_apply(|instance, args| {
            let old_router_id = instance.get_router_id();
            instance.config.router_id = None;

            if instance.get_router_id() != old_router_id {
                let event_queue = args.event_queue;
                event_queue.insert(Event::InstanceReset);
                event_queue.insert(Event::InstanceUpdate);
            }
        })
        .path(ospf::preference::all::PATH)
        .modify_apply(|instance, args| {
            let preference = args.dnode.get_u8();
            instance.config.preference.intra_area = preference;
            instance.config.preference.inter_area = preference;
            instance.config.preference.external = preference;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReinstallRoutes);
        })
        .delete_apply(|instance, args| {
            let preference = ospf::preference::all::DFLT;
            instance.config.preference.intra_area = preference;
            instance.config.preference.inter_area = preference;
            instance.config.preference.external = preference;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReinstallRoutes);
        })
        .path(ospf::preference::intra_area::PATH)
        .modify_apply(|instance, args| {
            let preference = args.dnode.get_u8();
            instance.config.preference.intra_area = preference;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReinstallRoutes);
        })
        .delete_apply(|instance, args| {
            let preference = ospf::preference::all::DFLT;
            instance.config.preference.intra_area = preference;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReinstallRoutes);
        })
        .path(ospf::preference::inter_area::PATH)
        .modify_apply(|instance, args| {
            let preference = args.dnode.get_u8();
            instance.config.preference.inter_area = preference;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReinstallRoutes);
        })
        .delete_apply(|instance, args| {
            let preference = ospf::preference::all::DFLT;
            instance.config.preference.inter_area = preference;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReinstallRoutes);
        })
        .path(ospf::preference::internal::PATH)
        .modify_apply(|instance, args| {
            let preference = args.dnode.get_u8();
            instance.config.preference.intra_area = preference;
            instance.config.preference.inter_area = preference;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReinstallRoutes);
        })
        .delete_apply(|instance, args| {
            let preference = ospf::preference::all::DFLT;
            instance.config.preference.intra_area = preference;
            instance.config.preference.inter_area = preference;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReinstallRoutes);
        })
        .path(ospf::preference::external::PATH)
        .modify_apply(|instance, args| {
            let preference = args.dnode.get_u8();
            instance.config.preference.external = preference;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReinstallRoutes);
        })
        .delete_apply(|instance, args| {
            let preference = ospf::preference::all::DFLT;
            instance.config.preference.external = preference;

            let event_queue = args.event_queue;
            event_queue.insert(Event::ReinstallRoutes);
        })
        .path(ospf::graceful_restart::helper_enabled::PATH)
        .modify_apply(|instance, args| {
            let enabled = args.dnode.get_bool();
            instance.config.gr.helper_enabled = enabled;

            let event_queue = args.event_queue;
            event_queue.insert(Event::GrHelperChange);
        })
        .path(ospf::graceful_restart::helper_strict_lsa_checking::PATH)
        .modify_apply(|instance, args| {
            let strict_lsa_checking = args.dnode.get_bool();
            instance.config.gr.helper_strict_lsa_checking = strict_lsa_checking;
        })
        .path(ospf::spf_control::paths::PATH)
        .modify_apply(|instance, args| {
            let max_paths = args.dnode.get_u16();
            instance.config.max_paths = max_paths;

            let event_queue = args.event_queue;
            event_queue.insert(Event::RerunSpf);
        })
        .path(ospf::spf_control::ietf_spf_delay::initial_delay::PATH)
        .modify_apply(|instance, args| {
            let initial_delay = args.dnode.get_u32();
            instance.config.spf_initial_delay = initial_delay;
        })
        .path(ospf::spf_control::ietf_spf_delay::short_delay::PATH)
        .modify_apply(|instance, args| {
            let short_delay = args.dnode.get_u32();
            instance.config.spf_short_delay = short_delay;
        })
        .path(ospf::spf_control::ietf_spf_delay::long_delay::PATH)
        .modify_apply(|instance, args| {
            let long_delay = args.dnode.get_u32();
            instance.config.spf_long_delay = long_delay;
        })
        .path(ospf::spf_control::ietf_spf_delay::hold_down::PATH)
        .modify_apply(|instance, args| {
            let hold_down = args.dnode.get_u32();
            instance.config.spf_hold_down = hold_down;
        })
        .path(ospf::spf_control::ietf_spf_delay::time_to_learn::PATH)
        .modify_apply(|instance, args| {
            let time_to_learn = args.dnode.get_u32();
            instance.config.spf_time_to_learn = time_to_learn;
        })
        .path(ospf::stub_router::always::PATH)
        .create_apply(|instance, args| {
            instance.config.stub_router = true;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StubRouterChange);
        })
        .delete_apply(|instance, args| {
            instance.config.stub_router = false;

            let event_queue = args.event_queue;
            event_queue.insert(Event::StubRouterChange);
        })
        .path(ospf::node_tags::node_tag::PATH)
        .create_apply(|instance, args| {
            let node_tag = args.dnode.get_u32_relative("tag").unwrap();
            instance.config.node_tags.insert(node_tag);

            let event_queue = args.event_queue;
            event_queue.insert(Event::NodeTagsChange);
        })
        .delete_apply(|instance, args| {
            let node_tag = args.list_entry.into_node_tag().unwrap();
            instance.config.node_tags.remove(&node_tag);

            let event_queue = args.event_queue;
            event_queue.insert(Event::NodeTagsChange);
        })
        .lookup(|_instance, _list_entry, dnode| {
            let node_tag = dnode.get_u32_relative("tag").unwrap();
            ListEntry::NodeTag(node_tag)
        })
        .path(ospf::extended_lsa_support::PATH)
        .modify_apply(|instance, args| {
            let extended_lsa = args.dnode.get_bool();
            instance.config.extended_lsa = extended_lsa;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceReset);
        })
        .delete_apply(|_instance, _args| {
            // Nothing to do.
        })
        .path(ospf::segment_routing::enabled::PATH)
        .modify_apply(|instance, args| {
            let sr_enabled = args.dnode.get_bool();
            instance.config.sr_enabled = sr_enabled;

            let event_queue = args.event_queue;
            event_queue.insert(Event::SrEnableChange(sr_enabled));
        })
        .path(ospf::areas::area::PATH)
        .create_apply(|instance, args| {
            let area_id = args.dnode.get_ipv4_relative("area-id").unwrap();
            let (area_idx, _) = instance.arenas.areas.insert(area_id);

            let event_queue = args.event_queue;
            event_queue.insert(Event::AreaCreate(area_idx));
        })
        .delete_apply(|_instance, args| {
            let area_idx = args.list_entry.into_area().unwrap();

            let event_queue = args.event_queue;
            event_queue.insert(Event::AreaDelete(area_idx));
            event_queue.insert(Event::RerunSpf);
        })
        .lookup(|instance, _list_entry, dnode| {
            let area_id = dnode.get_ipv4_relative("./area-id").unwrap();
            instance.arenas.areas.get_mut_by_area_id(area_id).map(|(area_idx, _)| ListEntry::Area(area_idx)).expect("could not find OSPF area")
        })
        .path(ospf::areas::area::area_type::PATH)
        .modify_apply(|instance, args| {
            let area_idx = args.list_entry.into_area().unwrap();
            let area = &mut instance.arenas.areas[area_idx];

            let area_type = args.dnode.get_string();
            let area_type = AreaType::try_from_yang(&area_type).unwrap();
            area.config.area_type = area_type;
            area.config.summary = ospf::areas::area::summary::DFLT;
            area.config.default_cost = ospf::areas::area::default_cost::DFLT;

            let event_queue = args.event_queue;
            event_queue.insert(Event::AreaTypeChange(area_idx));
            event_queue.insert(Event::AreaSyncHelloTx(area_idx));
        })
        .path(ospf::areas::area::summary::PATH)
        .modify_apply(|instance, args| {
            let area_idx = args.list_entry.into_area().unwrap();
            let area = &mut instance.arenas.areas[area_idx];

            let summary = args.dnode.get_bool();
            area.config.summary = summary;

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateSummaries);
        })
        .delete_apply(|_instance, _args| {
            // Nothing to do.
        })
        .path(ospf::areas::area::default_cost::PATH)
        .modify_apply(|instance, args| {
            let area_idx = args.list_entry.into_area().unwrap();
            let area = &mut instance.arenas.areas[area_idx];

            let default_cost = args.dnode.get_u32();
            area.config.default_cost = default_cost;

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateSummaries);
        })
        .delete_apply(|_instance, _args| {
            // Nothing to do.
        })
        .path(ospf::areas::area::ranges::range::PATH)
        .create_apply(|instance, args| {
            let area_idx = args.list_entry.into_area().unwrap();
            let area = &mut instance.arenas.areas[area_idx];

            let prefix = args.dnode.get_prefix_relative("prefix").unwrap();
            let prefix = V::IpNetwork::get(prefix).unwrap();
            area.ranges.insert(prefix, Default::default());

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateSummaries);
        })
        .delete_apply(|instance, args| {
            let (area_idx, prefix) = args.list_entry.into_area_range().unwrap();
            let area = &mut instance.arenas.areas[area_idx];

            area.ranges.remove(&prefix);

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateSummaries);
        })
        .lookup(|_instance, list_entry, dnode| {
            let area_idx = list_entry.into_area().unwrap();

            let prefix = dnode.get_prefix_relative("./prefix").unwrap();
            let prefix = V::IpNetwork::get(prefix).unwrap();
            ListEntry::AreaRange(area_idx, prefix)
        })
        .path(ospf::areas::area::ranges::range::advertise::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, prefix) = args.list_entry.into_area_range().unwrap();
            let area = &mut instance.arenas.areas[area_idx];
            let range = area.ranges.get_mut(&prefix).unwrap();

            let advertise = args.dnode.get_bool();
            range.config.advertise = advertise;

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateSummaries);
        })
        .path(ospf::areas::area::ranges::range::cost::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, prefix) = args.list_entry.into_area_range().unwrap();
            let area = &mut instance.arenas.areas[area_idx];
            let range = area.ranges.get_mut(&prefix).unwrap();

            let cost = args.dnode.get_u32();
            range.config.cost = Some(cost);

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateSummaries);
        })
        .delete_apply(|instance, args| {
            let (area_idx, prefix) = args.list_entry.into_area_range().unwrap();
            let area = &mut instance.arenas.areas[area_idx];
            let range = area.ranges.get_mut(&prefix).unwrap();

            range.config.cost = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateSummaries);
        })
        .path(ospf::areas::area::virtual_links::virtual_link::PATH)
        .create_apply(|instance, args| {
            let area_idx = args.list_entry.into_area().unwrap();
            let area = &mut instance.arenas.areas[area_idx];

            let transit_area_id = args.dnode.get_ipv4_relative("transit-area-id").unwrap();
            let router_id = args.dnode.get_ipv4_relative("router-id").unwrap();
            let ifname = format!("vlink-{transit_area_id}-{router_id}");
            let vlink_key = VirtualLinkKey {
                transit_area_id,
                router_id,
            };
            let (iface_idx, iface) = area.interfaces.insert(&mut instance.arenas.interfaces, ifname, Some(vlink_key));
            iface.config.if_type = InterfaceType::VirtualLink;

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateVirtualLinks);
            event_queue.insert(Event::InterfaceUpdateTraceOptions(iface_idx));
        })
        .delete_apply(|_instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceDelete(area_idx, iface_idx));
        })
        .lookup(|instance, list_entry, dnode| {
            let area_idx = list_entry.into_area().unwrap();
            let area = &mut instance.arenas.areas[area_idx];

            let transit_area_id = dnode.get_ipv4_relative("transit-area-id").unwrap();
            let router_id = dnode.get_ipv4_relative("router-id").unwrap();
            let ifname = format!("vlink-{transit_area_id}-{router_id}");
            area.interfaces
                .get_mut_by_name(&mut instance.arenas.interfaces, &ifname)
                .map(|(iface_idx, _)| ListEntry::Interface(area_idx, iface_idx))
                .expect("could not find OSPF virtual link")
        })
        .path(ospf::areas::area::virtual_links::virtual_link::hello_interval::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let hello_interval = args.dnode.get_u16();
            iface.config.hello_interval = hello_interval;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceResetHelloInterval(area_idx, iface_idx));
            event_queue.insert(Event::InterfaceSyncHelloTx(area_idx, iface_idx));
        })
        .path(ospf::areas::area::virtual_links::virtual_link::dead_interval::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let dead_interval = args.dnode.get_u16();
            iface.config.dead_interval = dead_interval;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceResetDeadInterval(area_idx, iface_idx));
            event_queue.insert(Event::InterfaceSyncHelloTx(area_idx, iface_idx));
        })
        .path(ospf::areas::area::virtual_links::virtual_link::retransmit_interval::PATH)
        .modify_apply(|instance, args| {
            let (_, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let retransmit_interval = args.dnode.get_u16();
            iface.config.retransmit_interval = retransmit_interval;
        })
        .path(ospf::areas::area::virtual_links::virtual_link::transmit_delay::PATH)
        .modify_apply(|instance, args| {
            let (_, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let transmit_delay = args.dnode.get_u16();
            iface.config.transmit_delay = transmit_delay;
        })
        .path(ospf::areas::area::virtual_links::virtual_link::lls::PATH)
        .modify_apply(|instance, args| {
            let (_area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let enabled = args.dnode.get_bool();
            iface.config.lls_enabled = enabled;
        })
        .path(ospf::areas::area::virtual_links::virtual_link::enabled::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let enabled = args.dnode.get_bool();
            iface.config.enabled = enabled;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdate(area_idx, iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::PATH)
        .create_apply(|instance, args| {
            let area_idx = args.list_entry.into_area().unwrap();
            let area = &mut instance.arenas.areas[area_idx];

            let ifname = args.dnode.get_string_relative("name").unwrap();
            let (iface_idx, _) = area.interfaces.insert(&mut instance.arenas.interfaces, ifname.clone(), None);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceUpdate);
            event_queue.insert(Event::InterfaceUpdate(area_idx, iface_idx));
            event_queue.insert(Event::InterfaceUpdateTraceOptions(iface_idx));
            event_queue.insert(Event::InterfaceIbusSub(ifname));
        })
        .delete_apply(|_instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceUpdate);
            event_queue.insert(Event::InterfaceDelete(area_idx, iface_idx));
        })
        .lookup(|instance, list_entry, dnode| {
            let area_idx = list_entry.into_area().unwrap();
            let area = &mut instance.arenas.areas[area_idx];

            let ifname = dnode.get_string_relative("./name").unwrap();
            area.interfaces
                .get_mut_by_name(&mut instance.arenas.interfaces, &ifname)
                .map(|(iface_idx, _)| ListEntry::Interface(area_idx, iface_idx))
                .expect("could not find OSPF interface")
        })
        .path(ospf::areas::area::interfaces::interface::interface_type::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let if_type = args.dnode.get_string();
            let if_type = InterfaceType::try_from_yang(&if_type).unwrap();
            iface.config.if_type = if_type;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceReset(area_idx, iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::passive::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let passive = args.dnode.get_bool();
            iface.config.passive = passive;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceReset(area_idx, iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::priority::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let priority = args.dnode.get_u8();
            iface.config.priority = priority;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfacePriorityChange(area_idx, iface_idx));
            event_queue.insert(Event::InterfaceSyncHelloTx(area_idx, iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::static_neighbors::neighbor::PATH)
        .create_apply(|instance, args| {
            let (_, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let identifier = args.dnode.get_ip_relative("identifier").unwrap();
            let identifier = V::NetIpAddr::get(identifier).unwrap();
            iface.config.static_nbrs.insert(identifier, Default::default());
        })
        .delete_apply(|instance, args| {
            let (iface_idx, addr) = args.list_entry.into_static_nbr().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.static_nbrs.remove(&addr);
        })
        .lookup(|_instance, list_entry, dnode| {
            let (_, iface_idx) = list_entry.into_interface().unwrap();

            let identifier = dnode.get_ip_relative("./identifier").unwrap();
            let identifier = V::NetIpAddr::get(identifier).unwrap();
            ListEntry::StaticNbr(iface_idx, identifier)
        })
        .path(ospf::areas::area::interfaces::interface::static_neighbors::neighbor::cost::PATH)
        .modify_apply(|instance, args| {
            let (iface_idx, addr) = args.list_entry.into_static_nbr().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];
            let snbr = iface.config.static_nbrs.get_mut(&addr).unwrap();

            let cost = args.dnode.get_u16();
            snbr.cost = Some(cost);
        })
        .delete_apply(|instance, args| {
            let (iface_idx, addr) = args.list_entry.into_static_nbr().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];
            let snbr = iface.config.static_nbrs.get_mut(&addr).unwrap();

            snbr.cost = None;
        })
        .path(ospf::areas::area::interfaces::interface::static_neighbors::neighbor::poll_interval::PATH)
        .modify_apply(|instance, args| {
            let (iface_idx, addr) = args.list_entry.into_static_nbr().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];
            let snbr = iface.config.static_nbrs.get_mut(&addr).unwrap();

            let poll_interval = args.dnode.get_u16();
            snbr.poll_interval = poll_interval;
        })
        .path(ospf::areas::area::interfaces::interface::static_neighbors::neighbor::priority::PATH)
        .modify_apply(|instance, args| {
            let (iface_idx, addr) = args.list_entry.into_static_nbr().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];
            let snbr = iface.config.static_nbrs.get_mut(&addr).unwrap();

            let priority = args.dnode.get_u8();
            snbr.priority = priority;
        })
        .path(ospf::areas::area::interfaces::interface::bfd::enabled::PATH)
        .modify_apply(|instance, args| {
            let (_, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let enabled = args.dnode.get_bool();
            iface.config.bfd_enabled = enabled;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceBfdChange(iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::bfd::local_multiplier::PATH)
        .modify_apply(|instance, args| {
            let (_, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let local_multiplier = args.dnode.get_u8();
            iface.config.bfd_params.local_multiplier = local_multiplier;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceBfdChange(iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::bfd::desired_min_tx_interval::PATH)
        .modify_apply(|instance, args| {
            let (_, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let min_tx = args.dnode.get_u32();
            iface.config.bfd_params.min_tx = min_tx;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceBfdChange(iface_idx));
        })
        .delete_apply(|_instance, _args| {
            // Nothing to do.
        })
        .path(ospf::areas::area::interfaces::interface::bfd::required_min_rx_interval::PATH)
        .modify_apply(|instance, args| {
            let (_, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let min_rx = args.dnode.get_u32();
            iface.config.bfd_params.min_rx = min_rx;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceBfdChange(iface_idx));
        })
        .delete_apply(|_instance, _args| {
            // Nothing to do.
        })
        .path(ospf::areas::area::interfaces::interface::bfd::min_interval::PATH)
        .modify_apply(|instance, args| {
            let (_, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let min_interval = args.dnode.get_u32();
            iface.config.bfd_params.min_tx = min_interval;
            iface.config.bfd_params.min_rx = min_interval;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceBfdChange(iface_idx));
        })
        .delete_apply(|_instance, _args| {
            // Nothing to do.
        })
        .path(ospf::areas::area::interfaces::interface::hello_interval::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let hello_interval = args.dnode.get_u16();
            iface.config.hello_interval = hello_interval;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceResetHelloInterval(area_idx, iface_idx));
            event_queue.insert(Event::InterfaceSyncHelloTx(area_idx, iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::dead_interval::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let dead_interval = args.dnode.get_u16();
            iface.config.dead_interval = dead_interval;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceResetDeadInterval(area_idx, iface_idx));
            event_queue.insert(Event::InterfaceSyncHelloTx(area_idx, iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::retransmit_interval::PATH)
        .modify_apply(|instance, args| {
            let (_, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let retransmit_interval = args.dnode.get_u16();
            iface.config.retransmit_interval = retransmit_interval;
        })
        .path(ospf::areas::area::interfaces::interface::transmit_delay::PATH)
        .modify_apply(|instance, args| {
            let (_, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let transmit_delay = args.dnode.get_u16();
            iface.config.transmit_delay = transmit_delay;
        })
        .path(ospf::areas::area::interfaces::interface::lls::PATH)
        .modify_apply(|instance, args| {
            let (_area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let enabled = args.dnode.get_bool();
            iface.config.lls_enabled = enabled;
        })
        .path(ospf::areas::area::interfaces::interface::enabled::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let enabled = args.dnode.get_bool();
            iface.config.enabled = enabled;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdate(area_idx, iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::cost::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let cost = args.dnode.get_u16();
            iface.config.cost = cost;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceCostChange(area_idx));
        })
        .path(ospf::areas::area::interfaces::interface::mtu_ignore::PATH)
        .modify_apply(|instance, args| {
            let (_, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let mtu_ignore = args.dnode.get_bool();
            iface.config.mtu_ignore = mtu_ignore;
        })
        .path(ospf::areas::area::interfaces::interface::node_flag::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let node_flag = args.dnode.get_bool();
            iface.config.node_flag = node_flag;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceFlagChange(area_idx));
        })
        .path(ospf::areas::area::interfaces::interface::anycast_flag::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let anycast_flag = args.dnode.get_bool();
            iface.config.anycast_flag = anycast_flag;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceFlagChange(area_idx));
        })
        .delete_apply(|_instance, _args| {
            // Nothing to do.
        })
        .path(ospf::areas::area::interfaces::interface::trace_options::flag::PATH)
        .create_apply(|instance, args| {
            let (_, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let trace_opt = args.dnode.get_string_relative("name").unwrap();
            let trace_opt = InterfaceTraceOption::try_from_yang(&trace_opt).unwrap();
            let trace_opts = &mut iface.config.trace_opts;
            match trace_opt {
                InterfaceTraceOption::PacketsAll => {
                    trace_opts.packets.all.get_or_insert_default();
                }
                InterfaceTraceOption::PacketsHello => {
                    trace_opts.packets.hello.get_or_insert_default();
                }
                InterfaceTraceOption::PacketsDbDesc => {
                    trace_opts.packets.dbdesc.get_or_insert_default();
                }
                InterfaceTraceOption::PacketsLsRequest => {
                    trace_opts.packets.lsreq.get_or_insert_default();
                }
                InterfaceTraceOption::PacketsLsUpdate => {
                    trace_opts.packets.lsupd.get_or_insert_default();
                }
                InterfaceTraceOption::PacketsLsAck => {
                    trace_opts.packets.lsack.get_or_insert_default();
                }
            }

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateTraceOptions(iface_idx));
        })
        .delete_apply(|instance, args| {
            let (iface_idx, trace_opt) = args.list_entry.into_interface_trace_option().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let trace_opts = &mut iface.config.trace_opts;
            match trace_opt {
                InterfaceTraceOption::PacketsAll => trace_opts.packets.all = None,
                InterfaceTraceOption::PacketsHello => trace_opts.packets.hello = None,
                InterfaceTraceOption::PacketsDbDesc => trace_opts.packets.dbdesc = None,
                InterfaceTraceOption::PacketsLsRequest => trace_opts.packets.lsreq = None,
                InterfaceTraceOption::PacketsLsUpdate => trace_opts.packets.lsupd = None,
                InterfaceTraceOption::PacketsLsAck => trace_opts.packets.lsack = None,
            }

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateTraceOptions(iface_idx));
        })
        .lookup(|_instance, list_entry, dnode| {
            let (_, iface_idx) = list_entry.into_interface().unwrap();
            let trace_opt = dnode.get_string_relative("name").unwrap();
            let trace_opt = InterfaceTraceOption::try_from_yang(&trace_opt).unwrap();
            ListEntry::InterfaceTraceOption(iface_idx, trace_opt)
        })
        .path(ospf::areas::area::interfaces::interface::trace_options::flag::send::PATH)
        .modify_apply(|instance, args| {
            let (iface_idx, trace_opt) = args.list_entry.into_interface_trace_option().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let enable = args.dnode.get_bool();
            let trace_opts = &mut iface.config.trace_opts;
            let Some(trace_opt_packet) = (match trace_opt {
                InterfaceTraceOption::PacketsAll => trace_opts.packets.all.as_mut(),
                InterfaceTraceOption::PacketsHello => trace_opts.packets.hello.as_mut(),
                InterfaceTraceOption::PacketsDbDesc => trace_opts.packets.dbdesc.as_mut(),
                InterfaceTraceOption::PacketsLsRequest => trace_opts.packets.lsreq.as_mut(),
                InterfaceTraceOption::PacketsLsUpdate => trace_opts.packets.lsupd.as_mut(),
                InterfaceTraceOption::PacketsLsAck => trace_opts.packets.lsack.as_mut(),
            }) else {
                return;
            };
            trace_opt_packet.tx = enable;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateTraceOptions(iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::trace_options::flag::receive::PATH)
        .modify_apply(|instance, args| {
            let (iface_idx, trace_opt) = args.list_entry.into_interface_trace_option().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let enable = args.dnode.get_bool();
            let trace_opts = &mut iface.config.trace_opts;
            let Some(trace_opt_packet) = (match trace_opt {
                InterfaceTraceOption::PacketsAll => trace_opts.packets.all.as_mut(),
                InterfaceTraceOption::PacketsHello => trace_opts.packets.hello.as_mut(),
                InterfaceTraceOption::PacketsDbDesc => trace_opts.packets.dbdesc.as_mut(),
                InterfaceTraceOption::PacketsLsRequest => trace_opts.packets.lsreq.as_mut(),
                InterfaceTraceOption::PacketsLsUpdate => trace_opts.packets.lsupd.as_mut(),
                InterfaceTraceOption::PacketsLsAck => trace_opts.packets.lsack.as_mut(),
            }) else {
                return;
            };
            trace_opt_packet.rx = enable;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateTraceOptions(iface_idx));
        })
        .path(ospf::bier::mt_id::PATH)
        .modify_apply(|instance, args| {
            let mt_id = args.dnode.get_u8();
            instance.config.bier.mt_id = mt_id;

            // TODO: should reoriginate LSA
        })
        .delete_apply(|instance, _args| {
            let mt_id = 0;
            instance.config.bier.mt_id = mt_id;
        })
        .path(ospf::bier::bier::enable::PATH)
        .modify_apply(|instance, args| {
            let enable = args.dnode.get_bool();
            instance.config.bier.enabled = enable;

            let event_queue = args.event_queue;
            event_queue.insert(Event::BierEnableChange(enable));
        })
        .path(ospf::bier::bier::advertise::PATH)
        .modify_apply(|instance, args| {
            let advertise = args.dnode.get_bool();
            instance.config.bier.advertise = advertise;
        })
        .path(ospf::bier::bier::receive::PATH)
        .modify_apply(|instance, args| {
            let receive = args.dnode.get_bool();
            instance.config.bier.receive = receive;
        })
        .path(ospf::trace_options::flag::PATH)
        .create_apply(|instance, args| {
            let trace_opt = args.dnode.get_string_relative("name").unwrap();
            let trace_opt = InstanceTraceOption::try_from_yang(&trace_opt).unwrap();
            let trace_opts = &mut instance.config.trace_opts;
            match trace_opt {
                InstanceTraceOption::Flooding => trace_opts.flooding = true,
                InstanceTraceOption::GracefulRestart => trace_opts.gr = true,
                InstanceTraceOption::InternalBus => trace_opts.ibus = true,
                InstanceTraceOption::Lsdb => trace_opts.lsdb = true,
                InstanceTraceOption::Neighbor => trace_opts.neighbor = true,
                InstanceTraceOption::PacketsAll => {
                    trace_opts.packets.all.get_or_insert_default();
                }
                InstanceTraceOption::PacketsHello => {
                    trace_opts.packets.hello.get_or_insert_default();
                }
                InstanceTraceOption::PacketsDbDesc => {
                    trace_opts.packets.dbdesc.get_or_insert_default();
                }
                InstanceTraceOption::PacketsLsRequest => {
                    trace_opts.packets.lsreq.get_or_insert_default();
                }
                InstanceTraceOption::PacketsLsUpdate => {
                    trace_opts.packets.lsupd.get_or_insert_default();
                }
                InstanceTraceOption::PacketsLsAck => {
                    trace_opts.packets.lsack.get_or_insert_default();
                }
                InstanceTraceOption::Spf => trace_opts.spf = true,
            }

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateTraceOptions);
        })
        .delete_apply(|instance, args| {
            let trace_opt = args.list_entry.into_trace_option().unwrap();
            let trace_opts = &mut instance.config.trace_opts;
            match trace_opt {
                InstanceTraceOption::Flooding => trace_opts.flooding = false,
                InstanceTraceOption::GracefulRestart => trace_opts.gr = false,
                InstanceTraceOption::InternalBus => trace_opts.ibus = false,
                InstanceTraceOption::Lsdb => trace_opts.lsdb = false,
                InstanceTraceOption::Neighbor => trace_opts.neighbor = false,
                InstanceTraceOption::PacketsAll => trace_opts.packets.all = None,
                InstanceTraceOption::PacketsHello => trace_opts.packets.hello = None,
                InstanceTraceOption::PacketsDbDesc => trace_opts.packets.dbdesc = None,
                InstanceTraceOption::PacketsLsRequest => trace_opts.packets.lsreq = None,
                InstanceTraceOption::PacketsLsUpdate => trace_opts.packets.lsupd = None,
                InstanceTraceOption::PacketsLsAck => trace_opts.packets.lsack = None,
                InstanceTraceOption::Spf => trace_opts.spf = false,
            }

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateTraceOptions);
        })
        .lookup(|_instance, _list_entry, dnode| {
            let trace_opt = dnode.get_string_relative("name").unwrap();
            let trace_opt = InstanceTraceOption::try_from_yang(&trace_opt).unwrap();
            ListEntry::TraceOption(trace_opt)
        })
        .path(ospf::trace_options::flag::send::PATH)
        .modify_apply(|instance, args| {
            let trace_opt = args.list_entry.into_trace_option().unwrap();
            let enable = args.dnode.get_bool();
            let trace_opts = &mut instance.config.trace_opts;
            let Some(trace_opt_packet) = (match trace_opt {
                InstanceTraceOption::PacketsAll => trace_opts.packets.all.as_mut(),
                InstanceTraceOption::PacketsHello => trace_opts.packets.hello.as_mut(),
                InstanceTraceOption::PacketsDbDesc => trace_opts.packets.dbdesc.as_mut(),
                InstanceTraceOption::PacketsLsRequest => trace_opts.packets.lsreq.as_mut(),
                InstanceTraceOption::PacketsLsUpdate => trace_opts.packets.lsupd.as_mut(),
                InstanceTraceOption::PacketsLsAck => trace_opts.packets.lsack.as_mut(),
                _ => None,
            }) else {
                return;
            };
            trace_opt_packet.tx = enable;

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateTraceOptions);
        })
        .path(ospf::trace_options::flag::receive::PATH)
        .modify_apply(|instance, args| {
            let trace_opt = args.list_entry.into_trace_option().unwrap();
            let enable = args.dnode.get_bool();
            let trace_opts = &mut instance.config.trace_opts;
            let Some(trace_opt_packet) = (match trace_opt {
                InstanceTraceOption::PacketsAll => trace_opts.packets.all.as_mut(),
                InstanceTraceOption::PacketsHello => trace_opts.packets.hello.as_mut(),
                InstanceTraceOption::PacketsDbDesc => trace_opts.packets.dbdesc.as_mut(),
                InstanceTraceOption::PacketsLsRequest => trace_opts.packets.lsreq.as_mut(),
                InstanceTraceOption::PacketsLsUpdate => trace_opts.packets.lsupd.as_mut(),
                InstanceTraceOption::PacketsLsAck => trace_opts.packets.lsack.as_mut(),
                _ => None,
            }) else {
                return;
            };
            trace_opt_packet.rx = enable;

            let event_queue = args.event_queue;
            event_queue.insert(Event::UpdateTraceOptions);
        })
        .build()
}

fn load_callbacks_ospfv2() -> Callbacks<Instance<Ospfv2>> {
    let core_cbs = load_callbacks();
    CallbacksBuilder::<Instance<Ospfv2>>::new(core_cbs)
        .path(ospf::areas::area::virtual_links::virtual_link::authentication::ospfv2_key_chain::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let auth_keychain = args.dnode.get_string();
            iface.config.auth_keychain = Some(auth_keychain);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .delete_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.auth_keychain = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .path(ospf::areas::area::virtual_links::virtual_link::authentication::ospfv2_key_id::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let auth_keyid = args.dnode.get_u32();
            iface.config.auth_keyid = Some(auth_keyid);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .delete_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.auth_keyid = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .path(ospf::areas::area::virtual_links::virtual_link::authentication::ospfv2_key::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let auth_key = args.dnode.get_string();
            iface.config.auth_key = Some(auth_key);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .delete_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.auth_key = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .path(ospf::areas::area::virtual_links::virtual_link::authentication::ospfv2_crypto_algorithm::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let auth_algo = args.dnode.get_string();
            let auth_algo = CryptoAlgo::try_from_yang(&auth_algo).unwrap();
            iface.config.auth_algo = Some(auth_algo);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .delete_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.auth_algo = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::authentication::ospfv2_key_chain::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let auth_keychain = args.dnode.get_string();
            iface.config.auth_keychain = Some(auth_keychain);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .delete_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.auth_keychain = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::authentication::ospfv2_key_id::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let auth_keyid = args.dnode.get_u32();
            iface.config.auth_keyid = Some(auth_keyid);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .delete_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.auth_keyid = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::authentication::ospfv2_key::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let auth_key = args.dnode.get_string();
            iface.config.auth_key = Some(auth_key);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .delete_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.auth_key = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::authentication::ospfv2_crypto_algorithm::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let auth_algo = args.dnode.get_string();
            let auth_algo = CryptoAlgo::try_from_yang(&auth_algo).unwrap();
            iface.config.auth_algo = Some(auth_algo);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .delete_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.auth_algo = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .build()
}

fn load_callbacks_ospfv3() -> Callbacks<Instance<Ospfv3>> {
    let core_cbs = load_callbacks();
    CallbacksBuilder::<Instance<Ospfv3>>::new(core_cbs)
        .path(ospf::instance_id::PATH)
        .modify_apply(|instance, args| {
            let instance_id = args.dnode.get_u8();
            instance.config.instance_id = instance_id;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InstanceIdUpdate);
        })
        .delete_apply(|_instance, _args| {
            // Nothing to do.
        })
        .path(ospf::areas::area::interfaces::interface::mdr::enabled::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.mdr.enabled = args.dnode.get_bool();

            queue_mdr_config_change(args.event_queue, area_idx, iface_idx);
        })
        .path(ospf::areas::area::interfaces::interface::mdr::hello_interval::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.mdr.hello_interval = args.dnode.get_u16();

            queue_mdr_config_change(args.event_queue, area_idx, iface_idx);
        })
        .path(ospf::areas::area::interfaces::interface::mdr::dead_interval::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.mdr.dead_interval = args.dnode.get_u16();

            queue_mdr_config_change(args.event_queue, area_idx, iface_idx);
        })
        .path(ospf::areas::area::interfaces::interface::mdr::retransmit_interval::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.mdr.retransmit_interval = args.dnode.get_u16();

            queue_mdr_config_change(args.event_queue, area_idx, iface_idx);
        })
        .path(ospf::areas::area::interfaces::interface::mdr::router_priority::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.mdr.router_priority = args.dnode.get_u8();

            queue_mdr_config_change(args.event_queue, area_idx, iface_idx);
        })
        .path(ospf::areas::area::interfaces::interface::mdr::adj_connectivity::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.mdr.adj_connectivity =
                mdr_adj_connectivity_from_dnode(&args.dnode);

            queue_mdr_config_change(args.event_queue, area_idx, iface_idx);
        })
        .path(ospf::areas::area::interfaces::interface::mdr::lsa_fullness::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.mdr.lsa_fullness =
                mdr_lsa_fullness_from_dnode(&args.dnode);

            queue_mdr_config_change(args.event_queue, area_idx, iface_idx);
        })
        .path(ospf::areas::area::interfaces::interface::mdr::mdr_constraint::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.mdr.mdr_constraint = args.dnode.get_u8();

            queue_mdr_config_change(args.event_queue, area_idx, iface_idx);
        })
        .path(ospf::areas::area::interfaces::interface::mdr::backup_wait_interval::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.mdr.backup_wait_interval =
                mdr_duration_from_yang(&args.dnode.get_string());

            queue_mdr_config_change(args.event_queue, area_idx, iface_idx);
        })
        .path(ospf::areas::area::interfaces::interface::mdr::ack_interval::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.mdr.ack_interval =
                mdr_duration_from_yang(&args.dnode.get_string());

            queue_mdr_config_change(args.event_queue, area_idx, iface_idx);
        })
        .path(ospf::areas::area::interfaces::interface::mdr::two_hop_refresh::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.mdr.two_hop_refresh = args.dnode.get_u16();

            queue_mdr_config_change(args.event_queue, area_idx, iface_idx);
        })
        .path(ospf::areas::area::interfaces::interface::mdr::full_hello_repeat_count::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.mdr.full_hello_repeat_count = args.dnode.get_u16();

            queue_mdr_config_change(args.event_queue, area_idx, iface_idx);
        })
        .path(ospf::areas::area::interfaces::interface::mdr::consecutive_hello_threshold::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.mdr.consecutive_hello_threshold = args.dnode.get_u8();

            queue_mdr_config_change(args.event_queue, area_idx, iface_idx);
        })
        .path(ospf::areas::area::interfaces::interface::mdr::metric_tlv_enabled::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.mdr.metric_tlv_enabled = args.dnode.get_bool();

            queue_mdr_config_change(args.event_queue, area_idx, iface_idx);
        })
        .path(ospf::areas::area::virtual_links::virtual_link::authentication::ospfv3_key_chain::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let auth_keychain = args.dnode.get_string();
            iface.config.auth_keychain = Some(auth_keychain);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .delete_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.auth_keychain = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .path(ospf::areas::area::virtual_links::virtual_link::authentication::ospfv3_sa_id::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let auth_keyid = args.dnode.get_u16();
            iface.config.auth_keyid = Some(auth_keyid as u32);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .delete_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.auth_keyid = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .path(ospf::areas::area::virtual_links::virtual_link::authentication::ospfv3_key::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let auth_key = args.dnode.get_string();
            iface.config.auth_key = Some(auth_key);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .delete_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.auth_key = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .path(ospf::areas::area::virtual_links::virtual_link::authentication::ospfv3_crypto_algorithm::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let auth_algo = args.dnode.get_string();
            let auth_algo = CryptoAlgo::try_from_yang(&auth_algo).unwrap();
            iface.config.auth_algo = Some(auth_algo);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .delete_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.auth_algo = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::instance_id::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let instance_id = args.dnode.get_u8();
            iface.config.instance_id.explicit = Some(instance_id);
            iface.config.instance_id.resolved = instance_id;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceSyncHelloTx(area_idx, iface_idx));
        })
        .delete_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.instance_id.explicit = None;
            iface.config.instance_id.resolved = instance.config.instance_id;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceSyncHelloTx(area_idx, iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::authentication::ospfv3_key_chain::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let auth_keychain = args.dnode.get_string();
            iface.config.auth_keychain = Some(auth_keychain);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .delete_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.auth_keychain = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::authentication::ospfv3_sa_id::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let auth_keyid = args.dnode.get_u16();
            iface.config.auth_keyid = Some(auth_keyid as u32);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .delete_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.auth_keyid = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::authentication::ospfv3_key::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let auth_key = args.dnode.get_string();
            iface.config.auth_key = Some(auth_key);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .delete_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.auth_key = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .path(ospf::areas::area::interfaces::interface::authentication::ospfv3_crypto_algorithm::PATH)
        .modify_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            let auth_algo = args.dnode.get_string();
            let auth_algo = CryptoAlgo::try_from_yang(&auth_algo).unwrap();
            iface.config.auth_algo = Some(auth_algo);

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .delete_apply(|instance, args| {
            let (area_idx, iface_idx) = args.list_entry.into_interface().unwrap();
            let iface = &mut instance.arenas.interfaces[iface_idx];

            iface.config.auth_algo = None;

            let event_queue = args.event_queue;
            event_queue.insert(Event::InterfaceUpdateAuth(area_idx, iface_idx));
        })
        .build()
}

fn load_validation_callbacks() -> ValidationCallbacks {
    ValidationCallbacksBuilder::default()
        .path(ospf::areas::PATH)
        .validate(|args| {
            // Ensure no interface is configured in more than one area.
            let mut ifnames = HashSet::new();
            for dnode in args
                .dnode
                .find_xpath("./area/interfaces/interface/name")
                .unwrap()
            {
                if !ifnames.insert(dnode.get_string()) {
                    return Err(format!(
                        "interface '{}' configured in more than one area",
                        dnode.get_string()
                    ));
                }
            }

            Ok(())
        })
        .path(ospf::areas::area::area_type::PATH)
        .validate(|args| {
            let area_type = args.dnode.get_string();
            let Some(area_type) = AreaType::try_from_yang(&area_type) else {
                return Err("unsupported area type".to_string());
            };
            if area_type == AreaType::Nssa {
                return Err("unsupported area type".to_string());
            }

            let area_id = args.dnode.get_ipv4_relative("../area-id").unwrap();
            if area_type != AreaType::Normal && area_id == BACKBONE_AREA_ID {
                return Err(
                    "can't change type of the backbone area".to_string()
                );
            }

            Ok(())
        })
        .build()
}

fn load_validation_callbacks_ospfv2() -> ValidationCallbacks {
    let core_cbs = load_validation_callbacks();
    ValidationCallbacksBuilder::new(core_cbs)
        .path(ospf::areas::area::interfaces::interface::authentication::ospfv2_crypto_algorithm::PATH)
        .validate(|args| {
            let valid_options = [
                CryptoAlgo::Md5.to_yang(),
                CryptoAlgo::HmacSha1.to_yang(),
                CryptoAlgo::HmacSha256.to_yang(),
                CryptoAlgo::HmacSha384.to_yang(),
                CryptoAlgo::HmacSha512.to_yang(),
            ];

            let algo = args.dnode.get_string();
            if !valid_options.iter().any(|option| *option == algo) {
                return Err(format!("unsupported cryptographic algorithm (valid options: \"{}\")", valid_options.join(", "),));
            }

            Ok(())
        })
        .build()
}

fn load_validation_callbacks_ospfv3() -> ValidationCallbacks {
    let core_cbs = load_validation_callbacks();
    ValidationCallbacksBuilder::new(core_cbs)
        .path(ospf::instance_id::PATH)
        .validate(|args| {
            let instance_id = args.dnode.get_u8();
            let af = args.dnode.get_af_relative("../address-family").unwrap_or(AddressFamily::Ipv6);

            // Validate interface Instance ID based on RFC5838's address-family
            // Instance ID ranges.
            let range = match af {
                AddressFamily::Ipv6 => 0..=31,
                AddressFamily::Ipv4 => 64..=95,
            };
            if !range.contains(&instance_id) {
                return Err(format!("Instance ID {instance_id} isn't valid for the {af} address family"));
            }

            Ok(())
        })
        .path(ospf::areas::area::interfaces::interface::instance_id::PATH)
        .validate(|args| {
            let instance_id = args.dnode.get_u8();
            let af = args.dnode.get_af_relative("../../../../../address-family").unwrap_or(AddressFamily::Ipv6);

            // Validate interface Instance ID based on RFC5838's
            // address-family Instance ID ranges.
            let range = match af {
                AddressFamily::Ipv6 => 0..=31,
                AddressFamily::Ipv4 => 64..=95,
            };
            if !range.contains(&instance_id) {
                return Err(format!("Instance ID {instance_id} isn't valid for the {af} address family"));
            }

            Ok(())
        })
        .path(ospf::areas::area::interfaces::interface::mdr::PATH)
        .validate(|args| validate_mdr_interface_config(&args.dnode))
        .path(ospf::segment_routing::enabled::PATH)
        .validate(|args| {
            let ptype = args.dnode.get_string_relative("../../../type").unwrap();
            let ptype = Protocol::try_from_yang(&ptype).unwrap();
            if ptype != Protocol::OSPFV3 {
                return Ok(());
            }

            let sr_enabled = args.dnode.get_bool();
            let extended_lsa = args.dnode.get_bool_relative("../../extended-lsa-support");

            if sr_enabled && extended_lsa != Some(true) {
                return Err("Segment Routing for OSPFv3 requires extended LSA support enabled".to_string());
            }

            Ok(())
        })
        .path(ospf::areas::area::interfaces::interface::authentication::ospfv3_crypto_algorithm::PATH)
        .validate(|args| {
            let valid_options = [CryptoAlgo::HmacSha1.to_yang(), CryptoAlgo::HmacSha256.to_yang(), CryptoAlgo::HmacSha384.to_yang(), CryptoAlgo::HmacSha512.to_yang()];

            let algo = args.dnode.get_string();
            if !valid_options.iter().any(|option| *option == algo) {
                return Err(format!("unsupported cryptographic algorithm (valid options: \"{}\")", valid_options.join(", "),));
            }

            Ok(())
        })
        .build()
}

// ===== impl Instance =====

impl<V> Provider for Instance<V>
where
    V: Version,
{
    type ListEntry = ListEntry<V>;
    type Event = Event;
    type Resource = Resource;

    fn callbacks() -> &'static Callbacks<Instance<V>> {
        V::configuration_callbacks()
    }

    fn process_event(&mut self, event: Event) {
        match event {
            Event::InstanceReset => self.reset(),
            Event::InstanceUpdate => self.update(),
            Event::InstanceIdUpdate => {
                for area_idx in self.arenas.areas.indexes().collect::<Vec<_>>()
                {
                    let area = &mut self.arenas.areas[area_idx];
                    for iface_idx in
                        area.interfaces.indexes().collect::<Vec<_>>()
                    {
                        let iface = &mut self.arenas.interfaces[iface_idx];
                        iface.config.instance_id.resolved = iface
                            .config
                            .instance_id
                            .explicit
                            .unwrap_or(self.config.instance_id);
                    }

                    self.process_event(Event::AreaSyncHelloTx(area_idx));
                }
            }
            Event::AreaCreate(area_idx) => {
                let area = &mut self.arenas.areas[area_idx];

                // Originate Router Information LSA(s).
                self.tx.protocol_input.lsa_orig_event(
                    LsaOriginateEvent::AreaStart { area_id: area.id },
                );
            }
            Event::AreaDelete(area_idx) => {
                let area = &mut self.arenas.areas[area_idx];

                // Delete area's interfaces.
                for iface_idx in area.interfaces.indexes().collect::<Vec<_>>() {
                    self.process_event(Event::InterfaceDelete(
                        area_idx, iface_idx,
                    ));
                }

                // Delete area.
                self.arenas.areas.delete(area_idx);
            }
            Event::AreaTypeChange(area_idx) => {
                if let Some((instance, arenas)) = self.as_up() {
                    let area = &arenas.areas[area_idx];

                    // Kill all neighbors in the area to speed-up reconvergence.
                    for iface_idx in area.interfaces.indexes() {
                        let iface = &mut arenas.interfaces[iface_idx];

                        for nbr in iface.state.neighbors.iter(&arenas.neighbors)
                        {
                            instance.tx.protocol_input.nsm_event(
                                area.id,
                                iface.id,
                                nbr.id,
                                nsm::Event::Kill,
                            );
                        }
                    }

                    // Purge all AS-scoped LSAs in the absence of at least one
                    // active normal area.
                    if !arenas.areas.iter().any(|area| {
                        area.config.area_type == AreaType::Normal
                            && area.is_active(&arenas.interfaces)
                    }) {
                        instance.state.lsdb = Default::default();
                    }
                }
            }
            Event::AreaSyncHelloTx(area_idx) => {
                if let Some((instance, arenas)) = self.as_up() {
                    let area = &arenas.areas[area_idx];

                    for iface_idx in area.interfaces.indexes() {
                        let iface = &mut arenas.interfaces[iface_idx];

                        iface.sync_hello_tx(area, &instance);
                    }
                }
            }
            Event::InterfaceUpdate(area_idx, iface_idx) => {
                if let Some((mut instance, arenas)) = self.as_up() {
                    let area = &arenas.areas[area_idx];
                    let iface = &mut arenas.interfaces[iface_idx];

                    iface.update(
                        area,
                        &mut instance,
                        &mut arenas.neighbors,
                        &arenas.lsa_entries,
                    );
                }
            }
            Event::InterfaceDelete(area_idx, iface_idx) => {
                if let Some((mut instance, arenas)) = self.as_up() {
                    let area = &arenas.areas[area_idx];
                    let iface = &mut arenas.interfaces[iface_idx];

                    // Cancel ibus subscription.
                    if !iface.is_virtual_link() {
                        instance
                            .tx
                            .ibus
                            .interface_unsub(Some(iface.name.clone()));
                    }

                    // Stop interface if it's active.
                    let reason = InterfaceInactiveReason::AdminDown;
                    iface.fsm(
                        area,
                        &mut instance,
                        &mut arenas.neighbors,
                        &arenas.lsa_entries,
                        ism::Event::InterfaceDown(reason),
                    );

                    // Update the routing table to remove nexthops that are no
                    // longer reachable.
                    for route in instance.state.rib.values_mut() {
                        route.nexthops.retain(|_, nexthop| {
                            nexthop.iface_idx != iface_idx
                        });
                    }
                }

                let area = &mut self.arenas.areas[area_idx];
                area.interfaces
                    .delete(&mut self.arenas.interfaces, iface_idx);
            }
            Event::InterfaceReset(area_idx, iface_idx) => {
                if let Some((mut instance, arenas)) = self.as_up() {
                    let area = &arenas.areas[area_idx];
                    let iface = &mut arenas.interfaces[iface_idx];

                    if !iface.is_down() {
                        iface.reset(
                            area,
                            &mut instance,
                            &mut arenas.neighbors,
                            &arenas.lsa_entries,
                        );
                    }
                }
            }
            Event::InterfaceResetHelloInterval(area_idx, iface_idx) => {
                if let Some((instance, arenas)) = self.as_up() {
                    let area = &arenas.areas[area_idx];
                    let iface = &mut arenas.interfaces[iface_idx];

                    if iface.state.tasks.hello_interval.is_some() {
                        iface.hello_interval_start(area, &instance);
                    }
                }
            }
            Event::InterfaceResetDeadInterval(area_idx, iface_idx) => {
                if let Some((instance, arenas)) = self.as_up() {
                    let area = &arenas.areas[area_idx];
                    let iface = &mut arenas.interfaces[iface_idx];

                    // Reset neighbor inactivity timers
                    for nbr_idx in iface.state.neighbors.indexes() {
                        let nbr = &mut arenas.neighbors[nbr_idx];

                        if nbr.tasks.inactivity_timer.is_some() {
                            nbr.inactivity_timer_start(iface, area, &instance);
                        }
                    }

                    // Also reset the interface wait timer if it exists
                    if iface.state.tasks.wait_timer.is_some() {
                        let task =
                            tasks::ism_wait_timer(iface, area, &instance);
                        iface.state.tasks.wait_timer = Some(task);
                    }
                }
            }
            Event::InterfacePriorityChange(area_idx, iface_idx) => {
                if let Some((instance, arenas)) = self.as_up() {
                    let area = &arenas.areas[area_idx];
                    let iface = &arenas.interfaces[iface_idx];

                    // Rerun the DR election algorithm if necessary.
                    if !iface.is_down() && iface.is_broadcast_or_nbma() {
                        instance.tx.protocol_input.ism_event(
                            area.id,
                            iface.id,
                            ism::Event::NbrChange,
                        );
                    }
                }
            }
            Event::InterfaceCostChange(area_idx) => {
                if let Some((instance, arenas)) = self.as_up() {
                    let area = &arenas.areas[area_idx];

                    instance.tx.protocol_input.lsa_orig_event(
                        LsaOriginateEvent::InterfaceCostChange {
                            area_id: area.id,
                        },
                    );
                }
            }
            Event::InterfaceFlagChange(area_idx) => {
                if let Some((instance, arenas)) = self.as_up() {
                    let area = &arenas.areas[area_idx];

                    instance.tx.protocol_input.lsa_orig_event(
                        LsaOriginateEvent::InterfaceFlagChange {
                            area_id: area.id,
                        },
                    );
                }
            }
            Event::InterfaceSyncHelloTx(area_idx, iface_idx) => {
                if let Some((instance, arenas)) = self.as_up() {
                    let area = &arenas.areas[area_idx];
                    let iface = &mut arenas.interfaces[iface_idx];

                    iface.sync_hello_tx(area, &instance);
                }
            }
            Event::InterfaceMdrConfigChange(area_idx, iface_idx) => {
                if let Some((mut instance, arenas)) = self.as_up() {
                    let area = &arenas.areas[area_idx];
                    let iface = &mut arenas.interfaces[iface_idx];

                    iface.mdr_config_change(
                        area,
                        &mut instance,
                        &mut arenas.neighbors,
                        &arenas.lsa_entries,
                    );
                    iface.run_mdr_selection_if_pending(
                        area,
                        &instance,
                        &mut arenas.neighbors,
                    );
                    iface.run_mdr_adjacency_reevaluation_if_pending(
                        area,
                        &mut instance,
                        &mut arenas.neighbors,
                        &arenas.lsa_entries,
                    );
                } else {
                    let iface = &mut self.arenas.interfaces[iface_idx];
                    iface.sync_mdr_state_from_config();
                }
            }
            Event::InterfaceUpdateAuth(_area_idx, iface_idx) => {
                if let Some((instance, arenas)) = self.as_up() {
                    let iface = &mut arenas.interfaces[iface_idx];

                    // Update interface authentication keys.
                    iface.auth_update(&instance);
                }
            }
            Event::InterfaceBfdChange(iface_idx) => {
                if let Some((instance, arenas)) = self.as_up() {
                    let iface = &mut arenas.interfaces[iface_idx];

                    for nbr in iface
                        .state
                        .neighbors
                        .iter(&arenas.neighbors)
                        .filter(|nbr| nbr.state >= nsm::State::TwoWay)
                    {
                        if iface.config.bfd_enabled {
                            nbr.bfd_register(iface, &instance);
                        } else {
                            nbr.bfd_unregister(iface, &instance);
                        }
                    }
                }
            }
            Event::InterfaceUpdateTraceOptions(iface_idx) => {
                let iface = &mut self.arenas.interfaces[iface_idx];
                iface.config.update_trace_options(&self.config);
            }
            Event::InterfaceIbusSub(ifname) => {
                if self.is_active() {
                    let af = match (V::PROTOCOL, V::address_family(self)) {
                        (Protocol::OSPFV3, AddressFamily::Ipv4) => {
                            // OSPFv3 supports both IPv4 and IPv6 but runs over
                            // IPv6 transport. When routing IPv4, both IPv4 and
                            // IPv6 interface addresses are required.
                            None
                        }
                        (_, af) => Some(af),
                    };
                    self.tx.ibus.interface_sub(Some(ifname), af);
                }
            }
            Event::StubRouterChange => {
                if let Some((instance, _)) = self.as_up() {
                    // (Re)originate Router-LSAs.
                    instance
                        .tx
                        .protocol_input
                        .lsa_orig_event(LsaOriginateEvent::StubRouterChange);
                }
            }
            Event::GrHelperChange => {
                if let Some((mut instance, arenas)) = self.as_up() {
                    // Exit from the helper mode for all neighbors.
                    if !instance.config.gr.helper_enabled {
                        gr::helper_process_topology_change(
                            None,
                            &mut instance,
                            arenas,
                        );
                    }

                    // (Re)originate Router Information LSAs.
                    instance
                        .tx
                        .protocol_input
                        .lsa_orig_event(LsaOriginateEvent::GrHelperChange);
                }
            }
            Event::SrEnableChange(sr_enabled) => {
                if let Some((instance, arenas)) = self.as_up() {
                    // (Re)originate LSAs that might have been affected.
                    instance
                        .tx
                        .protocol_input
                        .lsa_orig_event(LsaOriginateEvent::SrEnableChange);

                    // Iterate over all existing adjacencies.
                    for area in arenas.areas.iter_mut() {
                        for iface in area.interfaces.iter(&arenas.interfaces) {
                            for nbr_idx in iface.state.neighbors.indexes() {
                                let nbr = &mut arenas.neighbors[nbr_idx];
                                if nbr.state < nsm::State::TwoWay {
                                    continue;
                                }

                                if sr_enabled {
                                    // Add SR Adj-SID.
                                    sr::adj_sid_add(nbr, iface, &instance);
                                } else {
                                    // Delete SR Adj-SIDs.
                                    sr::adj_sid_del_all(nbr, iface, &instance);
                                }
                            }
                        }
                    }
                }
            }
            Event::BierEnableChange(bier_enabled) => {
                if let Some((instance, _arenas)) = self.as_up() {
                    // (Re)originate LSAs that might have been affected.
                    instance
                        .tx
                        .protocol_input
                        .lsa_orig_event(LsaOriginateEvent::BierEnableChange);

                    // Purge BIRT if bier disabled or re-install routes if enabled
                    if bier_enabled {
                        self.process_event(Event::ReinstallRoutes);
                    } else {
                        instance.tx.ibus.bier_purge();
                    }
                }
            }
            Event::RerunSpf => {
                if let Some((instance, _)) = self.as_up() {
                    instance
                        .tx
                        .protocol_input
                        .spf_delay_event(spf::fsm::Event::ConfigChange);
                }
            }
            Event::UpdateVirtualLinks => {
                if let Some((instance, arenas)) = self.as_up() {
                    area::update_virtual_links(
                        &instance,
                        &mut arenas.areas,
                        &mut arenas.interfaces,
                        &arenas.lsa_entries,
                    );
                }
            }
            Event::UpdateSummaries => {
                if let Some((mut instance, arenas)) = self.as_up() {
                    area::update_summary_lsas(
                        &mut instance,
                        &mut arenas.areas,
                        &arenas.interfaces,
                        &arenas.lsa_entries,
                    );
                }
            }
            Event::ReinstallRoutes => {
                if let Some((instance, arenas)) = self.as_up() {
                    for (dest, route) in
                        instance.state.rib.iter().filter(|(_, route)| {
                            route.flags.contains(RouteNetFlags::INSTALLED)
                        })
                    {
                        let distance = route.distance(instance.config);
                        ibus::tx::route_install(
                            &instance.tx.ibus,
                            dest,
                            route,
                            None,
                            distance,
                            &arenas.interfaces,
                        );
                    }
                }
            }
            Event::NodeTagsChange => {
                if let Some((instance, arenas)) = self.as_up() {
                    let _ = V::lsa_orig_event(
                        &instance,
                        arenas,
                        LsaOriginateEvent::NodeTagsChange,
                    );
                }
            }
            Event::UpdateTraceOptions => {
                for area_idx in self.arenas.areas.indexes().collect::<Vec<_>>()
                {
                    let area = &mut self.arenas.areas[area_idx];
                    for iface_idx in
                        area.interfaces.indexes().collect::<Vec<_>>()
                    {
                        let iface = &mut self.arenas.interfaces[iface_idx];
                        iface.config.update_trace_options(&self.config);
                    }
                }
            }
        }
    }
}

// ===== configuration helpers =====

impl<V> InterfaceCfg<V>
where
    V: Version,
{
    // Resolves packet trace options by merging interface-specific and
    // instance-level options. Interface options override instance options,
    // and per-packet options override "all" options.
    pub(crate) fn update_trace_options(&mut self, instance_cfg: &InstanceCfg) {
        let iface_trace_opts = &self.trace_opts.packets;
        let instance_trace_opts = &instance_cfg.trace_opts.packets;

        let disabled = TraceOptionPacketType {
            tx: false,
            rx: false,
        };
        let hello = iface_trace_opts
            .hello
            .or(iface_trace_opts.all)
            .or(instance_trace_opts.hello)
            .or(instance_trace_opts.all)
            .unwrap_or(disabled);
        let dbdesc = iface_trace_opts
            .dbdesc
            .or(iface_trace_opts.all)
            .or(instance_trace_opts.dbdesc)
            .or(instance_trace_opts.all)
            .unwrap_or(disabled);
        let lsreq = iface_trace_opts
            .lsreq
            .or(iface_trace_opts.all)
            .or(instance_trace_opts.lsreq)
            .or(instance_trace_opts.all)
            .unwrap_or(disabled);
        let lsupd = iface_trace_opts
            .lsupd
            .or(iface_trace_opts.all)
            .or(instance_trace_opts.lsupd)
            .or(instance_trace_opts.all)
            .unwrap_or(disabled);
        let lsack = iface_trace_opts
            .lsack
            .or(iface_trace_opts.all)
            .or(instance_trace_opts.lsack)
            .or(instance_trace_opts.all)
            .unwrap_or(disabled);

        let resolved = Arc::new(TraceOptionPacketResolved {
            hello,
            dbdesc,
            lsreq,
            lsupd,
            lsack,
        });
        self.trace_opts.packets_resolved.store(resolved);
    }
}

impl TraceOptionPacketResolved {
    pub(crate) fn tx(&self, pkt_type: PacketType) -> bool {
        match pkt_type {
            PacketType::Hello => self.hello.tx,
            PacketType::DbDesc => self.dbdesc.tx,
            PacketType::LsRequest => self.lsreq.tx,
            PacketType::LsUpdate => self.lsupd.tx,
            PacketType::LsAck => self.lsack.tx,
        }
    }

    pub(crate) fn rx(&self, pkt_type: PacketType) -> bool {
        match pkt_type {
            PacketType::Hello => self.hello.rx,
            PacketType::DbDesc => self.dbdesc.rx,
            PacketType::LsRequest => self.lsreq.rx,
            PacketType::LsUpdate => self.lsupd.rx,
            PacketType::LsAck => self.lsack.rx,
        }
    }
}

// ===== impl ListEntry =====

#[allow(clippy::derivable_impls)]
impl<V> Default for ListEntry<V>
where
    V: Version,
{
    fn default() -> ListEntry<V> {
        ListEntry::None
    }
}

// ===== configuration defaults =====

impl Default for InstanceCfg {
    fn default() -> InstanceCfg {
        let enabled = ospf::enabled::DFLT;
        let max_paths = ospf::spf_control::paths::DFLT;
        let spf_initial_delay =
            ospf::spf_control::ietf_spf_delay::initial_delay::DFLT;
        let spf_short_delay =
            ospf::spf_control::ietf_spf_delay::short_delay::DFLT;
        let spf_long_delay =
            ospf::spf_control::ietf_spf_delay::long_delay::DFLT;
        let spf_hold_down = ospf::spf_control::ietf_spf_delay::hold_down::DFLT;
        let spf_time_to_learn =
            ospf::spf_control::ietf_spf_delay::time_to_learn::DFLT;
        let extended_lsa = ospf::extended_lsa_support::DFLT;
        let sr_enabled = ospf::segment_routing::enabled::DFLT;
        let instance_id = ospf::instance_id::DFLT;

        InstanceCfg {
            af: None,
            enabled,
            router_id: None,
            preference: Default::default(),
            gr: Default::default(),
            max_paths,
            spf_initial_delay,
            spf_short_delay,
            spf_long_delay,
            spf_hold_down,
            spf_time_to_learn,
            stub_router: false,
            node_tags: Default::default(),
            extended_lsa,
            sr_enabled,
            instance_id,
            bier: Default::default(),
            trace_opts: Default::default(),
        }
    }
}

impl Default for BierOspfCfg {
    fn default() -> Self {
        let enabled = ospf::bier::bier::enable::DFLT;
        let advertise = ospf::bier::bier::advertise::DFLT;
        let receive = ospf::bier::bier::receive::DFLT;
        Self {
            mt_id: 0,
            enabled,
            advertise,
            receive,
        }
    }
}

impl Default for Preference {
    fn default() -> Preference {
        let intra_area = ospf::preference::all::DFLT;
        let inter_area = ospf::preference::all::DFLT;
        let external = ospf::preference::all::DFLT;

        Preference {
            intra_area,
            inter_area,
            external,
        }
    }
}

impl Default for InstanceGrCfg {
    fn default() -> InstanceGrCfg {
        let helper_enabled = ospf::graceful_restart::helper_enabled::DFLT;
        let helper_strict_lsa_checking =
            ospf::graceful_restart::helper_strict_lsa_checking::DFLT;

        InstanceGrCfg {
            helper_enabled,
            helper_strict_lsa_checking,
        }
    }
}

impl Default for AreaCfg {
    fn default() -> AreaCfg {
        let area_type = ospf::areas::area::area_type::DFLT;
        let area_type = AreaType::try_from_yang(area_type).unwrap();
        let summary = ospf::areas::area::summary::DFLT;
        let default_cost = ospf::areas::area::default_cost::DFLT;

        AreaCfg {
            area_type,
            summary,
            default_cost,
        }
    }
}

impl Default for RangeCfg {
    fn default() -> RangeCfg {
        let advertise = ospf::areas::area::ranges::range::advertise::DFLT;

        RangeCfg {
            advertise,
            cost: None,
        }
    }
}

impl<V> Default for InterfaceCfg<V>
where
    V: Version,
{
    fn default() -> InterfaceCfg<V> {
        let instance_id = ospf::instance_id::DFLT;
        let if_type =
            ospf::areas::area::interfaces::interface::interface_type::DFLT;
        let if_type = InterfaceType::try_from_yang(if_type).unwrap();
        let passive = ospf::areas::area::interfaces::interface::passive::DFLT;
        let priority = ospf::areas::area::interfaces::interface::priority::DFLT;
        let hello_interval =
            ospf::areas::area::interfaces::interface::hello_interval::DFLT;
        let dead_interval =
            ospf::areas::area::interfaces::interface::dead_interval::DFLT;
        let retransmit_interval =
            ospf::areas::area::interfaces::interface::retransmit_interval::DFLT;
        let transmit_delay =
            ospf::areas::area::interfaces::interface::transmit_delay::DFLT;
        let enabled = ospf::areas::area::interfaces::interface::enabled::DFLT;
        let cost = ospf::areas::area::interfaces::interface::cost::DFLT;
        let mtu_ignore =
            ospf::areas::area::interfaces::interface::mtu_ignore::DFLT;
        let node_flag =
            ospf::areas::area::interfaces::interface::node_flag::DFLT;
        let anycast_flag =
            ospf::areas::area::interfaces::interface::anycast_flag::DFLT;
        let bfd_enabled =
            ospf::areas::area::interfaces::interface::bfd::enabled::DFLT;
        let lls_enabled = ospf::areas::area::interfaces::interface::lls::DFLT;

        InterfaceCfg {
            instance_id: InheritableConfig::new(instance_id),
            if_type,
            passive,
            priority,
            hello_interval,
            dead_interval,
            retransmit_interval,
            transmit_delay,
            enabled,
            cost,
            mtu_ignore,
            node_flag,
            anycast_flag,
            static_nbrs: Default::default(),
            auth_keychain: None,
            auth_keyid: None,
            auth_key: None,
            auth_algo: None,
            bfd_enabled,
            bfd_params: Default::default(),
            trace_opts: Default::default(),
            lls_enabled,
            mdr: Default::default(),
        }
    }
}

impl Default for MdrInterfaceCfg {
    fn default() -> MdrInterfaceCfg {
        use ospf::areas::area::interfaces::interface::mdr;

        let adj_connectivity =
            MdrAdjConnectivity::try_from_yang(mdr::adj_connectivity::DFLT)
                .unwrap();
        let lsa_fullness =
            MdrLsaFullness::try_from_yang(mdr::lsa_fullness::DFLT).unwrap();
        let backup_wait_interval =
            mdr_duration_from_yang(mdr::backup_wait_interval::DFLT);
        let ack_interval = mdr_duration_from_yang(mdr::ack_interval::DFLT);

        MdrInterfaceCfg {
            enabled: mdr::enabled::DFLT,
            hello_interval: mdr::hello_interval::DFLT,
            dead_interval: mdr::dead_interval::DFLT,
            retransmit_interval: mdr::retransmit_interval::DFLT,
            router_priority: mdr::router_priority::DFLT,
            adj_connectivity,
            lsa_fullness,
            mdr_constraint: mdr::mdr_constraint::DFLT,
            backup_wait_interval,
            ack_interval,
            ack_cache_timeout: Duration::from_secs(100),
            two_hop_refresh: mdr::two_hop_refresh::DFLT,
            full_hello_repeat_count: mdr::full_hello_repeat_count::DFLT,
            consecutive_hello_threshold: mdr::consecutive_hello_threshold::DFLT,
            metric_tlv_enabled: mdr::metric_tlv_enabled::DFLT,
        }
    }
}

impl Default for StaticNbr {
    fn default() -> StaticNbr {
        let poll_interval = ospf::areas::area::interfaces::interface::static_neighbors::neighbor::poll_interval::DFLT;
        let priority = ospf::areas::area::interfaces::interface::static_neighbors::neighbor::priority::DFLT;

        StaticNbr {
            cost: None,
            poll_interval,
            priority,
        }
    }
}

impl Default for TraceOptionPacketResolved {
    fn default() -> TraceOptionPacketResolved {
        let disabled = TraceOptionPacketType {
            tx: false,
            rx: false,
        };
        TraceOptionPacketResolved {
            hello: disabled,
            dbdesc: disabled,
            lsreq: disabled,
            lsupd: disabled,
            lsack: disabled,
        }
    }
}

impl Default for TraceOptionPacketType {
    fn default() -> TraceOptionPacketType {
        let tx = ospf::trace_options::flag::send::DFLT;
        let rx = ospf::trace_options::flag::receive::DFLT;

        TraceOptionPacketType { tx, rx }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, OnceLock};

    use holo_northbound::configuration as nb_config;
    use holo_northbound::configuration::{
        CallbackArgs, CallbackKey, CallbackOp,
    };
    use holo_protocol::{InstanceChannelsTx, InstanceShared, ProtocolInstance};
    use holo_utils::ibus;
    use holo_utils::yang::{ContextExt, DataNodeRefExt};
    use holo_yang::YANG_CTX;
    use tokio::sync::mpsc;
    use yang5::context::Context;
    use yang5::data::{
        DataFormat, DataParserFlags, DataPrinterFlags, DataTree,
        DataValidationFlags,
    };

    use super::*;
    use crate::interface::Interface;

    static TEST_YANG_CTX: OnceLock<Arc<Context>> = OnceLock::new();

    fn yang_ctx() -> &'static Arc<Context> {
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
        })
    }

    fn ospfv3_mdr_config(mdr: &str, extra_interface: &str) -> String {
        format!(
            r#"{{
  "ietf-interfaces:interfaces": {{
    "interface": [
      {{
        "name": "eth0",
        "type": "iana-if-type:ethernetCsmacd",
        "ietf-ip:ipv6": {{"enabled": true}}
      }}
    ]
  }},
  "ietf-routing:routing": {{
    "control-plane-protocols": {{
      "control-plane-protocol": [
        {{
          "type": "ietf-ospf:ospfv3",
          "name": "main",
          "ietf-ospf:ospf": {{
            "areas": {{
              "area": [
                {{
                  "area-id": "0.0.0.0",
                  "interfaces": {{
                    "interface": [
                      {{
                        "name": "eth0",
                        "interface-type": "broadcast"{extra_interface},
                        "holo-ospf:mdr": {mdr}
                      }}
                    ]
                  }}
                }}
              ]
            }}
          }}
        }}
      ]
    }}
  }}
}}"#
        )
    }

    fn ospfv2_mdr_config() -> String {
        r#"{
  "ietf-interfaces:interfaces": {
    "interface": [
      {
        "name": "eth0",
        "type": "iana-if-type:ethernetCsmacd",
        "ietf-ip:ipv4": {}
      }
    ]
  },
  "ietf-routing:routing": {
    "control-plane-protocols": {
      "control-plane-protocol": [
        {
          "type": "ietf-ospf:ospfv2",
          "name": "main",
          "ietf-ospf:ospf": {
            "areas": {
              "area": [
                {
                  "area-id": "0.0.0.0",
                  "interfaces": {
                    "interface": [
                      {
                        "name": "eth0",
                        "interface-type": "broadcast",
                        "holo-ospf:mdr": {"enabled": true}
                      }
                    ]
                  }
                }
              ]
            }
          }
        }
      ]
    }
  }
}"#
        .to_string()
    }

    fn parse_config(data: &str) -> DataTree<'static> {
        DataTree::parse_string(
            yang_ctx(),
            data,
            DataFormat::JSON,
            DataParserFlags::empty(),
            DataValidationFlags::NO_STATE,
        )
        .expect("failed to parse data tree")
    }

    fn validate_ospfv3_config(config: DataTree<'static>) -> Result<(), String> {
        nb_config::validate(&[&VALIDATION_CALLBACKS_OSPFV3], &Arc::new(config))
            .map_err(|error| error.to_string())
    }

    fn find_mdr<'a>(config: &'a DataTree<'static>) -> DataNodeRef<'a> {
        config
            .find_xpath(
                ospf::areas::area::interfaces::interface::mdr::PATH.as_ref(),
            )
            .unwrap()
            .next()
            .expect("MDR container")
    }

    fn find_leaf<'a>(
        config: &'a DataTree<'static>,
        path: impl AsRef<str>,
    ) -> DataNodeRef<'a> {
        config
            .find_xpath(path.as_ref())
            .unwrap()
            .next()
            .expect("leaf")
    }

    fn test_instance() -> Instance<Ospfv3> {
        let (nb_tx, _nb_rx) = mpsc::unbounded_channel();
        let (ibus_tx, _ibus_rx) = ibus::ibus_channels();
        let (proto_tx, _proto_rx) =
            <Instance<Ospfv3> as ProtocolInstance>::protocol_input_channels();
        #[cfg(feature = "testing")]
        let (protocol_output_tx, _protocol_output_rx) = mpsc::channel(4);
        let channels_tx = InstanceChannelsTx::new(
            nb_tx,
            ibus_tx,
            proto_tx,
            #[cfg(feature = "testing")]
            protocol_output_tx,
        );

        <Instance<Ospfv3> as ProtocolInstance>::new(
            "test".into(),
            InstanceShared::default(),
            channels_tx,
        )
    }

    fn add_test_interface(
        instance: &mut Instance<Ospfv3>,
    ) -> (AreaIndex, InterfaceIndex) {
        let (area_idx, area) = instance.arenas.areas.insert(BACKBONE_AREA_ID);
        let (iface_idx, _) = area.interfaces.insert(
            &mut instance.arenas.interfaces,
            "eth0".into(),
            None,
        );
        (area_idx, iface_idx)
    }

    fn apply_mdr_modify(
        instance: &mut Instance<Ospfv3>,
        config: &Arc<DataTree<'static>>,
        area_idx: AreaIndex,
        iface_idx: InterfaceIndex,
        path: impl AsRef<str>,
    ) -> BTreeSet<Event> {
        let callbacks = Instance::<Ospfv3>::callbacks();
        let key = CallbackKey {
            path: path.as_ref().to_string(),
            operation: CallbackOp::Modify,
        };
        let cb = callbacks
            .0
            .get(&key)
            .and_then(|node| node.apply)
            .expect("MDR modify callback");
        let mut event_queue = BTreeSet::new();
        let mut resource: Option<Resource> = None;
        let dnode = find_leaf(config, path);
        let args = CallbackArgs {
            event_queue: &mut event_queue,
            list_entry: ListEntry::Interface(area_idx, iface_idx),
            resource: &mut resource,
            old_config: config,
            new_config: config,
            dnode,
        };

        cb(instance, args);

        event_queue
    }

    #[test]
    fn mdr_interface_config_defaults_match_rfc_5614_section_3_2() {
        let config = MdrInterfaceCfg::default();

        assert!(!config.enabled);
        assert_eq!(config.hello_interval, 2);
        assert_eq!(config.dead_interval, 6);
        assert_eq!(config.retransmit_interval, 7);
        assert_eq!(config.router_priority, 1);
        assert_eq!(config.adj_connectivity, MdrAdjConnectivity::Uniconnected);
        assert_eq!(config.lsa_fullness, MdrLsaFullness::MinCost);
        assert_eq!(config.mdr_constraint, 3);
        assert_eq!(config.backup_wait_interval, Duration::from_millis(500));
        assert_eq!(config.ack_interval, Duration::from_secs(1));
        assert_eq!(config.two_hop_refresh, 1);
        assert_eq!(config.full_hello_repeat_count, 3);
        assert_eq!(config.consecutive_hello_threshold, 1);
        assert!(config.metric_tlv_enabled);
    }

    #[test]
    fn mdr_config_round_trips_through_datastore() {
        let config = parse_config(&ospfv3_mdr_config(
            r#"{
              "enabled": true,
              "two-hop-refresh": 3
            }"#,
            "",
        ));
        validate_ospfv3_config(config.duplicate().unwrap()).unwrap();

        let printed = config
            .print_string(
                DataFormat::JSON,
                DataPrinterFlags::WITH_SIBLINGS | DataPrinterFlags::WD_TRIM,
            )
            .unwrap();
        let reparsed = parse_config(&printed);
        let mdr = find_mdr(&reparsed);

        assert_eq!(mdr.get_bool_relative("./enabled"), Some(true));
        assert_eq!(mdr.get_u16_relative("./two-hop-refresh"), Some(3));
    }

    #[test]
    fn mdr_rfc7038_value5_round_trips_as_single_hop_full() {
        let config = parse_config(&ospfv3_mdr_config(
            r#"{
              "enabled": true,
              "lsa-fullness": "single-hop-full"
            }"#,
            "",
        ));
        validate_ospfv3_config(config.duplicate().unwrap()).unwrap();
        let mdr = find_mdr(&config);

        assert_eq!(
            MdrLsaFullness::try_from_yang(
                &mdr.get_string_relative("./lsa-fullness").unwrap()
            ),
            Some(MdrLsaFullness::SingleHopFull)
        );

        let printed = config
            .print_string(
                DataFormat::JSON,
                DataPrinterFlags::WITH_SIBLINGS | DataPrinterFlags::WD_TRIM,
            )
            .unwrap();
        let reparsed = parse_config(&printed);
        let mdr = find_mdr(&reparsed);
        assert_eq!(
            mdr.get_string_relative("./lsa-fullness").as_deref(),
            Some("single-hop-full")
        );
    }

    #[test]
    fn mdr_modify_callbacks_update_runtime_config() {
        let config = Arc::new(parse_config(&ospfv3_mdr_config(
            r#"{
              "enabled": true,
              "hello-interval": 4,
              "dead-interval": 12,
              "retransmit-interval": 9,
              "router-priority": 7,
              "adj-connectivity": "biconnected",
              "lsa-fullness": "full",
              "mdr-constraint": 4,
              "backup-wait-interval": "0.250",
              "ack-interval": "0.750",
              "two-hop-refresh": 3,
              "full-hello-repeat-count": 4,
              "consecutive-hello-threshold": 2,
              "metric-tlv-enabled": false
            }"#,
            "",
        )));
        let mut instance = test_instance();
        let (area_idx, iface_idx) = add_test_interface(&mut instance);
        use ospf::areas::area::interfaces::interface::mdr;

        let paths = [
            mdr::enabled::PATH,
            mdr::hello_interval::PATH,
            mdr::dead_interval::PATH,
            mdr::retransmit_interval::PATH,
            mdr::router_priority::PATH,
            mdr::adj_connectivity::PATH,
            mdr::lsa_fullness::PATH,
            mdr::mdr_constraint::PATH,
            mdr::backup_wait_interval::PATH,
            mdr::ack_interval::PATH,
            mdr::two_hop_refresh::PATH,
            mdr::full_hello_repeat_count::PATH,
            mdr::consecutive_hello_threshold::PATH,
            mdr::metric_tlv_enabled::PATH,
        ];

        for path in paths {
            let events = apply_mdr_modify(
                &mut instance,
                &config,
                area_idx,
                iface_idx,
                path,
            );
            assert!(events.contains(&Event::InterfaceMdrConfigChange(
                area_idx, iface_idx
            )));
        }

        let iface: &Interface<Ospfv3> = &instance.arenas.interfaces[iface_idx];
        let config = &iface.config.mdr;
        assert!(config.enabled);
        assert_eq!(config.hello_interval, 4);
        assert_eq!(config.dead_interval, 12);
        assert_eq!(config.retransmit_interval, 9);
        assert_eq!(config.router_priority, 7);
        assert_eq!(config.adj_connectivity, MdrAdjConnectivity::Biconnected);
        assert_eq!(config.lsa_fullness, MdrLsaFullness::Full);
        assert_eq!(config.mdr_constraint, 4);
        assert_eq!(config.backup_wait_interval, Duration::from_millis(250));
        assert_eq!(config.ack_interval, Duration::from_millis(750));
        assert_eq!(config.two_hop_refresh, 3);
        assert_eq!(config.full_hello_repeat_count, 4);
        assert_eq!(config.consecutive_hello_threshold, 2);
        assert!(!config.metric_tlv_enabled);
    }

    #[test]
    fn mdr_validation_rejects_unsupported_combinations() {
        let invalid_full_minimal = parse_config(&ospfv3_mdr_config(
            r#"{
              "enabled": true,
              "adj-connectivity": "full",
              "lsa-fullness": "minimal"
            }"#,
            "",
        ));
        let error =
            validate_mdr_interface_config(&find_mdr(&invalid_full_minimal))
                .unwrap_err();
        assert!(error.contains("LSAFullness"), "{error}");
        assert!(validate_ospfv3_config(invalid_full_minimal).is_err());

        let invalid_ack = parse_config(&ospfv3_mdr_config(
            r#"{
              "enabled": true,
              "retransmit-interval": 1,
              "ack-interval": "1.0"
            }"#,
            "",
        ));
        let error =
            validate_mdr_interface_config(&find_mdr(&invalid_ack)).unwrap_err();
        assert!(error.contains("AckInterval"), "{error}");
        assert!(validate_ospfv3_config(invalid_ack).is_err());

        let passive = parse_config(&ospfv3_mdr_config(
            r#"{"enabled": true}"#,
            r#", "passive": true"#,
        ));
        let error =
            validate_mdr_interface_config(&find_mdr(&passive)).unwrap_err();
        assert!(error.contains("passive interface"), "{error}");
        assert!(validate_ospfv3_config(passive).is_err());
    }

    #[test]
    fn mdr_config_is_ospfv3_only() {
        let result = DataTree::parse_string(
            yang_ctx(),
            &ospfv2_mdr_config(),
            DataFormat::JSON,
            DataParserFlags::empty(),
            DataValidationFlags::NO_STATE,
        );

        assert!(result.is_err());
    }
}
