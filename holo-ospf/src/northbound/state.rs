//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use holo_northbound::state::{ListIterator, Provider, YangContainer, YangList, YangOps};
use holo_utils::ip::IpAddrKind;
use holo_utils::num::SaturatingInto;
use holo_utils::option::OptionExt;
use holo_utils::protocol::Protocol;
use holo_utils::sr::IgpAlgoType;
use holo_yang::types::{HexStr, TimerValueMillis, TimerValueSecs16, Timeticks};
use holo_yang::{ToYang, ToYangFlags};
use num_traits::FromPrimitive;

use crate::area::Area;
use crate::collections::LsdbSingleType;
use crate::instance::Instance;
use crate::interface::{Interface, ism};
use crate::lsdb::{LsaEntry, LsaLogEntry, LsaLogId};
use crate::neighbor::{Neighbor, nsm};
use crate::northbound::yang::FletcherChecksum16;
use crate::northbound::yang_gen::ospf;
use crate::ospfv3::mdr::MdrLevel;
use crate::packet::lsa::{LsaBodyVersion, LsaHdrVersion};
use crate::packet::tlv::{BierEncapSubStlv, BierStlv, GrReason, NodeAdminTagTlv, SidLabelRangeTlv, SrLocalBlockTlv, UnknownTlv};
use crate::route::{Nexthop, RouteNet};
use crate::spf::SpfLogEntry;
use crate::version::{Ospfv2, Ospfv3, Version};
use crate::{ospfv2, ospfv3};

impl<V> Provider for Instance<V>
where
    V: Version,
{
    type ListEntry<'a> = V::ListEntry<'a>;
    const YANG_OPS: YangOps<Self> = V::YANG_OPS_STATE;

    fn top_level_node(&self) -> String {
        format!("/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='{}'][name='{}']/ietf-ospf:ospf", V::PROTOCOL.to_yang(), self.name)
    }
}

// ListEntry for OSPFv3 extended Router-LSA link sub-TLV lists.
#[derive(Debug)]
pub enum Ospfv3RouterLinkSubTlv<'a> {
    AdjSids(&'a Vec<ospfv3::packet::lsa::AdjSid>),
    Unknown(&'a UnknownTlv),
}

// ListEntry for OSPFv3 extended prefix sub-TLV lists.
#[derive(Debug)]
pub enum Ospfv3PrefixSubTlv<'a> {
    PrefixSids(&'a BTreeMap<IgpAlgoType, ospfv3::packet::lsa::PrefixSid>),
    Biers(&'a Vec<BierStlv>),
    Unknown(&'a UnknownTlv),
}

// ListEntry for OSPFv3 BIER sub-sub-TLV lists.
#[derive(Debug)]
pub enum Ospfv3BierSubSubTlv<'a> {
    BierEncaps(&'a Vec<BierEncapSubStlv>),
    Unknown(&'a UnknownTlv),
}

// ListEntry for the OSPFv3 E-Link-LSA TLV list.
#[derive(Debug)]
pub enum Ospfv3ELinkTlv<'a> {
    LinkPrefix(&'a ospfv3::packet::lsa::LsaLinkPrefix),
    LinkLocalAddr(IpAddr),
}

// ===== YANG impls =====

impl<'a, V: Version> YangContainer<'a, Instance<V>> for ospf::Ospf {
    type ParentListEntry = ();

    fn new(instance: &'a Instance<V>, _: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            router_id: instance.state.as_ref().map(|state| state.router_id),
        })
    }
}

impl<'a, V: Version> YangContainer<'a, Instance<V>> for ospf::spf_control::ietf_spf_delay::IetfSpfDelay<'a> {
    type ParentListEntry = ();

    fn new(instance: &'a Instance<V>, _: &Self::ParentListEntry) -> Option<Self> {
        let state = instance.state.as_ref()?;
        Some(Self {
            current_state: Some(state.spf_delay_state.to_yang()),
            remaining_time_to_learn: state.spf_learn_timer.as_ref().map(|task| TimerValueMillis(task.remaining())).ignore_in_testing(),
            remaining_hold_down: state.spf_hold_down_timer.as_ref().map(|task| TimerValueMillis(task.remaining())).ignore_in_testing(),
            last_event_received: state.spf_last_event_rcvd.as_ref().map(|t| Timeticks(*t)).ignore_in_testing(),
            next_spf_time: state.spf_delay_timer.as_ref().map(|timer| Timeticks(Instant::now() + timer.remaining())).ignore_in_testing(),
            last_spf_time: state.spf_last_time.as_ref().map(|t| Timeticks(*t)).ignore_in_testing(),
        })
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::local_rib::route::Route {
    type ParentListEntry = ();
    type ListEntry = (&'a V::IpNetwork, &'a RouteNet<V>);

    fn iter(instance: &'a Instance<V>, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let rib = &instance.state.as_ref()?.rib;
        let iter = rib.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<V>, (prefix, route): &Self::ListEntry) -> Self {
        Self {
            prefix: (**prefix).into(),
            metric: Some(route.metric),
            route_type: Some(route.path_type),
            route_tag: route.tag,
        }
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::local_rib::route::next_hops::next_hop::NextHop<'a> {
    type ParentListEntry = (&'a V::IpNetwork, &'a RouteNet<V>);
    type ListEntry = &'a Nexthop<V::IpAddr>;

    fn iter(_instance: &'a Instance<V>, (_, route): &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = route.nexthops.values();
        Some(iter)
    }

    fn new(instance: &'a Instance<V>, nexthop: &Self::ListEntry) -> Self {
        let iface = &instance.arenas.interfaces[nexthop.iface_idx];
        Self {
            outgoing_interface: Some(iface.name.as_str().into()),
            next_hop: nexthop.addr.map(std::convert::Into::into),
        }
    }
}

impl<'a, V: Version> YangContainer<'a, Instance<V>> for ospf::statistics::Statistics {
    type ParentListEntry = ();

    fn new(instance: &'a Instance<V>, _: &Self::ParentListEntry) -> Option<Self> {
        let state = instance.state.as_ref()?;
        Some(Self {
            discontinuity_time: Some(state.discontinuity_time).ignore_in_testing(),
            originate_new_lsa_count: Some(state.orig_lsa_count).ignore_in_testing(),
            rx_new_lsas_count: Some(state.rx_lsa_count).ignore_in_testing(),
            as_scope_lsa_count: Some(state.lsdb.lsa_count()),
            as_scope_lsa_chksum_sum: Some(state.lsdb.cksum_sum()).ignore_in_testing(),
        })
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::statistics::database::as_scope_lsa_type::AsScopeLsaType {
    type ParentListEntry = ();
    type ListEntry = &'a LsdbSingleType<V>;

    fn iter(instance: &'a Instance<V>, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsdb = &instance.state.as_ref()?.lsdb;
        let iter = lsdb.iter_types();
        Some(iter)
    }

    fn new(_instance: &'a Instance<V>, lsdb_type: &Self::ListEntry) -> Self {
        Self {
            lsa_type: Some(lsdb_type.lsa_type().into()),
            lsa_count: Some(lsdb_type.lsa_count()),
            lsa_cksum_sum: Some(lsdb_type.cksum_sum()).ignore_in_testing(),
        }
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::database::as_scope_lsa_type::AsScopeLsaType {
    type ParentListEntry = ();
    type ListEntry = &'a LsdbSingleType<V>;

    fn iter(instance: &'a Instance<V>, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsdb = &instance.state.as_ref()?.lsdb;
        let iter = lsdb.iter_types();
        Some(iter)
    }

    fn new(_instance: &'a Instance<V>, lsdb_type: &Self::ListEntry) -> Self {
        Self {
            lsa_type: lsdb_type.lsa_type().into(),
        }
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::AsScopeLsa<'a> {
    type ParentListEntry = &'a LsdbSingleType<V>;
    type ListEntry = &'a LsaEntry<V>;

    fn iter(instance: &'a Instance<V>, lsdb_type: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = lsdb_type.iter(&instance.arenas.lsa_entries).map(|(_, lse)| lse);
        Some(iter)
    }

    fn new(_instance: &'a Instance<V>, lse: &Self::ListEntry) -> Self {
        let lsa = &lse.data;
        Self {
            lsa_id: lsa.hdr.lsa_id().to_string().into(),
            adv_router: lsa.hdr.adv_rtr(),
            decode_completed: Some(!lsa.body.is_unknown()),
            raw_data: Some(HexStr(lsa.raw.as_ref())).ignore_in_testing(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::header::Header<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;

    fn new(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let (opaque_type, opaque_id) = lsa_hdr_opaque_data(&lsa.hdr);
        Some(Self {
            lsa_id: Some(lsa.hdr.lsa_id),
            opaque_type,
            opaque_id,
            age: Some(lsa.age()).ignore_in_testing(),
            r#type: Some(lsa.hdr.lsa_type.to_yang()),
            adv_router: Some(lsa.hdr.adv_rtr),
            seq_num: Some(lsa.hdr.seq_no).ignore_in_testing(),
            checksum: Some(FletcherChecksum16(lsa.hdr.cksum)).ignore_in_testing(),
            length: Some(lsa.hdr.length),
            maxage: lsa.hdr.is_maxage().then_some(()).only_in_testing(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::header::lsa_options::LsaOptions<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;

    fn new(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        Some(Self {
            lsa_options: lsa.hdr.options.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::external::External {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;

    fn new(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        Some(Self {
            network_mask: lsa.body.as_as_external().map(|lsa_body| lsa_body.mask),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::external::topologies::topology::Topology<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;
    type ListEntry = &'a LsaEntry<Ospfv2>;

    fn iter(_instance: &'a Instance<Ospfv2>, &lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let _lsa_body = lsa.body.as_as_external()?;
        let iter = std::iter::once(lse);
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, lse: &Self::ListEntry) -> Self {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_as_external().unwrap();
        Self {
            mt_id: Some(0),
            flags: Some(lsa_body.flags.to_yang()),
            metric: Some(lsa_body.metric),
            forwarding_address: lsa_body.fwd_addr,
            external_route_tag: Some(lsa_body.tag),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>>
    for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::router_informational_capabilities::RouterInformationalCapabilities<'a>
{
    type ParentListEntry = &'a LsaEntry<Ospfv2>;

    fn new(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let info_caps = lsa.body.as_opaque_as()?.as_router_info()?.info_caps.as_ref()?;
        Some(Self {
            informational_capabilities: info_caps.get().to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::informational_capabilities_flags::InformationalCapabilitiesFlags {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;
    type ListEntry = u32;

    fn iter(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let info_caps = lsa.body.as_opaque_as()?.as_router_info()?.info_caps.as_ref()?;
        let info_caps = info_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| info_caps & flag != 0);
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, flag: &Self::ListEntry) -> Self {
        Self {
            informational_flag: Some(*flag),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::functional_capabilities::FunctionalCapabilities {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;
    type ListEntry = u32;

    fn iter(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let func_caps = lsa.body.as_opaque_as()?.as_router_info()?.func_caps.as_ref()?;
        let func_caps = func_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| func_caps & flag != 0);
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, flag: &Self::ListEntry) -> Self {
        Self {
            functional_flag: Some(*flag),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::dynamic_hostname_tlv::DynamicHostnameTlv<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;

    fn new(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let hostname = lsa.body.as_opaque_as()?.as_router_info()?.info_hostname.as_ref()?;
        Some(Self {
            hostname: Some(Cow::Borrowed(hostname.get())),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::maximum_sid_depth_tlv::msd_type::MsdType {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;
    type ListEntry = (u8, u8);

    fn iter(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let msds = lsa.body.as_opaque_as()?.as_router_info()?.msds.as_ref()?;
        let iter = msds.get().iter().map(|(msd_type, msd_value)| (*msd_type, *msd_value));
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, (msd_type, msd_value): &Self::ListEntry) -> Self {
        Self {
            msd_type: Some(*msd_type),
            msd_value: Some(*msd_value),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;
    type ListEntry = &'a UnknownTlv;

    fn iter(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_as()?.as_router_info()?;
        let iter = lsa_body.unknown_tlvs.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, tlv: &Self::ListEntry) -> Self {
        Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(HexStr(tlv.value.as_ref())),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::sr_algorithm_tlv::SrAlgorithmTlv<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;

    fn new(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_link()?.as_router_info()?;
        let iter = lsa_body.sr_algo.iter().flat_map(|tlv| tlv.get().iter()).map(|algo| algo.to_yang());
        Some(Self {
            sr_algorithm: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::sid_range_tlvs::sid_range_tlv::SidRangeTlv {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;
    type ListEntry = &'a SidLabelRangeTlv;

    fn iter(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_as()?.as_router_info()?;
        let iter = lsa_body.srgb.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, srgb: &Self::ListEntry) -> Self {
        Self {
            range_size: Some(srgb.range),
            label_value: srgb.first.as_label().map(|label| label.get()),
            index_value: srgb.first.as_index().copied(),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::local_block_tlvs::local_block_tlv::LocalBlockTlv {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;
    type ListEntry = &'a SrLocalBlockTlv;

    fn iter(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_link()?.as_router_info()?;
        let iter = lsa_body.srlb.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, srlb: &Self::ListEntry) -> Self {
        Self {
            range_size: Some(srlb.range),
            label_value: srlb.first.as_label().map(|label| label.get()),
            index_value: srlb.first.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::ri_opaque::srms_preference_tlv::SrmsPreferenceTlv {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;

    fn new(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_as()?.as_router_info()?;
        Some(Self {
            preference: lsa_body.srms_pref.as_ref().map(|tlv| tlv.get()),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::ExtendedPrefixTlv<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;
    type ListEntry = &'a ospfv2::packet::lsa_opaque::ExtPrefixTlv;

    fn iter(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_as()?.as_ext_prefix()?;
        let iter = lsa_body.prefixes.values();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, tlv: &Self::ListEntry) -> Self {
        Self {
            route_type: Some(tlv.route_type.to_yang()),
            prefix: Some(tlv.prefix.into()),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::flags::Flags<'a> {
    type ParentListEntry = &'a ospfv2::packet::lsa_opaque::ExtPrefixTlv;

    fn new(_instance: &'a Instance<Ospfv2>, tlv: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            extended_prefix_flags: tlv.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    type ParentListEntry = &'a ospfv2::packet::lsa_opaque::ExtPrefixTlv;
    type ListEntry = &'a UnknownTlv;

    fn iter(_instance: &'a Instance<Ospfv2>, tlv: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = tlv.unknown_tlvs.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, tlv: &Self::ListEntry) -> Self {
        Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(HexStr(tlv.value.as_ref())),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PrefixSidSubTlv<'a> {
    type ParentListEntry = &'a ospfv2::packet::lsa_opaque::ExtPrefixTlv;
    type ListEntry = &'a ospfv2::packet::lsa_opaque::PrefixSid;

    fn iter(_instance: &'a Instance<Ospfv2>, tlv: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = tlv.prefix_sids.values();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, stlv: &Self::ListEntry) -> Self {
        Self {
            mt_id: Some(0),
            algorithm: Some(stlv.algo.to_yang()),
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>>
    for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::prefix_sid_flags::PrefixSidFlags<'a>
{
    type ParentListEntry = &'a ospfv2::packet::lsa_opaque::PrefixSid;

    fn new(_instance: &'a Instance<Ospfv2>, prefix_sid: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            flag: prefix_sid.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::header::Header<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        Some(Self {
            lsa_id: Some(lsa.hdr.lsa_id.into()),
            age: Some(lsa.age()).ignore_in_testing(),
            r#type: Some(lsa.hdr.lsa_type.to_yang()),
            adv_router: Some(lsa.hdr.adv_rtr),
            seq_num: Some(lsa.hdr.seq_no).ignore_in_testing(),
            checksum: Some(FletcherChecksum16(lsa.hdr.cksum)).ignore_in_testing(),
            length: Some(lsa.hdr.length),
            maxage: lsa.hdr.is_maxage().then_some(()).only_in_testing(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::as_external::AsExternal<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_as_external()?;
        Some(Self {
            metric: Some(lsa_body.metric),
            flags: Some(lsa_body.flags.to_yang()),
            referenced_ls_type: lsa_body.ref_lsa_type.map(|lsa_type| lsa_type.to_yang()),
            unknown_referenced_ls_type: lsa_body.ref_lsa_type.and_then(|ref_lsa_type| if ref_lsa_type.function_code().is_none() { Some(ref_lsa_type.0) } else { None }),
            prefix: Some(lsa_body.prefix),
            forwarding_address: lsa_body.fwd_addr.map(|addr| match addr {
                IpAddr::V4(addr) => addr.to_ipv6_mapped(),
                IpAddr::V6(addr) => addr,
            }),
            external_route_tag: lsa_body.tag,
            referenced_link_state_id: lsa_body.ref_lsa_id.map(|lsa_id| lsa_id.into()),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::as_external::prefix_options::PrefixOptions<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_as_external()?;
        Some(Self {
            prefix_options: lsa_body.prefix_options.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::router_informational_capabilities::RouterInformationalCapabilities<'a>
{
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let info_caps = lsa.body.as_router_info()?.info_caps.as_ref()?;
        Some(Self {
            informational_capabilities: info_caps.get().to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::informational_capabilities_flags::InformationalCapabilitiesFlags {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;
    type ListEntry = u32;

    fn iter(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let info_caps = lsa.body.as_router_info()?.info_caps.as_ref()?;
        let info_caps = info_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| info_caps & flag != 0);
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, flag: &Self::ListEntry) -> Self {
        Self {
            informational_flag: Some(*flag),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::functional_capabilities::FunctionalCapabilities {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;
    type ListEntry = u32;

    fn iter(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let func_caps = lsa.body.as_router_info()?.func_caps.as_ref()?;
        let func_caps = func_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| func_caps & flag != 0);
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, flag: &Self::ListEntry) -> Self {
        Self {
            functional_flag: Some(*flag),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::dynamic_hostname_tlv::DynamicHostnameTlv<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let info_hostname = lsa.body.as_router_info()?.info_hostname.as_ref()?;
        Some(Self {
            hostname: Some(Cow::Borrowed(info_hostname.get())),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::sr_algorithm_tlv::SrAlgorithmTlv<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_router_info()?;
        let iter = lsa_body.sr_algo.iter().flat_map(|tlv| tlv.get().iter()).map(|algo| algo.to_yang());
        Some(Self {
            sr_algorithm: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::sid_range_tlvs::sid_range_tlv::SidRangeTlv {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;
    type ListEntry = &'a SidLabelRangeTlv;

    fn iter(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_router_info()?;
        let iter = lsa_body.srgb.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, srgb: &Self::ListEntry) -> Self {
        Self {
            range_size: Some(srgb.range),
            label_value: srgb.first.as_label().map(|label| label.get()),
            index_value: srgb.first.as_index().copied(),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::local_block_tlvs::local_block_tlv::LocalBlockTlv {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;
    type ListEntry = &'a SrLocalBlockTlv;

    fn iter(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_router_info()?;
        let iter = lsa_body.srlb.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, srlb: &Self::ListEntry) -> Self {
        Self {
            range_size: Some(srlb.range),
            label_value: srlb.first.as_label().map(|label| label.get()),
            index_value: srlb.first.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::router_information::srms_preference_tlv::SrmsPreferenceTlv {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_router_info()?;
        Some(Self {
            preference: lsa_body.srms_pref.as_ref().map(|tlv| tlv.get()),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::EExternalTlvs {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;
    type ListEntry = &'a LsaEntry<Ospfv3>;

    fn iter(_instance: &'a Instance<Ospfv3>, &lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let _ = lsa.body.as_ext_as_external()?;
        let iter = std::iter::once(lse);
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, _tlv: &Self::ListEntry) -> Self {
        Self {}
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::unknown_tlv::UnknownTlv<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, _lse: &Self::ParentListEntry) -> Option<Self> {
        // TODO: unknown TLVs aren't tracked at this level yet.
        None
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::ExternalPrefixTlv {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_as_external()?;
        Some(Self {
            metric: Some(lsa_body.metric),
            prefix: Some(lsa_body.prefix),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::flags::Flags<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_as_external()?;
        Some(Self {
            ospfv3_e_external_prefix_bits: lsa_body.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::prefix_options::PrefixOptions<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_as_external()?;
        Some(Self {
            prefix_options: lsa_body.prefix_options.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::SubTlvs {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;
    type ListEntry = Ospfv3PrefixSubTlv<'a>;

    fn iter(_instance: &'a Instance<Ospfv3>, _lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        None::<std::iter::Empty<_>> // TODO
    }

    fn new(_instance: &'a Instance<Ospfv3>, _tlv: &Self::ListEntry) -> Self {
        Self {}
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::ipv6_fwd_addr_sub_tlv::Ipv6FwdAddrSubTlv {
    type ParentListEntry = Ospfv3PrefixSubTlv<'a>;

    fn new(_instance: &'a Instance<Ospfv3>, _sub_tlv: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            forwarding_address: None, // TODO
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::ipv4_fwd_addr_sub_tlv::Ipv4FwdAddrSubTlv {
    type ParentListEntry = Ospfv3PrefixSubTlv<'a>;

    fn new(_instance: &'a Instance<Ospfv3>, _sub_tlv: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            forwarding_address: None, // TODO
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::route_tag_sub_tlv::RouteTagSubTlv {
    type ParentListEntry = Ospfv3PrefixSubTlv<'a>;

    fn new(_instance: &'a Instance<Ospfv3>, _sub_tlv: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            route_tag: None, // TODO
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::unknown_sub_tlv::UnknownSubTlv<'a> {
    type ParentListEntry = Ospfv3PrefixSubTlv<'a>;

    fn new(_instance: &'a Instance<Ospfv3>, parent: &Self::ParentListEntry) -> Option<Self> {
        let Ospfv3PrefixSubTlv::Unknown(tlv) = parent else {
            return None;
        };
        Some(Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(HexStr(tlv.value.as_ref())),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>>
    for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PrefixSidSubTlv<'a>
{
    type ParentListEntry = Ospfv3PrefixSubTlv<'a>;
    type ListEntry = &'a ospfv3::packet::lsa::PrefixSid;

    fn iter(_instance: &'a Instance<Ospfv3>, parent: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let Ospfv3PrefixSubTlv::PrefixSids(prefix_sids) = parent else {
            return None;
        };
        let iter = prefix_sids.values();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, stlv: &Self::ListEntry) -> Self {
        Self {
            algorithm: Some(stlv.algo.to_yang()),
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::database::as_scope_lsa_type::as_scope_lsas::as_scope_lsa::ospfv3::body::e_as_external::e_external_tlvs::external_prefix_tlv::sub_tlvs::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::ospfv3_prefix_sid_flags::Ospfv3PrefixSidFlags<'a>
{
    type ParentListEntry = &'a ospfv3::packet::lsa::PrefixSid;

    fn new(_instance: &'a Instance<Ospfv3>, prefix_sid: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            flag: prefix_sid.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::spf_log::event::Event<'a> {
    type ParentListEntry = ();
    type ListEntry = &'a SpfLogEntry<V>;

    fn iter(instance: &'a Instance<V>, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let spf_log = &instance.state.as_ref()?.spf_log;
        let iter = spf_log.iter();
        Some(iter).ignore_in_testing()
    }

    fn new(_instance: &'a Instance<V>, log: &Self::ListEntry) -> Self {
        Self {
            id: log.id,
            spf_type: Some(log.spf_type.to_yang()),
            schedule_timestamp: Some(Timeticks(log.schedule_time)),
            start_timestamp: Some(Timeticks(log.start_time)),
            end_timestamp: Some(Timeticks(log.end_time)),
        }
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::spf_log::event::trigger_lsa::TriggerLsa<'a> {
    type ParentListEntry = &'a SpfLogEntry<V>;
    type ListEntry = &'a LsaLogId<V>;

    fn iter(_instance: &'a Instance<V>, log: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = log.trigger_lsas.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<V>, lsa_id: &Self::ListEntry) -> Self {
        Self {
            area_id: lsa_id.area_id,
            r#type: Some(lsa_id.lsa_type.into()),
            lsa_id: Some(lsa_id.lsa_id.to_string().into()),
            adv_router: Some(lsa_id.adv_rtr),
            seq_num: Some(lsa_id.seq_no).ignore_in_testing(),
        }
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::lsa_log::event::Event<'a> {
    type ParentListEntry = ();
    type ListEntry = &'a LsaLogEntry<V>;

    fn iter(instance: &'a Instance<V>, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa_log = &instance.state.as_ref()?.lsa_log;
        let iter = lsa_log.iter();
        Some(iter).ignore_in_testing()
    }

    fn new(_instance: &'a Instance<V>, log: &Self::ListEntry) -> Self {
        Self {
            id: log.id,
            received_timestamp: log.rcvd_time.as_ref().map(|t| Timeticks(*t)).ignore_in_testing(),
            reason: Some(log.reason.to_yang()),
        }
    }
}

impl<'a, V: Version> YangContainer<'a, Instance<V>> for ospf::lsa_log::event::lsa::Lsa<'a> {
    type ParentListEntry = &'a LsaLogEntry<V>;

    fn new(_instance: &'a Instance<V>, log: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            area_id: log.lsa.area_id,
            r#type: Some(log.lsa.lsa_type.into()),
            lsa_id: Some(log.lsa.lsa_id.to_string().into()),
            adv_router: Some(log.lsa.adv_rtr),
            seq_num: Some(log.lsa.seq_no).ignore_in_testing(),
        })
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::areas::area::Area {
    type ParentListEntry = ();
    type ListEntry = &'a Area<V>;

    fn iter(instance: &'a Instance<V>, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = instance.arenas.areas.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<V>, area: &Self::ListEntry) -> Self {
        Self {
            area_id: area.area_id,
        }
    }
}

impl<'a, V: Version> YangContainer<'a, Instance<V>> for ospf::areas::area::statistics::Statistics {
    type ParentListEntry = &'a Area<V>;

    fn new(_instance: &'a Instance<V>, area: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            discontinuity_time: Some(area.state.discontinuity_time).ignore_in_testing(),
            spf_runs_count: Some(area.state.spf_run_count).ignore_in_testing(),
            abr_count: Some(area.abr_count() as _),
            asbr_count: Some(area.asbr_count() as _),
            area_scope_lsa_count: Some(area.state.lsdb.lsa_count()),
            area_scope_lsa_cksum_sum: Some(area.state.lsdb.cksum_sum()).ignore_in_testing(),
        })
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::areas::area::statistics::database::area_scope_lsa_type::AreaScopeLsaType {
    type ParentListEntry = &'a Area<V>;
    type ListEntry = &'a LsdbSingleType<V>;

    fn iter(_instance: &'a Instance<V>, area: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = area.state.lsdb.iter_types();
        Some(iter)
    }

    fn new(_instance: &'a Instance<V>, lsdb_type: &Self::ListEntry) -> Self {
        Self {
            lsa_type: Some(lsdb_type.lsa_type().into()),
            lsa_count: Some(lsdb_type.lsa_count()),
            lsa_cksum_sum: Some(lsdb_type.cksum_sum()).ignore_in_testing(),
        }
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::areas::area::database::area_scope_lsa_type::AreaScopeLsaType {
    type ParentListEntry = &'a Area<V>;
    type ListEntry = &'a LsdbSingleType<V>;

    fn iter(_instance: &'a Instance<V>, area: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = area.state.lsdb.iter_types();
        Some(iter)
    }

    fn new(_instance: &'a Instance<V>, lsdb_type: &Self::ListEntry) -> Self {
        Self {
            lsa_type: lsdb_type.lsa_type().into(),
        }
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::AreaScopeLsa<'a> {
    type ParentListEntry = &'a LsdbSingleType<V>;
    type ListEntry = &'a LsaEntry<V>;

    fn iter(instance: &'a Instance<V>, lsdb_type: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = lsdb_type.iter(&instance.arenas.lsa_entries).map(|(_, lse)| lse);
        Some(iter)
    }

    fn new(_instance: &'a Instance<V>, lse: &Self::ListEntry) -> Self {
        let lsa = &lse.data;
        Self {
            lsa_id: lsa.hdr.lsa_id().to_string().into(),
            adv_router: lsa.hdr.adv_rtr(),
            decode_completed: Some(!lsa.body.is_unknown()),
            raw_data: Some(HexStr(lsa.raw.as_ref())).ignore_in_testing(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::header::Header<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;

    fn new(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let (opaque_type, opaque_id) = lsa_hdr_opaque_data(&lsa.hdr);
        Some(Self {
            lsa_id: Some(lsa.hdr.lsa_id),
            opaque_type,
            opaque_id,
            age: Some(lsa.age()).ignore_in_testing(),
            r#type: Some(lsa.hdr.lsa_type.to_yang()),
            adv_router: Some(lsa.hdr.adv_rtr),
            seq_num: Some(lsa.hdr.seq_no).ignore_in_testing(),
            checksum: Some(FletcherChecksum16(lsa.hdr.cksum)).ignore_in_testing(),
            length: Some(lsa.hdr.length),
            maxage: lsa.hdr.is_maxage().then_some(()).only_in_testing(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::header::lsa_options::LsaOptions<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;

    fn new(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        Some(Self {
            lsa_options: lsa.hdr.options.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::router::Router {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;

    fn new(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_router()?;
        Some(Self {
            num_of_links: Some(lsa_body.links.len() as u16),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::router::router_bits::RouterBits<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;

    fn new(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_router()?;
        Some(Self {
            rtr_lsa_bits: lsa_body.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::router::links::link::Link<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;
    type ListEntry = &'a ospfv2::packet::lsa::LsaRouterLink;

    fn iter(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_router()?;
        let iter = lsa_body.links.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, rtr_link: &Self::ListEntry) -> Self {
        Self {
            link_id: Some(rtr_link.link_id.to_string().into()),
            link_data: Some(rtr_link.link_data.to_string().into()),
            r#type: Some(rtr_link.link_type.to_yang()),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::router::links::link::topologies::topology::Topology {
    type ParentListEntry = &'a ospfv2::packet::lsa::LsaRouterLink;
    type ListEntry = &'a ospfv2::packet::lsa::LsaRouterLink;

    fn iter(_instance: &'a Instance<Ospfv2>, rtr_link: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = std::iter::once(*rtr_link);
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, rtr_link: &Self::ListEntry) -> Self {
        Self {
            mt_id: Some(0),
            metric: Some(rtr_link.metric),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::network::Network {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;

    fn new(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_network()?;
        Some(Self {
            network_mask: Some(lsa_body.mask),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::network::attached_routers::AttachedRouters<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;

    fn new(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_network()?;
        let iter = lsa_body.attached_rtrs.iter().copied();
        Some(Self {
            attached_router: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::summary::Summary {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;

    fn new(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_summary()?;
        Some(Self {
            network_mask: Some(lsa_body.mask),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::summary::topologies::topology::Topology {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;
    type ListEntry = &'a LsaEntry<Ospfv2>;

    fn iter(_instance: &'a Instance<Ospfv2>, &lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let _ = lsa.body.as_summary()?;
        let iter = std::iter::once(lse);
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, lse: &Self::ListEntry) -> Self {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_summary().unwrap();
        Self {
            mt_id: Some(0),
            metric: Some(lsa_body.metric),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::router_informational_capabilities::RouterInformationalCapabilities<'a>
{
    type ParentListEntry = &'a LsaEntry<Ospfv2>;

    fn new(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let info_caps = lsa.body.as_opaque_area()?.as_router_info()?.info_caps.as_ref()?;
        Some(Self {
            informational_capabilities: info_caps.get().to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::informational_capabilities_flags::InformationalCapabilitiesFlags
{
    type ParentListEntry = &'a LsaEntry<Ospfv2>;
    type ListEntry = u32;

    fn iter(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let info_caps = lsa.body.as_opaque_area()?.as_router_info()?.info_caps.as_ref()?;
        let info_caps = info_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| info_caps & flag != 0);
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, flag: &Self::ListEntry) -> Self {
        Self {
            informational_flag: Some(*flag),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::functional_capabilities::FunctionalCapabilities {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;
    type ListEntry = u32;

    fn iter(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let func_caps = lsa.body.as_opaque_area()?.as_router_info()?.func_caps.as_ref()?;
        let func_caps = func_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| func_caps & flag != 0);
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, flag: &Self::ListEntry) -> Self {
        Self {
            functional_flag: Some(*flag),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::node_tag_tlvs::node_tag_tlv::NodeTagTlv {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;
    type ListEntry = &'a NodeAdminTagTlv;

    fn iter(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_area()?.as_router_info()?;
        let iter = lsa_body.node_tags.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, _tlv: &Self::ListEntry) -> Self {
        Self {}
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::node_tag_tlvs::node_tag_tlv::node_tag::NodeTag {
    type ParentListEntry = &'a NodeAdminTagTlv;
    type ListEntry = &'a u32;

    fn iter(_instance: &'a Instance<Ospfv2>, tlv: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = tlv.tags.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, tag: &Self::ListEntry) -> Self {
        Self {
            tag: Some(**tag),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::dynamic_hostname_tlv::DynamicHostnameTlv<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;

    fn new(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let hostname = lsa.body.as_opaque_area()?.as_router_info()?.info_hostname.as_ref()?;
        Some(Self {
            hostname: Some(Cow::Borrowed(hostname.get())),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::maximum_sid_depth_tlv::msd_type::MsdType {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;
    type ListEntry = (u8, u8);

    fn iter(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let msds = lsa.body.as_opaque_area()?.as_router_info()?.msds.as_ref()?;
        let iter = msds.get().iter().map(|(msd_type, msd_value)| (*msd_type, *msd_value));
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, (msd_type, msd_value): &Self::ListEntry) -> Self {
        Self {
            msd_type: Some(*msd_type),
            msd_value: Some(*msd_value),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;
    type ListEntry = &'a UnknownTlv;

    fn iter(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_area()?.as_router_info()?;
        let iter = lsa_body.unknown_tlvs.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, tlv: &Self::ListEntry) -> Self {
        Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(HexStr(tlv.value.as_ref())),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::sr_algorithm_tlv::SrAlgorithmTlv<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;

    fn new(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_area()?.as_router_info()?;
        let iter = lsa_body.sr_algo.iter().flat_map(|tlv| tlv.get().iter()).map(|algo| algo.to_yang());
        Some(Self {
            sr_algorithm: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::sid_range_tlvs::sid_range_tlv::SidRangeTlv {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;
    type ListEntry = &'a SidLabelRangeTlv;

    fn iter(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_area()?.as_router_info()?;
        let iter = lsa_body.srgb.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, srgb: &Self::ListEntry) -> Self {
        Self {
            range_size: Some(srgb.range),
            label_value: srgb.first.as_label().map(|label| label.get()),
            index_value: srgb.first.as_index().copied(),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::local_block_tlvs::local_block_tlv::LocalBlockTlv {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;
    type ListEntry = &'a SrLocalBlockTlv;

    fn iter(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_area()?.as_router_info()?;
        let iter = lsa_body.srlb.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, srlb: &Self::ListEntry) -> Self {
        Self {
            range_size: Some(srlb.range),
            label_value: srlb.first.as_label().map(|label| label.get()),
            index_value: srlb.first.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::ri_opaque::srms_preference_tlv::SrmsPreferenceTlv {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;

    fn new(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_area()?.as_router_info()?;
        Some(Self {
            preference: lsa_body.srms_pref.as_ref().map(|tlv| tlv.get()),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::ExtendedPrefixTlv<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;
    type ListEntry = &'a ospfv2::packet::lsa_opaque::ExtPrefixTlv;

    fn iter(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_area()?.as_ext_prefix()?;
        let iter = lsa_body.prefixes.values();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, tlv: &Self::ListEntry) -> Self {
        Self {
            route_type: Some(tlv.route_type.to_yang()),
            prefix: Some(tlv.prefix.into()),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::flags::Flags<'a> {
    type ParentListEntry = &'a ospfv2::packet::lsa_opaque::ExtPrefixTlv;

    fn new(_instance: &'a Instance<Ospfv2>, tlv: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            extended_prefix_flags: tlv.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    type ParentListEntry = &'a ospfv2::packet::lsa_opaque::ExtPrefixTlv;
    type ListEntry = &'a UnknownTlv;

    fn iter(_instance: &'a Instance<Ospfv2>, tlv: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = tlv.unknown_tlvs.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, tlv: &Self::ListEntry) -> Self {
        Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(HexStr(tlv.value.as_ref())),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PrefixSidSubTlv<'a>
{
    type ParentListEntry = &'a ospfv2::packet::lsa_opaque::ExtPrefixTlv;
    type ListEntry = &'a ospfv2::packet::lsa_opaque::PrefixSid;

    fn iter(_instance: &'a Instance<Ospfv2>, tlv: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = tlv.prefix_sids.values();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, stlv: &Self::ListEntry) -> Self {
        Self {
            mt_id: Some(0),
            algorithm: Some(stlv.algo.to_yang()),
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_prefix_opaque::extended_prefix_tlv::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::prefix_sid_flags::PrefixSidFlags<'a>
{
    type ParentListEntry = &'a ospfv2::packet::lsa_opaque::PrefixSid;

    fn new(_instance: &'a Instance<Ospfv2>, prefix_sid: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            flag: prefix_sid.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::ExtendedLinkTlv<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;

    fn new(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let tlv = lsa.body.as_opaque_area()?.as_ext_link()?.link.as_ref()?;
        Some(Self {
            link_id: Some(tlv.link_id.to_string().into()),
            link_data: Some(tlv.link_data.to_string().into()),
            r#type: Some(tlv.link_type.to_yang()),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::maximum_sid_depth_tlv::msd_type::MsdType {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;
    type ListEntry = (u8, u8);

    fn iter(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let msds = lsa.body.as_opaque_area()?.as_ext_link()?.link.as_ref()?.msds.as_ref()?;
        let iter = msds.get().iter().map(|(msd_type, msd_value)| (*msd_type, *msd_value));
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, (msd_type, msd_value): &Self::ListEntry) -> Self {
        Self {
            msd_type: Some(*msd_type),
            msd_value: Some(*msd_value),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;
    type ListEntry = &'a UnknownTlv;

    fn iter(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let tlv = lsa.body.as_opaque_area()?.as_ext_link()?.link.as_ref()?;
        let iter = tlv.unknown_tlvs.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, tlv: &Self::ListEntry) -> Self {
        Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(HexStr(tlv.value.as_ref())),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::adj_sid_sub_tlvs::adj_sid_sub_tlv::AdjSidSubTlv {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;
    type ListEntry = &'a ospfv2::packet::lsa_opaque::AdjSid;

    fn iter(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let tlv = lsa.body.as_opaque_area()?.as_ext_link()?.link.as_ref()?;
        let iter = tlv.adj_sids.iter().filter(|adj_sid| adj_sid.nbr_router_id.is_none());
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, stlv: &Self::ListEntry) -> Self {
        Self {
            mt_id: Some(0),
            weight: Some(stlv.weight),
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::adj_sid_sub_tlvs::adj_sid_sub_tlv::adj_sid_flags::AdjSidFlags<'a>
{
    type ParentListEntry = &'a ospfv2::packet::lsa_opaque::AdjSid;

    fn new(_instance: &'a Instance<Ospfv2>, adj_sid: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            flag: adj_sid.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::lan_adj_sid_sub_tlvs::lan_adj_sid_sub_tlv::LanAdjSidSubTlv
{
    type ParentListEntry = &'a LsaEntry<Ospfv2>;
    type ListEntry = &'a ospfv2::packet::lsa_opaque::AdjSid;

    fn iter(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let tlv = lsa.body.as_opaque_area()?.as_ext_link()?.link.as_ref()?;
        let iter = tlv.adj_sids.iter().filter(|adj_sid| adj_sid.nbr_router_id.is_some());
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, stlv: &Self::ListEntry) -> Self {
        Self {
            mt_id: Some(0),
            weight: Some(stlv.weight),
            neighbor_router_id: Some(stlv.nbr_router_id.unwrap()),
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv2::body::opaque::extended_link_opaque::extended_link_tlv::lan_adj_sid_sub_tlvs::lan_adj_sid_sub_tlv::lan_adj_sid_flags::LanAdjSidFlags<'a>
{
    type ParentListEntry = &'a ospfv2::packet::lsa_opaque::AdjSid;

    fn new(_instance: &'a Instance<Ospfv2>, adj_sid: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            flag: adj_sid.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::header::Header<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        Some(Self {
            lsa_id: Some(lsa.hdr.lsa_id.into()),
            age: Some(lsa.age()).ignore_in_testing(),
            r#type: Some(lsa.hdr.lsa_type.to_yang()),
            adv_router: Some(lsa.hdr.adv_rtr),
            seq_num: Some(lsa.hdr.seq_no).ignore_in_testing(),
            checksum: Some(FletcherChecksum16(lsa.hdr.cksum)).ignore_in_testing(),
            length: Some(lsa.hdr.length),
            maxage: lsa.hdr.is_maxage().then_some(()).only_in_testing(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router::router_bits::RouterBits<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_router()?;
        Some(Self {
            rtr_lsa_bits: lsa_body.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router::lsa_options::LsaOptions<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_router()?;
        Some(Self {
            lsa_options: lsa_body.options.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router::links::link::Link<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;
    type ListEntry = &'a ospfv3::packet::lsa::LsaRouterLink;

    fn iter(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_router()?;
        let iter = lsa_body.links.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, rtr_link: &Self::ListEntry) -> Self {
        Self {
            interface_id: Some(rtr_link.iface_id),
            neighbor_interface_id: Some(rtr_link.nbr_iface_id),
            neighbor_router_id: Some(rtr_link.nbr_router_id),
            r#type: Some(rtr_link.link_type.to_yang()),
            metric: Some(rtr_link.metric),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::network::lsa_options::LsaOptions<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_network()?;
        Some(Self {
            lsa_options: lsa_body.options.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::network::attached_routers::AttachedRouters<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_network()?;
        let iter = lsa_body.attached_rtrs.iter().copied();
        Some(Self {
            attached_router: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::inter_area_prefix::InterAreaPrefix {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_inter_area_prefix()?;
        Some(Self {
            metric: Some(lsa_body.metric),
            prefix: Some(lsa_body.prefix),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::inter_area_prefix::prefix_options::PrefixOptions<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_inter_area_prefix()?;
        Some(Self {
            prefix_options: lsa_body.prefix_options.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::inter_area_router::InterAreaRouter {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_inter_area_router()?;
        Some(Self {
            metric: Some(lsa_body.metric),
            destination_router_id: Some(lsa_body.router_id),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::inter_area_router::lsa_options::LsaOptions<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_inter_area_router()?;
        Some(Self {
            lsa_options: lsa_body.options.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::intra_area_prefix::IntraAreaPrefix<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_intra_area_prefix()?;
        Some(Self {
            referenced_ls_type: Some(lsa_body.ref_lsa_type.to_yang()),
            unknown_referenced_ls_type: if lsa_body.ref_lsa_type.function_code().is_none() { Some(lsa_body.ref_lsa_type.0) } else { None },
            referenced_link_state_id: Some(lsa_body.ref_lsa_id.into()),
            referenced_adv_router: Some(lsa_body.ref_adv_rtr),
            num_of_prefixes: Some(lsa_body.prefixes.len() as _),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::intra_area_prefix::prefixes::prefix::Prefix {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;
    type ListEntry = &'a ospfv3::packet::lsa::LsaIntraAreaPrefixEntry;

    fn iter(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_intra_area_prefix()?;
        let iter = lsa_body.prefixes.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, prefix: &Self::ListEntry) -> Self {
        Self {
            prefix: Some(prefix.value),
            metric: Some(prefix.metric),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::intra_area_prefix::prefixes::prefix::prefix_options::PrefixOptions<'a> {
    type ParentListEntry = &'a ospfv3::packet::lsa::LsaIntraAreaPrefixEntry;

    fn new(_instance: &'a Instance<Ospfv3>, prefix: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            prefix_options: prefix.options.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::router_informational_capabilities::RouterInformationalCapabilities<'a>
{
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let info_caps = lsa.body.as_router_info()?.info_caps.as_ref()?;
        Some(Self {
            informational_capabilities: info_caps.get().to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::informational_capabilities_flags::InformationalCapabilitiesFlags
{
    type ParentListEntry = &'a LsaEntry<Ospfv3>;
    type ListEntry = u32;

    fn iter(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let info_caps = lsa.body.as_router_info()?.info_caps.as_ref()?;
        let info_caps = info_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| info_caps & flag != 0);
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, flag: &Self::ListEntry) -> Self {
        Self {
            informational_flag: Some(*flag),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::functional_capabilities::FunctionalCapabilities {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;
    type ListEntry = u32;

    fn iter(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let func_caps = lsa.body.as_router_info()?.func_caps.as_ref()?;
        let func_caps = func_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| func_caps & flag != 0);
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, flag: &Self::ListEntry) -> Self {
        Self {
            functional_flag: Some(*flag),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::node_tag_tlvs::node_tag_tlv::NodeTagTlv {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;
    type ListEntry = &'a NodeAdminTagTlv;

    fn iter(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_router_info()?;
        let iter = lsa_body.node_tags.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, _tlv: &Self::ListEntry) -> Self {
        Self {}
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::node_tag_tlvs::node_tag_tlv::node_tag::NodeTag {
    type ParentListEntry = &'a NodeAdminTagTlv;
    type ListEntry = &'a u32;

    fn iter(_instance: &'a Instance<Ospfv3>, tlv: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = tlv.tags.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, tag: &Self::ListEntry) -> Self {
        Self {
            tag: Some(**tag),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::dynamic_hostname_tlv::DynamicHostnameTlv<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let info_hostname = lsa.body.as_router_info()?.info_hostname.as_ref()?;
        Some(Self {
            hostname: Some(Cow::Borrowed(info_hostname.get())),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::sr_algorithm_tlv::SrAlgorithmTlv<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_router_info()?;
        let iter = lsa_body.sr_algo.iter().flat_map(|tlv| tlv.get().iter()).map(|algo| algo.to_yang());
        Some(Self {
            sr_algorithm: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::sid_range_tlvs::sid_range_tlv::SidRangeTlv {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;
    type ListEntry = &'a SidLabelRangeTlv;

    fn iter(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_router_info()?;
        let iter = lsa_body.srgb.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, srgb: &Self::ListEntry) -> Self {
        Self {
            range_size: Some(srgb.range),
            label_value: srgb.first.as_label().map(|label| label.get()),
            index_value: srgb.first.as_index().copied(),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::local_block_tlvs::local_block_tlv::LocalBlockTlv {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;
    type ListEntry = &'a SrLocalBlockTlv;

    fn iter(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_router_info()?;
        let iter = lsa_body.srlb.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, srlb: &Self::ListEntry) -> Self {
        Self {
            range_size: Some(srlb.range),
            label_value: srlb.first.as_label().map(|label| label.get()),
            index_value: srlb.first.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::router_information::srms_preference_tlv::SrmsPreferenceTlv {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_router_info()?;
        Some(Self {
            preference: lsa_body.srms_pref.as_ref().map(|tlv| tlv.get()),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::router_bits::RouterBits<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_router()?;
        Some(Self {
            rtr_lsa_bits: lsa_body.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::lsa_options::LsaOptions<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_router()?;
        Some(Self {
            lsa_options: lsa_body.options.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::ERouterTlvs {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;
    type ListEntry = &'a ospfv3::packet::lsa::LsaRouterLink;

    fn iter(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_router()?;
        let iter = lsa_body.links.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, _tlv: &Self::ListEntry) -> Self {
        Self {}
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::unknown_tlv::UnknownTlv<'a> {
    type ParentListEntry = &'a ospfv3::packet::lsa::LsaRouterLink;

    fn new(_instance: &'a Instance<Ospfv3>, _rtr_link: &Self::ParentListEntry) -> Option<Self> {
        // TODO: unknown TLVs aren't tracked at this level yet.
        None
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::LinkTlv<'a> {
    type ParentListEntry = &'a ospfv3::packet::lsa::LsaRouterLink;

    fn new(_instance: &'a Instance<Ospfv3>, rtr_link: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            interface_id: Some(rtr_link.iface_id),
            neighbor_interface_id: Some(rtr_link.nbr_iface_id),
            neighbor_router_id: Some(rtr_link.nbr_router_id),
            r#type: Some(rtr_link.link_type.to_yang()),
            metric: Some(rtr_link.metric),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::sub_tlvs::SubTlvs {
    type ParentListEntry = &'a ospfv3::packet::lsa::LsaRouterLink;
    type ListEntry = Ospfv3RouterLinkSubTlv<'a>;

    fn iter(_instance: &'a Instance<Ospfv3>, &tlv: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = tlv.unknown_stlvs.iter().map(Ospfv3RouterLinkSubTlv::Unknown).chain(std::iter::once(Ospfv3RouterLinkSubTlv::AdjSids(&tlv.adj_sids)));
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, _tlv: &Self::ListEntry) -> Self {
        Self {}
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::sub_tlvs::unknown_sub_tlv::UnknownSubTlv<'a> {
    type ParentListEntry = Ospfv3RouterLinkSubTlv<'a>;

    fn new(_instance: &'a Instance<Ospfv3>, parent: &Self::ParentListEntry) -> Option<Self> {
        let Ospfv3RouterLinkSubTlv::Unknown(tlv) = parent else {
            return None;
        };
        Some(Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(HexStr(tlv.value.as_ref())),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::sub_tlvs::adj_sid_sub_tlvs::adj_sid_sub_tlv::AdjSidSubTlv {
    type ParentListEntry = Ospfv3RouterLinkSubTlv<'a>;
    type ListEntry = &'a ospfv3::packet::lsa::AdjSid;

    fn iter(_instance: &'a Instance<Ospfv3>, parent: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let Ospfv3RouterLinkSubTlv::AdjSids(adj_sids) = parent else {
            return None;
        };
        let iter = adj_sids.iter().filter(|adj_sid| adj_sid.nbr_router_id.is_none());
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, stlv: &Self::ListEntry) -> Self {
        Self {
            weight: Some(stlv.weight),
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::sub_tlvs::adj_sid_sub_tlvs::adj_sid_sub_tlv::adj_sid_flags::AdjSidFlags<'a>
{
    type ParentListEntry = &'a ospfv3::packet::lsa::AdjSid;

    fn new(_instance: &'a Instance<Ospfv3>, adj_sid: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            flag: adj_sid.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::sub_tlvs::lan_adj_sid_sub_tlvs::lan_adj_sid_sub_tlv::LanAdjSidSubTlv
{
    type ParentListEntry = Ospfv3RouterLinkSubTlv<'a>;
    type ListEntry = &'a ospfv3::packet::lsa::AdjSid;

    fn iter(_instance: &'a Instance<Ospfv3>, parent: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let Ospfv3RouterLinkSubTlv::AdjSids(adj_sids) = parent else {
            return None;
        };
        let iter = adj_sids.iter().filter(|adj_sid| adj_sid.nbr_router_id.is_some());
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, stlv: &Self::ListEntry) -> Self {
        Self {
            weight: Some(stlv.weight),
            neighbor_router_id: Some(stlv.nbr_router_id.unwrap()),
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_router::e_router_tlvs::link_tlv::sub_tlvs::lan_adj_sid_sub_tlvs::lan_adj_sid_sub_tlv::lan_adj_sid_flags::LanAdjSidFlags<'a>
{
    type ParentListEntry = &'a ospfv3::packet::lsa::AdjSid;

    fn new(_instance: &'a Instance<Ospfv3>, adj_sid: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            flag: adj_sid.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_network::lsa_options::LsaOptions<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_network()?;
        Some(Self {
            lsa_options: lsa_body.options.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_network::e_network_tlvs::ENetworkTlvs {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;
    type ListEntry = &'a LsaEntry<Ospfv3>;

    fn iter(_instance: &'a Instance<Ospfv3>, _lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        // Nothing to do.
        None::<std::iter::Empty<_>> // TODO
    }

    fn new(_instance: &'a Instance<Ospfv3>, _tlv: &Self::ListEntry) -> Self {
        Self {}
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_network::e_network_tlvs::unknown_tlv::UnknownTlv<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, _lse: &Self::ParentListEntry) -> Option<Self> {
        // TODO: unknown TLVs aren't tracked at this level yet.
        None
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_network::e_network_tlvs::attached_router_tlv::AttachedRouterTlv<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_network()?;
        let iter = lsa_body.attached_rtrs.iter().copied();
        Some(Self {
            adjacent_neighbor_router_id: Some(Box::new(iter)),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::EInterPrefixTlvs {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;
    type ListEntry = &'a LsaEntry<Ospfv3>;

    fn iter(_instance: &'a Instance<Ospfv3>, &lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let _ = lsa.body.as_ext_inter_area_prefix()?;
        let iter = std::iter::once(lse);
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, _tlv: &Self::ListEntry) -> Self {
        Self {}
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::unknown_tlv::UnknownTlv<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, _lse: &Self::ParentListEntry) -> Option<Self> {
        // TODO: unknown TLVs aren't tracked at this level yet.
        None
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::InterPrefixTlv {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_inter_area_prefix()?;
        Some(Self {
            metric: Some(lsa_body.metric),
            prefix: Some(lsa_body.prefix),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::prefix_options::PrefixOptions<'a>
{
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_inter_area_prefix()?;
        Some(Self {
            prefix_options: lsa_body.prefix_options.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::sub_tlvs::SubTlvs {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;
    type ListEntry = Ospfv3PrefixSubTlv<'a>;

    fn iter(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_inter_area_prefix()?;
        let iter = lsa_body.unknown_stlvs.iter().map(Ospfv3PrefixSubTlv::Unknown).chain(std::iter::once(Ospfv3PrefixSubTlv::PrefixSids(&lsa_body.prefix_sids)));
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, _tlv: &Self::ListEntry) -> Self {
        Self {}
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::sub_tlvs::unknown_sub_tlv::UnknownSubTlv<'a>
{
    type ParentListEntry = Ospfv3PrefixSubTlv<'a>;

    fn new(_instance: &'a Instance<Ospfv3>, parent: &Self::ParentListEntry) -> Option<Self> {
        let Ospfv3PrefixSubTlv::Unknown(tlv) = parent else {
            return None;
        };
        Some(Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(HexStr(tlv.value.as_ref())),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::sub_tlvs::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PrefixSidSubTlv<'a>
{
    type ParentListEntry = Ospfv3PrefixSubTlv<'a>;
    type ListEntry = &'a ospfv3::packet::lsa::PrefixSid;

    fn iter(_instance: &'a Instance<Ospfv3>, parent: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let Ospfv3PrefixSubTlv::PrefixSids(prefix_sids) = parent else {
            return None;
        };
        let iter = prefix_sids.values();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, stlv: &Self::ListEntry) -> Self {
        Self {
            algorithm: Some(stlv.algo.to_yang()),
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_prefix::e_inter_prefix_tlvs::inter_prefix_tlv::sub_tlvs::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::ospfv3_prefix_sid_flags::Ospfv3PrefixSidFlags<'a>
{
    type ParentListEntry = &'a ospfv3::packet::lsa::PrefixSid;

    fn new(_instance: &'a Instance<Ospfv3>, prefix_sid: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            flag: prefix_sid.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::EInterRouterTlvs {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;
    type ListEntry = &'a LsaEntry<Ospfv3>;

    fn iter(_instance: &'a Instance<Ospfv3>, &lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let _ = lsa.body.as_ext_inter_area_router()?;
        let iter = std::iter::once(lse);
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, _tlv: &Self::ListEntry) -> Self {
        Self {}
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::unknown_tlv::UnknownTlv<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, _lse: &Self::ParentListEntry) -> Option<Self> {
        // TODO: unknown TLVs aren't tracked at this level yet.
        None
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::inter_router_tlv::InterRouterTlv {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_inter_area_router()?;
        Some(Self {
            metric: Some(lsa_body.metric),
            destination_router_id: Some(lsa_body.router_id),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::inter_router_tlv::lsa_options::LsaOptions<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_inter_area_router()?;
        Some(Self {
            lsa_options: lsa_body.options.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::inter_router_tlv::sub_tlvs::SubTlvs {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;
    type ListEntry = &'a UnknownTlv;

    fn iter(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_inter_area_router()?;
        let iter = lsa_body.unknown_stlvs.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, _tlv: &Self::ListEntry) -> Self {
        Self {}
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_inter_area_router::e_inter_router_tlvs::inter_router_tlv::sub_tlvs::unknown_sub_tlv::UnknownSubTlv<'a>
{
    type ParentListEntry = &'a UnknownTlv;

    fn new(_instance: &'a Instance<Ospfv3>, tlv: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(HexStr(tlv.value.as_ref())),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::EIntraAreaPrefix {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_intra_area_prefix()?;
        Some(Self {
            referenced_ls_type: Some(lsa_body.ref_lsa_type.into()),
            referenced_link_state_id: Some(lsa_body.ref_lsa_id.into()),
            referenced_adv_router: Some(lsa_body.ref_adv_rtr),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::EIntraPrefixTlvs {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;
    type ListEntry = &'a ospfv3::packet::lsa::LsaIntraAreaPrefixEntry;

    fn iter(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_intra_area_prefix()?;
        let iter = lsa_body.prefixes.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, _tlv: &Self::ListEntry) -> Self {
        Self {}
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::unknown_tlv::UnknownTlv<'a> {
    type ParentListEntry = &'a ospfv3::packet::lsa::LsaIntraAreaPrefixEntry;

    fn new(_instance: &'a Instance<Ospfv3>, _prefix: &Self::ParentListEntry) -> Option<Self> {
        // TODO: unknown TLVs aren't tracked at this level yet.
        None
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::IntraPrefixTlv {
    type ParentListEntry = &'a ospfv3::packet::lsa::LsaIntraAreaPrefixEntry;

    fn new(_instance: &'a Instance<Ospfv3>, prefix: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            metric: Some(prefix.metric as u32),
            prefix: Some(prefix.value),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::prefix_options::PrefixOptions<'a>
{
    type ParentListEntry = &'a ospfv3::packet::lsa::LsaIntraAreaPrefixEntry;

    fn new(_instance: &'a Instance<Ospfv3>, prefix: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            prefix_options: prefix.options.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::SubTlvs {
    type ParentListEntry = &'a ospfv3::packet::lsa::LsaIntraAreaPrefixEntry;
    type ListEntry = Ospfv3PrefixSubTlv<'a>;

    fn iter(_instance: &'a Instance<Ospfv3>, &prefix: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = prefix
            .unknown_stlvs
            .iter()
            .map(Ospfv3PrefixSubTlv::Unknown)
            .chain((!prefix.prefix_sids.is_empty()).then_some(Ospfv3PrefixSubTlv::PrefixSids(&prefix.prefix_sids)))
            .chain((!prefix.bier.is_empty()).then_some(Ospfv3PrefixSubTlv::Biers(&prefix.bier)));
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, _tlv: &Self::ListEntry) -> Self {
        Self {}
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::unknown_sub_tlv::UnknownSubTlv<'a>
{
    type ParentListEntry = Ospfv3PrefixSubTlv<'a>;

    fn new(_instance: &'a Instance<Ospfv3>, parent: &Self::ParentListEntry) -> Option<Self> {
        let Ospfv3PrefixSubTlv::Unknown(tlv) = parent else {
            return None;
        };
        Some(Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(HexStr(tlv.value.as_ref())),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::bier_info_sub_tlvs::bier_info_sub_tlv::BierInfoSubTlv
{
    type ParentListEntry = Ospfv3PrefixSubTlv<'a>;
    type ListEntry = &'a BierStlv;

    fn iter(_instance: &'a Instance<Ospfv3>, parent: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let Ospfv3PrefixSubTlv::Biers(biers) = parent else {
            return None;
        };
        let iter = biers.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, bier: &Self::ListEntry) -> Self {
        Self {
            sub_domain_id: Some(bier.sub_domain_id),
            mt_id: Some(bier.mt_id),
            bfr_id: Some(bier.bfr_id),
            bar: Some(bier.bar),
            ipa: Some(bier.ipa),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::bier_info_sub_tlvs::bier_info_sub_tlv::sub_sub_tlvs::SubSubTlvs
{
    type ParentListEntry = &'a BierStlv;
    type ListEntry = Ospfv3BierSubSubTlv<'a>;

    fn iter(_instance: &'a Instance<Ospfv3>, &bier: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = bier.unknown_sstlvs.iter().map(Ospfv3BierSubSubTlv::Unknown).chain(std::iter::once(Ospfv3BierSubSubTlv::BierEncaps(&bier.encaps)));
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, _tlv: &Self::ListEntry) -> Self {
        Self {}
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::bier_info_sub_tlvs::bier_info_sub_tlv::sub_sub_tlvs::bier_encap_sub_sub_tlvs::bier_encap_sub_sub_tlv::BierEncapSubSubTlv
{
    type ParentListEntry = Ospfv3BierSubSubTlv<'a>;
    type ListEntry = &'a BierEncapSubStlv;

    fn iter(_instance: &'a Instance<Ospfv3>, parent: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let Ospfv3BierSubSubTlv::BierEncaps(bier_encaps) = parent else {
            return None;
        };
        let iter = bier_encaps.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, bier_encap: &Self::ListEntry) -> Self {
        Self {
            max_si: Some(bier_encap.max_si),
            id: Some(bier_encap.id.clone().get()),
            bs_len: Some(u8::from(bier_encap.bs_len))
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::bier_info_sub_tlvs::bier_info_sub_tlv::sub_sub_tlvs::unknown_sub_tlv::UnknownSubTlv<'a>
{
    type ParentListEntry = Ospfv3BierSubSubTlv<'a>;

    fn new(_instance: &'a Instance<Ospfv3>, parent: &Self::ParentListEntry) -> Option<Self> {
        let Ospfv3BierSubSubTlv::Unknown(tlv) = parent else {
            return None;
        };
        Some(Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(HexStr(tlv.value.as_ref())),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PrefixSidSubTlv<'a>
{
    type ParentListEntry = Ospfv3PrefixSubTlv<'a>;
    type ListEntry = &'a ospfv3::packet::lsa::PrefixSid;

    fn iter(_instance: &'a Instance<Ospfv3>, parent: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let Ospfv3PrefixSubTlv::PrefixSids(prefix_sids) = parent else {
            return None;
        };
        let iter = prefix_sids.values();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, stlv: &Self::ListEntry) -> Self {
        Self {
            algorithm: Some(stlv.algo.to_yang()),
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::database::area_scope_lsa_type::area_scope_lsas::area_scope_lsa::ospfv3::body::e_intra_area_prefix::e_intra_prefix_tlvs::intra_prefix_tlv::sub_tlvs::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::ospfv3_prefix_sid_flags::Ospfv3PrefixSidFlags<'a>
{
    type ParentListEntry = &'a ospfv3::packet::lsa::PrefixSid;

    fn new(_instance: &'a Instance<Ospfv3>, prefix_sid: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            flag: prefix_sid.flags.to_yang_flags_iter(),
        })
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::areas::area::virtual_links::virtual_link::VirtualLink {
    type ParentListEntry = &'a Area<V>;
    type ListEntry = &'a Interface<V>;

    fn iter(instance: &'a Instance<V>, area: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = area.interfaces.iter(&instance.arenas.interfaces).filter(|iface| iface.is_virtual_link());
        Some(iter)
    }

    fn new(_instance: &'a Instance<V>, iface: &Self::ListEntry) -> Self {
        let vlink_key = iface.vlink_key.unwrap();
        Self {
            transit_area_id: vlink_key.transit_area_id,
            router_id: vlink_key.router_id,
            cost: iface.state.vlink.as_ref().map(|vlink| vlink.cost as u16),
            state: Some(iface.state.ism_state),
            hello_timer: iface.state.tasks.hello_interval.as_ref().map(|task| TimerValueSecs16(task.remaining())).ignore_in_testing(),
            wait_timer: iface.state.tasks.wait_timer.as_ref().map(|task| TimerValueSecs16(task.remaining())).ignore_in_testing(),
            dr_router_id: None,
            dr_ip_addr: None,
            bdr_router_id: None,
            bdr_ip_addr: None,
        }
    }
}

impl<'a, V: Version> YangContainer<'a, Instance<V>> for ospf::areas::area::virtual_links::virtual_link::statistics::Statistics {
    type ParentListEntry = &'a Interface<V>;

    fn new(_instance: &'a Instance<V>, iface: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            discontinuity_time: Some(iface.state.discontinuity_time).ignore_in_testing(),
            if_event_count: Some(iface.state.event_count).ignore_in_testing(),
            link_scope_lsa_count: Some(iface.state.lsdb.lsa_count()),
            link_scope_lsa_cksum_sum: Some(iface.state.lsdb.cksum_sum()).ignore_in_testing(),
        })
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::areas::area::virtual_links::virtual_link::statistics::database::link_scope_lsa_type::LinkScopeLsaType {
    type ParentListEntry = &'a Interface<V>;
    type ListEntry = &'a LsdbSingleType<V>;

    fn iter(_instance: &'a Instance<V>, iface: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = iface.state.lsdb.iter_types();
        Some(iter)
    }

    fn new(_instance: &'a Instance<V>, lsdb_type: &Self::ListEntry) -> Self {
        Self {
            lsa_type: Some(lsdb_type.lsa_type().into()),
            lsa_count: Some(lsdb_type.lsa_count()),
            lsa_cksum_sum: Some(lsdb_type.cksum_sum()).ignore_in_testing(),
        }
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::areas::area::virtual_links::virtual_link::neighbors::neighbor::Neighbor {
    type ParentListEntry = &'a Interface<V>;
    type ListEntry = (&'a Interface<V>, &'a Neighbor<V>);

    fn iter(instance: &'a Instance<V>, &iface: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = iface.state.neighbors.iter(&instance.arenas.neighbors).map(move |nbr| (iface, nbr));
        Some(iter)
    }

    fn new(_instance: &'a Instance<V>, (_iface, nbr): &Self::ListEntry) -> Self {
        Self {
            neighbor_router_id: nbr.router_id,
            address: Some(nbr.src.into()),
            dr_router_id: None,
            dr_ip_addr: None,
            bdr_router_id: None,
            bdr_ip_addr: None,
            state: Some(nbr.state),
            cost: None,
            dead_timer: nbr.tasks.inactivity_timer.as_ref().map(|task| TimerValueSecs16(task.remaining())).ignore_in_testing(),
        }
    }
}

impl<'a, V: Version> YangContainer<'a, Instance<V>> for ospf::areas::area::virtual_links::virtual_link::neighbors::neighbor::statistics::Statistics {
    type ParentListEntry = (&'a Interface<V>, &'a Neighbor<V>);

    fn new(_instance: &'a Instance<V>, (_, nbr): &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            discontinuity_time: Some(nbr.discontinuity_time).ignore_in_testing(),
            nbr_event_count: Some(nbr.event_count).ignore_in_testing(),
            nbr_retrans_qlen: Some(nbr.lists.ls_rxmt.len() as u32),
        })
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::areas::area::virtual_links::virtual_link::database::link_scope_lsa_type::LinkScopeLsaType {
    type ParentListEntry = &'a Interface<V>;
    type ListEntry = &'a LsdbSingleType<V>;

    fn iter(_instance: &'a Instance<V>, iface: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = iface.state.lsdb.iter_types();
        Some(iter)
    }

    fn new(_instance: &'a Instance<V>, lsdb_type: &Self::ListEntry) -> Self {
        Self {
            lsa_type: lsdb_type.lsa_type().into(),
        }
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::areas::area::virtual_links::virtual_link::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::LinkScopeLsa<'a> {
    type ParentListEntry = &'a LsdbSingleType<V>;
    type ListEntry = &'a LsaEntry<V>;

    fn iter(instance: &'a Instance<V>, lsdb_type: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = lsdb_type.iter(&instance.arenas.lsa_entries).map(|(_, lse)| lse);
        Some(iter)
    }

    fn new(_instance: &'a Instance<V>, lse: &Self::ListEntry) -> Self {
        let lsa = &lse.data;
        Self {
            lsa_id: lsa.hdr.lsa_id().to_string().into(),
            adv_router: lsa.hdr.adv_rtr(),
            decode_completed: Some(!lsa.body.is_unknown()),
            raw_data: Some(HexStr(lsa.raw.as_ref())).ignore_in_testing(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::virtual_links::virtual_link::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::header::Header<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;

    fn new(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let (opaque_type, opaque_id) = lsa_hdr_opaque_data(&lsa.hdr);
        Some(Self {
            lsa_id: Some(lsa.hdr.lsa_id),
            opaque_type,
            opaque_id,
            age: Some(lsa.age()).ignore_in_testing(),
            r#type: Some(lsa.hdr.lsa_type.to_yang()),
            adv_router: Some(lsa.hdr.adv_rtr),
            seq_num: Some(lsa.hdr.seq_no).ignore_in_testing(),
            checksum: Some(FletcherChecksum16(lsa.hdr.cksum)).ignore_in_testing(),
            length: Some(lsa.hdr.length),
            maxage: lsa.hdr.is_maxage().then_some(()).only_in_testing(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::virtual_links::virtual_link::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::header::lsa_options::LsaOptions<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;

    fn new(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        Some(Self {
            lsa_options: lsa.hdr.options.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>>
    for ospf::areas::area::virtual_links::virtual_link::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::router_informational_capabilities::RouterInformationalCapabilities<'a>
{
    type ParentListEntry = &'a LsaEntry<Ospfv2>;

    fn new(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let info_caps = lsa.body.as_opaque_link()?.as_router_info()?.info_caps.as_ref()?;
        Some(Self {
            informational_capabilities: info_caps.get().to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>>
    for ospf::areas::area::virtual_links::virtual_link::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::informational_capabilities_flags::InformationalCapabilitiesFlags
{
    type ParentListEntry = &'a LsaEntry<Ospfv2>;
    type ListEntry = u32;

    fn iter(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let info_caps = lsa.body.as_opaque_link()?.as_router_info()?.info_caps.as_ref()?;
        let info_caps = info_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| info_caps & flag != 0);
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, flag: &Self::ListEntry) -> Self {
        Self {
            informational_flag: Some(*flag),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>>
    for ospf::areas::area::virtual_links::virtual_link::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::functional_capabilities::FunctionalCapabilities
{
    type ParentListEntry = &'a LsaEntry<Ospfv2>;
    type ListEntry = u32;

    fn iter(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let func_caps = lsa.body.as_opaque_link()?.as_router_info()?.func_caps.as_ref()?;
        let func_caps = func_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| func_caps & flag != 0);
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, flag: &Self::ListEntry) -> Self {
        Self {
            functional_flag: Some(*flag),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::virtual_links::virtual_link::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::maximum_sid_depth_tlv::msd_type::MsdType {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;
    type ListEntry = (u8, u8);

    fn iter(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let msds = lsa.body.as_opaque_link()?.as_ext_link()?.link.as_ref()?.msds.as_ref()?;
        let iter = msds.get().iter().map(|(msd_type, msd_value)| (*msd_type, *msd_value));
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, (msd_type, msd_value): &Self::ListEntry) -> Self {
        Self {
            msd_type: Some(*msd_type),
            msd_value: Some(*msd_value),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::virtual_links::virtual_link::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;
    type ListEntry = &'a UnknownTlv;

    fn iter(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_link()?.as_router_info()?;
        let iter = lsa_body.unknown_tlvs.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, tlv: &Self::ListEntry) -> Self {
        Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(HexStr(tlv.value.as_ref())),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::virtual_links::virtual_link::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::header::Header<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        Some(Self {
            lsa_id: Some(lsa.hdr.lsa_id.into()),
            age: Some(lsa.age()).ignore_in_testing(),
            r#type: Some(lsa.hdr.lsa_type.to_yang()),
            adv_router: Some(lsa.hdr.adv_rtr),
            seq_num: Some(lsa.hdr.seq_no).ignore_in_testing(),
            checksum: Some(FletcherChecksum16(lsa.hdr.cksum)).ignore_in_testing(),
            length: Some(lsa.hdr.length),
            maxage: lsa.hdr.is_maxage().then_some(()).only_in_testing(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::virtual_links::virtual_link::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::router_informational_capabilities::RouterInformationalCapabilities<'a>
{
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let info_caps = lsa.body.as_router_info()?.info_caps.as_ref()?;
        Some(Self {
            informational_capabilities: info_caps.get().to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>>
    for ospf::areas::area::virtual_links::virtual_link::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::informational_capabilities_flags::InformationalCapabilitiesFlags
{
    type ParentListEntry = &'a LsaEntry<Ospfv3>;
    type ListEntry = u32;

    fn iter(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let info_caps = lsa.body.as_router_info()?.info_caps.as_ref()?;
        let info_caps = info_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| info_caps & flag != 0);
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, flag: &Self::ListEntry) -> Self {
        Self {
            informational_flag: Some(*flag),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>>
    for ospf::areas::area::virtual_links::virtual_link::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::functional_capabilities::FunctionalCapabilities
{
    type ParentListEntry = &'a LsaEntry<Ospfv3>;
    type ListEntry = u32;

    fn iter(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let func_caps = lsa.body.as_router_info()?.func_caps.as_ref()?;
        let func_caps = func_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| func_caps & flag != 0);
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, flag: &Self::ListEntry) -> Self {
        Self {
            functional_flag: Some(*flag),
        }
    }
}

fn mdr_duration_to_yang(duration: Duration) -> Cow<'static, str> {
    let millis = duration.as_millis();
    Cow::Owned(format!("{}.{:03}", millis / 1000, millis % 1000))
}

fn mdr_area_lsa_counts<V>(instance: &Instance<V>, iface: &Interface<V>) -> (u32, u32, u32)
where
    V: Version,
{
    if V::PROTOCOL != Protocol::OSPFV3 {
        return (0, 0, 0);
    }

    let Some(area) = mdr_area_for_interface(instance, iface) else {
        return (0, 0, 0);
    };

    let mut router_lsa_count = 0;
    let mut network_lsa_count = 0;
    let mut intra_area_prefix_lsa_count = 0;
    for (_, lse) in area.state.lsdb.iter(&instance.arenas.lsa_entries) {
        match mdr_ospfv3_lsa_function_code::<V>(lse.data.hdr.lsa_type()) {
            1 | 33 => router_lsa_count += 1,
            2 | 34 => network_lsa_count += 1,
            9 | 41 => intra_area_prefix_lsa_count += 1,
            _ => (),
        }
    }

    (router_lsa_count, network_lsa_count, intra_area_prefix_lsa_count)
}

fn mdr_link_lsa_count<V>(iface: &Interface<V>) -> u32
where
    V: Version,
{
    if V::PROTOCOL != Protocol::OSPFV3 {
        return 0;
    }

    iface
        .state
        .lsdb
        .iter_types()
        .filter(|lsdb_type| matches!(mdr_ospfv3_lsa_function_code::<V>(lsdb_type.lsa_type()), 8 | 40))
        .map(|lsdb_type| lsdb_type.lsa_count())
        .sum()
}

fn mdr_area_for_interface<'a, V>(instance: &'a Instance<V>, iface: &Interface<V>) -> Option<&'a Area<V>>
where
    V: Version,
{
    instance.arenas.areas.iter().find(|area| {
        area.interfaces
            .get_by_id(&instance.arenas.interfaces, iface.id)
            .is_ok()
    })
}

fn mdr_ospfv3_lsa_function_code<V>(lsa_type: V::LsaType) -> u16
where
    V: Version,
{
    let raw: u16 = lsa_type.into();
    raw & 0x1fff
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::areas::area::interfaces::interface::Interface<'a> {
    type ParentListEntry = &'a Area<V>;
    type ListEntry = &'a Interface<V>;

    fn iter(instance: &'a Instance<V>, area: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = area.interfaces.iter(&instance.arenas.interfaces).filter(|iface| !iface.is_virtual_link());
        Some(iter)
    }

    fn new(instance: &'a Instance<V>, iface: &Self::ListEntry) -> Self {
        let mut dr_router_id = None;
        let mut dr_ip_addr = None;
        let mut bdr_router_id = None;
        let mut bdr_ip_addr = None;
        if let Some(instance_state) = &instance.state {
            if iface.state.ism_state == ism::State::Dr {
                dr_router_id = Some(instance_state.router_id);
                dr_ip_addr = Some(iface.state.src_addr.unwrap().into());
            } else if let Some(dr_net_id) = iface.state.dr
                && let Some((_, nbr)) = iface.state.neighbors.get_by_net_id(&instance.arenas.neighbors, dr_net_id)
            {
                dr_router_id = Some(nbr.router_id);
                dr_ip_addr = Some(nbr.src.into());
            }
            if iface.state.ism_state == ism::State::Backup {
                bdr_router_id = Some(instance_state.router_id);
                bdr_ip_addr = Some(iface.state.src_addr.unwrap().into());
            } else if let Some(bdr_net_id) = iface.state.bdr
                && let Some((_, nbr)) = iface.state.neighbors.get_by_net_id(&instance.arenas.neighbors, bdr_net_id)
            {
                bdr_router_id = Some(nbr.router_id);
                bdr_ip_addr = Some(nbr.src.into());
            }
        }
        Self {
            name: Cow::Borrowed(&iface.name),
            state: Some(iface.state.ism_state),
            hello_timer: iface.state.tasks.hello_interval.as_ref().map(|task| TimerValueSecs16(task.remaining())).ignore_in_testing(),
            wait_timer: iface.state.tasks.wait_timer.as_ref().map(|task| TimerValueSecs16(task.remaining())).ignore_in_testing(),
            dr_router_id,
            dr_ip_addr,
            bdr_router_id,
            bdr_ip_addr,
            interface_id: if V::PROTOCOL == Protocol::OSPFV3 { iface.system.ifindex } else { None },
        }
    }
}

impl<'a, V: Version> YangContainer<'a, Instance<V>> for ospf::areas::area::interfaces::interface::mdr_state::MdrState<'a> {
    fn new(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Option<Self> {
        let iface = list_entry.as_interface().unwrap();
        let mdr = iface.state.mdr.as_ref()?;
        let cfg = &mdr.config;
        Some(Self {
            enabled: Some(true),
            configured_enabled: Some(iface.config.mdr.enabled),
            mdr_level: Some(mdr.mdr_level.to_yang()),
            parent_router_id: mdr.parent,
            backup_parent_router_id: mdr.backup_parent,
            hello_sequence_number: Some(mdr.hello_sequence_number),
            full_hello_count: Some(mdr.full_hello_count.into()),
            differential_hello_count: Some(mdr.differential_hello_count.into()),
            mdr_neighbor_change: Some(mdr.mdr_neighbor_change),
            adjacency_reevaluation_pending: Some(mdr.adjacency_reevaluation_pending),
            lsa_reevaluation_pending: Some(mdr.lsa_reevaluation_pending),
            non_flooding_mdr: Some(mdr.non_flooding_mdr),
            pending_backup_wait_count: Some(mdr.backup_wait.len() as u32),
            pending_backup_wait_neighbor_count: Some(mdr.backup_wait.values().map(|entry| entry.neighbors.len() as u32).sum()),
            delayed_ack_count: Some(mdr.delayed_acks.len() as u32),
            pending_flood_count: Some(iface.state.ls_update_list.len() as u32),
            effective_hello_interval: Some(cfg.hello_interval),
            effective_dead_interval: Some(cfg.dead_interval),
            effective_retransmit_interval: Some(cfg.retransmit_interval),
            effective_router_priority: Some(cfg.router_priority),
            effective_adj_connectivity: Some(cfg.adj_connectivity.to_yang()),
            effective_lsa_fullness: Some(cfg.lsa_fullness.to_yang()),
            effective_mdr_constraint: Some(cfg.mdr_constraint),
            effective_backup_wait_interval: Some(mdr_duration_to_yang(cfg.backup_wait_interval)),
            effective_ack_interval: Some(mdr_duration_to_yang(cfg.ack_interval)),
            effective_two_hop_refresh: Some(cfg.two_hop_refresh),
            effective_full_hello_repeat_count: Some(cfg.full_hello_repeat_count),
            effective_consecutive_hello_threshold: Some(cfg.consecutive_hello_threshold),
            effective_metric_tlv_enabled: Some(cfg.metric_tlv_enabled),
        })
    }
}

impl<'a, V: Version> YangContainer<'a, Instance<V>> for ospf::areas::area::interfaces::interface::mdr_state::summary::Summary {
    fn new(instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Option<Self> {
        let iface = list_entry.as_interface().unwrap();
        let mdr = iface.state.mdr.as_ref()?;

        let mut neighbor_down_count = 0;
        let mut neighbor_attempt_count = 0;
        let mut neighbor_init_count = 0;
        let mut neighbor_two_way_count = 0;
        let mut neighbor_ex_start_count = 0;
        let mut neighbor_exchange_count = 0;
        let mut neighbor_loading_count = 0;
        let mut neighbor_full_count = 0;
        let mut neighbor_mdr_count = 0;
        let mut neighbor_backup_count = 0;
        let mut neighbor_other_count = 0;
        let mut relay_set_size = 0;
        let mut relay_selector_count = 0;
        let mut routable_neighbor_count = 0;

        for nbr in iface.state.neighbors.iter(&instance.arenas.neighbors) {
            match nbr.state {
                nsm::State::Down => neighbor_down_count += 1,
                nsm::State::Attempt => neighbor_attempt_count += 1,
                nsm::State::Init => neighbor_init_count += 1,
                nsm::State::TwoWay => neighbor_two_way_count += 1,
                nsm::State::ExStart => neighbor_ex_start_count += 1,
                nsm::State::Exchange => neighbor_exchange_count += 1,
                nsm::State::Loading => neighbor_loading_count += 1,
                nsm::State::Full => neighbor_full_count += 1,
            }

            match nbr.mdr.mdr_level {
                MdrLevel::Mdr => neighbor_mdr_count += 1,
                MdrLevel::Backup => neighbor_backup_count += 1,
                MdrLevel::Other => neighbor_other_count += 1,
            }

            if nbr.mdr.selected_advertised {
                relay_set_size += 1;
            }
            if nbr.mdr.child || nbr.mdr.dependent_selector {
                relay_selector_count += 1;
            }
            if nbr.mdr.routable {
                routable_neighbor_count += 1;
            }
        }

        let (router_lsa_count, network_lsa_count, intra_area_prefix_lsa_count) = mdr_area_lsa_counts(instance, iface);
        let link_lsa_count = mdr_link_lsa_count(iface);

        Some(Self {
            neighbor_down_count: Some(neighbor_down_count),
            neighbor_attempt_count: Some(neighbor_attempt_count),
            neighbor_init_count: Some(neighbor_init_count),
            neighbor_two_way_count: Some(neighbor_two_way_count),
            neighbor_ex_start_count: Some(neighbor_ex_start_count),
            neighbor_exchange_count: Some(neighbor_exchange_count),
            neighbor_loading_count: Some(neighbor_loading_count),
            neighbor_full_count: Some(neighbor_full_count),
            neighbor_mdr_count: Some(neighbor_mdr_count),
            neighbor_backup_count: Some(neighbor_backup_count),
            neighbor_other_count: Some(neighbor_other_count),
            relay_participation_primary_count: Some((mdr.mdr_level == MdrLevel::Mdr) as u32),
            relay_participation_backup_count: Some((mdr.mdr_level == MdrLevel::Backup) as u32),
            relay_participation_ordinary_count: Some((mdr.mdr_level == MdrLevel::Other) as u32),
            relay_set_size: Some(relay_set_size),
            relay_selector_count: Some(relay_selector_count),
            routable_neighbor_count: Some(routable_neighbor_count),
            router_lsa_count: Some(router_lsa_count),
            network_lsa_count: Some(network_lsa_count),
            link_lsa_count: Some(link_lsa_count),
            intra_area_prefix_lsa_count: Some(intra_area_prefix_lsa_count),
        })
    }
}

impl<'a, V: Version> YangContainer<'a, Instance<V>> for ospf::areas::area::interfaces::interface::statistics::Statistics {
    type ParentListEntry = &'a Interface<V>;

    fn new(_instance: &'a Instance<V>, iface: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            discontinuity_time: Some(iface.state.discontinuity_time).ignore_in_testing(),
            if_event_count: Some(iface.state.event_count).ignore_in_testing(),
            link_scope_lsa_count: Some(iface.state.lsdb.lsa_count()),
            link_scope_lsa_cksum_sum: Some(iface.state.lsdb.cksum_sum()).ignore_in_testing(),
        })
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::areas::area::interfaces::interface::statistics::database::link_scope_lsa_type::LinkScopeLsaType {
    type ParentListEntry = &'a Interface<V>;
    type ListEntry = &'a LsdbSingleType<V>;

    fn iter(_instance: &'a Instance<V>, iface: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = iface.state.lsdb.iter_types();
        Some(iter)
    }

    fn new(_instance: &'a Instance<V>, lsdb_type: &Self::ListEntry) -> Self {
        Self {
            lsa_type: Some(lsdb_type.lsa_type().into()),
            lsa_count: Some(lsdb_type.lsa_count()),
            lsa_cksum_sum: Some(lsdb_type.cksum_sum()).ignore_in_testing(),
        }
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::areas::area::interfaces::interface::neighbors::neighbor::Neighbor {
    type ParentListEntry = &'a Interface<V>;
    type ListEntry = (&'a Interface<V>, &'a Neighbor<V>);

    fn iter(instance: &'a Instance<V>, &iface: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = iface.state.neighbors.iter(&instance.arenas.neighbors).map(move |nbr| (iface, nbr));
        Some(iter)
    }

    fn new(instance: &'a Instance<V>, (iface, nbr): &Self::ListEntry) -> Self {
        let mut dr_router_id = None;
        let mut dr_ip_addr = None;
        let mut bdr_router_id = None;
        let mut bdr_ip_addr = None;
        if let Some(instance_state) = &instance.state {
            if let Some(dr_net_id) = nbr.dr
                && let Some((_, nbr)) = iface.state.neighbors.get_by_net_id(&instance.arenas.neighbors, dr_net_id)
            {
                dr_router_id = Some(nbr.router_id);
                dr_ip_addr = Some(nbr.src.into());
            } else {
                let iface_src_addr = iface.state.src_addr.unwrap();
                let iface_net_id = V::network_id(&iface_src_addr, instance_state.router_id);
                if nbr.dr == Some(iface_net_id) {
                    dr_router_id = Some(instance_state.router_id);
                    dr_ip_addr = Some(iface_src_addr.into());
                }
            }
            if let Some(bdr_net_id) = nbr.bdr
                && let Some((_, nbr)) = iface.state.neighbors.get_by_net_id(&instance.arenas.neighbors, bdr_net_id)
            {
                bdr_router_id = Some(nbr.router_id);
                bdr_ip_addr = Some(nbr.src.into());
            } else {
                let iface_src_addr = iface.state.src_addr.unwrap();
                let iface_net_id = V::network_id(&iface_src_addr, instance_state.router_id);
                if nbr.bdr == Some(iface_net_id) {
                    bdr_router_id = Some(instance_state.router_id);
                    bdr_ip_addr = Some(iface_src_addr.into());
                }
            }
        }
        Self {
            neighbor_router_id: nbr.router_id,
            address: Some(nbr.src.into()),
            dr_router_id,
            dr_ip_addr,
            bdr_router_id,
            bdr_ip_addr,
            state: Some(nbr.state),
            dead_timer: nbr.tasks.inactivity_timer.as_ref().map(|task| TimerValueSecs16(task.remaining())).ignore_in_testing(),
        }
    }
}

impl<'a, V: Version> YangContainer<'a, Instance<V>> for ospf::areas::area::interfaces::interface::neighbors::neighbor::mdr_state::MdrState<'a> {
    fn new(_instance: &'a Instance<V>, list_entry: &ListEntry<'a, V>) -> Option<Self> {
        let (iface, nbr) = list_entry.as_neighbor().unwrap();
        if V::PROTOCOL != Protocol::OSPFV3 || iface.state.mdr.is_none() {
            return None;
        }
        let mdr = &nbr.mdr;
        Some(Self {
            remote_interface_id: mdr.remote_interface_id,
            hello_sequence_number: Some(mdr.hello_sequence_number),
            a_bit: Some(mdr.a_bit),
            full_hello_received: Some(mdr.full_hello_received),
            last_hello_differential: Some(mdr.last_hello_differential),
            mdr_level: Some(mdr.mdr_level.to_yang()),
            parent_router_id: mdr.parent,
            backup_parent_router_id: mdr.backup_parent,
            child: Some(mdr.child),
            dependent: Some(mdr.dependent),
            dependent_selector: Some(mdr.dependent_selector),
            backbone: Some(mdr.backbone),
            selected_advertised: Some(mdr.selected_advertised),
            routable: Some(mdr.routable),
            reverse_two_way: Some(mdr.reverse_2way),
            adjacency_desired: Some(mdr.adjacency_desired),
            adjacency_formed: Some(nbr.state >= nsm::State::ExStart),
            consecutive_hello_count: Some(mdr.consecutive_hellos),
            request_list_count: Some((nbr.lists.ls_request.len() + nbr.lists.ls_request_pending.len()) as u32),
            retransmission_list_count: Some(nbr.lists.ls_rxmt.len() as u32),
            update_list_count: Some(nbr.lists.ls_update.len() as u32),
            acked_lsa_cache_size: Some(mdr.acked_lsas.len() as u32),
            incoming_metric: mdr.incoming_link_metric,
            outgoing_metric: mdr.outgoing_link_metric,
            advertised_metric: mdr.hello_advertised_metric,
            reported_link_metric_count: Some(mdr.link_metrics.len() as u32),
            bidirectional_neighbor_count: Some(mdr.bidirectional_neighbors.len() as u32),
            dependent_neighbor_count: Some(mdr.dependent_neighbors.len() as u32),
            selected_advertised_neighbor_count: Some(mdr.selected_advertised_neighbors.len() as u32),
        })
    }
}

impl<'a, V: Version> YangContainer<'a, Instance<V>> for ospf::areas::area::interfaces::interface::neighbors::neighbor::statistics::Statistics {
    type ParentListEntry = (&'a Interface<V>, &'a Neighbor<V>);

    fn new(_instance: &'a Instance<V>, (_, nbr): &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            discontinuity_time: Some(nbr.discontinuity_time).ignore_in_testing(),
            nbr_event_count: Some(nbr.event_count).ignore_in_testing(),
            nbr_retrans_qlen: Some(nbr.lists.ls_rxmt.len() as u32),
        })
    }
}

impl<'a, V: Version> YangContainer<'a, Instance<V>> for ospf::areas::area::interfaces::interface::neighbors::neighbor::graceful_restart::GracefulRestart {
    type ParentListEntry = (&'a Interface<V>, &'a Neighbor<V>);

    fn new(_instance: &'a Instance<V>, (_, nbr): &Self::ParentListEntry) -> Option<Self> {
        let gr = nbr.gr.as_ref()?;
        Some(Self {
            restart_reason: Some(gr.restart_reason),
            grace_timer: Some(gr.grace_period.remaining().as_secs().saturating_into()).ignore_in_testing(),
        })
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::LinkScopeLsaType {
    type ParentListEntry = &'a Interface<V>;
    type ListEntry = &'a LsdbSingleType<V>;

    fn iter(_instance: &'a Instance<V>, iface: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = iface.state.lsdb.iter_types();
        Some(iter)
    }

    fn new(_instance: &'a Instance<V>, lsdb_type: &Self::ListEntry) -> Self {
        Self {
            lsa_type: lsdb_type.lsa_type().into(),
        }
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::LinkScopeLsa<'a> {
    type ParentListEntry = &'a LsdbSingleType<V>;
    type ListEntry = &'a LsaEntry<V>;

    fn iter(instance: &'a Instance<V>, lsdb_type: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let iter = lsdb_type.iter(&instance.arenas.lsa_entries).map(|(_, lse)| lse);
        Some(iter)
    }

    fn new(_instance: &'a Instance<V>, lse: &Self::ListEntry) -> Self {
        let lsa = &lse.data;
        Self {
            lsa_id: lsa.hdr.lsa_id().to_string().into(),
            adv_router: lsa.hdr.adv_rtr(),
            decode_completed: Some(!lsa.body.is_unknown()),
            raw_data: Some(HexStr(lsa.raw.as_ref())).ignore_in_testing(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::header::Header<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;

    fn new(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let (opaque_type, opaque_id) = lsa_hdr_opaque_data(&lsa.hdr);
        Some(Self {
            lsa_id: Some(lsa.hdr.lsa_id),
            opaque_type,
            opaque_id,
            age: Some(lsa.age()).ignore_in_testing(),
            r#type: Some(lsa.hdr.lsa_type.to_yang()),
            adv_router: Some(lsa.hdr.adv_rtr),
            seq_num: Some(lsa.hdr.seq_no).ignore_in_testing(),
            checksum: Some(FletcherChecksum16(lsa.hdr.cksum)).ignore_in_testing(),
            length: Some(lsa.hdr.length),
            maxage: lsa.hdr.is_maxage().then_some(()).only_in_testing(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::header::lsa_options::LsaOptions<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;

    fn new(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        Some(Self {
            lsa_options: lsa.hdr.options.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>>
    for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::router_informational_capabilities::RouterInformationalCapabilities<
        'a,
    >
{
    type ParentListEntry = &'a LsaEntry<Ospfv2>;

    fn new(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let info_caps = lsa.body.as_opaque_link()?.as_router_info()?.info_caps.as_ref()?;
        Some(Self {
            informational_capabilities: info_caps.get().to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>>
    for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::informational_capabilities_flags::InformationalCapabilitiesFlags
{
    type ParentListEntry = &'a LsaEntry<Ospfv2>;
    type ListEntry = u32;

    fn iter(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let info_caps = lsa.body.as_opaque_link()?.as_router_info()?.info_caps.as_ref()?;
        let info_caps = info_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| info_caps & flag != 0);
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, flag: &Self::ListEntry) -> Self {
        Self {
            informational_flag: Some(*flag),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>>
    for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::router_capabilities_tlv::functional_capabilities::FunctionalCapabilities
{
    type ParentListEntry = &'a LsaEntry<Ospfv2>;
    type ListEntry = u32;

    fn iter(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let func_caps = lsa.body.as_opaque_link()?.as_router_info()?.func_caps.as_ref()?;
        let func_caps = func_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| func_caps & flag != 0);
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, flag: &Self::ListEntry) -> Self {
        Self {
            functional_flag: Some(*flag),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::maximum_sid_depth_tlv::msd_type::MsdType {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;
    type ListEntry = (u8, u8);

    fn iter(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let msds = lsa.body.as_opaque_link()?.as_ext_link()?.link.as_ref()?.msds.as_ref()?;
        let iter = msds.get().iter().map(|(msd_type, msd_value)| (*msd_type, *msd_value));
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, (msd_type, msd_value): &Self::ListEntry) -> Self {
        Self {
            msd_type: Some(*msd_type),
            msd_value: Some(*msd_value),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv2>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::ri_opaque::unknown_tlvs::unknown_tlv::UnknownTlv<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;
    type ListEntry = &'a UnknownTlv;

    fn iter(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_link()?.as_router_info()?;
        let iter = lsa_body.unknown_tlvs.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv2>, tlv: &Self::ListEntry) -> Self {
        Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(HexStr(tlv.value.as_ref())),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv2>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv2::body::opaque::grace::Grace {
    type ParentListEntry = &'a LsaEntry<Ospfv2>;

    fn new(_instance: &'a Instance<Ospfv2>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_opaque_link()?.as_grace()?;
        Some(Self {
            grace_period: lsa_body.grace_period.as_ref().map(|tlv| tlv.get()),
            graceful_restart_reason: lsa_body.gr_reason.as_ref().and_then(|tlv| GrReason::from_u8(tlv.get())),
            ip_interface_address: lsa_body.addr.as_ref().map(|tlv| tlv.get()),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::header::Header<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        Some(Self {
            lsa_id: Some(lsa.hdr.lsa_id.into()),
            age: Some(lsa.age()).ignore_in_testing(),
            r#type: Some(lsa.hdr.lsa_type.to_yang()),
            adv_router: Some(lsa.hdr.adv_rtr),
            seq_num: Some(lsa.hdr.seq_no).ignore_in_testing(),
            checksum: Some(FletcherChecksum16(lsa.hdr.cksum)).ignore_in_testing(),
            length: Some(lsa.hdr.length),
            maxage: lsa.hdr.is_maxage().then_some(()).only_in_testing(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::link::Link {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_link()?;
        Some(Self {
            rtr_priority: Some(lsa_body.priority),
            link_local_interface_address: Some(match lsa_body.linklocal {
                IpAddr::V4(addr) => addr.to_ipv6_mapped(),
                IpAddr::V6(addr) => addr,
            }),
            num_of_prefixes: Some(lsa_body.prefixes.len() as _),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::link::lsa_options::LsaOptions<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_link()?;
        Some(Self {
            lsa_options: lsa_body.options.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::link::prefixes::prefix::Prefix {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;
    type ListEntry = &'a ospfv3::packet::lsa::LsaLinkPrefix;

    fn iter(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_std_link()?;
        let iter = lsa_body.prefixes.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, prefix: &Self::ListEntry) -> Self {
        Self {
            prefix: Some(prefix.value),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::link::prefixes::prefix::prefix_options::PrefixOptions<'a> {
    type ParentListEntry = &'a ospfv3::packet::lsa::LsaLinkPrefix;

    fn new(_instance: &'a Instance<Ospfv3>, prefix: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            prefix_options: prefix.options.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::router_informational_capabilities::RouterInformationalCapabilities<
        'a,
    >
{
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let info_caps = lsa.body.as_router_info()?.info_caps.as_ref()?;
        Some(Self {
            informational_capabilities: info_caps.get().to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>>
    for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::informational_capabilities_flags::InformationalCapabilitiesFlags
{
    type ParentListEntry = &'a LsaEntry<Ospfv3>;
    type ListEntry = u32;

    fn iter(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let info_caps = lsa.body.as_router_info()?.info_caps.as_ref()?;
        let info_caps = info_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| info_caps & flag != 0);
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, flag: &Self::ListEntry) -> Self {
        Self {
            informational_flag: Some(*flag),
        }
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>>
    for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::router_information::router_capabilities_tlv::functional_capabilities::FunctionalCapabilities
{
    type ParentListEntry = &'a LsaEntry<Ospfv3>;
    type ListEntry = u32;

    fn iter(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let func_caps = lsa.body.as_router_info()?.func_caps.as_ref()?;
        let func_caps = func_caps.get().bits();
        let iter = (0..31).map(|flag| 1 << flag).filter(move |flag| func_caps & flag != 0);
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, flag: &Self::ListEntry) -> Self {
        Self {
            functional_flag: Some(*flag),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::grace::Grace {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_grace()?;
        Some(Self {
            grace_period: lsa_body.grace_period.as_ref().map(|tlv| tlv.get()),
            graceful_restart_reason: lsa_body.gr_reason.as_ref().and_then(|tlv| GrReason::from_u8(tlv.get())),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::ELink {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        Some(Self {
            rtr_priority: lsa.body.as_ext_link().map(|lsa_body| lsa_body.priority),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::lsa_options::LsaOptions<'a> {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;

    fn new(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<Self> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_link()?;
        Some(Self {
            lsa_options: lsa_body.options.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ELinkTlvs {
    type ParentListEntry = &'a LsaEntry<Ospfv3>;
    type ListEntry = Ospfv3ELinkTlv<'a>;

    fn iter(_instance: &'a Instance<Ospfv3>, lse: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let lsa = &lse.data;
        let lsa_body = lsa.body.as_ext_link()?;
        let iter_prefixes = lsa_body.prefixes.iter().map(Ospfv3ELinkTlv::LinkPrefix);
        let iter_linklocal = std::iter::once(lsa_body.linklocal).map(Ospfv3ELinkTlv::LinkLocalAddr);
        let iter = iter_prefixes.chain(iter_linklocal);
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, _tlv: &Self::ListEntry) -> Self {
        Self {}
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::unknown_tlv::UnknownTlv<'a> {
    type ParentListEntry = Ospfv3ELinkTlv<'a>;

    fn new(_instance: &'a Instance<Ospfv3>, _tlv: &Self::ParentListEntry) -> Option<Self> {
        // TODO: unknown TLVs aren't tracked at this level yet.
        None
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::IntraPrefixTlv {
    type ParentListEntry = Ospfv3ELinkTlv<'a>;

    fn new(_instance: &'a Instance<Ospfv3>, parent: &Self::ParentListEntry) -> Option<Self> {
        let Ospfv3ELinkTlv::LinkPrefix(lsa_prefix) = parent else {
            return None;
        };
        Some(Self {
            metric: None, // TODO
            prefix: Some(lsa_prefix.value),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::prefix_options::PrefixOptions<'a>
{
    type ParentListEntry = Ospfv3ELinkTlv<'a>;

    fn new(_instance: &'a Instance<Ospfv3>, parent: &Self::ParentListEntry) -> Option<Self> {
        let Ospfv3ELinkTlv::LinkPrefix(prefix) = parent else {
            return None;
        };
        Some(Self {
            prefix_options: prefix.options.to_yang_flags_iter(),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::sub_tlvs::SubTlvs {
    type ParentListEntry = Ospfv3ELinkTlv<'a>;
    type ListEntry = &'a UnknownTlv;

    fn iter(_instance: &'a Instance<Ospfv3>, parent: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let Ospfv3ELinkTlv::LinkPrefix(prefix) = parent else {
            return None;
        };
        let iter = prefix.unknown_stlvs.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<Ospfv3>, _tlv: &Self::ListEntry) -> Self {
        Self {}
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::sub_tlvs::unknown_sub_tlv::UnknownSubTlv<'a>
{
    type ParentListEntry = &'a UnknownTlv;

    fn new(_instance: &'a Instance<Ospfv3>, tlv: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(HexStr(tlv.value.as_ref())),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>>
    for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::sub_tlvs::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::PrefixSidSubTlv<'a>
{
    type ParentListEntry = &'a UnknownTlv;
    type ListEntry = &'a ospfv3::packet::lsa::PrefixSid;

    fn iter(_instance: &'a Instance<Ospfv3>, _tlv: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        None::<std::iter::Empty<_>> // TODO
    }

    fn new(_instance: &'a Instance<Ospfv3>, stlv: &Self::ListEntry) -> Self {
        Self {
            algorithm: Some(stlv.algo.to_yang()),
            label_value: stlv.sid.as_label().map(|label| label.get()),
            index_value: stlv.sid.as_index().copied(),
        }
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::intra_prefix_tlv::sub_tlvs::prefix_sid_sub_tlvs::prefix_sid_sub_tlv::ospfv3_prefix_sid_flags::Ospfv3PrefixSidFlags<'a>
{
    type ParentListEntry = &'a ospfv3::packet::lsa::PrefixSid;

    fn new(_instance: &'a Instance<Ospfv3>, _prefix_sid: &Self::ParentListEntry) -> Option<Self> {
        None
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv6_link_local_addr_tlv::Ipv6LinkLocalAddrTlv {
    type ParentListEntry = Ospfv3ELinkTlv<'a>;

    fn new(_instance: &'a Instance<Ospfv3>, parent: &Self::ParentListEntry) -> Option<Self> {
        let Ospfv3ELinkTlv::LinkLocalAddr(lladdr) = parent else {
            return None;
        };
        Some(Self {
            link_local_address: Ipv6Addr::get(*lladdr),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv6_link_local_addr_tlv::sub_tlvs::SubTlvs {
    type ParentListEntry = Ospfv3ELinkTlv<'a>;
    type ListEntry = &'a UnknownTlv;

    fn iter(_instance: &'a Instance<Ospfv3>, _tlv: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        None::<std::iter::Empty<_>> // TODO
    }

    fn new(_instance: &'a Instance<Ospfv3>, _tlv: &Self::ListEntry) -> Self {
        Self {}
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv6_link_local_addr_tlv::sub_tlvs::unknown_sub_tlv::UnknownSubTlv<'a>
{
    type ParentListEntry = &'a UnknownTlv;

    fn new(_instance: &'a Instance<Ospfv3>, tlv: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(HexStr(tlv.value.as_ref())),
        })
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv4_link_local_addr_tlv::Ipv4LinkLocalAddrTlv {
    type ParentListEntry = Ospfv3ELinkTlv<'a>;

    fn new(_instance: &'a Instance<Ospfv3>, parent: &Self::ParentListEntry) -> Option<Self> {
        let Ospfv3ELinkTlv::LinkLocalAddr(lladdr) = parent else {
            return None;
        };
        Some(Self {
            link_local_address: Ipv4Addr::get(*lladdr),
        })
    }
}

impl<'a> YangList<'a, Instance<Ospfv3>> for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv4_link_local_addr_tlv::sub_tlvs::SubTlvs {
    type ParentListEntry = Ospfv3ELinkTlv<'a>;
    type ListEntry = &'a UnknownTlv;

    fn iter(_instance: &'a Instance<Ospfv3>, _tlv: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        None::<std::iter::Empty<_>> // TODO
    }

    fn new(_instance: &'a Instance<Ospfv3>, _tlv: &Self::ListEntry) -> Self {
        Self {}
    }
}

impl<'a> YangContainer<'a, Instance<Ospfv3>>
    for ospf::areas::area::interfaces::interface::database::link_scope_lsa_type::link_scope_lsas::link_scope_lsa::ospfv3::body::e_link::e_link_tlvs::ipv4_link_local_addr_tlv::sub_tlvs::unknown_sub_tlv::UnknownSubTlv<'a>
{
    type ParentListEntry = &'a UnknownTlv;

    fn new(_instance: &'a Instance<Ospfv3>, tlv: &Self::ParentListEntry) -> Option<Self> {
        Some(Self {
            r#type: Some(tlv.tlv_type),
            length: Some(tlv.length),
            value: Some(HexStr(tlv.value.as_ref())),
        })
    }
}

impl<'a, V: Version> YangList<'a, Instance<V>> for ospf::hostnames::hostname::Hostname<'a> {
    type ParentListEntry = ();
    type ListEntry = (&'a Ipv4Addr, &'a String);

    fn iter(instance: &'a Instance<V>, _: &Self::ParentListEntry) -> Option<impl ListIterator<'a, Self::ListEntry>> {
        let hostnames = &instance.state.as_ref()?.hostnames;
        let iter = hostnames.iter();
        Some(iter)
    }

    fn new(_instance: &'a Instance<V>, (router_id, hostname): &Self::ListEntry) -> Self {
        Self {
            router_id: **router_id,
            hostname: Some(Cow::Borrowed(hostname)),
        }
    }
}

// ===== helper functions =====

fn lsa_hdr_opaque_data(lsa_hdr: &ospfv2::packet::lsa::LsaHdr) -> (Option<u8>, Option<u32>) {
    let mut opaque_type = None;
    let mut opaque_id = None;
    if lsa_hdr.lsa_type.is_opaque() {
        let mut lsa_id = lsa_hdr.lsa_id.octets();
        lsa_id[0] = 0;
        opaque_type = Some(lsa_hdr.lsa_id.octets()[0]);
        opaque_id = Some(u32::from_be_bytes(lsa_id));
    }
    (opaque_type, opaque_id)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::{Arc, OnceLock};
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use holo_northbound::state::YangContainer;
    use holo_protocol::{InstanceChannelsTx, InstanceShared, ProtocolInstance};
    use holo_utils::ibus;
    use holo_utils::southbound::InterfaceFlags;
    use holo_utils::yang::ContextExt;
    use ipnetwork::{IpNetwork, Ipv6Network};
    use tokio::sync::mpsc;
    use yang5::context::Context;

    use super::*;
    use crate::area::BACKBONE_AREA_ID;
    use crate::collections::{AreaId, InterfaceId, InterfaceIndex, LsdbId};
    use crate::interface::InterfaceType;
    use crate::lsdb::LSA_INIT_SEQ_NO;
    use crate::ospfv3::mdr::{BackupWaitEntry, MdrAckedLsa};
    use crate::ospfv3::packet::lsa::{LsaBody, LsaHdr, LsaType, LsaUnknown};
    use crate::packet::lsa::{Lsa, LsaHdrVersion, LsaKey};
    use crate::version::Ospfv3;

    type InterfaceMdrState<'a> = ospf::areas::area::interfaces::interface::mdr_state::MdrState<'a>;
    type InterfaceMdrSummary = ospf::areas::area::interfaces::interface::mdr_state::summary::Summary;
    type NeighborMdrState<'a> = ospf::areas::area::interfaces::interface::neighbors::neighbor::mdr_state::MdrState<'a>;

    struct TestTopo {
        iface_idx: InterfaceIndex,
        area_id: AreaId,
        iface_id: InterfaceId,
    }

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
            let _ = holo_yang::YANG_CTX.set(yang_ctx.clone());
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
        instance.config.router_id = Some(router_id(1));
        instance
    }

    fn add_mdr_interface(instance: &mut Instance<Ospfv3>) -> TestTopo {
        let (_area_idx, area) = instance.arenas.areas.insert(BACKBONE_AREA_ID);
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
        iface.config.cost = 10;
        iface.config.mdr.enabled = true;
        iface.config.mdr.ack_interval = Duration::from_millis(750);
        iface.config.mdr.backup_wait_interval = Duration::from_millis(250);
        iface.config.mdr.router_priority = 7;

        let topo = TestTopo {
            iface_idx,
            area_id: area.id,
            iface_id: iface.id,
        };

        instance.update();
        let iface = &mut instance.arenas.interfaces[iface_idx];
        let mdr = iface.state.mdr.as_mut().expect("MDR runtime state");
        mdr.mdr_level = MdrLevel::Mdr;
        mdr.parent = Some(router_id(1));
        mdr.backup_parent = Some(router_id(2));
        mdr.hello_sequence_number = 42;
        mdr.full_hello_count = 3;
        mdr.differential_hello_count = 2;
        mdr.mdr_neighbor_change = true;
        mdr.adjacency_reevaluation_pending = true;
        mdr.lsa_reevaluation_pending = true;

        topo
    }

    fn add_neighbor(
        instance: &mut Instance<Ospfv3>,
        iface_idx: InterfaceIndex,
        nbr_router_id: Ipv4Addr,
        iface_id: u32,
        state: nsm::State,
        mdr_level: MdrLevel,
    ) {
        let (_, nbr) = instance.arenas.interfaces[iface_idx]
            .state
            .neighbors
            .insert(
                &mut instance.arenas.neighbors,
                nbr_router_id,
                Ipv6Addr::LOCALHOST,
            );
        nbr.state = state;
        nbr.iface_id = Some(iface_id);
        nbr.mdr.remote_interface_id = Some(iface_id);
        nbr.mdr.hello_sequence_number = 9;
        nbr.mdr.a_bit = true;
        nbr.mdr.full_hello_received = true;
        nbr.mdr.mdr_level = mdr_level;
        nbr.mdr.parent = Some(router_id(1));
        nbr.mdr.backup_parent = Some(router_id(3));
        nbr.mdr.child = true;
        nbr.mdr.dependent = true;
        nbr.mdr.dependent_selector = true;
        nbr.mdr.backbone = true;
        nbr.mdr.selected_advertised = true;
        nbr.mdr.routable = true;
        nbr.mdr.reverse_2way = true;
        nbr.mdr.adjacency_desired = true;
        nbr.mdr.consecutive_hellos = 4;
        nbr.mdr.incoming_link_metric = Some(11);
        nbr.mdr.outgoing_link_metric = Some(12);
        nbr.mdr.hello_advertised_metric = Some(13);
        nbr.mdr.bidirectional_neighbors.insert(router_id(3));
        nbr.mdr.dependent_neighbors.insert(router_id(4));
        nbr.mdr.selected_advertised_neighbors.insert(router_id(5));
        nbr.mdr.link_metrics.insert(router_id(6), 16);
    }

    fn iface_mdr_state<'a>(
        instance: &'a Instance<Ospfv3>,
        topo: &TestTopo,
    ) -> InterfaceMdrState<'a> {
        let iface = &instance.arenas.interfaces[topo.iface_idx];
        <InterfaceMdrState<'_> as YangContainer<'_, Instance<Ospfv3>>>::new(
            instance,
            &ListEntry::Interface(iface),
        )
        .unwrap()
    }

    fn iface_mdr_summary(instance: &Instance<Ospfv3>, topo: &TestTopo) -> InterfaceMdrSummary {
        let iface = &instance.arenas.interfaces[topo.iface_idx];
        <InterfaceMdrSummary as YangContainer<'_, Instance<Ospfv3>>>::new(
            instance,
            &ListEntry::Interface(iface),
        )
        .unwrap()
    }

    fn neighbor_mdr_state<'a>(
        instance: &'a Instance<Ospfv3>,
        topo: &TestTopo,
        router_id: Ipv4Addr,
    ) -> NeighborMdrState<'a> {
        let iface = &instance.arenas.interfaces[topo.iface_idx];
        let (_, nbr) = iface
            .state
            .neighbors
            .get_by_router_id(&instance.arenas.neighbors, router_id)
            .expect("test neighbor");
        <NeighborMdrState<'_> as YangContainer<'_, Instance<Ospfv3>>>::new(
            instance,
            &ListEntry::Neighbor(iface, nbr),
        )
        .unwrap()
    }

    fn router_id(octet: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, octet)
    }

    fn lsa_key(octet: u8) -> LsaKey<LsaType> {
        LsaKey::new(
            LsaType(0x2001),
            router_id(octet),
            Ipv4Addr::UNSPECIFIED,
        )
    }

    fn lsa_hdr(octet: u8, lsa_type: u16) -> LsaHdr {
        LsaHdr::new(
            0,
            None,
            LsaType(lsa_type),
            Ipv4Addr::UNSPECIFIED,
            router_id(octet),
            LSA_INIT_SEQ_NO,
        )
    }

    fn test_lsa(octet: u8, lsa_type: u16) -> Arc<Lsa<Ospfv3>> {
        Arc::new(Lsa {
            raw: Bytes::new(),
            hdr: lsa_hdr(octet, lsa_type),
            body: LsaBody::Unknown(LsaUnknown {}),
            base_time: None,
        })
    }

    fn populate_lsa_visibility(instance: &mut Instance<Ospfv3>, topo: &TestTopo) {
        let router_lsa = test_lsa(1, 0x2001);
        let network_lsa = test_lsa(2, 0x2002);
        let intra_area_prefix_lsa = test_lsa(3, 0x2009);
        let link_lsa = test_lsa(4, 0x0008);
        let protocol_input = &instance.tx.protocol_input;

        {
            let (_, area) = instance
                .arenas
                .areas
                .get_mut_by_id(topo.area_id)
                .expect("test area");
            area.state.lsdb.insert(
                &mut instance.arenas.lsa_entries,
                LsdbId::Area(topo.area_id),
                router_lsa,
                protocol_input,
            );
            area.state.lsdb.insert(
                &mut instance.arenas.lsa_entries,
                LsdbId::Area(topo.area_id),
                network_lsa,
                protocol_input,
            );
            area.state.lsdb.insert(
                &mut instance.arenas.lsa_entries,
                LsdbId::Area(topo.area_id),
                intra_area_prefix_lsa,
                protocol_input,
            );
        }

        instance.arenas.interfaces[topo.iface_idx].state.lsdb.insert(
            &mut instance.arenas.lsa_entries,
            LsdbId::Link(topo.area_id, topo.iface_id),
            link_lsa,
            protocol_input,
        );

        let key = lsa_key(9);
        let hdr = lsa_hdr(9, 0x2001);
        let lsa = test_lsa(9, 0x2001);
        let iface = &mut instance.arenas.interfaces[topo.iface_idx];
        let mdr = iface.state.mdr.as_mut().expect("MDR runtime state");
        mdr.delayed_acks.insert(key, hdr);
        mdr.backup_wait.insert(
            key,
            BackupWaitEntry {
                lsa: lsa.clone(),
                neighbors: BTreeSet::from([router_id(2), router_id(3)]),
            },
        );
        iface.state.ls_update_list.insert(key, lsa.clone());

        let (_, nbr) = iface
            .state
            .neighbors
            .get_mut_by_router_id(&mut instance.arenas.neighbors, router_id(2))
            .expect("test neighbor");
        nbr.mdr.acked_lsas.insert(
            key,
            MdrAckedLsa {
                hdr,
                received_at: Instant::now(),
            },
        );
        nbr.lists.ls_request.insert(key, hdr);
        nbr.lists.ls_request_pending.insert(key, hdr);
        nbr.lists.ls_rxmt.insert(key, lsa.clone());
        nbr.lists.ls_update.insert(key, lsa);
    }

    #[tokio::test]
    async fn mdr_northbound_state_walk_exports_stable_topology() {
        let mut instance = test_instance();
        let topo = add_mdr_interface(&mut instance);
        add_neighbor(
            &mut instance,
            topo.iface_idx,
            router_id(2),
            22,
            nsm::State::Full,
            MdrLevel::Backup,
        );
        add_neighbor(
            &mut instance,
            topo.iface_idx,
            router_id(3),
            33,
            nsm::State::TwoWay,
            MdrLevel::Other,
        );

        let iface_state = iface_mdr_state(&instance, &topo);
        assert_eq!(iface_state.enabled, Some(true));
        assert_eq!(iface_state.configured_enabled, Some(true));
        assert_eq!(iface_state.mdr_level.as_deref(), Some("mdr"));
        assert_eq!(iface_state.parent_router_id, Some(router_id(1)));
        assert_eq!(iface_state.backup_parent_router_id, Some(router_id(2)));
        assert_eq!(iface_state.hello_sequence_number, Some(42));
        assert_eq!(iface_state.effective_ack_interval.as_deref(), Some("0.750"));
        assert_eq!(
            iface_state.effective_backup_wait_interval.as_deref(),
            Some("0.250")
        );
        assert_eq!(iface_state.effective_router_priority, Some(7));

        let summary = iface_mdr_summary(&instance, &topo);
        assert_eq!(summary.neighbor_full_count, Some(1));
        assert_eq!(summary.neighbor_two_way_count, Some(1));
        assert_eq!(summary.neighbor_backup_count, Some(1));
        assert_eq!(summary.neighbor_other_count, Some(1));
        assert_eq!(summary.relay_participation_primary_count, Some(1));
        assert_eq!(summary.relay_set_size, Some(2));
        assert_eq!(summary.relay_selector_count, Some(2));
        assert_eq!(summary.routable_neighbor_count, Some(2));

        let nbr_state = neighbor_mdr_state(&instance, &topo, router_id(2));
        assert_eq!(nbr_state.remote_interface_id, Some(22));
        assert_eq!(nbr_state.mdr_level.as_deref(), Some("backup"));
        assert_eq!(nbr_state.parent_router_id, Some(router_id(1)));
        assert_eq!(nbr_state.backup_parent_router_id, Some(router_id(3)));
        assert_eq!(nbr_state.child, Some(true));
        assert_eq!(nbr_state.dependent, Some(true));
        assert_eq!(nbr_state.dependent_selector, Some(true));
        assert_eq!(nbr_state.selected_advertised, Some(true));
        assert_eq!(nbr_state.routable, Some(true));
        assert_eq!(nbr_state.reverse_two_way, Some(true));
        assert_eq!(nbr_state.adjacency_desired, Some(true));
        assert_eq!(nbr_state.adjacency_formed, Some(true));
        assert_eq!(nbr_state.incoming_metric, Some(11));
        assert_eq!(nbr_state.outgoing_metric, Some(12));
        assert_eq!(nbr_state.advertised_metric, Some(13));
        assert_eq!(nbr_state.reported_link_metric_count, Some(1));
    }

    #[tokio::test]
    async fn mdr_northbound_state_walk_tracks_role_transition() {
        let mut instance = test_instance();
        let topo = add_mdr_interface(&mut instance);
        let before = iface_mdr_state(&instance, &topo);
        assert_eq!(before.mdr_level.as_deref(), Some("mdr"));
        assert_eq!(before.parent_router_id, Some(router_id(1)));

        let iface = &mut instance.arenas.interfaces[topo.iface_idx];
        let mdr = iface.state.mdr.as_mut().expect("MDR runtime state");
        mdr.mdr_level = MdrLevel::Backup;
        mdr.parent = Some(router_id(2));
        mdr.backup_parent = Some(router_id(1));

        let after = iface_mdr_state(&instance, &topo);
        assert_eq!(after.mdr_level.as_deref(), Some("backup"));
        assert_eq!(after.parent_router_id, Some(router_id(2)));
        assert_eq!(after.backup_parent_router_id, Some(router_id(1)));
    }

    #[tokio::test]
    async fn mdr_northbound_state_walk_exports_acked_lsa_and_queue_depths() {
        let mut instance = test_instance();
        let topo = add_mdr_interface(&mut instance);
        add_neighbor(
            &mut instance,
            topo.iface_idx,
            router_id(2),
            22,
            nsm::State::Full,
            MdrLevel::Backup,
        );
        populate_lsa_visibility(&mut instance, &topo);

        let iface_state = iface_mdr_state(&instance, &topo);
        assert_eq!(iface_state.pending_backup_wait_count, Some(1));
        assert_eq!(iface_state.pending_backup_wait_neighbor_count, Some(2));
        assert_eq!(iface_state.delayed_ack_count, Some(1));
        assert_eq!(iface_state.pending_flood_count, Some(1));

        let summary = iface_mdr_summary(&instance, &topo);
        assert_eq!(summary.router_lsa_count, Some(1));
        assert_eq!(summary.network_lsa_count, Some(1));
        assert_eq!(summary.link_lsa_count, Some(1));
        assert_eq!(summary.intra_area_prefix_lsa_count, Some(1));

        let nbr_state = neighbor_mdr_state(&instance, &topo, router_id(2));
        assert_eq!(nbr_state.acked_lsa_cache_size, Some(1));
        assert_eq!(nbr_state.request_list_count, Some(2));
        assert_eq!(nbr_state.retransmission_list_count, Some(1));
        assert_eq!(nbr_state.update_list_count, Some(1));
    }

    #[tokio::test]
    async fn mdr_northbound_state_is_absent_without_runtime_state() {
        let mut instance = test_instance();
        let (_area_idx, area) = instance.arenas.areas.insert(BACKBONE_AREA_ID);
        let (iface_idx, iface) = area.interfaces.insert(
            &mut instance.arenas.interfaces,
            "eth1".into(),
            None,
        );
        iface.config.enabled = true;
        instance.update();

        let iface = &instance.arenas.interfaces[iface_idx];
        assert!(
            <InterfaceMdrState<'_> as YangContainer<'_, Instance<Ospfv3>>>::new(
                &instance,
                &ListEntry::Interface(iface),
            )
            .is_none()
        );
    }
}
