//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeSet;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, LazyLock as Lazy};

use bytes::Bytes;
use const_addrs::{ip, ip4, net};
use holo_ospf::ospfv3::packet::iana::*;
use holo_ospf::ospfv3::packet::lsa::*;
use holo_ospf::ospfv3::packet::*;
use holo_ospf::packet::auth::{AuthDecodeCtx, AuthEncodeCtx, AuthMethod};
use holo_ospf::packet::error::DecodeError;
use holo_ospf::packet::iana::*;
use holo_ospf::packet::lls::{
    ExtendedOptionsFlags, LlsDbDescData, LlsHelloData, MdrDdTlv, MdrHelloTlv,
    MdrMetricEntry, MdrMetricTlv,
};
use holo_ospf::packet::lsa::{Lsa, LsaKey};
use holo_ospf::packet::tlv::*;
use holo_ospf::packet::{DbDescFlags, Packet};
use holo_ospf::version::Ospfv3;
use holo_protocol::assert_eq_hex;
use holo_utils::bier::{BierEncapId, BiftId, Bsl};
use holo_utils::crypto::CryptoAlgo;
use holo_utils::ip::AddressFamily;
use holo_utils::keychain::Key;
use holo_utils::mpls::Label;
use holo_utils::sr::{IgpAlgoType, Sid};
use maplit::{btreemap, btreeset};
use serde::Deserialize;

const SRC_ADDR: Ipv6Addr = Ipv6Addr::UNSPECIFIED;

//
// Helper functions.
//

fn test_encode_packet(
    bytes_expected: &[u8],
    auth_data: &Option<(Key, u64)>,
    packet: &Packet<Ospfv3>,
) {
    // Prepare authentication context.
    let mut auth = None;
    let auth_seqno;
    if let Some((auth_key, seqno)) = auth_data {
        auth_seqno = Arc::new(AtomicU64::new(*seqno));
        auth = Some(AuthEncodeCtx::new(auth_key, &auth_seqno, SRC_ADDR.into()));
    }

    // Encode the packet.
    let bytes_actual = packet.encode(auth);
    assert_eq_hex!(bytes_expected, bytes_actual);
}

fn test_decode_packet(
    bytes: &[u8],
    auth_data: &Option<(Key, u64)>,
    packet_expected: &Packet<Ospfv3>,
    af: AddressFamily,
) {
    // Prepare authentication context.
    let mut auth = None;
    let auth_method;
    if let Some((auth_key, _)) = auth_data {
        auth_method = AuthMethod::ManualKey(auth_key.clone());
        auth = Some(AuthDecodeCtx::new(&auth_method, SRC_ADDR.into()));
    };

    // Decode the packet.
    let mut buf = Bytes::copy_from_slice(bytes);
    let packet_actual = Packet::decode(af, &mut buf, auth).unwrap();
    assert_eq!(*packet_expected, packet_actual);
}

fn test_encode_lsa(bytes_expected: &[u8], lsa: &Lsa<Ospfv3>) {
    assert_eq_hex!(bytes_expected, lsa.raw);
}

fn test_decode_lsa(
    bytes: &[u8],
    lsa_expected: &Lsa<Ospfv3>,
    af: AddressFamily,
) {
    let mut bytes = Bytes::copy_from_slice(bytes);
    let lsa_actual = Lsa::decode(af, &mut bytes).unwrap();
    assert_eq!(*lsa_expected, lsa_actual);
}

fn decode_ospfv3_packet(bytes: &[u8]) -> Result<Packet<Ospfv3>, DecodeError> {
    let mut buf = Bytes::copy_from_slice(bytes);
    Packet::decode(AddressFamily::Ipv6, &mut buf, None)
}

fn mdr_hello_packet(lls: LlsHelloData) -> Packet<Ospfv3> {
    Packet::Hello(Hello {
        hdr: PacketHdr {
            pkt_type: PacketType::Hello,
            router_id: ip4!("1.1.1.1"),
            area_id: ip4!("0.0.0.1"),
            instance_id: 0,
            auth_seqno: None,
        },
        iface_id: 4,
        priority: 1,
        options: Options::R | Options::E | Options::V6 | Options::L,
        hello_interval: 3,
        dead_interval: 36,
        dr: Some(ip4!("1.1.1.1").into()),
        bdr: Some(ip4!("1.1.1.2").into()),
        neighbors: [ip4!("2.2.2.2"), ip4!("3.3.3.3")].into(),
        lls: Some(lls),
    })
}

fn mdr_dbdesc_packet(lls: LlsDbDescData) -> Packet<Ospfv3> {
    Packet::DbDesc(DbDesc {
        hdr: PacketHdr {
            pkt_type: PacketType::DbDesc,
            router_id: ip4!("1.1.1.1"),
            area_id: ip4!("0.0.0.1"),
            instance_id: 0,
            auth_seqno: None,
        },
        options: Options::R | Options::E | Options::V6 | Options::L,
        mtu: 1500,
        dd_flags: DbDescFlags::I | DbDescFlags::M | DbDescFlags::MS,
        dd_seq_no: 93968,
        lsa_hdrs: vec![],
        lls: Some(lls),
    })
}

fn packet_len(bytes: &[u8]) -> usize {
    u16::from_be_bytes([bytes[2], bytes[3]]) as usize
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&remaining) = chunks.remainder().first() {
        sum += u16::from_be_bytes([remaining, 0]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn recompute_lls_checksum(bytes: &mut [u8]) {
    let lls_start = packet_len(bytes);
    let lls_len =
        u16::from_be_bytes([bytes[lls_start + 2], bytes[lls_start + 3]])
            as usize
            * 4;
    bytes[lls_start] = 0;
    bytes[lls_start + 1] = 0;
    let checksum = internet_checksum(&bytes[lls_start..lls_start + lls_len]);
    bytes[lls_start..lls_start + 2].copy_from_slice(&checksum.to_be_bytes());
}

fn lls_wire_len(bytes: &[u8]) -> usize {
    let lls_start = packet_len(bytes);
    u16::from_be_bytes([bytes[lls_start + 2], bytes[lls_start + 3]]) as usize
        * 4
}

#[derive(Debug)]
struct MdrGoldenCase {
    id: &'static str,
    bytes: &'static [u8],
    expected_json: &'static str,
}

#[derive(Debug, Deserialize)]
struct ExpectedPacket {
    id: String,
    expected_outcome: String,
    packet_type: String,
    #[serde(default)]
    malformed: bool,
    ospfv3_header: ExpectedOspfv3Header,
    #[serde(default)]
    hello: Option<ExpectedHello>,
    #[serde(default)]
    database_description: Option<ExpectedDbDesc>,
    #[serde(default)]
    mdr_tlvs: Option<ExpectedMdrTlvs>,
    #[serde(default)]
    lsa_headers: Vec<ExpectedLsaHeader>,
}

#[derive(Debug, Deserialize)]
struct ExpectedOspfv3Header {
    version: u8,
    packet_type: u8,
    packet_length: u16,
    router_id: ExpectedRouterId,
    area_id: u32,
    checksum: u16,
    instance_id: u8,
}

#[derive(Debug, Deserialize)]
struct ExpectedRouterId {
    value: Option<u32>,
}

impl ExpectedRouterId {
    fn addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.value.expect("Router ID value"))
    }

    fn addr_opt(&self) -> Option<Ipv4Addr> {
        self.value.map(Ipv4Addr::from)
    }
}

#[derive(Debug, Deserialize)]
struct ExpectedHello {
    interface_id: u32,
    router_priority: u8,
    options: Vec<u8>,
    hello_interval_secs: u16,
    dead_interval_secs: u16,
    designated_router: ExpectedRouterId,
    backup_designated_router: ExpectedRouterId,
    neighbors: Vec<ExpectedRouterId>,
}

#[derive(Debug, Deserialize)]
struct ExpectedDbDesc {
    options: Vec<u8>,
    interface_mtu: u16,
    bits: u8,
    sequence_number: u32,
    has_l_bit: bool,
}

#[derive(Debug, Deserialize)]
struct ExpectedMdrTlvs {
    #[serde(default)]
    mdr_hello: Option<ExpectedMdrHelloTlv>,
    #[serde(default)]
    mdr_dd: Option<ExpectedMdrDdTlv>,
    #[serde(default)]
    mdr_metric: Option<ExpectedMdrMetricTlv>,
}

#[derive(Debug, Deserialize)]
struct ExpectedMdrHelloTlv {
    hello_sequence_number: u16,
    adjacency_reduction_disabled: bool,
    differential: bool,
    n1: u8,
    n2: u8,
    n3: u8,
    n4: u8,
}

#[derive(Debug, Deserialize)]
struct ExpectedMdrDdTlv {
    designated_router: ExpectedRouterId,
    backup_designated_router: ExpectedRouterId,
}

#[derive(Debug, Deserialize)]
struct ExpectedMdrMetricTlv {
    default_metric: u16,
    include_ids: bool,
    metrics: Vec<ExpectedMdrMetricEntry>,
}

#[derive(Debug, Deserialize)]
struct ExpectedMdrMetricEntry {
    #[serde(default)]
    neighbor_id: Option<ExpectedRouterId>,
    metric: u16,
}

#[derive(Debug, Deserialize)]
struct ExpectedLsaHeader {
    ls_age: u16,
    ls_type: u16,
    link_state_id: u32,
    advertising_router: ExpectedRouterId,
    ls_sequence_number: u32,
    ls_checksum: u16,
    length: u16,
}

fn parse_expected(json: &str) -> ExpectedPacket {
    serde_json::from_str(json).expect("fixture sidecar JSON")
}

fn expected_options(options: &[u8]) -> Options {
    assert_eq!(options.len(), 3, "OSPFv3 options field is 3 bytes");
    Options::from_bits_truncate(u16::from_be_bytes([options[1], options[2]]))
}

fn assert_wire_header(bytes: &[u8], expected: &ExpectedOspfv3Header) {
    assert_eq!(bytes[0], expected.version);
    assert_eq!(bytes[1], expected.packet_type);
    assert_eq!(
        u16::from_be_bytes([bytes[2], bytes[3]]),
        expected.packet_length
    );
    assert_eq!(
        u16::from_be_bytes([bytes[12], bytes[13]]),
        expected.checksum
    );
}

fn assert_header(
    actual: &PacketHdr,
    expected: &ExpectedOspfv3Header,
    packet_type: PacketType,
) {
    assert_eq!(actual.pkt_type, packet_type);
    assert_eq!(actual.pkt_type as u8, expected.packet_type);
    assert_eq!(actual.router_id, expected.router_id.addr());
    assert_eq!(actual.area_id, Ipv4Addr::from(expected.area_id));
    assert_eq!(actual.instance_id, expected.instance_id);
    assert_eq!(actual.auth_seqno, None);
}

fn assert_expected_mdr_hello(
    actual: Option<&MdrHelloTlv>,
    expected: Option<&ExpectedMdrHelloTlv>,
    id: &str,
) {
    match (actual, expected) {
        (Some(actual), Some(expected)) => {
            assert_eq!(
                actual.hello_sequence_number, expected.hello_sequence_number,
                "{id}"
            );
            assert_eq!(
                actual.adjacency_reduction_disabled,
                expected.adjacency_reduction_disabled,
                "{id}"
            );
            assert_eq!(actual.differential, expected.differential, "{id}");
            assert_eq!(actual.n1, expected.n1, "{id}");
            assert_eq!(actual.n2, expected.n2, "{id}");
            assert_eq!(actual.n3, expected.n3, "{id}");
            assert_eq!(actual.n4, expected.n4, "{id}");
        }
        (None, None) => {}
        _ => panic!("{id}: MDR-Hello TLV presence mismatch"),
    }
}

fn assert_expected_mdr_dd(
    actual: Option<&MdrDdTlv>,
    expected: Option<&ExpectedMdrDdTlv>,
    id: &str,
) {
    match (actual, expected) {
        (Some(actual), Some(expected)) => {
            assert_eq!(
                actual.designated_router,
                expected.designated_router.addr(),
                "{id}"
            );
            assert_eq!(
                actual.backup_designated_router,
                expected.backup_designated_router.addr(),
                "{id}"
            );
        }
        (None, None) => {}
        _ => panic!("{id}: MDR-DD TLV presence mismatch"),
    }
}

fn assert_expected_mdr_metric(
    actual: Option<&MdrMetricTlv>,
    expected: Option<&ExpectedMdrMetricTlv>,
    id: &str,
) {
    match (actual, expected) {
        (Some(actual), Some(expected)) => {
            assert_eq!(actual.default_metric, expected.default_metric, "{id}");
            assert_eq!(actual.include_ids, expected.include_ids, "{id}");
            assert_eq!(actual.metrics.len(), expected.metrics.len(), "{id}");
            for (actual, expected) in
                actual.metrics.iter().zip(&expected.metrics)
            {
                assert_eq!(
                    actual.neighbor_id,
                    expected
                        .neighbor_id
                        .as_ref()
                        .and_then(ExpectedRouterId::addr_opt),
                    "{id}"
                );
                assert_eq!(actual.metric, expected.metric, "{id}");
            }
        }
        (None, None) => {}
        _ => panic!("{id}: MDR-Metric TLV presence mismatch"),
    }
}

fn assert_lsa_header(actual: &LsaHdr, expected: &ExpectedLsaHeader, id: &str) {
    assert_eq!(actual.age, expected.ls_age, "{id}");
    assert_eq!(actual.lsa_type.0, expected.ls_type, "{id}");
    assert_eq!(u32::from(actual.lsa_id), expected.link_state_id, "{id}");
    assert_eq!(actual.adv_rtr, expected.advertising_router.addr(), "{id}");
    assert_eq!(actual.seq_no, expected.ls_sequence_number, "{id}");
    assert_eq!(actual.cksum, expected.ls_checksum, "{id}");
    assert_eq!(actual.length, expected.length, "{id}");
}

fn assert_expected_hello(
    bytes: &[u8],
    hello: &Hello,
    expected: &ExpectedPacket,
) {
    let expected_hello = expected.hello.as_ref().expect("Hello sidecar");
    let expected_tlvs = expected.mdr_tlvs.as_ref().expect("MDR TLV sidecar");

    assert_eq!(expected.packet_type, "Hello");
    assert_wire_header(bytes, &expected.ospfv3_header);
    assert_header(&hello.hdr, &expected.ospfv3_header, PacketType::Hello);
    assert_eq!(
        hello.iface_id, expected_hello.interface_id,
        "{}",
        expected.id
    );
    assert_eq!(
        hello.priority, expected_hello.router_priority,
        "{}",
        expected.id
    );
    assert_eq!(
        hello.options,
        expected_options(&expected_hello.options),
        "{}",
        expected.id
    );
    assert_eq!(
        hello.hello_interval, expected_hello.hello_interval_secs,
        "{}",
        expected.id
    );
    assert_eq!(
        hello.dead_interval, expected_hello.dead_interval_secs,
        "{}",
        expected.id
    );
    assert_eq!(
        hello.dr,
        expected_hello.designated_router.addr_opt().map(Into::into),
        "{}",
        expected.id
    );
    assert_eq!(
        hello.bdr,
        expected_hello
            .backup_designated_router
            .addr_opt()
            .map(Into::into),
        "{}",
        expected.id
    );
    let expected_neighbors = expected_hello
        .neighbors
        .iter()
        .map(ExpectedRouterId::addr)
        .collect::<BTreeSet<_>>();
    assert_eq!(hello.neighbors, expected_neighbors, "{}", expected.id);

    let lls = hello.lls.as_ref().expect("Hello LLS data");
    assert_expected_mdr_hello(
        lls.mdr_hello.as_ref(),
        expected_tlvs.mdr_hello.as_ref(),
        &expected.id,
    );
    assert_expected_mdr_metric(
        lls.mdr_metric.as_ref(),
        expected_tlvs.mdr_metric.as_ref(),
        &expected.id,
    );
}

fn assert_expected_dbdesc(
    bytes: &[u8],
    dbdesc: &DbDesc,
    expected: &ExpectedPacket,
) {
    let expected_dbdesc = expected
        .database_description
        .as_ref()
        .expect("Database Description sidecar");
    let expected_tlvs = expected.mdr_tlvs.as_ref().expect("MDR TLV sidecar");

    assert_eq!(expected.packet_type, "DatabaseDescription");
    assert_wire_header(bytes, &expected.ospfv3_header);
    assert_header(&dbdesc.hdr, &expected.ospfv3_header, PacketType::DbDesc);
    assert_eq!(
        dbdesc.options,
        expected_options(&expected_dbdesc.options),
        "{}",
        expected.id
    );
    assert_eq!(dbdesc.mtu, expected_dbdesc.interface_mtu, "{}", expected.id);
    assert_eq!(
        dbdesc.dd_flags.bits(),
        expected_dbdesc.bits,
        "{}",
        expected.id
    );
    assert_eq!(
        dbdesc.dd_seq_no, expected_dbdesc.sequence_number,
        "{}",
        expected.id
    );
    assert_eq!(
        dbdesc.options.contains(Options::L),
        expected_dbdesc.has_l_bit,
        "{}",
        expected.id
    );
    assert_eq!(
        dbdesc.lsa_hdrs.len(),
        expected.lsa_headers.len(),
        "{}",
        expected.id
    );
    for (actual, expected_lsa) in
        dbdesc.lsa_hdrs.iter().zip(&expected.lsa_headers)
    {
        assert_lsa_header(actual, expected_lsa, &expected.id);
    }

    let lls = dbdesc.lls.as_ref().expect("DD LLS data");
    assert_expected_mdr_dd(
        lls.mdr_dd.as_ref(),
        expected_tlvs.mdr_dd.as_ref(),
        &expected.id,
    );
}

fn assert_expected_lsupdate(
    bytes: &[u8],
    lsupdate: &LsUpdate,
    expected: &ExpectedPacket,
) {
    assert_eq!(expected.packet_type, "LinkStateUpdate");
    assert_wire_header(bytes, &expected.ospfv3_header);
    assert_header(&lsupdate.hdr, &expected.ospfv3_header, PacketType::LsUpdate);
    assert_eq!(
        lsupdate.lsas.len(),
        expected.lsa_headers.len(),
        "{}",
        expected.id
    );
    for (actual, expected_lsa) in
        lsupdate.lsas.iter().zip(&expected.lsa_headers)
    {
        assert_lsa_header(&actual.hdr, expected_lsa, &expected.id);
    }
}

fn assert_expected_lsack(
    bytes: &[u8],
    lsack: &LsAck,
    expected: &ExpectedPacket,
) {
    assert_eq!(expected.packet_type, "LinkStateAcknowledgment");
    assert_wire_header(bytes, &expected.ospfv3_header);
    assert_header(&lsack.hdr, &expected.ospfv3_header, PacketType::LsAck);
    assert_eq!(
        lsack.lsa_hdrs.len(),
        expected.lsa_headers.len(),
        "{}",
        expected.id
    );
    for (actual, expected_lsa) in
        lsack.lsa_hdrs.iter().zip(&expected.lsa_headers)
    {
        assert_lsa_header(actual, expected_lsa, &expected.id);
    }
}

fn assert_expected_packet(
    bytes: &[u8],
    packet: &Packet<Ospfv3>,
    expected: &ExpectedPacket,
) {
    assert_eq!(expected.expected_outcome, "accepted_round_trip");
    assert!(!expected.malformed);
    match packet {
        Packet::Hello(hello) => assert_expected_hello(bytes, hello, expected),
        Packet::DbDesc(dbdesc) => {
            assert_expected_dbdesc(bytes, dbdesc, expected)
        }
        Packet::LsUpdate(lsupdate) => {
            assert_expected_lsupdate(bytes, lsupdate, expected)
        }
        Packet::LsAck(lsack) => assert_expected_lsack(bytes, lsack, expected),
        packet => panic!("{}: unexpected packet {packet:?}", expected.id),
    }
}

fn maybe_export_holo_emitted(case: &MdrGoldenCase, bytes: &[u8]) {
    let Ok(output_dir) = std::env::var("HOLO_MDR_EXPORT_DIR") else {
        return;
    };

    let output_dir = Path::new(&output_dir);
    fs::create_dir_all(output_dir).expect("create Holo-emitted export dir");
    fs::write(output_dir.join(format!("{}.bin", case.id)), bytes)
        .expect("write Holo-emitted packet");
    fs::write(
        output_dir.join(format!("{}.json", case.id)),
        case.expected_json,
    )
    .expect("write Holo-emitted sidecar");
}

fn assert_auth_lls_layout(bytes: &[u8], algo: CryptoAlgo) {
    let pkt_len = packet_len(bytes);
    let lls_len = lls_wire_len(bytes);
    let lls_start = pkt_len;
    let digest_size = usize::from(algo.digest_size());
    assert_eq!(&bytes[lls_start..lls_start + 2], &[0, 0]);

    let auth_start = pkt_len + lls_len;
    assert_eq!(
        u16::from_be_bytes([bytes[auth_start], bytes[auth_start + 1]]),
        AuthType::HmacCryptographic as u16
    );
    assert_eq!(
        u16::from_be_bytes([bytes[auth_start + 2], bytes[auth_start + 3]]),
        16 + digest_size as u16
    );
    assert_eq!(auth_start + 16 + digest_size, bytes.len());
}

static MDR_WELL_FORMED_GOLDENS: &[MdrGoldenCase] = &[
    MdrGoldenCase {
        id: "hello_full_no_metric",
        bytes: include_bytes!("fixtures/mdr/packets/hello_full_no_metric.bin"),
        expected_json: include_str!(
            "fixtures/mdr/packets/hello_full_no_metric.json"
        ),
    },
    MdrGoldenCase {
        id: "hello_full_metric",
        bytes: include_bytes!("fixtures/mdr/packets/hello_full_metric.bin"),
        expected_json: include_str!(
            "fixtures/mdr/packets/hello_full_metric.json"
        ),
    },
    MdrGoldenCase {
        id: "hello_differential",
        bytes: include_bytes!("fixtures/mdr/packets/hello_differential.bin"),
        expected_json: include_str!(
            "fixtures/mdr/packets/hello_differential.json"
        ),
    },
    MdrGoldenCase {
        id: "database_description_mdr_dd",
        bytes: include_bytes!(
            "fixtures/mdr/packets/database_description_mdr_dd.bin"
        ),
        expected_json: include_str!(
            "fixtures/mdr/packets/database_description_mdr_dd.json"
        ),
    },
    MdrGoldenCase {
        id: "link_state_update_router_link_intra_prefix",
        bytes: include_bytes!(
            "fixtures/mdr/packets/link_state_update_router_link_intra_prefix.bin"
        ),
        expected_json: include_str!(
            "fixtures/mdr/packets/link_state_update_router_link_intra_prefix.json"
        ),
    },
    MdrGoldenCase {
        id: "link_state_ack",
        bytes: include_bytes!("fixtures/mdr/packets/link_state_ack.bin"),
        expected_json: include_str!("fixtures/mdr/packets/link_state_ack.json"),
    },
];

//
// Test packets.
//

static HELLO1: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x03, 0x01, 0x00, 0x28, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
                0x01, 0x00, 0x00, 0x13, 0x00, 0x03, 0x00, 0x24, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02,
            ],
            None,
            Packet::Hello(Hello {
                hdr: PacketHdr {
                    pkt_type: PacketType::Hello,
                    router_id: ip4!("1.1.1.1"),
                    area_id: ip4!("0.0.0.1"),
                    instance_id: 0,
                    auth_seqno: None,
                },
                iface_id: 4,
                priority: 1,
                options: Options::R | Options::E | Options::V6,
                hello_interval: 3,
                dead_interval: 36,
                dr: None,
                bdr: None,
                neighbors: [ip4!("2.2.2.2")].into(),
                lls: None,
            }),
        )
    });

static HELLO1_LLS: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x03, 0x01, 0x00, 0x28, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
                0x01, 0x00, 0x02, 0x13, 0x00, 0x03, 0x00, 0x24, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02,
                0xff, 0xf4, 0x00, 0x03, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00,
                0x00, 0x03,
            ],
            None,
            Packet::Hello(Hello {
                hdr: PacketHdr {
                    pkt_type: PacketType::Hello,
                    router_id: ip4!("1.1.1.1"),
                    area_id: ip4!("0.0.0.1"),
                    instance_id: 0,
                    auth_seqno: None,
                },
                iface_id: 4,
                priority: 1,
                options: Options::R | Options::E | Options::V6 | Options::L,
                hello_interval: 3,
                dead_interval: 36,
                dr: None,
                bdr: None,
                neighbors: [ip4!("2.2.2.2")].into(),
                lls: Some(holo_ospf::packet::lls::LlsHelloData {
                    eof: Some(
                        ExtendedOptionsFlags::LR | ExtendedOptionsFlags::RS,
                    ),
                    ..Default::default()
                }),
            }),
        )
    });

static HELLO1_HMAC_SHA1: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x03, 0x01, 0x00, 0x28, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
                0x01, 0x00, 0x04, 0x13, 0x00, 0x03, 0x00, 0x24, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02,
                0x00, 0x01, 0x00, 0x24, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x32, 0x45, 0xd0, 0x14, 0x72, 0xac, 0xc6, 0xd9,
                0xaf, 0x89, 0x4a, 0x11, 0xb6, 0x43, 0xe0, 0x7c, 0x77, 0xce,
                0x6b, 0xf9, 0x9a, 0xd1, 0x4f, 0x4b,
            ],
            Some((
                Key::new(1, CryptoAlgo::HmacSha1, "HOLO".as_bytes().to_vec()),
                843436052,
            )),
            Packet::Hello(Hello {
                hdr: PacketHdr {
                    pkt_type: PacketType::Hello,
                    router_id: ip4!("1.1.1.1"),
                    area_id: ip4!("0.0.0.1"),
                    instance_id: 0,
                    auth_seqno: Some(843436052),
                },
                iface_id: 4,
                priority: 1,
                options: Options::R | Options::E | Options::V6 | Options::AT,
                hello_interval: 3,
                dead_interval: 36,
                dr: None,
                bdr: None,
                neighbors: [ip4!("2.2.2.2")].into(),
                lls: None,
            }),
        )
    });

static HELLO1_HMAC_SHA1_LLS: Lazy<(
    Vec<u8>,
    Option<(Key, u64)>,
    Packet<Ospfv3>,
)> = Lazy::new(|| {
    (
        vec![
            0x03, 0x01, 0x00, 0x28, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00,
            0x06, 0x13, 0x00, 0x03, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00, 0x00, 0x03,
            0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00,
            0x24, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x32, 0x45,
            0xd0, 0x14, 0xfe, 0xef, 0xc6, 0xce, 0x7d, 0xbe, 0x66, 0x4e, 0xc3,
            0x92, 0x0c, 0xc9, 0x2f, 0x6d, 0x42, 0x1f, 0x38, 0xb2, 0xd2, 0x3c,
        ],
        Some((
            Key::new(1, CryptoAlgo::HmacSha1, "HOLO".as_bytes().to_vec()),
            843436052,
        )),
        Packet::Hello(Hello {
            hdr: PacketHdr {
                pkt_type: PacketType::Hello,
                router_id: ip4!("1.1.1.1"),
                area_id: ip4!("0.0.0.1"),
                instance_id: 0,
                auth_seqno: Some(843436052),
            },
            iface_id: 4,
            priority: 1,
            options: Options::R
                | Options::E
                | Options::V6
                | Options::AT
                | Options::L,
            hello_interval: 3,
            dead_interval: 36,
            dr: None,
            bdr: None,
            neighbors: [ip4!("2.2.2.2")].into(),
            lls: Some(holo_ospf::packet::lls::LlsHelloData {
                eof: Some(ExtendedOptionsFlags::LR | ExtendedOptionsFlags::RS),
                ..Default::default()
            }),
        }),
    )
});

static HELLO1_HMAC_SHA256: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x03, 0x01, 0x00, 0x28, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
                0x01, 0x00, 0x04, 0x13, 0x00, 0x03, 0x00, 0x24, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02,
                0x00, 0x01, 0x00, 0x30, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x32, 0x45, 0xd0, 0x14, 0xda, 0xbc, 0x49, 0xc0,
                0x9b, 0xc2, 0x3c, 0x5d, 0x58, 0x19, 0xe1, 0x1f, 0xa0, 0xa3,
                0xef, 0x4b, 0xd0, 0xf4, 0xb4, 0xe2, 0x51, 0xea, 0xee, 0xe8,
                0x78, 0x1b, 0x72, 0xd2, 0xa9, 0x9f, 0x0f, 0x91,
            ],
            Some((
                Key::new(1, CryptoAlgo::HmacSha256, "HOLO".as_bytes().to_vec()),
                843436052,
            )),
            Packet::Hello(Hello {
                hdr: PacketHdr {
                    pkt_type: PacketType::Hello,
                    router_id: ip4!("1.1.1.1"),
                    area_id: ip4!("0.0.0.1"),
                    instance_id: 0,
                    auth_seqno: Some(843436052),
                },
                iface_id: 4,
                priority: 1,
                options: Options::R | Options::E | Options::V6 | Options::AT,
                hello_interval: 3,
                dead_interval: 36,
                dr: None,
                bdr: None,
                neighbors: [ip4!("2.2.2.2")].into(),
                lls: None,
            }),
        )
    });

static HELLO1_HMAC_SHA256_LLS: Lazy<(
    Vec<u8>,
    Option<(Key, u64)>,
    Packet<Ospfv3>,
)> = Lazy::new(|| {
    (
        vec![
            0x03, 0x01, 0x00, 0x28, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00,
            0x06, 0x13, 0x00, 0x03, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00, 0x00, 0x03,
            0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00,
            0x30, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x32, 0x45,
            0xd0, 0x14, 0xdf, 0x4b, 0x87, 0x87, 0xea, 0x1f, 0xaf, 0x92, 0xe9,
            0xcc, 0x0d, 0x1f, 0xbc, 0x70, 0xf7, 0xbc, 0x58, 0xa7, 0x1e, 0x37,
            0xc1, 0x4e, 0x6e, 0x8a, 0x22, 0xe3, 0xd1, 0xc7, 0x2d, 0xed, 0xef,
            0x67,
        ],
        Some((
            Key::new(1, CryptoAlgo::HmacSha256, "HOLO".as_bytes().to_vec()),
            843436052,
        )),
        Packet::Hello(Hello {
            hdr: PacketHdr {
                pkt_type: PacketType::Hello,
                router_id: ip4!("1.1.1.1"),
                area_id: ip4!("0.0.0.1"),
                instance_id: 0,
                auth_seqno: Some(843436052),
            },
            iface_id: 4,
            priority: 1,
            options: Options::R
                | Options::E
                | Options::V6
                | Options::AT
                | Options::L,
            hello_interval: 3,
            dead_interval: 36,
            dr: None,
            bdr: None,
            neighbors: [ip4!("2.2.2.2")].into(),
            lls: Some(holo_ospf::packet::lls::LlsHelloData {
                eof: Some(ExtendedOptionsFlags::LR | ExtendedOptionsFlags::RS),
                ..Default::default()
            }),
        }),
    )
});

static HELLO1_HMAC_SHA384: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x03, 0x01, 0x00, 0x28, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
                0x01, 0x00, 0x04, 0x13, 0x00, 0x03, 0x00, 0x24, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02,
                0x00, 0x01, 0x00, 0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x32, 0x45, 0xd0, 0x14, 0xa6, 0x5c, 0xb4, 0x0d,
                0x57, 0x94, 0x5f, 0x3d, 0xad, 0xba, 0x91, 0x4c, 0x52, 0xf1,
                0xc3, 0x6d, 0xeb, 0x5d, 0xa4, 0x49, 0xde, 0x08, 0xa2, 0x75,
                0x5f, 0x23, 0x13, 0x4d, 0x58, 0xf5, 0x29, 0xcf, 0x3a, 0x1c,
                0xa7, 0x87, 0x1c, 0x2f, 0xa7, 0xcc, 0xa8, 0xf1, 0xbd, 0xab,
                0x21, 0x76, 0xa2, 0x65,
            ],
            Some((
                Key::new(1, CryptoAlgo::HmacSha384, "HOLO".as_bytes().to_vec()),
                843436052,
            )),
            Packet::Hello(Hello {
                hdr: PacketHdr {
                    pkt_type: PacketType::Hello,
                    router_id: ip4!("1.1.1.1"),
                    area_id: ip4!("0.0.0.1"),
                    instance_id: 0,
                    auth_seqno: Some(843436052),
                },
                iface_id: 4,
                priority: 1,
                options: Options::R | Options::E | Options::V6 | Options::AT,
                hello_interval: 3,
                dead_interval: 36,
                dr: None,
                bdr: None,
                neighbors: [ip4!("2.2.2.2")].into(),
                lls: None,
            }),
        )
    });

static HELLO1_HMAC_SHA384_LLS: Lazy<(
    Vec<u8>,
    Option<(Key, u64)>,
    Packet<Ospfv3>,
)> = Lazy::new(|| {
    (
        vec![
            0x03, 0x01, 0x00, 0x28, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00,
            0x06, 0x13, 0x00, 0x03, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00, 0x00, 0x03,
            0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00,
            0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x32, 0x45,
            0xd0, 0x14, 0xb2, 0xe6, 0x9b, 0x9e, 0x54, 0xd0, 0xad, 0xb9, 0x59,
            0xad, 0x9c, 0x35, 0x1c, 0x08, 0x96, 0xda, 0x72, 0x77, 0x30, 0x4b,
            0x15, 0x88, 0xcc, 0x18, 0xf0, 0xc4, 0x02, 0xa9, 0x67, 0x65, 0x82,
            0x87, 0x68, 0xf5, 0xc0, 0x72, 0x10, 0x2b, 0xa0, 0x4c, 0x1e, 0x44,
            0x8f, 0xa1, 0xbe, 0x69, 0xac, 0x6e,
        ],
        Some((
            Key::new(1, CryptoAlgo::HmacSha384, "HOLO".as_bytes().to_vec()),
            843436052,
        )),
        Packet::Hello(Hello {
            hdr: PacketHdr {
                pkt_type: PacketType::Hello,
                router_id: ip4!("1.1.1.1"),
                area_id: ip4!("0.0.0.1"),
                instance_id: 0,
                auth_seqno: Some(843436052),
            },
            iface_id: 4,
            priority: 1,
            options: Options::R
                | Options::E
                | Options::V6
                | Options::AT
                | Options::L,
            hello_interval: 3,
            dead_interval: 36,
            dr: None,
            bdr: None,
            neighbors: [ip4!("2.2.2.2")].into(),
            lls: Some(holo_ospf::packet::lls::LlsHelloData {
                eof: Some(ExtendedOptionsFlags::LR | ExtendedOptionsFlags::RS),
                ..Default::default()
            }),
        }),
    )
});

static HELLO1_HMAC_SHA512: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x03, 0x01, 0x00, 0x28, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
                0x01, 0x00, 0x04, 0x13, 0x00, 0x03, 0x00, 0x24, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02,
                0x00, 0x01, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x32, 0x45, 0xd0, 0x14, 0xae, 0x30, 0x68, 0x54,
                0xbc, 0xd2, 0x7f, 0x76, 0x66, 0x64, 0x6b, 0x6f, 0xb0, 0x15,
                0xf6, 0x42, 0x8d, 0xbd, 0x4e, 0xd7, 0xae, 0x9b, 0x3d, 0xd1,
                0xbc, 0xa2, 0x7d, 0xb6, 0xf8, 0x14, 0xb5, 0xbe, 0xde, 0xb8,
                0x4b, 0x9d, 0x61, 0x76, 0x33, 0xef, 0x55, 0x63, 0x0b, 0x61,
                0x3a, 0x2f, 0x49, 0x7e, 0xe7, 0x08, 0x70, 0xd0, 0x6e, 0xc6,
                0x2c, 0xab, 0xab, 0x92, 0x99, 0x2d, 0xae, 0xec, 0x0c, 0xf7,
            ],
            Some((
                Key::new(1, CryptoAlgo::HmacSha512, "HOLO".as_bytes().to_vec()),
                843436052,
            )),
            Packet::Hello(Hello {
                hdr: PacketHdr {
                    pkt_type: PacketType::Hello,
                    router_id: ip4!("1.1.1.1"),
                    area_id: ip4!("0.0.0.1"),
                    instance_id: 0,
                    auth_seqno: Some(843436052),
                },
                iface_id: 4,
                priority: 1,
                options: Options::R | Options::E | Options::V6 | Options::AT,
                hello_interval: 3,
                dead_interval: 36,
                dr: None,
                bdr: None,
                neighbors: [ip4!("2.2.2.2")].into(),
                lls: None,
            }),
        )
    });

static HELLO1_HMAC_SHA512_LLS: Lazy<(
    Vec<u8>,
    Option<(Key, u64)>,
    Packet<Ospfv3>,
)> = Lazy::new(|| {
    (
        vec![
            0x03, 0x01, 0x00, 0x28, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00,
            0x06, 0x13, 0x00, 0x03, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00, 0x00, 0x03,
            0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00,
            0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x32, 0x45,
            0xd0, 0x14, 0x43, 0x1e, 0x7b, 0xcd, 0x00, 0x46, 0xe5, 0x6c, 0xb6,
            0x46, 0x63, 0x87, 0x02, 0xeb, 0x5b, 0x10, 0xe0, 0xd0, 0x7e, 0x96,
            0x20, 0xdb, 0x34, 0x7e, 0x12, 0xd8, 0x8c, 0xf0, 0xaa, 0xfd, 0xd9,
            0x32, 0xcc, 0x2f, 0x85, 0xef, 0x5f, 0x63, 0xcd, 0x5f, 0x0b, 0x10,
            0xa8, 0x0a, 0xf7, 0x7a, 0x27, 0x7f, 0x3c, 0xc9, 0x4b, 0xc4, 0xc0,
            0xf8, 0x92, 0xa5, 0x43, 0xf0, 0xac, 0x73, 0xe1, 0xf5, 0xfe, 0x7a,
        ],
        Some((
            Key::new(1, CryptoAlgo::HmacSha512, "HOLO".as_bytes().to_vec()),
            843436052,
        )),
        Packet::Hello(Hello {
            hdr: PacketHdr {
                pkt_type: PacketType::Hello,
                router_id: ip4!("1.1.1.1"),
                area_id: ip4!("0.0.0.1"),
                instance_id: 0,
                auth_seqno: Some(843436052),
            },
            iface_id: 4,
            priority: 1,
            options: Options::R
                | Options::E
                | Options::V6
                | Options::AT
                | Options::L,
            hello_interval: 3,
            dead_interval: 36,
            dr: None,
            bdr: None,
            neighbors: [ip4!("2.2.2.2")].into(),
            lls: Some(holo_ospf::packet::lls::LlsHelloData {
                eof: Some(ExtendedOptionsFlags::LR | ExtendedOptionsFlags::RS),
                ..Default::default()
            }),
        }),
    )
});

static DBDESCR1: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x03, 0x02, 0x00, 0x1c, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13,
                0x05, 0xdc, 0x00, 0x07, 0x00, 0x01, 0x6f, 0x10,
            ],
            None,
            Packet::DbDesc(DbDesc {
                hdr: PacketHdr {
                    pkt_type: PacketType::DbDesc,
                    router_id: ip4!("1.1.1.1"),
                    area_id: ip4!("0.0.0.1"),
                    instance_id: 0,
                    auth_seqno: None,
                },
                options: Options::R | Options::E | Options::V6,
                mtu: 1500,
                dd_flags: DbDescFlags::I | DbDescFlags::M | DbDescFlags::MS,
                dd_seq_no: 93968,
                lsa_hdrs: vec![],
                lls: None,
            }),
        )
    });

static DBDESCR1_LLS: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x03, 0x02, 0x00, 0x1c, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x13,
                0x05, 0xdc, 0x00, 0x07, 0x00, 0x01, 0x6f, 0x10, 0xff, 0xf6,
                0x00, 0x03, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01,
            ],
            None,
            Packet::DbDesc(DbDesc {
                hdr: PacketHdr {
                    pkt_type: PacketType::DbDesc,
                    router_id: ip4!("1.1.1.1"),
                    area_id: ip4!("0.0.0.1"),
                    instance_id: 0,
                    auth_seqno: None,
                },
                options: Options::R | Options::E | Options::V6 | Options::L,
                mtu: 1500,
                dd_flags: DbDescFlags::I | DbDescFlags::M | DbDescFlags::MS,
                dd_seq_no: 93968,
                lsa_hdrs: vec![],
                lls: Some(holo_ospf::packet::lls::LlsDbDescData {
                    eof: Some(ExtendedOptionsFlags::LR),
                    ..Default::default()
                }),
            }),
        )
    });

static DBDESCR2: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x03, 0x02, 0x00, 0x58, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13,
                0x05, 0xdc, 0x00, 0x01, 0x00, 0x01, 0x6f, 0x11, 0x00, 0x04,
                0x00, 0x08, 0x00, 0x00, 0x00, 0x03, 0x02, 0x02, 0x02, 0x02,
                0x80, 0x00, 0x00, 0x01, 0x16, 0x3a, 0x00, 0x2c, 0x00, 0x04,
                0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02,
                0x80, 0x00, 0x00, 0x01, 0xf4, 0x34, 0x00, 0x18, 0x00, 0x04,
                0x20, 0x03, 0x00, 0x00, 0x00, 0x01, 0x02, 0x02, 0x02, 0x02,
                0x80, 0x00, 0x00, 0x01, 0x97, 0x0b, 0x00, 0x2c,
            ],
            None,
            Packet::DbDesc(DbDesc {
                hdr: PacketHdr {
                    pkt_type: PacketType::DbDesc,
                    router_id: ip4!("2.2.2.2"),
                    area_id: ip4!("0.0.0.1"),
                    instance_id: 0,
                    auth_seqno: None,
                },
                options: Options::R | Options::E | Options::V6,
                mtu: 1500,
                dd_flags: DbDescFlags::MS,
                dd_seq_no: 93969,
                lsa_hdrs: vec![
                    LsaHdr {
                        age: 4,
                        lsa_type: LsaType(0x0008),
                        lsa_id: ip4!("0.0.0.3"),
                        adv_rtr: ip4!("2.2.2.2"),
                        seq_no: 0x80000001,
                        cksum: 0x163a,
                        length: 44,
                    },
                    LsaHdr {
                        age: 4,
                        lsa_type: LsaType(0x2001),
                        lsa_id: ip4!("0.0.0.0"),
                        adv_rtr: ip4!("2.2.2.2"),
                        seq_no: 0x80000001,
                        cksum: 0xf434,
                        length: 24,
                    },
                    LsaHdr {
                        age: 4,
                        lsa_type: LsaType(0x2003),
                        lsa_id: ip4!("0.0.0.1"),
                        adv_rtr: ip4!("2.2.2.2"),
                        seq_no: 0x80000001,
                        cksum: 0x970b,
                        length: 44,
                    },
                ],
                lls: None,
            }),
        )
    });

static DBDESCR2_LLS: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x03, 0x02, 0x00, 0x58, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x13,
                0x05, 0xdc, 0x00, 0x01, 0x00, 0x01, 0x6f, 0x11, 0x00, 0x04,
                0x00, 0x08, 0x00, 0x00, 0x00, 0x03, 0x02, 0x02, 0x02, 0x02,
                0x80, 0x00, 0x00, 0x01, 0x16, 0x3a, 0x00, 0x2c, 0x00, 0x04,
                0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02,
                0x80, 0x00, 0x00, 0x01, 0xf4, 0x34, 0x00, 0x18, 0x00, 0x04,
                0x20, 0x03, 0x00, 0x00, 0x00, 0x01, 0x02, 0x02, 0x02, 0x02,
                0x80, 0x00, 0x00, 0x01, 0x97, 0x0b, 0x00, 0x2c, 0xff, 0xf6,
                0x00, 0x03, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01,
            ],
            None,
            Packet::DbDesc(DbDesc {
                hdr: PacketHdr {
                    pkt_type: PacketType::DbDesc,
                    router_id: ip4!("2.2.2.2"),
                    area_id: ip4!("0.0.0.1"),
                    instance_id: 0,
                    auth_seqno: None,
                },
                options: Options::R | Options::E | Options::V6 | Options::L,
                mtu: 1500,
                dd_flags: DbDescFlags::MS,
                dd_seq_no: 93969,
                lsa_hdrs: vec![
                    LsaHdr {
                        age: 4,
                        lsa_type: LsaType(0x0008),
                        lsa_id: ip4!("0.0.0.3"),
                        adv_rtr: ip4!("2.2.2.2"),
                        seq_no: 0x80000001,
                        cksum: 0x163a,
                        length: 44,
                    },
                    LsaHdr {
                        age: 4,
                        lsa_type: LsaType(0x2001),
                        lsa_id: ip4!("0.0.0.0"),
                        adv_rtr: ip4!("2.2.2.2"),
                        seq_no: 0x80000001,
                        cksum: 0xf434,
                        length: 24,
                    },
                    LsaHdr {
                        age: 4,
                        lsa_type: LsaType(0x2003),
                        lsa_id: ip4!("0.0.0.1"),
                        adv_rtr: ip4!("2.2.2.2"),
                        seq_no: 0x80000001,
                        cksum: 0x970b,
                        length: 44,
                    },
                ],
                lls: Some(holo_ospf::packet::lls::LlsDbDescData {
                    eof: Some(ExtendedOptionsFlags::LR),
                    ..Default::default()
                }),
            }),
        )
    });

static LSREQUEST1: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x03, 0x03, 0x00, 0x40, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
                0x00, 0x00, 0x00, 0x04, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01,
                0x00, 0x00, 0x20, 0x09, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
                0x01, 0x01, 0x00, 0x00, 0x40, 0x05, 0x00, 0x00, 0x00, 0x01,
                0x01, 0x01, 0x01, 0x01,
            ],
            None,
            Packet::LsRequest(LsRequest {
                hdr: PacketHdr {
                    pkt_type: PacketType::LsRequest,
                    router_id: ip4!("2.2.2.2"),
                    area_id: ip4!("0.0.0.1"),
                    instance_id: 0,
                    auth_seqno: None,
                },
                entries: vec![
                    LsaKey {
                        lsa_type: LsaType(0x0008),
                        adv_rtr: ip4!("1.1.1.1"),
                        lsa_id: ip4!("0.0.0.4"),
                    },
                    LsaKey {
                        lsa_type: LsaType(0x2001),
                        adv_rtr: ip4!("1.1.1.1"),
                        lsa_id: ip4!("0.0.0.0"),
                    },
                    LsaKey {
                        lsa_type: LsaType(0x2009),
                        adv_rtr: ip4!("1.1.1.1"),
                        lsa_id: ip4!("0.0.0.0"),
                    },
                    LsaKey {
                        lsa_type: LsaType(0x4005),
                        adv_rtr: ip4!("1.1.1.1"),
                        lsa_id: ip4!("0.0.0.1"),
                    },
                ],
            }),
        )
    });

static LSUPDATE1: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x03, 0x04, 0x00, 0x84, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
                0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 0x03, 0x02, 0x02,
                0x02, 0x02, 0x80, 0x00, 0x00, 0x01, 0x16, 0x3a, 0x00, 0x2c,
                0x01, 0x00, 0x00, 0x13, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0xcc, 0x81, 0x6e, 0xff, 0xfe, 0xa8, 0x26, 0xd0,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x20, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x02, 0x02, 0x02, 0x02, 0x80, 0x00, 0x00, 0x01,
                0xf4, 0x34, 0x00, 0x18, 0x01, 0x00, 0x00, 0x13, 0x00, 0x04,
                0x20, 0x03, 0x00, 0x00, 0x00, 0x01, 0x02, 0x02, 0x02, 0x02,
                0x80, 0x00, 0x00, 0x01, 0x97, 0x0b, 0x00, 0x2c, 0x00, 0x00,
                0x00, 0x0a, 0x80, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8,
                0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x02,
            ],
            None,
            Packet::LsUpdate(LsUpdate {
                hdr: PacketHdr {
                    pkt_type: PacketType::LsUpdate,
                    router_id: ip4!("2.2.2.2"),
                    area_id: ip4!("0.0.0.1"),
                    instance_id: 0,
                    auth_seqno: None,
                },
                lsas: vec![
                    Lsa::new(
                        4,
                        None,
                        ip4!("0.0.0.3"),
                        ip4!("2.2.2.2"),
                        0x80000001,
                        LsaBody::Link(LsaLink {
                            extended: false,
                            priority: 1,
                            options: Options::R | Options::E | Options::V6,
                            linklocal: ip!("fe80::cc81:6eff:fea8:26d0"),
                            prefixes: vec![],
                            unknown_tlvs: vec![],
                        }),
                    ),
                    Lsa::new(
                        4,
                        None,
                        ip4!("0.0.0.0"),
                        ip4!("2.2.2.2"),
                        0x80000001,
                        LsaBody::Router(LsaRouter {
                            extended: false,
                            flags: LsaRouterFlags::B,
                            options: Options::R | Options::E | Options::V6,
                            links: vec![],
                            unknown_tlvs: vec![],
                        }),
                    ),
                    Lsa::new(
                        4,
                        None,
                        ip4!("0.0.0.1"),
                        ip4!("2.2.2.2"),
                        0x80000001,
                        LsaBody::InterAreaPrefix(LsaInterAreaPrefix {
                            extended: false,
                            metric: 10,
                            prefix_options: PrefixOptions::empty(),
                            prefix: net!("2001:db8:1000::2/128"),
                            prefix_sids: Default::default(),
                            unknown_tlvs: vec![],
                            unknown_stlvs: vec![],
                        }),
                    ),
                ],
            }),
        )
    });

static LSACK1: Lazy<(Vec<u8>, Option<(Key, u64)>, Packet<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x03, 0x05, 0x00, 0x60, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x08,
                0x00, 0x00, 0x00, 0x04, 0x01, 0x01, 0x01, 0x01, 0x80, 0x00,
                0x00, 0x01, 0x77, 0x58, 0x00, 0x2c, 0x00, 0x08, 0x20, 0x01,
                0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x80, 0x00,
                0x00, 0x01, 0x16, 0x16, 0x00, 0x18, 0x00, 0x08, 0x20, 0x09,
                0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x80, 0x00,
                0x00, 0x01, 0x7a, 0xf9, 0x00, 0x34, 0x00, 0x08, 0x40, 0x05,
                0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x80, 0x00,
                0x00, 0x01, 0xe5, 0x91, 0x00, 0x2c,
            ],
            None,
            Packet::LsAck(LsAck {
                hdr: PacketHdr {
                    pkt_type: PacketType::LsAck,
                    router_id: ip4!("2.2.2.2"),
                    area_id: ip4!("0.0.0.1"),
                    instance_id: 0,
                    auth_seqno: None,
                },
                lsa_hdrs: vec![
                    LsaHdr {
                        age: 7,
                        lsa_type: LsaType(0x0008),
                        lsa_id: ip4!("0.0.0.4"),
                        adv_rtr: ip4!("1.1.1.1"),
                        seq_no: 0x80000001,
                        cksum: 0x7758,
                        length: 44,
                    },
                    LsaHdr {
                        age: 8,
                        lsa_type: LsaType(0x2001),
                        lsa_id: ip4!("0.0.0.0"),
                        adv_rtr: ip4!("1.1.1.1"),
                        seq_no: 0x80000001,
                        cksum: 0x1616,
                        length: 24,
                    },
                    LsaHdr {
                        age: 8,
                        lsa_type: LsaType(0x2009),
                        lsa_id: ip4!("0.0.0.0"),
                        adv_rtr: ip4!("1.1.1.1"),
                        seq_no: 0x80000001,
                        cksum: 0x7af9,
                        length: 52,
                    },
                    LsaHdr {
                        age: 8,
                        lsa_type: LsaType(0x4005),
                        lsa_id: ip4!("0.0.0.1"),
                        adv_rtr: ip4!("1.1.1.1"),
                        seq_no: 0x80000001,
                        cksum: 0xe591,
                        length: 44,
                    },
                ],
            }),
        )
    });

//
// Test LSAs.
//

static LSA1: Lazy<(Vec<u8>, Lsa<Ospfv3>)> = Lazy::new(|| {
    (
        vec![
            0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 0x03, 0x02, 0x02, 0x02,
            0x02, 0x80, 0x00, 0x00, 0x01, 0x16, 0x3a, 0x00, 0x2c, 0x01, 0x00,
            0x00, 0x13, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xcc,
            0x81, 0x6e, 0xff, 0xfe, 0xa8, 0x26, 0xd0, 0x00, 0x00, 0x00, 0x00,
        ],
        Lsa::new(
            4,
            None,
            ip4!("0.0.0.3"),
            ip4!("2.2.2.2"),
            0x80000001,
            LsaBody::Link(LsaLink {
                extended: false,
                priority: 1,
                options: Options::R | Options::E | Options::V6,
                linklocal: ip!("fe80::cc81:6eff:fea8:26d0"),
                prefixes: vec![],
                unknown_tlvs: vec![],
            }),
        ),
    )
});

static LSA2: Lazy<(Vec<u8>, Lsa<Ospfv3>)> = Lazy::new(|| {
    (
        vec![
            0x00, 0x0a, 0x20, 0x09, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02,
            0x02, 0x80, 0x00, 0x00, 0x03, 0xe0, 0xed, 0x00, 0x28, 0x00, 0x01,
            0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02, 0x20,
            0x02, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02,
        ],
        Lsa::new(
            10,
            None,
            ip4!("0.0.0.0"),
            ip4!("2.2.2.2"),
            0x80000003,
            LsaBody::IntraAreaPrefix(LsaIntraAreaPrefix {
                extended: false,
                ref_lsa_type: LsaType(8193),
                ref_lsa_id: ip4!("0.0.0.0"),
                ref_adv_rtr: ip4!("2.2.2.2"),
                prefixes: vec![LsaIntraAreaPrefixEntry {
                    options: PrefixOptions::LA,
                    value: net!("2.2.2.2/32"),
                    metric: 0,
                    prefix_sids: Default::default(),
                    bier: vec![],
                    unknown_stlvs: vec![],
                }],
                unknown_tlvs: vec![],
            }),
        ),
    )
});

static LSA3: Lazy<(Vec<u8>, Lsa<Ospfv3>)> = Lazy::new(|| {
    (
        vec![
            0x00, 0x01, 0xa0, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01,
            0x01, 0x80, 0x00, 0x00, 0x01, 0xab, 0xc4, 0x00, 0x6c, 0x00, 0x01,
            0x00, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x04, 0x68,
            0x6f, 0x6c, 0x6f, 0x00, 0x0a, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x0a, 0x00,
            0x0c, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00,
            0x00, 0x06, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x09, 0x00, 0x0b, 0x00, 0x1f, 0x40, 0x00, 0x00, 0x01, 0x00, 0x03,
            0x00, 0x3e, 0x80, 0x00, 0x00, 0x0e, 0x00, 0x0b, 0x00, 0x03, 0xe8,
            0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x3a, 0x98, 0x00,
        ],
        Lsa::new(
            1,
            None,
            ip4!("0.0.0.0"),
            ip4!("1.1.1.1"),
            0x80000001,
            LsaBody::RouterInfo(LsaRouterInfo {
                scope: LsaScopeCode::Area,
                info_caps: Some(
                    (RouterInfoCaps::GR
                        | RouterInfoCaps::GR_HELPER
                        | RouterInfoCaps::TE)
                        .into(),
                ),
                func_caps: None,
                sr_algo: Some(SrAlgoTlv::new(btreeset!(IgpAlgoType::Spf))),
                srgb: vec![SidLabelRangeTlv::new(
                    Sid::Label(Label::new(16000)),
                    8000,
                )],
                srlb: vec![SrLocalBlockTlv::new(
                    Sid::Label(Label::new(15000)),
                    1000,
                )],
                msds: Default::default(),
                srms_pref: None,
                info_hostname: Some(DynamicHostnameTlv::new("holo".to_owned())),
                node_tags: vec![
                    NodeAdminTagTlv::new([1, 2, 3].into()),
                    NodeAdminTagTlv::new([4, 5, 6].into()),
                ],
                unknown_tlvs: vec![],
            }),
        ),
    )
});

static EXT_ROUTER_LSA1: Lazy<(Vec<u8>, Lsa<Ospfv3>)> = Lazy::new(|| {
    (
        vec![
            0x00, 0x06, 0xa0, 0x21, 0x00, 0x00, 0x00, 0x00, 0x06, 0x06, 0x06,
            0x06, 0x80, 0x00, 0x00, 0x02, 0x95, 0x65, 0x00, 0x38, 0x01, 0x00,
            0x01, 0x13, 0x00, 0x01, 0x00, 0x1c, 0x01, 0x00, 0x00, 0x0a, 0x00,
            0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x06, 0x03, 0x03, 0x03, 0x03,
            0x00, 0x05, 0x00, 0x07, 0x60, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xa0,
            0x00,
        ],
        Lsa::new(
            6,
            None,
            ip4!("0.0.0.0"),
            ip4!("6.6.6.6"),
            2147483650,
            LsaBody::Router(LsaRouter {
                extended: true,
                flags: LsaRouterFlags::B,
                options: Options::R | Options::E | Options::V6 | Options::AF,
                links: vec![LsaRouterLink {
                    link_type: LsaRouterLinkType::PointToPoint,
                    metric: 10,
                    iface_id: 5,
                    nbr_iface_id: 6,
                    nbr_router_id: ip4!("3.3.3.3"),
                    adj_sids: vec![AdjSid {
                        flags: AdjSidFlags::V | AdjSidFlags::L,
                        weight: 0,
                        nbr_router_id: None,
                        sid: Sid::Label(Label::new(4000)),
                    }],

                    unknown_stlvs: vec![],
                }],
                unknown_tlvs: vec![],
            }),
        ),
    )
});

static EXT_NETWORK_LSA1: Lazy<(Vec<u8>, Lsa<Ospfv3>)> = Lazy::new(|| {
    (
        vec![
            0x00, 0x00, 0xa0, 0x22, 0x00, 0x00, 0x00, 0x03, 0x03, 0x03, 0x03,
            0x03, 0x80, 0x00, 0x00, 0x01, 0x07, 0x4f, 0x00, 0x24, 0x00, 0x00,
            0x01, 0x13, 0x00, 0x02, 0x00, 0x08, 0x02, 0x02, 0x02, 0x02, 0x03,
            0x03, 0x03, 0x03,
        ],
        Lsa::new(
            0,
            None,
            ip4!("0.0.0.3"),
            ip4!("3.3.3.3"),
            2147483649,
            LsaBody::Network(LsaNetwork {
                extended: true,
                options: Options::R | Options::E | Options::V6 | Options::AF,
                attached_rtrs: btreeset![ip4!("2.2.2.2"), ip4!("3.3.3.3"),],
                unknown_tlvs: vec![],
            }),
        ),
    )
});

static EXT_INTER_AREA_PREFIX_LSA1: Lazy<(Vec<u8>, Lsa<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x00, 0x01, 0xa0, 0x23, 0x00, 0x00, 0x00, 0x02, 0x06, 0x06,
                0x06, 0x06, 0x80, 0x00, 0x00, 0x01, 0x2d, 0x9d, 0x00, 0x30,
                0x00, 0x03, 0x00, 0x18, 0x00, 0x00, 0x00, 0x0a, 0x80, 0x02,
                0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x10, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
            ],
            Lsa::new(
                1,
                None,
                ip4!("0.0.0.2"),
                ip4!("6.6.6.6"),
                2147483649,
                LsaBody::InterAreaPrefix(LsaInterAreaPrefix {
                    extended: true,
                    metric: 10,
                    prefix_options: PrefixOptions::LA,
                    prefix: net!("2001:db8:1000::7/128"),
                    prefix_sids: Default::default(),
                    unknown_tlvs: vec![],
                    unknown_stlvs: vec![],
                }),
            ),
        )
    });

static EXT_INTER_AREA_ROUTER_LSA1: Lazy<(Vec<u8>, Lsa<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x00, 0x0d, 0xa0, 0x24, 0x00, 0x00, 0x00, 0x01, 0x06, 0x06,
                0x06, 0x06, 0x80, 0x00, 0x00, 0x02, 0x5e, 0xce, 0x00, 0x24,
                0x00, 0x04, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x13, 0x00, 0x00,
                0x00, 0x0a, 0x08, 0x08, 0x08, 0x08,
            ],
            Lsa::new(
                13,
                None,
                ip4!("0.0.0.1"),
                ip4!("6.6.6.6"),
                2147483650,
                LsaBody::InterAreaRouter(LsaInterAreaRouter {
                    extended: true,
                    options: Options::R
                        | Options::E
                        | Options::V6
                        | Options::AF,
                    metric: 10,
                    router_id: ip4!("8.8.8.8"),
                    unknown_tlvs: vec![],
                    unknown_stlvs: vec![],
                }),
            ),
        )
    });

static EXT_AS_EXTERNAL_LSA1: Lazy<(Vec<u8>, Lsa<Ospfv3>)> = Lazy::new(|| {
    (
        vec![
            0x00, 0x01, 0xc0, 0x25, 0x00, 0x00, 0x00, 0x02, 0x06, 0x06, 0x06,
            0x06, 0x80, 0x00, 0x00, 0x01, 0x4e, 0x6b, 0x00, 0x4c, 0x00, 0x05,
            0x00, 0x34, 0x00, 0x00, 0x00, 0x0a, 0x80, 0x00, 0x00, 0x00, 0x20,
            0x01, 0x0d, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x10, 0x30, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x64,
        ],
        Lsa::new(
            1,
            None,
            ip4!("0.0.0.2"),
            ip4!("6.6.6.6"),
            2147483649,
            LsaBody::AsExternal(LsaAsExternal {
                extended: true,
                flags: LsaAsExternalFlags::empty(),
                metric: 10,
                prefix_options: PrefixOptions::empty(),
                prefix: net!("2001:db8:1000::10/128"),
                fwd_addr: Some(ip!("3000::1")),
                tag: Some(100),
                ref_lsa_type: None,
                ref_lsa_id: None,
                prefix_sids: Default::default(),
                unknown_tlvs: vec![],
                unknown_stlvs: vec![],
            }),
        ),
    )
});

static EXT_LINK_LSA1: Lazy<(Vec<u8>, Lsa<Ospfv3>)> = Lazy::new(|| {
    (
        vec![
            0x00, 0x0a, 0x80, 0x28, 0x00, 0x00, 0x00, 0x03, 0x01, 0x01, 0x01,
            0x01, 0x80, 0x00, 0x00, 0x03, 0x45, 0x03, 0x00, 0x40, 0x01, 0x00,
            0x00, 0x13, 0x00, 0x07, 0x00, 0x10, 0xfe, 0x80, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0xcc, 0x81, 0x6e, 0xff, 0xfe, 0xa8, 0x26, 0xd0,
            0x00, 0x06, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00,
            0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00,
        ],
        Lsa::new(
            10,
            None,
            ip4!("0.0.0.3"),
            ip4!("1.1.1.1"),
            0x80000003,
            LsaBody::Link(LsaLink {
                extended: true,
                priority: 1,
                options: Options::R | Options::E | Options::V6,
                linklocal: ip!("fe80::cc81:6eff:fea8:26d0"),
                prefixes: vec![LsaLinkPrefix {
                    options: PrefixOptions::empty(),
                    value: net!("2001:db8:1::/64"),
                    unknown_stlvs: vec![],
                }],
                unknown_tlvs: vec![],
            }),
        ),
    )
});

static EXT_INTRA_AREA_PREFIX_LSA1: Lazy<(Vec<u8>, Lsa<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x00, 0x0a, 0xa0, 0x29, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02,
                0x02, 0x02, 0x80, 0x00, 0x00, 0x03, 0xfb, 0xe0, 0x00, 0x3c,
                0x00, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02,
                0x02, 0x02, 0x00, 0x06, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00,
                0x20, 0x02, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02, 0x00, 0x04,
                0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14,
            ],
            Lsa::new(
                10,
                None,
                ip4!("0.0.0.0"),
                ip4!("2.2.2.2"),
                0x80000003,
                LsaBody::IntraAreaPrefix(LsaIntraAreaPrefix {
                    extended: true,
                    ref_lsa_type: LsaType(8193),
                    ref_lsa_id: ip4!("0.0.0.0"),
                    ref_adv_rtr: ip4!("2.2.2.2"),
                    prefixes: vec![LsaIntraAreaPrefixEntry {
                        options: PrefixOptions::LA,
                        value: net!("2.2.2.2/32"),
                        metric: 0,
                        prefix_sids: btreemap! {
                            IgpAlgoType::Spf => {
                                PrefixSid {
                                    flags: PrefixSidFlags::empty(),
                                    algo: IgpAlgoType::Spf,
                                    sid: Sid::Index(20),
                                }
                            }
                        },
                        bier: vec![],
                        unknown_stlvs: vec![],
                    }],
                    unknown_tlvs: vec![],
                }),
            ),
        )
    });

static EXT_INTRA_AREA_PREFIX_LSA_BIER_TLV: Lazy<(Vec<u8>, Lsa<Ospfv3>)> =
    Lazy::new(|| {
        (
            vec![
                0x00, 0x01, 0xa0, 0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x02, 0x80, 0x00, 0x00, 0x01, 0x93, 0x0d, 0x00, 0x54,
                0x00, 0x00, 0xa0, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x02, 0x00, 0x06, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00,
                0x80, 0x22, 0x00, 0x00, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                0x00, 0x2a, 0x00, 0x14, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x2a, 0x00, 0x08, 0x80, 0x00, 0x00, 0x00,
                0x30, 0x00, 0x00, 0x00,
            ],
            Lsa::new(
                1,
                None,
                ip4!("0.0.0.0"),
                ip4!("0.0.0.2"),
                0x80000001,
                LsaBody::IntraAreaPrefix(LsaIntraAreaPrefix {
                    extended: true,
                    ref_lsa_type: LsaType(40993),
                    ref_lsa_id: ip4!("0.0.0.0"),
                    ref_adv_rtr: ip4!("0.0.0.2"),
                    prefixes: vec![LsaIntraAreaPrefixEntry {
                        options: PrefixOptions::LA | PrefixOptions::N,
                        value: net!("fc00::1/128"),
                        metric: 0,
                        prefix_sids: btreemap![],
                        bier: vec![BierStlv {
                            sub_domain_id: 0,
                            mt_id: 0,
                            bfr_id: 2,
                            bar: 0,
                            ipa: 0,
                            encaps: vec![BierEncapSubStlv {
                                max_si: 128,
                                id: BierEncapId::NonMpls(BiftId::new(0)),
                                bs_len: Bsl::_256,
                            }],
                            unknown_sstlvs: vec![],
                        }],
                        unknown_stlvs: vec![],
                    }],
                    unknown_tlvs: vec![],
                }),
            ),
        )
    });

static GRACE_LSA1: Lazy<(Vec<u8>, Lsa<Ospfv3>)> = Lazy::new(|| {
    (
        vec![
            0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x05, 0x06, 0x06, 0x06,
            0x06, 0x80, 0x00, 0x00, 0x01, 0x39, 0x78, 0x00, 0x24, 0x00, 0x01,
            0x00, 0x04, 0x00, 0x00, 0x00, 0x78, 0x00, 0x02, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x00,
        ],
        Lsa::new(
            0,
            None,
            ip4!("0.0.0.5"),
            ip4!("6.6.6.6"),
            0x80000001,
            LsaBody::Grace(LsaGrace {
                grace_period: Some(GracePeriodTlv::new(120)),
                gr_reason: Some(GrReasonTlv::new(0)),
                unknown_tlvs: vec![],
            }),
        ),
    )
});

//
// Tests.
//

#[test]
fn test_encode_hello1() {
    let (ref bytes, ref auth, ref hello) = *HELLO1;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello1() {
    let (ref bytes, ref auth, ref hello) = *HELLO1;
    test_decode_packet(bytes, auth, hello, AddressFamily::Ipv6);
}

#[test]
fn test_encode_hello1_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_LLS;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello1_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_LLS;
    test_decode_packet(bytes, auth, hello, AddressFamily::Ipv6);
}

#[test]
fn test_encode_hello_hmac_sha1() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA1;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello_hmac_sha1() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA1;
    test_decode_packet(bytes, auth, hello, AddressFamily::Ipv6);
}

#[test]
fn test_encode_hello_hmac_sha1_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA1_LLS;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello_hmac_sha1_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA1_LLS;
    test_decode_packet(bytes, auth, hello, AddressFamily::Ipv6);
}

#[test]
fn test_encode_hello_hmac_sha256() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA256;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello_hmac_sha256() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA256;
    test_decode_packet(bytes, auth, hello, AddressFamily::Ipv6);
}

#[test]
fn test_encode_hello_hmac_sha256_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA256_LLS;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello_hmac_sha256_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA256_LLS;
    test_decode_packet(bytes, auth, hello, AddressFamily::Ipv6);
}

#[test]
fn test_encode_hello_hmac_sha384() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA384;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello_hmac_sha384() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA384;
    test_decode_packet(bytes, auth, hello, AddressFamily::Ipv6);
}

#[test]
fn test_encode_hello_hmac_sha384_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA384_LLS;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello_hmac_sha384_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA384_LLS;
    test_decode_packet(bytes, auth, hello, AddressFamily::Ipv6);
}

#[test]
fn test_encode_hello_hmac_sha512() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA512;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello_hmac_sha512() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA512;
    test_decode_packet(bytes, auth, hello, AddressFamily::Ipv6);
}

#[test]
fn test_encode_hello_hmac_sha512_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA512_LLS;
    test_encode_packet(bytes, auth, hello);
}

#[test]
fn test_decode_hello_hmac_sha512_lls() {
    let (ref bytes, ref auth, ref hello) = *HELLO1_HMAC_SHA512_LLS;
    test_decode_packet(bytes, auth, hello, AddressFamily::Ipv6);
}

#[test]
fn test_encode_dbdescr1() {
    let (ref bytes, ref auth, ref dbdescr) = *DBDESCR1;
    test_encode_packet(bytes, auth, dbdescr);
}

#[test]
fn test_decode_dbdescr1() {
    let (ref bytes, ref auth, ref dbdescr) = *DBDESCR1;
    test_decode_packet(bytes, auth, dbdescr, AddressFamily::Ipv6);
}

#[test]
fn test_encode_dbdescr1_lls() {
    let (ref bytes, ref auth, ref dbdescr) = *DBDESCR1_LLS;
    test_encode_packet(bytes, auth, dbdescr);
}

#[test]
fn test_decode_dbdescr1_lls() {
    let (ref bytes, ref auth, ref dbdescr) = *DBDESCR1_LLS;
    test_decode_packet(bytes, auth, dbdescr, AddressFamily::Ipv6);
}

#[test]
fn test_encode_dbdescr2() {
    let (ref bytes, ref auth, ref dbdescr) = *DBDESCR2;
    test_encode_packet(bytes, auth, dbdescr);
}

#[test]
fn test_decode_dbdescr2() {
    let (ref bytes, ref auth, ref dbdescr) = *DBDESCR2;
    test_decode_packet(bytes, auth, dbdescr, AddressFamily::Ipv6);
}

#[test]
fn test_encode_dbdescr2_lls() {
    let (ref bytes, ref auth, ref dbdescr) = *DBDESCR2_LLS;
    test_encode_packet(bytes, auth, dbdescr);
}

#[test]
fn test_decode_dbdescr2_lls() {
    let (ref bytes, ref auth, ref dbdescr) = *DBDESCR2_LLS;
    test_decode_packet(bytes, auth, dbdescr, AddressFamily::Ipv6);
}

/// Validates RFC 5613 §2.2/§2.3 and RFC 5614 Appendix A.2.3-A.2.5.
///
/// Holo decodes the Rust oracle's committed MDR packet bytes, asserts the
/// field-level packet and MDR TLV values from the JSON sidecars, and re-encodes
/// byte-identically for every well-formed fixture.
///
/// RFC chunks: rfcs/parsed/chunks/5613/{2.2,2.3}.json,
/// rfcs/parsed/chunks/5614/{a.2.3,a.2.4,a.2.5}.json
#[test]
fn test_mdr_rust_oracle_goldens_decode_and_reencode() {
    for case in MDR_WELL_FORMED_GOLDENS {
        let expected = parse_expected(case.expected_json);
        assert_eq!(expected.id, case.id);

        let packet = decode_ospfv3_packet(case.bytes).unwrap_or_else(|err| {
            panic!("{} failed to decode: {err:?}", case.id)
        });

        assert_expected_packet(case.bytes, &packet, &expected);
        let encoded = packet.encode(None);
        assert_eq_hex!(case.bytes, encoded);
        maybe_export_holo_emitted(case, &encoded);
    }
}

/// Validates RFC 5613 §2.2/§2.3 — malformed LLS handling.
///
/// A bad LLS checksum discards only the LLS block, a recognized MDR TLV with
/// invalid typed length is rejected, and the OSPFv3 L-bit cannot advertise
/// absent LLS data.
///
/// RFC chunks: rfcs/parsed/chunks/5613/{2.2,2.3}.json,
/// rfcs/parsed/chunks/5614/a.2.3.json
#[test]
fn test_mdr_rust_oracle_malformed_goldens() {
    let bad_checksum =
        include_bytes!("fixtures/mdr/packets/malformed_bad_lls_checksum.bin");
    let expected = parse_expected(include_str!(
        "fixtures/mdr/packets/malformed_bad_lls_checksum.json"
    ));
    assert_eq!(expected.id, "malformed_bad_lls_checksum");
    assert_eq!(expected.expected_outcome, "rejected_invalid_lls_checksum");
    assert!(expected.malformed);
    assert_wire_header(bad_checksum, &expected.ospfv3_header);
    match decode_ospfv3_packet(bad_checksum).unwrap() {
        Packet::Hello(hello) => assert!(hello.lls.is_none()),
        packet => panic!("unexpected packet: {packet:?}"),
    }

    let bad_tlv_len =
        include_bytes!("fixtures/mdr/packets/malformed_bad_tlv_length.bin");
    let expected = parse_expected(include_str!(
        "fixtures/mdr/packets/malformed_bad_tlv_length.json"
    ));
    assert_eq!(expected.id, "malformed_bad_tlv_length");
    assert_eq!(expected.expected_outcome, "rejected_malformed_lls_tlv");
    assert!(expected.malformed);
    assert_wire_header(bad_tlv_len, &expected.ospfv3_header);
    assert_eq!(
        decode_ospfv3_packet(bad_tlv_len).unwrap_err(),
        DecodeError::InvalidTlvLength(7)
    );

    let missing_lls =
        include_bytes!("fixtures/mdr/packets/malformed_l_bit_without_lls.bin");
    let expected = parse_expected(include_str!(
        "fixtures/mdr/packets/malformed_l_bit_without_lls.json"
    ));
    assert_eq!(expected.id, "malformed_l_bit_without_lls");
    assert_eq!(expected.expected_outcome, "rejected_missing_lls_data");
    assert!(expected.malformed);
    assert_wire_header(missing_lls, &expected.ospfv3_header);
    assert_eq!(
        decode_ospfv3_packet(missing_lls).unwrap_err(),
        DecodeError::InvalidLength(0)
    );
}

/// Validates RFC 7166 §2/§4.2 with RFC 5613 §2.2 — authenticated MDR Hello LLS.
///
/// The MDR-Hello LLS block is placed before the RFC 7166 auth trailer, its LLS
/// checksum is zero while authenticated, and authenticated decode validates the
/// digest over the packet plus LLS bytes.
///
/// RFC chunks: rfcs/parsed/chunks/5613/2.2.json,
/// rfcs/parsed/chunks/5614/a.2.3.json
#[test]
fn test_mdr_authenticated_hello_lls_round_trip() {
    let key = Key::new(7, CryptoAlgo::HmacSha256, b"HOLO-MDR".to_vec());
    let seqno = 0x0102_0304_0506_0708;
    let mut packet = mdr_hello_packet(LlsHelloData {
        mdr_hello: Some(MdrHelloTlv {
            hello_sequence_number: 77,
            adjacency_reduction_disabled: false,
            differential: true,
            n1: 1,
            n2: 0,
            n3: 0,
            n4: 1,
        }),
        ..Default::default()
    });
    let Packet::Hello(hello) = &mut packet else {
        unreachable!();
    };
    hello.options |= Options::AT;
    hello.hdr.auth_seqno = Some(seqno);

    let auth_seqno = Arc::new(AtomicU64::new(seqno));
    let bytes = packet.encode(Some(AuthEncodeCtx::new(
        &key,
        &auth_seqno,
        SRC_ADDR.into(),
    )));

    assert_auth_lls_layout(&bytes, CryptoAlgo::HmacSha256);
    test_decode_packet(
        &bytes,
        &Some((key, seqno)),
        &packet,
        AddressFamily::Ipv6,
    );
}

/// Validates RFC 7166 §2/§4.2 with RFC 5613 §2.2 — authenticated MDR-DD LLS.
///
/// The MDR-DD LLS block is skipped correctly while validating the auth trailer
/// and remains packet-visible after authenticated decode.
///
/// RFC chunks: rfcs/parsed/chunks/5613/2.2.json,
/// rfcs/parsed/chunks/5614/a.2.4.json
#[test]
fn test_mdr_authenticated_dbdesc_lls_round_trip() {
    let key = Key::new(8, CryptoAlgo::HmacSha256, b"HOLO-MDR".to_vec());
    let seqno = 0x1112_1314_1516_1718;
    let mut packet = mdr_dbdesc_packet(LlsDbDescData {
        mdr_dd: Some(MdrDdTlv {
            designated_router: ip4!("10.0.0.1"),
            backup_designated_router: ip4!("10.0.0.2"),
        }),
        ..Default::default()
    });
    let Packet::DbDesc(dbdesc) = &mut packet else {
        unreachable!();
    };
    dbdesc.options |= Options::AT;
    dbdesc.hdr.auth_seqno = Some(seqno);

    let auth_seqno = Arc::new(AtomicU64::new(seqno));
    let bytes = packet.encode(Some(AuthEncodeCtx::new(
        &key,
        &auth_seqno,
        SRC_ADDR.into(),
    )));

    assert_auth_lls_layout(&bytes, CryptoAlgo::HmacSha256);
    test_decode_packet(
        &bytes,
        &Some((key, seqno)),
        &packet,
        AddressFamily::Ipv6,
    );
}

/// Validates RFC 5614 Appendix A.2.3 — MDR-Hello TLV.
///
/// A Hello LLS block can carry the fixed-length type-14 MDR-Hello TLV,
/// preserving HSN, A-bit, D-bit, and neighbor-list counters.
///
/// RFC chunk: rfcs/parsed/chunks/5614/a.2.3.json
#[test]
fn test_mdr_hello_tlv_round_trip() {
    let packet = mdr_hello_packet(LlsHelloData {
        mdr_hello: Some(MdrHelloTlv {
            hello_sequence_number: 42,
            adjacency_reduction_disabled: true,
            differential: false,
            n1: 1,
            n2: 2,
            n3: 3,
            n4: 4,
        }),
        ..Default::default()
    });

    let bytes = packet.encode(None);
    let decoded = decode_ospfv3_packet(&bytes).unwrap();

    assert_eq!(decoded, packet);
}

/// Validates RFC 5614 Appendix A.2.4 — MDR-DD TLV.
///
/// A Database Description LLS block can carry the fixed-length type-15 MDR-DD
/// TLV with exactly the DR and Backup DR Router IDs.
///
/// RFC chunk: rfcs/parsed/chunks/5614/a.2.4.json
#[test]
fn test_mdr_dd_tlv_round_trip() {
    let packet = mdr_dbdesc_packet(LlsDbDescData {
        mdr_dd: Some(MdrDdTlv {
            designated_router: ip4!("1.1.1.1"),
            backup_designated_router: ip4!("1.1.1.2"),
        }),
        ..Default::default()
    });

    let bytes = packet.encode(None);
    let decoded = decode_ospfv3_packet(&bytes).unwrap();

    assert_eq!(decoded, packet);
}

/// Validates RFC 5614 Appendix A.2.5 — MDR-Metric TLV.
///
/// A Hello LLS block can carry the variable-length type-16 MDR-Metric TLV with
/// Router IDs included and TLV padding excluded from the decoded value.
///
/// RFC chunk: rfcs/parsed/chunks/5614/a.2.5.json
#[test]
fn test_mdr_metric_tlv_with_ids_round_trip() {
    let packet = mdr_hello_packet(LlsHelloData {
        mdr_metric: Some(MdrMetricTlv {
            default_metric: 7,
            include_ids: true,
            metrics: vec![MdrMetricEntry {
                neighbor_id: Some(ip4!("2.2.2.2")),
                metric: 42,
            }],
        }),
        ..Default::default()
    });

    let bytes = packet.encode(None);
    let decoded = decode_ospfv3_packet(&bytes).unwrap();

    assert_eq!(decoded, packet);
}

/// Validates RFC 5614 Appendix A.2.3 and A.2.5 — MDR Hello LLS TLVs.
///
/// A single Hello LLS block can combine EOF, MDR-Hello, and MDR-Metric TLVs
/// without losing any packet-visible typed data.
///
/// RFC chunks: rfcs/parsed/chunks/5614/a.2.3.json,
/// rfcs/parsed/chunks/5614/a.2.5.json
#[test]
fn test_mdr_hello_combined_lls_block_round_trip() {
    let packet = mdr_hello_packet(LlsHelloData {
        eof: Some(ExtendedOptionsFlags::LR),
        mdr_hello: Some(MdrHelloTlv {
            hello_sequence_number: 65535,
            adjacency_reduction_disabled: false,
            differential: true,
            n1: 0,
            n2: 1,
            n3: 1,
            n4: 2,
        }),
        mdr_metric: Some(MdrMetricTlv {
            default_metric: 1,
            include_ids: false,
            metrics: vec![
                MdrMetricEntry {
                    neighbor_id: None,
                    metric: 1,
                },
                MdrMetricEntry {
                    neighbor_id: None,
                    metric: 9,
                },
            ],
        }),
        ..Default::default()
    });

    let bytes = packet.encode(None);
    let decoded = decode_ospfv3_packet(&bytes).unwrap();

    assert_eq!(decoded, packet);
}

/// Validates RFC 5614 Appendix A.2.2 — Unknown MDR LLS TLVs.
///
/// Unknown TLVs remain retained alongside typed MDR TLVs at the packet-visible
/// LLS data layer instead of being silently dropped by block conversions.
///
/// RFC chunk: rfcs/parsed/chunks/5614/a.2.2.json
#[test]
fn test_mdr_lls_unknown_tlv_coexists_with_typed_tlv() {
    let unknown = UnknownTlv::new(65000, 4, Bytes::from_static(&[1, 2, 3, 4]));
    let packet = mdr_hello_packet(LlsHelloData {
        mdr_hello: Some(MdrHelloTlv {
            hello_sequence_number: 7,
            adjacency_reduction_disabled: false,
            differential: false,
            n1: 0,
            n2: 0,
            n3: 0,
            n4: 0,
        }),
        unknown_tlvs: vec![unknown],
        ..Default::default()
    });

    let bytes = packet.encode(None);
    let decoded = decode_ospfv3_packet(&bytes).unwrap();

    assert_eq!(decoded, packet);
}

/// Validates RFC 5614 Appendix A.2.3 and RFC 5613 §2.3 — LLS TLV length.
///
/// A recognized MDR-Hello TLV with an invalid fixed length is rejected and is
/// not downgraded into an unknown TLV.
///
/// RFC chunks: rfcs/parsed/chunks/5614/a.2.3.json,
/// rfcs/parsed/chunks/5613/2.3.json
#[test]
fn test_mdr_hello_tlv_rejects_invalid_length() {
    let packet = mdr_hello_packet(LlsHelloData {
        mdr_hello: Some(MdrHelloTlv {
            hello_sequence_number: 1,
            adjacency_reduction_disabled: false,
            differential: false,
            n1: 0,
            n2: 0,
            n3: 0,
            n4: 0,
        }),
        ..Default::default()
    });
    let mut bytes = packet.encode(None).to_vec();
    let lls_start = packet_len(&bytes);
    bytes[lls_start + 6] = 0;
    bytes[lls_start + 7] = 4;
    recompute_lls_checksum(&mut bytes);

    let err = decode_ospfv3_packet(&bytes).unwrap_err();

    assert_eq!(err, DecodeError::InvalidTlvLength(4));
}

/// Validates RFC 5614 Appendix A.2.5 and RFC 5613 §2.3 — LLS TLV length.
///
/// An MDR-Metric TLV whose value length does not match the I-bit layout is
/// rejected as malformed typed data.
///
/// RFC chunks: rfcs/parsed/chunks/5614/a.2.5.json,
/// rfcs/parsed/chunks/5613/2.3.json
#[test]
fn test_mdr_metric_tlv_rejects_invalid_metric_body_length() {
    let packet = mdr_hello_packet(LlsHelloData {
        mdr_metric: Some(MdrMetricTlv {
            default_metric: 1,
            include_ids: true,
            metrics: vec![MdrMetricEntry {
                neighbor_id: Some(ip4!("2.2.2.2")),
                metric: 8,
            }],
        }),
        ..Default::default()
    });
    let mut bytes = packet.encode(None).to_vec();
    let lls_start = packet_len(&bytes);
    bytes[lls_start + 6] = 0;
    bytes[lls_start + 7] = 8;
    recompute_lls_checksum(&mut bytes);

    let err = decode_ospfv3_packet(&bytes).unwrap_err();

    assert_eq!(err, DecodeError::InvalidTlvLength(8));
}

/// Validates RFC 5613 §2.2 — LLS Data Block checksum.
///
/// A bad LLS checksum discards only the LLS block; the enclosing OSPFv3 Hello
/// packet is still decoded.
///
/// RFC chunk: rfcs/parsed/chunks/5613/2.2.json
#[test]
fn test_mdr_lls_bad_checksum_discards_lls_block_only() {
    let packet = mdr_hello_packet(LlsHelloData {
        mdr_hello: Some(MdrHelloTlv {
            hello_sequence_number: 99,
            adjacency_reduction_disabled: false,
            differential: false,
            n1: 0,
            n2: 0,
            n3: 0,
            n4: 0,
        }),
        ..Default::default()
    });
    let mut bytes = packet.encode(None).to_vec();
    let lls_start = packet_len(&bytes);
    bytes[lls_start + 4] ^= 0x01;

    let decoded = decode_ospfv3_packet(&bytes).unwrap();

    match decoded {
        Packet::Hello(hello) => assert!(hello.lls.is_none()),
        packet => panic!("unexpected packet: {packet:?}"),
    }
}

/// Validates RFC 5613 §2.2 and RFC 5340 §2.6 — OSPFv3 L-bit consistency.
///
/// A Hello with the L-bit set but no trailing LLS data is rejected rather than
/// exposing an empty LLS block.
///
/// RFC chunks: rfcs/parsed/chunks/5613/2.2.json,
/// rfcs/parsed/chunks/5340/2.6.json
#[test]
fn test_hello_l_bit_without_lls_data_is_rejected() {
    let (ref bytes, _, _) = *HELLO1;
    let mut bytes = bytes.clone();
    bytes[22] |= 0x02;

    let err = decode_ospfv3_packet(&bytes).unwrap_err();

    assert_eq!(err, DecodeError::InvalidLength(0));
}

#[test]
fn test_encode_lsrequest1() {
    let (ref bytes, ref auth, ref request) = *LSREQUEST1;
    test_encode_packet(bytes, auth, request);
}

#[test]
fn test_decode_lsrequest1() {
    let (ref bytes, ref auth, ref request) = *LSREQUEST1;
    test_decode_packet(bytes, auth, request, AddressFamily::Ipv6);
}

#[test]
fn test_encode_lsupdate1() {
    let (ref bytes, ref auth, ref lsupdate) = *LSUPDATE1;
    test_encode_packet(bytes, auth, lsupdate);
}

#[test]
fn test_decode_lsupdate1() {
    let (ref bytes, ref auth, ref lsupdate) = *LSUPDATE1;
    test_decode_packet(bytes, auth, lsupdate, AddressFamily::Ipv6);
}

#[test]
fn test_encode_lsack1() {
    let (ref bytes, ref auth, ref lsack) = *LSACK1;
    test_encode_packet(bytes, auth, lsack);
}

#[test]
fn test_decode_lsack1() {
    let (ref bytes, ref auth, ref lsack) = *LSACK1;
    test_decode_packet(bytes, auth, lsack, AddressFamily::Ipv6);
}

#[test]
fn test_encode_lsa1() {
    let (ref bytes, ref lsa) = *LSA1;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_lsa1() {
    let (ref bytes, ref lsa) = *LSA1;
    test_decode_lsa(bytes, lsa, AddressFamily::Ipv6);
}

#[test]
fn test_encode_lsa2() {
    let (ref bytes, ref lsa) = *LSA2;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_lsa2() {
    let (ref bytes, ref lsa) = *LSA2;
    test_decode_lsa(bytes, lsa, AddressFamily::Ipv4);
}

#[test]
fn test_encode_lsa3() {
    let (ref bytes, ref lsa) = *LSA3;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_lsa3() {
    let (ref bytes, ref lsa) = *LSA3;
    test_decode_lsa(bytes, lsa, AddressFamily::Ipv4);
}

#[test]
fn test_encode_extended_router_lsa1() {
    let (ref bytes, ref lsa) = *EXT_ROUTER_LSA1;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_extended_router_lsa1() {
    let (ref bytes, ref lsa) = *EXT_ROUTER_LSA1;
    test_decode_lsa(bytes, lsa, AddressFamily::Ipv6);
}

#[test]
fn test_encode_extended_network_lsa1() {
    let (ref bytes, ref lsa) = *EXT_NETWORK_LSA1;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_extended_network_lsa1() {
    let (ref bytes, ref lsa) = *EXT_NETWORK_LSA1;
    test_decode_lsa(bytes, lsa, AddressFamily::Ipv6);
}

#[test]
fn test_encode_extended_inter_area_prefix_lsa1() {
    let (ref bytes, ref lsa) = *EXT_INTER_AREA_PREFIX_LSA1;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_extended_inter_area_prefix_lsa1() {
    let (ref bytes, ref lsa) = *EXT_INTER_AREA_PREFIX_LSA1;
    test_decode_lsa(bytes, lsa, AddressFamily::Ipv6);
}

#[test]
fn test_encode_extended_inter_area_router_lsa1() {
    let (ref bytes, ref lsa) = *EXT_INTER_AREA_ROUTER_LSA1;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_extended_inter_area_router_lsa1() {
    let (ref bytes, ref lsa) = *EXT_INTER_AREA_ROUTER_LSA1;
    test_decode_lsa(bytes, lsa, AddressFamily::Ipv6);
}

#[test]
fn test_encode_extended_as_external_lsa1() {
    let (ref bytes, ref lsa) = *EXT_AS_EXTERNAL_LSA1;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_extended_as_external_lsa1() {
    let (ref bytes, ref lsa) = *EXT_AS_EXTERNAL_LSA1;
    test_decode_lsa(bytes, lsa, AddressFamily::Ipv6);
}

#[test]
fn test_encode_extended_link_lsa1() {
    let (ref bytes, ref lsa) = *EXT_LINK_LSA1;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_extended_link_lsa1() {
    let (ref bytes, ref lsa) = *EXT_LINK_LSA1;
    test_decode_lsa(bytes, lsa, AddressFamily::Ipv6);
}

#[test]
fn test_encode_extended_intra_area_prefix_lsa1() {
    let (ref bytes, ref lsa) = *EXT_INTRA_AREA_PREFIX_LSA1;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_extended_intra_area_prefix_lsa1() {
    let (ref bytes, ref lsa) = *EXT_INTRA_AREA_PREFIX_LSA1;
    test_decode_lsa(bytes, lsa, AddressFamily::Ipv4);
}

#[test]
fn test_encode_extended_intra_are_prefix_lsa_bier_tlv_non_mpls_encap() {
    let (ref bytes, ref lsa) = *EXT_INTRA_AREA_PREFIX_LSA_BIER_TLV;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_extended_intra_are_prefix_lsa_bier_tlv_non_mpls_encap() {
    let (ref bytes, ref lsa) = *EXT_INTRA_AREA_PREFIX_LSA_BIER_TLV;
    test_decode_lsa(bytes, lsa, AddressFamily::Ipv6);
}

#[test]
fn test_encode_grace_lsa1() {
    let (ref bytes, ref lsa) = *GRACE_LSA1;
    test_encode_lsa(bytes, lsa);
}

#[test]
fn test_decode_grace_lsa1() {
    let (ref bytes, ref lsa) = *GRACE_LSA1;
    test_decode_lsa(bytes, lsa, AddressFamily::Ipv4);
}

#[test]
fn test_decode_invalid_lls_length() {
    let (ref bytes, ref auth_data, _) = *HELLO1_HMAC_SHA1_LLS;

    // Zero out the LLS Data Length field.
    let mut bytes = bytes.clone();
    bytes[42] = 0x00;
    bytes[43] = 0x00;

    let (auth_key, _) = auth_data.as_ref().unwrap();
    let auth_method = AuthMethod::ManualKey(auth_key.clone());
    let auth = Some(AuthDecodeCtx::new(&auth_method, SRC_ADDR.into()));

    let mut buf = Bytes::copy_from_slice(&bytes);
    let result = Packet::<Ospfv3>::decode(AddressFamily::Ipv6, &mut buf, auth);
    assert_eq!(result.unwrap_err(), DecodeError::InvalidLength(44));
}
