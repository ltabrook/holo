//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::net::Ipv4Addr;

use bitflags::bitflags;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use holo_utils::bytes::{BytesExt, BytesMutExt};
use internet_checksum::Checksum;
use num_derive::{FromPrimitive, ToPrimitive};
use serde::{self, Deserialize, Serialize};

use super::auth::AuthEncodeCtx;
use super::error::{DecodeError, DecodeResult};
use super::tlv::{UnknownTlv, tlv_encode_end, tlv_encode_start};
use crate::packet::AuthDecodeCtx;
use crate::version::Version;

// LLS header size.
pub const LLS_HDR_SIZE: u16 = 4;

pub trait LlsVersion<V: Version> {
    type LlsDataBlock: From<LlsHelloData>
        + From<LlsDbDescData>
        + std::fmt::Debug;

    fn encode_lls_block(
        buf: &mut BytesMut,
        lls: V::LlsDataBlock,
        auth: Option<&AuthEncodeCtx<'_>>,
    );

    fn decode_lls_block(
        buf: &[u8],
        pkt_len: u16,
        hdr_auth: V::PacketHdrAuth,
        auth: Option<&AuthDecodeCtx<'_>>,
    ) -> DecodeResult<Option<V::LlsDataBlock>>;

    const CKSUM_RANGE: std::ops::Range<usize> = 0..2;
    const LENGTH_RANGE: std::ops::Range<usize> = 2..4;

    fn update_len(buf: &mut BytesMut, start_pos: usize, len: u16) {
        buf[start_pos + Self::LENGTH_RANGE.start
            ..start_pos + Self::LENGTH_RANGE.end]
            .copy_from_slice(&len.to_be_bytes());
    }

    fn update_cksum(buf: &mut BytesMut, start_pos: usize) {
        let mut cksum = Checksum::new();
        cksum.add_bytes(&buf[start_pos..]);
        buf[start_pos + Self::CKSUM_RANGE.start
            ..start_pos + Self::CKSUM_RANGE.end]
            .copy_from_slice(&cksum.checksum());
    }

    fn verify_cksum(data: &[u8]) -> DecodeResult<()> {
        let mut cksum = Checksum::new();
        cksum.add_bytes(&data[Self::CKSUM_RANGE.end..]);
        if cksum.checksum() != data[Self::CKSUM_RANGE] {
            return Err(DecodeError::InvalidChecksum);
        }
        Ok(())
    }
}

// LLS TLV types.
//
// IANA Registry:
// https://www.iana.org/assignments/ospf-lls-tlvs/ospf-lls-tlvs.xhtml
#[derive(ToPrimitive, FromPrimitive)]
pub enum LlsTlvType {
    ExtendedOptionsFlags = 1,
    CryptoAuth = 2,
    MdrHello = 14,
    MdrDd = 15,
    MdrMetric = 16,
}

#[derive(PartialEq, Eq, Debug, Clone)]
#[derive(Serialize, Deserialize)]
pub enum LlsData {
    Hello(LlsHelloData),
    DbDesc(LlsDbDescData),
}

impl LlsData {
    pub(crate) fn encode<V>(
        &self,
        buf: &mut BytesMut,
        auth: Option<&AuthEncodeCtx<'_>>,
    ) where
        V: Version,
    {
        let lls: V::LlsDataBlock = match self {
            Self::Hello(hello) => hello.clone().into(),
            Self::DbDesc(dbdesc) => dbdesc.clone().into(),
        };
        V::encode_lls_block(buf, lls, auth);
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Default)]
#[derive(Serialize, Deserialize)]
pub struct LlsHelloData {
    pub eof: Option<ExtendedOptionsFlags>,
    #[serde(default)]
    pub mdr_hello: Option<MdrHelloTlv>,
    #[serde(default)]
    pub mdr_metric: Option<MdrMetricTlv>,
    #[serde(default)]
    pub unknown_tlvs: Vec<UnknownTlv>,
}

#[derive(PartialEq, Eq, Debug, Clone, Default)]
#[derive(Serialize, Deserialize)]
pub struct LlsDbDescData {
    pub eof: Option<ExtendedOptionsFlags>,
    #[serde(default)]
    pub mdr_dd: Option<MdrDdTlv>,
    #[serde(default)]
    pub unknown_tlvs: Vec<UnknownTlv>,
}

// Extended Options and Flags
//
// IANA Registry:
// https://www.iana.org/assignments/ospf-lls-tlvs/ospf-lls-tlvs.xhtml#ospf-lls-tlvs-2
bitflags! {
    #[derive(Clone, Debug, Eq, PartialEq, Copy)]
    #[derive(Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct ExtendedOptionsFlags: u32 {
        const LR = 0x00000001;
        const RS = 0x00000002;
    }
}

// RFC 5613 : LLS Extended Options and Flags TLV.
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |             1                 |            4                  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                  Extended Options and Flags                   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub struct ExtendedOptionsFlagsTlv(pub ExtendedOptionsFlags);

impl ExtendedOptionsFlagsTlv {
    pub(crate) fn decode(tlv_len: u16, buf: &mut Bytes) -> DecodeResult<Self> {
        if tlv_len != 4 {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }
        let opts = ExtendedOptionsFlags::from_bits_truncate(buf.try_get_u32()?);
        Ok(ExtendedOptionsFlagsTlv(opts))
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, LlsTlvType::ExtendedOptionsFlags);
        buf.put_u32(self.0.bits());
        tlv_encode_end(buf, start_pos);
    }
}

// RFC 5614 Appendix A.2.3: MDR-Hello TLV.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub struct MdrHelloTlv {
    pub hello_sequence_number: u16,
    pub adjacency_reduction_disabled: bool,
    pub differential: bool,
    pub n1: u8,
    pub n2: u8,
    pub n3: u8,
    pub n4: u8,
}

impl MdrHelloTlv {
    pub(crate) fn decode(tlv_len: u16, buf: &mut Bytes) -> DecodeResult<Self> {
        if tlv_len != 8 {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        let hello_sequence_number = buf.try_get_u16()?;
        let flags = buf.try_get_u16()?;
        let n1 = buf.try_get_u8()?;
        let n2 = buf.try_get_u8()?;
        let n3 = buf.try_get_u8()?;
        let n4 = buf.try_get_u8()?;

        Ok(MdrHelloTlv {
            hello_sequence_number,
            adjacency_reduction_disabled: flags & 0x0002 != 0,
            differential: flags & 0x0001 != 0,
            n1,
            n2,
            n3,
            n4,
        })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, LlsTlvType::MdrHello);
        let mut flags = 0u16;
        if self.adjacency_reduction_disabled {
            flags |= 0x0002;
        }
        if self.differential {
            flags |= 0x0001;
        }

        buf.put_u16(self.hello_sequence_number);
        buf.put_u16(flags);
        buf.put_u8(self.n1);
        buf.put_u8(self.n2);
        buf.put_u8(self.n3);
        buf.put_u8(self.n4);
        tlv_encode_end(buf, start_pos);
    }
}

// RFC 5614 Appendix A.2.4: MDR-DD TLV.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub struct MdrDdTlv {
    pub designated_router: Ipv4Addr,
    pub backup_designated_router: Ipv4Addr,
}

impl MdrDdTlv {
    pub(crate) fn decode(tlv_len: u16, buf: &mut Bytes) -> DecodeResult<Self> {
        if tlv_len != 8 {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        Ok(MdrDdTlv {
            designated_router: buf.try_get_ipv4()?,
            backup_designated_router: buf.try_get_ipv4()?,
        })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, LlsTlvType::MdrDd);
        buf.put_ipv4(&self.designated_router);
        buf.put_ipv4(&self.backup_designated_router);
        tlv_encode_end(buf, start_pos);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub struct MdrMetricEntry {
    pub neighbor_id: Option<Ipv4Addr>,
    pub metric: u16,
}

// RFC 5614 Appendix A.2.5: MDR-Metric TLV.
#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub struct MdrMetricTlv {
    pub default_metric: u16,
    pub include_ids: bool,
    pub metrics: Vec<MdrMetricEntry>,
}

impl MdrMetricTlv {
    pub(crate) fn decode(tlv_len: u16, buf: &mut Bytes) -> DecodeResult<Self> {
        if tlv_len < 4 || buf.remaining() < tlv_len as usize {
            return Err(DecodeError::InvalidTlvLength(tlv_len));
        }

        let default_metric = buf.try_get_u16()?;
        let flags = buf.try_get_u16()?;
        let include_ids = flags & 0x0001 != 0;
        let body_len = tlv_len as usize - 4;

        let metrics = if include_ids {
            if !body_len.is_multiple_of(6) {
                return Err(DecodeError::InvalidTlvLength(tlv_len));
            }
            let mut metrics = Vec::with_capacity(body_len / 6);
            for _ in 0..body_len / 6 {
                metrics.push(MdrMetricEntry {
                    neighbor_id: Some(buf.try_get_ipv4()?),
                    metric: buf.try_get_u16()?,
                });
            }
            metrics
        } else {
            if !body_len.is_multiple_of(2) {
                return Err(DecodeError::InvalidTlvLength(tlv_len));
            }
            let mut metrics = Vec::with_capacity(body_len / 2);
            for _ in 0..body_len / 2 {
                metrics.push(MdrMetricEntry {
                    neighbor_id: None,
                    metric: buf.try_get_u16()?,
                });
            }
            metrics
        };

        Ok(MdrMetricTlv {
            default_metric,
            include_ids,
            metrics,
        })
    }

    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        let start_pos = tlv_encode_start(buf, LlsTlvType::MdrMetric);
        buf.put_u16(self.default_metric);
        buf.put_u16(u16::from(self.include_ids));
        if self.include_ids {
            for entry in &self.metrics {
                if let Some(neighbor_id) = entry.neighbor_id {
                    buf.put_ipv4(&neighbor_id);
                    buf.put_u16(entry.metric);
                }
            }
        } else {
            for entry in &self.metrics {
                buf.put_u16(entry.metric);
            }
        }
        tlv_encode_end(buf, start_pos);
    }
}

pub(crate) fn encode_unknown_tlv(buf: &mut BytesMut, tlv: &UnknownTlv) {
    let start_pos = buf.len();
    buf.put_u16(tlv.tlv_type);
    buf.put_u16(tlv.length);
    buf.put_slice(&tlv.value[..tlv.length as usize]);
    tlv_encode_end(buf, start_pos);
}

// ===== global functions =====

pub(crate) fn lls_encode_start(buf: &mut BytesMut) -> usize {
    let start_pos = buf.len();
    // Checksum will be rewritten later.
    buf.put_u16(0);
    // The LLS data block length will be rewritten later.
    buf.put_u16(0);
    start_pos
}

pub(crate) fn lls_encode_end<V>(
    buf: &mut BytesMut,
    start_pos: usize,
    skip_cksum: bool,
) where
    V: Version,
{
    // RFC 5613 : "The 16-bit LLS Data Length field contains the length (in
    // 32-bit words) of the LLS block including the header and payload."
    let lls_len = ((buf.len() - start_pos) / 4) as u16;

    // Rewrite LLS length.
    V::update_len(buf, start_pos, lls_len);

    // Rewrite LLS checksum if authentication is disabled.
    if !skip_cksum {
        V::update_cksum(buf, start_pos);
    }
}
