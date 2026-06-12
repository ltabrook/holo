# Holo OSPF-MDR Packet Fixtures

These fixtures are a vendored copy of the Rust oracle packet fixtures from the
simulation repository. The two workspaces deliberately share no build graph, so
the packet bytes and expected-value JSON sidecars are committed here.

Source path:

```text
/home/brian/repo/simulation/ospf-mdr_reference/fixtures/holo/packets/
```

Simulation checkout rev at vendoring: `e530afa0d315`

Source manifest generator:

- Generator rev: `43348fccf30d`
- Command: `cargo run -p manet-ospf-mdr --example mdr_fixture_export -- all`
- Gate: `just ospf-mdr-fixture-export`

Per-file SHA-256 values copied from
`ospf-mdr_reference/fixtures/holo/manifest.json`:

- `packets/database_description_mdr_dd.bin` - `b8f83c575c02192c670842465cfc515681892def0cce410c1c2f2d5cc3dfc1d1`
- `packets/database_description_mdr_dd.json` - `eb45d5d2dacc3d106a169612ef494577c8758b224e69c05a097906e8636cb444`
- `packets/hello_differential.bin` - `6dec07cebf458239a6cf5b0d1a502f944a3b2fc3696df914b9464c417617db54`
- `packets/hello_differential.json` - `25dcb97511ad41642f2b1550548aa0253a42d3dad13b12d57751b5e4af81a10a`
- `packets/hello_full_metric.bin` - `50ee42660a74548c2274eb2aa5567512de8a297f82cf5bc5f9357692128aa76a`
- `packets/hello_full_metric.json` - `ab582dd502826006e1df84a53376b1dc3c7dff5ca6e7fcb4bbc7f88302dd199d`
- `packets/hello_full_no_metric.bin` - `2a31c06f1e04dfe0e48b55cc869731a0c56e02ad6b0475628abbf6453d02b5ed`
- `packets/hello_full_no_metric.json` - `98cff2c707be8518c91960238500b6c91184572e5c0cbcaafb3e7da38a9c5b69`
- `packets/link_state_ack.bin` - `6aa6a3b44f40e806b65cdc1f0b3b5d3fe1ffb6b53f39b68ae33d8b32e92dc4f7`
- `packets/link_state_ack.json` - `f6d6fb94af4e4273a2b3822cbebd9dc0087f5d39cecc404d84b1839dcb1afb0e`
- `packets/link_state_update_router_link_intra_prefix.bin` - `e892159bcdda2b777e92700bcd6700e54d6f85301e64e3924529904c9a0134f9`
- `packets/link_state_update_router_link_intra_prefix.json` - `8c3a3fc2ccef1683a58d431dccf681478f6f4e945976bd9a5c3123e613d7e52c`
- `packets/malformed_bad_lls_checksum.bin` - `5636847b44ff1d19528c69e8a8ec8a006335f015a938c68f5e6c7792205c0c9b`
- `packets/malformed_bad_lls_checksum.json` - `d9e8749d827b2468aa18ade77ee7310ffcec0e6f7c577e89924111df32d439e3`
- `packets/malformed_bad_tlv_length.bin` - `70397ce09c5e9db0a289ee07d7b10e3e5e3b8cdcf6aae548a0036b0f57b85b67`
- `packets/malformed_bad_tlv_length.json` - `07a749a1e442c1a208c99942b9efc99a189bba57de554746c2098cd7e76adaf3`
- `packets/malformed_l_bit_without_lls.bin` - `97a2095d9d2c5b8fcef5ffe6bfeaacf748a334c34ae3a22a555db4f4a8985d5c`
- `packets/malformed_l_bit_without_lls.json` - `6ebfef5c9110da26025f0302ca3fe00c8ab09968a0650cabb0f0ec1504750e06`
