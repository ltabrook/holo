//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_ospf::instance::Instance;
use holo_ospf::version::Ospfv3;
use holo_protocol::test::stub::run_test_topology;

async fn run_topology(name: &str, routers: &[&str]) {
    for router in routers {
        run_test_topology::<Instance<Ospfv3>>(name, router).await;
    }
}

#[tokio::test]
async fn line() {
    run_topology("mdr-line", &["rt-a", "rt-b", "rt-c"]).await;
}

#[tokio::test]
async fn triangle() {
    run_topology("mdr-triangle", &["rt-a", "rt-b", "rt-c"]).await;
}

#[tokio::test]
async fn square_with_backup() {
    run_topology("mdr-square-with-backup", &["rt-a", "rt-b", "rt-c", "rt-d"])
        .await;
}

#[tokio::test]
async fn partition_heal() {
    run_topology("mdr-partition-heal", &["rt-a", "rt-b", "rt-c", "rt-d"]).await;
}

#[tokio::test]
async fn single_hop() {
    run_topology("mdr-single-hop", &["rt-a", "rt-b"]).await;
}

#[tokio::test]
async fn metric_preferred_relay() {
    run_topology(
        "mdr-metric-preferred-relay",
        &["rt-a", "rt-b", "rt-c", "rt-d"],
    )
    .await;
}
