//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::Ipv4Addr;

use crate::northbound::configuration::{MdrAdjConnectivity, MdrInterfaceCfg};
use crate::packet::lsa::{LsaHdrVersion, LsaKey};
use crate::version::Version;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MdrLevel {
    #[default]
    Other,
    Backup,
    Mdr,
}

impl MdrLevel {
    pub(crate) const fn is_dr_or_backup(self) -> bool {
        matches!(self, MdrLevel::Backup | MdrLevel::Mdr)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MdrHelloListType {
    Down,
    Init,
    Dependent,
    SelectedAdvertised,
    Bidirectional,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MdrSelectionNeighbor {
    pub router_id: Ipv4Addr,
    pub router_priority: u8,
    pub mdr_level: MdrLevel,
    pub bidirectional: bool,
    pub full_hello_received: bool,
    pub adjacent: bool,
    pub bidirectional_neighbors: BTreeSet<Ipv4Addr>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MdrSelectionResult {
    pub mdr_level: MdrLevel,
    pub parent: Option<Ipv4Addr>,
    pub backup_parent: Option<Ipv4Addr>,
    pub dependent_neighbors: BTreeSet<Ipv4Addr>,
    pub non_flooding_mdr: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RankedNeighbor<'a> {
    router_id: Ipv4Addr,
    router_priority: u8,
    mdr_level: MdrLevel,
    source: &'a MdrSelectionNeighbor,
}

/// Selects MDR/BMDR role, parentage, and dependent neighbors per RFC 5614 §5.
///
/// This is intentionally pure: callers provide Hello-learned neighbor state
/// and receive the new selection result without mutating interface or neighbor
/// storage. Trigger wiring and propagation are owned by the later interface
/// session.
pub(crate) fn select_mdr(
    local_router_id: Ipv4Addr,
    current_level: MdrLevel,
    config: &MdrInterfaceCfg,
    neighbors: &[MdrSelectionNeighbor],
) -> MdrSelectionResult {
    let ranked_neighbors = ranked_bidirectional_neighbors(neighbors);
    let rmax = ranked_neighbors.first().copied();
    let mut new_level = MdrLevel::Other;
    let mut dependent_neighbors = BTreeSet::new();
    let mut self_outranks_all = false;
    let mut non_flooding_mdr = false;

    if let Some(rmax) = rmax {
        self_outranks_all = outranks(
            config.router_priority,
            current_level,
            local_router_id,
            rmax.router_priority,
            rmax.mdr_level,
            rmax.router_id,
        );

        if self_outranks_all {
            new_level = MdrLevel::Mdr;
            if config.adj_connectivity != MdrAdjConnectivity::Full {
                for neighbor in &ranked_neighbors {
                    if neighbor.mdr_level == MdrLevel::Mdr
                        || (config.adj_connectivity
                            == MdrAdjConnectivity::Biconnected
                            && neighbor.mdr_level == MdrLevel::Backup)
                    {
                        dependent_neighbors.insert(neighbor.router_id);
                    }
                }
            }
        } else {
            let connectivity = neighbor_connectivity_matrix(&ranked_neighbors);
            let hops = min_hops_from_rmax(
                &ranked_neighbors,
                &connectivity,
                0,
                config.router_priority,
                current_level,
                local_router_id,
            );
            let hop_limit = usize::from(config.mdr_constraint);
            let mut phase2_selected_mdr = false;

            for (index, neighbor) in ranked_neighbors.iter().enumerate().skip(1)
            {
                if hops[index] <= hop_limit {
                    continue;
                }
                phase2_selected_mdr = true;
                if config.adj_connectivity == MdrAdjConnectivity::Full {
                    continue;
                }
                if neighbor.mdr_level == MdrLevel::Mdr
                    || (config.adj_connectivity
                        == MdrAdjConnectivity::Biconnected
                        && neighbor.mdr_level == MdrLevel::Backup)
                {
                    dependent_neighbors.insert(neighbor.router_id);
                }
            }

            if phase2_selected_mdr {
                new_level = MdrLevel::Mdr;
                if config.adj_connectivity != MdrAdjConnectivity::Full
                    && rmax.mdr_level.is_dr_or_backup()
                {
                    dependent_neighbors.insert(rmax.router_id);
                }
            } else if current_level == MdrLevel::Mdr {
                new_level = MdrLevel::Backup;
            } else {
                new_level = current_level;
            }

            let run_phase3 = !(new_level == MdrLevel::Mdr
                && config.adj_connectivity != MdrAdjConnectivity::Biconnected);
            if run_phase3 {
                let mut missing_two_paths = BTreeSet::new();
                for index in 1..ranked_neighbors.len() {
                    if !has_two_node_disjoint_paths(
                        &ranked_neighbors,
                        &connectivity,
                        0,
                        index,
                        config.router_priority,
                        current_level,
                        local_router_id,
                    ) {
                        missing_two_paths
                            .insert(ranked_neighbors[index].router_id);
                    }
                }

                if missing_two_paths.is_empty() {
                    if new_level != MdrLevel::Mdr {
                        new_level = MdrLevel::Other;
                    }
                } else {
                    if new_level != MdrLevel::Mdr {
                        new_level = MdrLevel::Backup;
                    }
                    if config.adj_connectivity
                        == MdrAdjConnectivity::Biconnected
                    {
                        if rmax.mdr_level.is_dr_or_backup() {
                            dependent_neighbors.insert(rmax.router_id);
                        }
                        for neighbor in ranked_neighbors.iter().skip(1) {
                            if missing_two_paths.contains(&neighbor.router_id)
                                && neighbor.mdr_level.is_dr_or_backup()
                            {
                                dependent_neighbors.insert(neighbor.router_id);
                            }
                        }
                    }
                }
            }

            if new_level == MdrLevel::Mdr {
                non_flooding_mdr = compute_non_flooding_mdr(
                    &ranked_neighbors,
                    &connectivity,
                    0,
                    config,
                    local_router_id,
                );
            }
        }
    }

    let rmax_id = (!self_outranks_all)
        .then_some(rmax)
        .flatten()
        .map(|neighbor| neighbor.router_id);
    let parent = match new_level {
        MdrLevel::Mdr => Some(local_router_id),
        MdrLevel::Backup | MdrLevel::Other => {
            best_adjacent_parent(&ranked_neighbors, false, None).or(rmax_id)
        }
    };
    let backup_parent = match new_level {
        MdrLevel::Mdr => rmax_id,
        MdrLevel::Backup => Some(local_router_id),
        MdrLevel::Other
            if config.adj_connectivity == MdrAdjConnectivity::Biconnected =>
        {
            let parent_id = parent;
            best_adjacent_parent(&ranked_neighbors, true, parent_id).or_else(
                || {
                    ranked_neighbors
                        .iter()
                        .copied()
                        .filter(|neighbor| Some(neighbor.router_id) != parent)
                        .max_by(|left, right| compare_ranked(*left, *right))
                        .map(|neighbor| neighbor.router_id)
                },
            )
        }
        MdrLevel::Other => None,
    };

    let dependent_neighbors =
        if config.adj_connectivity == MdrAdjConnectivity::Full {
            BTreeSet::new()
        } else {
            dependent_neighbors
                .into_iter()
                .filter(|router_id| {
                    ranked_neighbors.iter().any(|neighbor| {
                        neighbor.router_id == *router_id
                            && neighbor.mdr_level.is_dr_or_backup()
                    })
                })
                .collect()
        };

    MdrSelectionResult {
        mdr_level: new_level,
        parent,
        backup_parent,
        dependent_neighbors,
        non_flooding_mdr,
    }
}

fn ranked_bidirectional_neighbors(
    neighbors: &[MdrSelectionNeighbor],
) -> Vec<RankedNeighbor<'_>> {
    let mut ranked = neighbors
        .iter()
        .enumerate()
        .filter(|(_, neighbor)| neighbor.bidirectional)
        .map(|(_, neighbor)| RankedNeighbor {
            router_id: neighbor.router_id,
            router_priority: neighbor.router_priority,
            mdr_level: neighbor.mdr_level,
            source: neighbor,
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| compare_ranked(*right, *left));
    ranked
}

fn neighbor_connectivity_matrix(
    neighbors: &[RankedNeighbor<'_>],
) -> Vec<Vec<bool>> {
    // RFC 5614 §5.1 trusts a neighbor-pair edge only when the available
    // full-Hello BNS evidence is sufficient for that pair.
    let mut connectivity = vec![vec![false; neighbors.len()]; neighbors.len()];
    for (left_index, left) in neighbors.iter().enumerate() {
        for (right_index, right) in
            neighbors.iter().enumerate().skip(left_index + 1)
        {
            let left_reports_right = left
                .source
                .bidirectional_neighbors
                .contains(&right.router_id);
            let right_reports_left = right
                .source
                .bidirectional_neighbors
                .contains(&left.router_id);
            let linked = match (
                left.source.full_hello_received,
                right.source.full_hello_received,
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

fn min_hops_from_rmax(
    neighbors: &[RankedNeighbor<'_>],
    connectivity: &[Vec<bool>],
    rmax_index: usize,
    local_priority: u8,
    local_level: MdrLevel,
    local_router_id: Ipv4Addr,
) -> Vec<usize> {
    let mut hops = vec![usize::MAX; neighbors.len()];
    let mut queue = VecDeque::from([rmax_index]);
    hops[rmax_index] = 0;

    while let Some(current) = queue.pop_front() {
        if current != rmax_index
            && !neighbor_outranks_local(
                neighbors[current],
                local_priority,
                local_level,
                local_router_id,
            )
        {
            continue;
        }

        let next_hops = hops[current].saturating_add(1);
        for next in 0..neighbors.len() {
            if !connectivity[current][next] || next_hops >= hops[next] {
                continue;
            }
            hops[next] = next_hops;
            queue.push_back(next);
        }
    }

    hops
}

fn has_two_node_disjoint_paths(
    neighbors: &[RankedNeighbor<'_>],
    connectivity: &[Vec<bool>],
    start_index: usize,
    target_index: usize,
    local_priority: u8,
    local_level: MdrLevel,
    local_router_id: Ipv4Addr,
) -> bool {
    if start_index == target_index {
        return true;
    }

    let node_count = neighbors.len().saturating_mul(2);
    let mut residual = vec![vec![0_u8; node_count]; node_count];
    for (index, neighbor) in neighbors.iter().copied().enumerate() {
        let in_node = index * 2;
        let out_node = in_node + 1;
        residual[in_node][out_node] =
            if index == start_index || index == target_index {
                2
            } else if neighbor_outranks_local(
                neighbor,
                local_priority,
                local_level,
                local_router_id,
            ) {
                1
            } else {
                0
            };
    }

    for (left_index, row) in connectivity.iter().enumerate() {
        for (right_index, linked) in row.iter().copied().enumerate() {
            if linked {
                residual[left_index * 2 + 1][right_index * 2] = 1;
            }
        }
    }

    max_flow_at_most_two(&mut residual, start_index * 2 + 1, target_index * 2)
        >= 2
}

fn max_flow_at_most_two(
    residual: &mut [Vec<u8>],
    source: usize,
    sink: usize,
) -> u8 {
    let mut flow = 0_u8;

    'augment: loop {
        let mut parent = vec![None; residual.len()];
        let mut queue = VecDeque::from([source]);
        parent[source] = Some(source);

        while let Some(node) = queue.pop_front() {
            for next in 0..residual.len() {
                if residual[node][next] == 0 || parent[next].is_some() {
                    continue;
                }
                parent[next] = Some(node);
                if next == sink {
                    let mut cursor = sink;
                    while cursor != source {
                        let Some(prev) = parent[cursor] else {
                            break 'augment;
                        };
                        residual[prev][cursor] =
                            residual[prev][cursor].saturating_sub(1);
                        residual[cursor][prev] =
                            residual[cursor][prev].saturating_add(1);
                        cursor = prev;
                    }
                    flow = flow.saturating_add(1);
                    if flow >= 2 {
                        break 'augment;
                    }
                    continue 'augment;
                }
                queue.push_back(next);
            }
        }

        break;
    }

    flow
}

fn compute_non_flooding_mdr(
    neighbors: &[RankedNeighbor<'_>],
    connectivity: &[Vec<bool>],
    rmax_index: usize,
    config: &MdrInterfaceCfg,
    local_router_id: Ipv4Addr,
) -> bool {
    let mut hops = vec![usize::MAX; neighbors.len()];
    let mut queue = VecDeque::from([rmax_index]);
    hops[rmax_index] = 0;

    while let Some(current) = queue.pop_front() {
        if current != rmax_index {
            let current_neighbor = neighbors[current];
            let lower_than_local = current_neighbor
                .router_priority
                .cmp(&config.router_priority)
                .then(current_neighbor.router_id.cmp(&local_router_id))
                .is_lt();
            if current_neighbor.mdr_level != MdrLevel::Mdr || !lower_than_local
            {
                continue;
            }
        }

        let next_hops = hops[current].saturating_add(1);
        for next in 0..neighbors.len() {
            if !connectivity[current][next] || next_hops >= hops[next] {
                continue;
            }
            hops[next] = next_hops;
            queue.push_back(next);
        }
    }

    hops.into_iter()
        .all(|hops| hops <= usize::from(config.mdr_constraint))
}

fn best_adjacent_parent(
    neighbors: &[RankedNeighbor<'_>],
    allow_backup: bool,
    exclude: Option<Ipv4Addr>,
) -> Option<Ipv4Addr> {
    neighbors
        .iter()
        .copied()
        .filter(|neighbor| neighbor.source.adjacent)
        .filter(|neighbor| exclude != Some(neighbor.router_id))
        .filter(|neighbor| {
            neighbor.mdr_level == MdrLevel::Mdr
                || (allow_backup && neighbor.mdr_level == MdrLevel::Backup)
        })
        .max_by(|left, right| compare_ranked(*left, *right))
        .map(|neighbor| neighbor.router_id)
}

fn neighbor_outranks_local(
    neighbor: RankedNeighbor<'_>,
    local_priority: u8,
    local_level: MdrLevel,
    local_router_id: Ipv4Addr,
) -> bool {
    outranks(
        neighbor.router_priority,
        neighbor.mdr_level,
        neighbor.router_id,
        local_priority,
        local_level,
        local_router_id,
    )
}

fn compare_ranked(
    left: RankedNeighbor<'_>,
    right: RankedNeighbor<'_>,
) -> Ordering {
    compare_rank(
        left.router_priority,
        left.mdr_level,
        left.router_id,
        right.router_priority,
        right.mdr_level,
        right.router_id,
    )
}

fn outranks(
    left_priority: u8,
    left_level: MdrLevel,
    left_router_id: Ipv4Addr,
    right_priority: u8,
    right_level: MdrLevel,
    right_router_id: Ipv4Addr,
) -> bool {
    compare_rank(
        left_priority,
        left_level,
        left_router_id,
        right_priority,
        right_level,
        right_router_id,
    )
    .is_gt()
}

fn compare_rank(
    left_priority: u8,
    left_level: MdrLevel,
    left_router_id: Ipv4Addr,
    right_priority: u8,
    right_level: MdrLevel,
    right_router_id: Ipv4Addr,
) -> Ordering {
    left_priority
        .cmp(&right_priority)
        .then(mdr_rank(left_level).cmp(&mdr_rank(right_level)))
        .then(left_router_id.cmp(&right_router_id))
}

const fn mdr_rank(level: MdrLevel) -> u8 {
    match level {
        MdrLevel::Other => 0,
        MdrLevel::Backup => 1,
        MdrLevel::Mdr => 2,
    }
}

#[derive(Debug)]
pub struct MdrInterfaceState<V: Version> {
    pub config: MdrInterfaceCfg,
    pub mdr_level: MdrLevel,
    pub parent: Option<Ipv4Addr>,
    pub backup_parent: Option<Ipv4Addr>,
    pub hello_sequence_number: u16,
    pub full_hello_count: u16,
    pub differential_hello_count: u16,
    pub mdr_neighbor_change: bool,
    pub adjacency_reevaluation_pending: bool,
    pub lsa_reevaluation_pending: bool,
    pub backup_wait: BTreeMap<LsaKey<V::LsaType>, BTreeSet<Ipv4Addr>>,
    pub delayed_acks: BTreeMap<LsaKey<V::LsaType>, V::LsaHdr>,
}

impl<V> MdrInterfaceState<V>
where
    V: Version,
{
    pub(crate) fn new(config: &MdrInterfaceCfg) -> Self {
        Self {
            config: config.clone(),
            mdr_level: MdrLevel::Other,
            parent: None,
            backup_parent: None,
            hello_sequence_number: 0,
            full_hello_count: 0,
            differential_hello_count: 0,
            mdr_neighbor_change: false,
            adjacency_reevaluation_pending: false,
            lsa_reevaluation_pending: false,
            backup_wait: Default::default(),
            delayed_acks: Default::default(),
        }
    }

    pub(crate) fn next_hello_is_differential(&mut self) -> bool {
        if self.full_hello_count > 1 {
            self.full_hello_count -= 1;
            self.differential_hello_count =
                self.differential_hello_count.wrapping_add(1);
            true
        } else {
            self.full_hello_count = self.config.two_hop_refresh.max(1);
            self.differential_hello_count = 0;
            false
        }
    }

    pub(crate) fn mark_hello_generated(&mut self) -> u16 {
        let hsn = self.hello_sequence_number;
        self.hello_sequence_number = self.hello_sequence_number.wrapping_add(1);
        hsn
    }

    pub(crate) fn advertised_designated_router(
        &self,
        local_router_id: Ipv4Addr,
    ) -> Ipv4Addr {
        match self.mdr_level {
            MdrLevel::Mdr => local_router_id,
            MdrLevel::Backup | MdrLevel::Other => {
                self.parent.unwrap_or(Ipv4Addr::UNSPECIFIED)
            }
        }
    }

    pub(crate) fn advertised_backup_designated_router(
        &self,
        local_router_id: Ipv4Addr,
    ) -> Ipv4Addr {
        match self.mdr_level {
            MdrLevel::Backup => local_router_id,
            MdrLevel::Mdr | MdrLevel::Other => {
                self.backup_parent.unwrap_or(Ipv4Addr::UNSPECIFIED)
            }
        }
    }
}

#[derive(Debug)]
pub struct MdrNeighborState<V: Version> {
    pub remote_interface_id: Option<u32>,
    pub hello_sequence_number: u16,
    pub a_bit: bool,
    pub last_hello_differential: bool,
    pub full_hello_received: bool,
    pub mdr_level: MdrLevel,
    pub parent: Option<Ipv4Addr>,
    pub backup_parent: Option<Ipv4Addr>,
    pub child: bool,
    pub dependent: bool,
    pub dependent_selector: bool,
    pub backbone: bool,
    pub selected_advertised: bool,
    pub routable: bool,
    pub reverse_2way: bool,
    pub consecutive_hellos: u16,
    pub adjacency_desired: bool,
    pub bidirectional_neighbors: BTreeSet<Ipv4Addr>,
    pub dependent_neighbors: BTreeSet<Ipv4Addr>,
    pub selected_advertised_neighbors: BTreeSet<Ipv4Addr>,
    pub incoming_link_metric: Option<u16>,
    pub outgoing_link_metric: Option<u16>,
    pub hello_list_type: Option<MdrHelloListType>,
    pub hello_changed_hsn: u16,
    pub hello_advertised_metric: Option<u16>,
    pub link_metrics: BTreeMap<Ipv4Addr, u16>,
    pub acked_lsas: BTreeMap<LsaKey<V::LsaType>, V::LsaHdr>,
}

impl<V> Default for MdrNeighborState<V>
where
    V: Version,
{
    fn default() -> Self {
        Self {
            remote_interface_id: None,
            hello_sequence_number: 0,
            a_bit: false,
            last_hello_differential: false,
            full_hello_received: false,
            mdr_level: Default::default(),
            parent: None,
            backup_parent: None,
            child: false,
            dependent: false,
            dependent_selector: false,
            backbone: false,
            selected_advertised: false,
            routable: false,
            reverse_2way: false,
            consecutive_hellos: 0,
            adjacency_desired: false,
            bidirectional_neighbors: Default::default(),
            dependent_neighbors: Default::default(),
            selected_advertised_neighbors: Default::default(),
            incoming_link_metric: None,
            outgoing_link_metric: None,
            hello_list_type: None,
            hello_changed_hsn: 0,
            hello_advertised_metric: None,
            link_metrics: Default::default(),
            acked_lsas: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    struct ExpectedNode {
        level: MdrLevel,
        parent: Option<usize>,
        backup_parent: Option<usize>,
        dependents: &'static [usize],
    }

    #[derive(Clone, Copy)]
    struct TopologyCase {
        name: &'static str,
        adj_connectivity: MdrAdjConnectivity,
        node_count: usize,
        edges: &'static [(usize, usize)],
        expected: &'static [ExpectedNode],
    }

    const LINE_EXPECTED: [ExpectedNode; 3] = [
        ExpectedNode {
            level: MdrLevel::Other,
            parent: Some(1),
            backup_parent: None,
            dependents: &[],
        },
        ExpectedNode {
            level: MdrLevel::Mdr,
            parent: Some(1),
            backup_parent: Some(2),
            dependents: &[2],
        },
        ExpectedNode {
            level: MdrLevel::Mdr,
            parent: Some(2),
            backup_parent: None,
            dependents: &[1],
        },
    ];
    const TRIANGLE_EXPECTED: [ExpectedNode; 3] = [
        ExpectedNode {
            level: MdrLevel::Backup,
            parent: Some(2),
            backup_parent: Some(0),
            dependents: &[],
        },
        ExpectedNode {
            level: MdrLevel::Backup,
            parent: Some(2),
            backup_parent: Some(1),
            dependents: &[],
        },
        ExpectedNode {
            level: MdrLevel::Mdr,
            parent: Some(2),
            backup_parent: None,
            dependents: &[],
        },
    ];
    const SQUARE_EXPECTED: [ExpectedNode; 4] = [
        ExpectedNode {
            level: MdrLevel::Backup,
            parent: Some(3),
            backup_parent: Some(0),
            dependents: &[],
        },
        ExpectedNode {
            level: MdrLevel::Backup,
            parent: Some(3),
            backup_parent: Some(1),
            dependents: &[],
        },
        ExpectedNode {
            level: MdrLevel::Backup,
            parent: Some(3),
            backup_parent: Some(2),
            dependents: &[],
        },
        ExpectedNode {
            level: MdrLevel::Mdr,
            parent: Some(3),
            backup_parent: None,
            dependents: &[],
        },
    ];
    const PARTITION_HEAL_EXPECTED: [ExpectedNode; 4] = [
        ExpectedNode {
            level: MdrLevel::Other,
            parent: Some(1),
            backup_parent: None,
            dependents: &[],
        },
        ExpectedNode {
            level: MdrLevel::Mdr,
            parent: Some(1),
            backup_parent: Some(2),
            dependents: &[2],
        },
        ExpectedNode {
            level: MdrLevel::Mdr,
            parent: Some(2),
            backup_parent: Some(3),
            dependents: &[1, 3],
        },
        ExpectedNode {
            level: MdrLevel::Mdr,
            parent: Some(3),
            backup_parent: None,
            dependents: &[2],
        },
    ];
    const SINGLE_HOP_EXPECTED: [ExpectedNode; 2] = [
        ExpectedNode {
            level: MdrLevel::Other,
            parent: Some(1),
            backup_parent: None,
            dependents: &[],
        },
        ExpectedNode {
            level: MdrLevel::Mdr,
            parent: Some(1),
            backup_parent: None,
            dependents: &[],
        },
    ];

    fn router_id(index: usize) -> Ipv4Addr {
        Ipv4Addr::new(10, 44, 0, index as u8 + 1)
    }

    fn config(adj_connectivity: MdrAdjConnectivity) -> MdrInterfaceCfg {
        MdrInterfaceCfg {
            enabled: true,
            router_priority: 1,
            adj_connectivity,
            mdr_constraint: 3,
            ..Default::default()
        }
    }

    fn neighbors_of(
        node_index: usize,
        edges: &[(usize, usize)],
    ) -> BTreeSet<Ipv4Addr> {
        edges
            .iter()
            .filter_map(|(left, right)| {
                if *left == node_index {
                    Some(router_id(*right))
                } else if *right == node_index {
                    Some(router_id(*left))
                } else {
                    None
                }
            })
            .collect()
    }

    fn selection_neighbors(
        local_index: usize,
        case: TopologyCase,
    ) -> Vec<MdrSelectionNeighbor> {
        let local_neighbors = neighbors_of(local_index, case.edges);
        (0..case.node_count)
            .filter(|index| local_neighbors.contains(&router_id(*index)))
            .map(|index| MdrSelectionNeighbor {
                router_id: router_id(index),
                router_priority: 1,
                mdr_level: case.expected[index].level,
                bidirectional: true,
                full_hello_received: true,
                adjacent: true,
                bidirectional_neighbors: neighbors_of(index, case.edges),
            })
            .collect()
    }

    fn assert_selection(case: TopologyCase) {
        for node_index in 0..case.node_count {
            let expected = case.expected[node_index];
            let result = select_mdr(
                router_id(node_index),
                expected.level,
                &config(case.adj_connectivity),
                &selection_neighbors(node_index, case),
            );

            assert_eq!(
                result.mdr_level, expected.level,
                "{} node {} role",
                case.name, node_index
            );
            assert_eq!(
                result.parent,
                expected.parent.map(router_id),
                "{} node {} parent",
                case.name,
                node_index
            );
            assert_eq!(
                result.backup_parent,
                expected.backup_parent.map(router_id),
                "{} node {} backup parent",
                case.name,
                node_index
            );
            assert_eq!(
                result.dependent_neighbors,
                expected
                    .dependents
                    .iter()
                    .map(|index| router_id(*index))
                    .collect::<BTreeSet<_>>(),
                "{} node {} dependents",
                case.name,
                node_index
            );
        }
    }

    /// Validates RFC 5614 §5.1 through §5.4 — MDR/BMDR selection over
    /// direct-state topology graphs.
    ///
    /// The stable session-04 topology shapes are converted directly into
    /// Hello-learned bidirectional-neighbor state, then checked for role,
    /// parent, backup-parent, and dependent-neighbor selection.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/{5.1,5.2,5.3,5.4}.json
    #[test]
    fn selection_matches_stable_session04_topology_shapes() {
        assert_selection(TopologyCase {
            name: "line",
            adj_connectivity: MdrAdjConnectivity::Uniconnected,
            node_count: 3,
            edges: &[(0, 1), (1, 2)],
            expected: &LINE_EXPECTED,
        });
        assert_selection(TopologyCase {
            name: "triangle",
            adj_connectivity: MdrAdjConnectivity::Uniconnected,
            node_count: 3,
            edges: &[(0, 1), (1, 2), (0, 2)],
            expected: &TRIANGLE_EXPECTED,
        });
        assert_selection(TopologyCase {
            name: "square-with-backup",
            adj_connectivity: MdrAdjConnectivity::Uniconnected,
            node_count: 4,
            edges: &[(0, 1), (1, 2), (2, 3), (3, 0), (1, 3)],
            expected: &SQUARE_EXPECTED,
        });
        assert_selection(TopologyCase {
            name: "partition-heal",
            adj_connectivity: MdrAdjConnectivity::Uniconnected,
            node_count: 4,
            edges: &[(0, 1), (1, 2), (2, 3)],
            expected: &PARTITION_HEAL_EXPECTED,
        });
        assert_selection(TopologyCase {
            name: "single-hop",
            adj_connectivity: MdrAdjConnectivity::Full,
            node_count: 2,
            edges: &[(0, 1)],
            expected: &SINGLE_HOP_EXPECTED,
        });
    }

    /// Validates RFC 5614 §5.1 and Appendix B.1 — NCM-driven MDRConstraint
    /// coverage.
    ///
    /// With `MDRConstraint = 1`, Rmax cannot cover the far MDR neighbor
    /// through the bridge, so the local router selects itself as an MDR and
    /// marks Rmax plus the uncovered MDR neighbor dependent.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/{5.1,5.2,b.1}.json
    #[test]
    fn selection_uses_mdr_constraint_to_cover_unreached_mdrs() {
        let mut cfg = config(MdrAdjConnectivity::Uniconnected);
        cfg.mdr_constraint = 1;
        let neighbors = vec![
            MdrSelectionNeighbor {
                router_id: router_id(9),
                router_priority: 2,
                mdr_level: MdrLevel::Mdr,
                bidirectional: true,
                full_hello_received: true,
                adjacent: true,
                bidirectional_neighbors: BTreeSet::from([
                    router_id(0),
                    router_id(8),
                ]),
            },
            MdrSelectionNeighbor {
                router_id: router_id(8),
                router_priority: 1,
                mdr_level: MdrLevel::Other,
                bidirectional: true,
                full_hello_received: true,
                adjacent: true,
                bidirectional_neighbors: BTreeSet::from([
                    router_id(0),
                    router_id(7),
                    router_id(9),
                ]),
            },
            MdrSelectionNeighbor {
                router_id: router_id(7),
                router_priority: 1,
                mdr_level: MdrLevel::Mdr,
                bidirectional: true,
                full_hello_received: true,
                adjacent: true,
                bidirectional_neighbors: BTreeSet::from([
                    router_id(0),
                    router_id(8),
                ]),
            },
        ];

        let result =
            select_mdr(router_id(0), MdrLevel::Other, &cfg, &neighbors);

        assert_eq!(result.mdr_level, MdrLevel::Mdr);
        assert_eq!(result.parent, Some(router_id(0)));
        assert_eq!(result.backup_parent, Some(router_id(9)));
        assert_eq!(
            result.dependent_neighbors,
            BTreeSet::from([router_id(7), router_id(9)])
        );
    }

    /// Validates RFC 5614 §5.3 and Appendix B.2 — Backup MDR selection.
    ///
    /// A router that is not needed as an MDR still becomes a BMDR when Rmax
    /// lacks two node-disjoint paths to each neighbor through higher-ranked
    /// bi-neighbors.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/{5.3,b.2}.json
    #[test]
    fn selection_chooses_backup_when_two_disjoint_paths_are_missing() {
        let cfg = config(MdrAdjConnectivity::Uniconnected);
        let neighbors = vec![
            MdrSelectionNeighbor {
                router_id: router_id(3),
                router_priority: 1,
                mdr_level: MdrLevel::Mdr,
                bidirectional: true,
                full_hello_received: true,
                adjacent: true,
                bidirectional_neighbors: BTreeSet::from([
                    router_id(0),
                    router_id(1),
                ]),
            },
            MdrSelectionNeighbor {
                router_id: router_id(1),
                router_priority: 1,
                mdr_level: MdrLevel::Other,
                bidirectional: true,
                full_hello_received: true,
                adjacent: true,
                bidirectional_neighbors: BTreeSet::from([
                    router_id(0),
                    router_id(3),
                ]),
            },
        ];

        let result =
            select_mdr(router_id(0), MdrLevel::Other, &cfg, &neighbors);

        assert_eq!(result.mdr_level, MdrLevel::Backup);
        assert_eq!(result.parent, Some(router_id(3)));
        assert_eq!(result.backup_parent, Some(router_id(0)));
    }

    /// Validates RFC 5614 §5.3 and §5.4 — biconnected dependent and backup
    /// parent selection.
    ///
    /// Under `AdjConnectivity = 2`, BMDR neighbors can be selected as
    /// dependents and an MDR Other chooses a backup parent distinct from its
    /// parent.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/{5.3,5.4}.json
    #[test]
    fn selection_uses_biconnected_backup_parent_and_dependents() {
        let cfg = config(MdrAdjConnectivity::Biconnected);
        let neighbors = vec![
            MdrSelectionNeighbor {
                router_id: router_id(4),
                router_priority: 2,
                mdr_level: MdrLevel::Mdr,
                bidirectional: true,
                full_hello_received: true,
                adjacent: true,
                bidirectional_neighbors: BTreeSet::from([
                    router_id(0),
                    router_id(3),
                    router_id(2),
                ]),
            },
            MdrSelectionNeighbor {
                router_id: router_id(3),
                router_priority: 2,
                mdr_level: MdrLevel::Backup,
                bidirectional: true,
                full_hello_received: true,
                adjacent: true,
                bidirectional_neighbors: BTreeSet::from([
                    router_id(0),
                    router_id(4),
                    router_id(2),
                ]),
            },
            MdrSelectionNeighbor {
                router_id: router_id(2),
                router_priority: 2,
                mdr_level: MdrLevel::Backup,
                bidirectional: true,
                full_hello_received: true,
                adjacent: false,
                bidirectional_neighbors: BTreeSet::from([
                    router_id(0),
                    router_id(3),
                    router_id(4),
                ]),
            },
        ];

        let result =
            select_mdr(router_id(0), MdrLevel::Other, &cfg, &neighbors);

        assert_eq!(result.mdr_level, MdrLevel::Other);
        assert_eq!(result.parent, Some(router_id(4)));
        assert_eq!(result.backup_parent, Some(router_id(3)));
        assert!(result.dependent_neighbors.is_empty());

        let dependents = vec![
            MdrSelectionNeighbor {
                router_id: router_id(0),
                router_priority: 1,
                mdr_level: MdrLevel::Mdr,
                bidirectional: true,
                full_hello_received: true,
                adjacent: true,
                bidirectional_neighbors: BTreeSet::from([router_id(9)]),
            },
            MdrSelectionNeighbor {
                router_id: router_id(1),
                router_priority: 1,
                mdr_level: MdrLevel::Backup,
                bidirectional: true,
                full_hello_received: true,
                adjacent: true,
                bidirectional_neighbors: BTreeSet::from([router_id(9)]),
            },
        ];

        let result = select_mdr(router_id(9), MdrLevel::Mdr, &cfg, &dependents);

        assert_eq!(result.mdr_level, MdrLevel::Mdr);
        assert_eq!(
            result.dependent_neighbors,
            BTreeSet::from([router_id(0), router_id(1)])
        );
    }

    /// Validates RFC 5614 §5.5 — optional non-flooding MDR calculation.
    ///
    /// A selected MDR reports non-flooding eligibility when Rmax covers every
    /// bi-neighbor within `MDRConstraint` through lower-ranked MDR
    /// intermediates.
    ///
    /// RFC chunk: rfcs/parsed/chunks/5614/5.5.json
    #[test]
    fn selection_reports_non_flooding_mdr_eligibility() {
        let mut cfg = config(MdrAdjConnectivity::Uniconnected);
        cfg.mdr_constraint = 2;
        let neighbors = vec![
            MdrSelectionNeighbor {
                router_id: router_id(9),
                router_priority: 2,
                mdr_level: MdrLevel::Mdr,
                bidirectional: true,
                full_hello_received: true,
                adjacent: true,
                bidirectional_neighbors: BTreeSet::from([
                    router_id(0),
                    router_id(1),
                ]),
            },
            MdrSelectionNeighbor {
                router_id: router_id(1),
                router_priority: 1,
                mdr_level: MdrLevel::Mdr,
                bidirectional: true,
                full_hello_received: true,
                adjacent: true,
                bidirectional_neighbors: BTreeSet::from([
                    router_id(0),
                    router_id(2),
                    router_id(9),
                ]),
            },
            MdrSelectionNeighbor {
                router_id: router_id(2),
                router_priority: 1,
                mdr_level: MdrLevel::Mdr,
                bidirectional: true,
                full_hello_received: true,
                adjacent: true,
                bidirectional_neighbors: BTreeSet::from([
                    router_id(0),
                    router_id(1),
                ]),
            },
        ];

        let result = select_mdr(router_id(8), MdrLevel::Mdr, &cfg, &neighbors);

        assert_eq!(result.mdr_level, MdrLevel::Mdr);
        assert!(result.non_flooding_mdr);
    }

    /// Documents the RFC 5614 §5 scope boundary for the session-04
    /// `metric-preferred-relay` fixture.
    ///
    /// MDR/BMDR role selection is rank and NCM based; the metric-preferred
    /// relay behavior in that fixture belongs to advertised-neighbor/SANS work
    /// rather than changing the §5 role calculation.
    ///
    /// RFC chunks: rfcs/parsed/chunks/5614/{5.1,5.2,5.3,5.4}.json
    #[test]
    fn metric_preferred_relay_metrics_do_not_change_mdr_role_selection() {
        let case = TopologyCase {
            name: "metric-preferred-relay",
            adj_connectivity: MdrAdjConnectivity::Uniconnected,
            node_count: 4,
            edges: &[(0, 1), (1, 3), (0, 2), (2, 3), (1, 2)],
            expected: &[
                ExpectedNode {
                    level: MdrLevel::Backup,
                    parent: Some(2),
                    backup_parent: Some(0),
                    dependents: &[],
                },
                ExpectedNode {
                    level: MdrLevel::Backup,
                    parent: Some(3),
                    backup_parent: Some(1),
                    dependents: &[],
                },
                ExpectedNode {
                    level: MdrLevel::Mdr,
                    parent: Some(2),
                    backup_parent: Some(3),
                    dependents: &[3],
                },
                ExpectedNode {
                    level: MdrLevel::Mdr,
                    parent: Some(3),
                    backup_parent: None,
                    dependents: &[2],
                },
            ],
        };

        assert_selection(case);
    }
}
