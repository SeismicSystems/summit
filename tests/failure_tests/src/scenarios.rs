use std::{collections::BTreeMap, time::Duration};
use test_utils::TestContext;

#[derive(Debug, Clone)]
pub enum NetworkPartition {
    Isolated(Vec<usize>),
    Split(Vec<usize>, Vec<usize>),
}

#[derive(Debug, Clone)]
pub enum ByzantineBehavior {
    Silent,
    DoubleVote,
    InvalidBlocks,
    DelayedMessages(Duration),
}

pub struct FailureScenario {
    pub name: String,
    pub partition: Option<NetworkPartition>,
    pub byzantine_nodes: Vec<(usize, ByzantineBehavior)>,
    pub expected_outcome: ExpectedOutcome,
}

#[derive(Debug, Clone)]
pub enum ExpectedOutcome {
    ConsensusSuccess,
    ConsensusTimeout,
    NoFinalization,
    PartialFinalization,
}

impl FailureScenario {
    pub fn network_partition_minority(minority_nodes: Vec<usize>) -> Self {
        Self {
            name: "Network partition isolates minority".to_string(),
            partition: Some(NetworkPartition::Isolated(minority_nodes)),
            byzantine_nodes: vec![],
            expected_outcome: ExpectedOutcome::ConsensusSuccess,
        }
    }

    pub fn network_partition_split(group_a: Vec<usize>, group_b: Vec<usize>) -> Self {
        Self {
            name: "Network split into two groups".to_string(),
            partition: Some(NetworkPartition::Split(group_a, group_b)),
            byzantine_nodes: vec![],
            expected_outcome: ExpectedOutcome::NoFinalization,
        }
    }

    pub fn byzantine_silent_nodes(nodes: Vec<usize>) -> Self {
        let byzantine_nodes = nodes.into_iter()
            .map(|n| (n, ByzantineBehavior::Silent))
            .collect();
        
        Self {
            name: "Byzantine nodes stay silent".to_string(),
            partition: None,
            byzantine_nodes,
            expected_outcome: ExpectedOutcome::ConsensusSuccess,
        }
    }

    pub fn byzantine_double_voting(nodes: Vec<usize>) -> Self {
        let byzantine_nodes = nodes.into_iter()
            .map(|n| (n, ByzantineBehavior::DoubleVote))
            .collect();
        
        Self {
            name: "Byzantine nodes double vote".to_string(),
            partition: None,
            byzantine_nodes,
            expected_outcome: ExpectedOutcome::ConsensusTimeout,
        }
    }

    pub fn mixed_failures(
        silent_nodes: Vec<usize>, 
        double_vote_nodes: Vec<usize>,
        partition: Option<NetworkPartition>
    ) -> Self {
        let mut byzantine_nodes = vec![];
        byzantine_nodes.extend(silent_nodes.into_iter().map(|n| (n, ByzantineBehavior::Silent)));
        byzantine_nodes.extend(double_vote_nodes.into_iter().map(|n| (n, ByzantineBehavior::DoubleVote)));
        
        Self {
            name: "Mixed failure scenario".to_string(),
            partition,
            byzantine_nodes,
            expected_outcome: ExpectedOutcome::NoFinalization,
        }
    }
}

pub struct ConsensusTestHarness {
    pub context: TestContext,
    pub scenario: Option<FailureScenario>,
    pub node_states: BTreeMap<usize, NodeState>,
}

#[derive(Debug, Clone)]
pub enum NodeState {
    Healthy,
    Partitioned,
    Byzantine(ByzantineBehavior),
    Crashed,
}

impl ConsensusTestHarness {
    pub fn new(num_validators: usize) -> Self {
        let context = TestContext::new(num_validators);
        let node_states = (0..num_validators)
            .map(|i| (i, NodeState::Healthy))
            .collect();
        
        Self {
            context,
            scenario: None,
            node_states,
        }
    }

    pub fn with_failure_scenario(mut self, scenario: FailureScenario) -> Self {
        if let Some(ref partition) = scenario.partition {
            match partition {
                NetworkPartition::Isolated(nodes) => {
                    for &node in nodes {
                        self.node_states.insert(node, NodeState::Partitioned);
                    }
                }
                NetworkPartition::Split(group_a, group_b) => {
                    for &node in group_a {
                        self.node_states.insert(node, NodeState::Partitioned);
                    }
                    for &node in group_b {
                        self.node_states.insert(node, NodeState::Partitioned);
                    }
                }
            }
        }

        for (node, behavior) in &scenario.byzantine_nodes {
            self.node_states.insert(*node, NodeState::Byzantine(behavior.clone()));
        }

        self.scenario = Some(scenario);
        self
    }

    pub fn is_node_byzantine(&self, node_id: usize) -> bool {
        matches!(self.node_states.get(&node_id), Some(NodeState::Byzantine(_)))
    }

    pub fn is_node_partitioned(&self, node_id: usize) -> bool {
        matches!(self.node_states.get(&node_id), Some(NodeState::Partitioned))
    }

    pub fn healthy_node_count(&self) -> usize {
        self.node_states.values()
            .filter(|state| matches!(state, NodeState::Healthy))
            .count()
    }

    pub fn byzantine_fault_tolerance_exceeded(&self) -> bool {
        let total_nodes = self.node_states.len();
        let byzantine_count = self.node_states.values()
            .filter(|state| matches!(state, NodeState::Byzantine(_)))
            .count();
        
        byzantine_count >= total_nodes / 3
    }
}

pub fn create_consensus_failure_scenarios() -> Vec<FailureScenario> {
    vec![
        // Network partition scenarios
        FailureScenario::network_partition_minority(vec![0]),
        FailureScenario::network_partition_minority(vec![0, 1]),
        FailureScenario::network_partition_split(vec![0, 1], vec![2, 3]),
        
        // Byzantine behavior scenarios  
        FailureScenario::byzantine_silent_nodes(vec![0]),
        FailureScenario::byzantine_double_voting(vec![0]),
        FailureScenario::byzantine_double_voting(vec![0, 1]),
        
        // Mixed failure scenarios
        FailureScenario::mixed_failures(
            vec![0], // silent
            vec![1], // double vote
            Some(NetworkPartition::Isolated(vec![2]))
        ),
    ]
}