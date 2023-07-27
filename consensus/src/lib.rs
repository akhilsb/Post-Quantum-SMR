// Copyright(C) Facebook, Inc. and its affiliates.
use config::{Committee, Stake};
use crypto::Hash as _;
use crypto::{Digest0, PublicKey};
//use glow_lib::node::GlowLib;
use hashrand::node::HashRand;
//use hashrand::node::HashRand;
use hnode::Node;
use log::{debug, info, log_enabled, warn};
use primary::{Certificate, Round};
use std::cmp::max;
use std::collections::{HashMap, HashSet};
use tokio::sync::mpsc::{Receiver, Sender, channel};
use signal_hook::consts::SIGINT;
use signal_hook::consts::SIGTERM;
use signal_hook::iterator::Signals;

#[cfg(test)]
#[path = "tests/consensus_tests.rs"]
pub mod consensus_tests;

/// The representation of the DAG in memory.
type Dag = HashMap<Round, HashMap<PublicKey, (Digest0, Certificate)>>;

/// The state that needs to be persisted for crash-recovery.
struct State {
    /// The last committed round.
    last_committed_round: Round,
    // Keeps the last committed round for each authority. This map is used to clean up the dag and
    // ensure we don't commit twice the same certificate.
    last_committed: HashMap<PublicKey, Round>,
    /// Keeps the latest committed certificate (and its parents) for every authority. Anything older
    /// must be regularly cleaned up through the function `update`.
    dag: Dag,
}

impl State {
    fn new(genesis: Vec<Certificate>) -> Self {
        let genesis = genesis
            .into_iter()
            .map(|x| (x.origin(), (x.digest(), x)))
            .collect::<HashMap<_, _>>();

        Self {
            last_committed_round: 0,
            last_committed: genesis.iter().map(|(x, (_, y))| (x.clone(), y.round())).collect(),
            dag: [(0, genesis)].iter().cloned().collect(),
        }
    }

    /// Update and clean up internal state base on committed certificates.
    fn update(&mut self, certificate: &Certificate, gc_depth: Round) {
        self.last_committed
            .entry(certificate.origin())
            .and_modify(|r| *r = max(*r, certificate.round()))
            .or_insert_with(|| certificate.round());

        let last_committed_round = *self.last_committed.values().max().unwrap();
        self.last_committed_round = last_committed_round;

        // TODO: This cleanup is dangerous: we need to ensure consensus can receive idempotent replies
        // from the primary. Here we risk cleaning up a certificate and receiving it again later.
        for (name, round) in &self.last_committed {
            self.dag.retain(|r, authorities| {
                authorities.retain(|n, _| n != name || r >= round);
                !authorities.is_empty() && r + gc_depth >= last_committed_round
            });
        }
    }
}

pub struct Consensus {
    /// The committee information.
    committee: Committee,
    /// The depth of the garbage collector.
    gc_depth: Round,

    /// Receives new certificates from the primary. The primary should send us new certificates only
    /// if it already sent us its whole history.
    rx_primary: Receiver<Certificate>,
    /// Outputs the sequence of ordered certificates to the primary (for cleanup and feedback).
    tx_primary: Sender<Certificate>,
    /// Outputs the sequence of ordered certificates to the application layer.
    tx_output: Sender<Certificate>,

    /// The genesis certificates.
    genesis: Vec<Certificate>,
    /// HashRand based coin construct and receive channels
    beacon_reconstruct_queue: Sender<u32>,
    beacon_queue: Receiver<(u32,u128)>,

    beacon_map: HashMap<u32,u128>
}

impl Consensus {
    pub fn spawn(
        committee: Committee,
        gc_depth: Round,
        rx_primary: Receiver<Certificate>,
        tx_primary: Sender<Certificate>,
        tx_output: Sender<Certificate>,
        (config_str,config,_batch,_frequency): (&str,Node,usize,u32)
    ) {
        let _exit_tx;
        let (coin_construct,coin_const_recv) = channel(10000);
        let (coin_send, coin_recv) = channel(10000);
        tokio::spawn(async move { 
            Self {
                committee: committee.clone(),
                gc_depth,
                rx_primary,
                tx_primary,
                tx_output,
                genesis: Certificate::genesis(&committee),
                beacon_reconstruct_queue:coin_construct,
                beacon_queue:coin_recv,
                beacon_map:HashMap::default(),
            }
            .run()
            .await;
        });
        let mut arr_strsplit:Vec<&str> = config_str.split("/").collect();
        let id_str = ((config.id +1)).to_string();
        let key_str = "key".to_string();
        let concat_str = key_str + &id_str;
        let _last_elem = arr_strsplit.pop();
        arr_strsplit.push(concat_str.as_str());
        // _exit_tx = GlowLib::spawn(
        //     config, 
        //     arr_strsplit.join("/").as_str(),
        //     coin_const_recv,
        //     coin_send
        // ).unwrap();
        _exit_tx = HashRand::spawn(
            config, 
            0, 
            _batch, 
            _frequency, 
            coin_const_recv, 
            coin_send
        ).unwrap();
        let mut signals = Signals::new(&[SIGINT, SIGTERM]).unwrap();
        signals.forever().next();
        log::error!("Received termination signal");
    }

    async fn run(&mut self) {
        // The consensus state (everything else is immutable).
        let mut state = State::new(self.genesis.clone());
        debug!("Requesting HashRand beacon for round {}",0);
        if let Err(e) = self.beacon_reconstruct_queue.send(0 as u32).await {
            log::warn!(
                "Failed to request a beacon for leader election of round {} because of error {}",
                0,e
            );
        }
        // Listen to incoming certificates.
        loop {
            tokio::select! {
                cert = self.rx_primary.recv() => {
                    match cert{
                        Some(certificate)=>{
                            log::error!("Processing {:?}", certificate);
                            let round = certificate.round();
                
                            // Add the new certificate to the local storage.
                            state
                                .dag
                                .entry(round)
                                .or_insert_with(HashMap::new)
                                .insert(certificate.origin(), (certificate.digest(), certificate));
                            
                            let r = round-1;
                            // request leader election for beacon id r/2
                            if r % 2 == 0 && r > 4 && !self.beacon_map.contains_key(&((r/2) as u32)){
                                log::error!("Requesting HashRand beacon for round {}",r/2);
                                if let Err(e) = self.beacon_reconstruct_queue.send((r/2) as u32).await {
                                    log::warn!(
                                        "Failed to request a beacon for leader election of round {} because of error {}",
                                        r/2,e
                                    );
                                }
                                self.beacon_map.insert((r/2) as u32,0);
                            }
                            else if self.beacon_map.contains_key(&((r/2) as u32)){
                                let beacon = self.beacon_map.get(&((r/2) as u32)).unwrap();
                                if beacon.clone() > 0{
                                    self.beacon_output((((r/2) as u32),*beacon), &mut state).await;
                                }
                            }
                        },
                        None => {
                            warn!("Consensus receive error received");
                        }
                    }
                },
                beacon = self.beacon_queue.recv() =>{
                    match beacon {
                        Some(beacon_tup)=>{
                            self.beacon_output(beacon_tup, &mut state).await;
                        },
                        None=>{}
                    }
                }
            }
        }
    }

    async fn beacon_output(&mut self,beacon_tup:(u32,u128),state:&mut State){
        log::info!("Received Beacon from HashRand {:?}",beacon_tup.clone());
        // Try to order the dag to commit. Start from the highest round for which we have at least
        // 2f+1 certificates. This is because we need them to reveal the common coin.
        let r = 2*beacon_tup.0 as u64;
        self.beacon_map.insert((r/2) as u32,beacon_tup.1);
        // Get the certificate's digest of the leader of round r-2. If we already ordered this leader,
        // there is nothing to do.
        let leader_round = r - 2;
        if leader_round <= state.last_committed_round {
            return;
        }
        let (leader_digest, leader) = match self.leader(leader_round,beacon_tup.1.clone(), &state.dag) {
            Some(x) => x,
            None => return,
        };
        if !state.dag.contains_key(&(r-1)){
            log::warn!("Certificate did not reach this point yet {}",r-1);
            return;
        }
        // Check if the leader has f+1 support from its children (ie. round r-1).
        let stake: Stake = state
            .dag
            .get(&(r - 1))
            .expect("We should have the whole history by now")
            .values()
            .filter(|(_, x)| x.header.parents.contains(&leader_digest))
            .map(|(_, x)| self.committee.stake(&x.origin()))
            .sum();

        // If it is the case, we can commit the leader. But first, we need to recursively go back to
        // the last committed leader, and commit all preceding leaders in the right order. Committing
        // a leader block means committing all its dependencies.
        if stake < self.committee.validity_threshold() {
            debug!("Leader {:?} does not have enough support", leader);
            return;
        }

        // Get an ordered list of past leaders that are linked to the current leader.
        debug!("Leader {:?} has enough support", leader);
        let mut sequence = Vec::new();
        for leader in self.order_leaders(leader,beacon_tup.1.clone(), &state).iter().rev() {
            // Starting from the oldest leader, flatten the sub-dag referenced by the leader.
            for x in self.order_dag(leader, &state) {
                // Update and clean up internal state.
                state.update(&x, self.gc_depth);

                // Add the certificate to the sequence.
                sequence.push(x);
            }
        }

        // Log the latest committed round of every authority (for debug).
        if log_enabled!(log::Level::Debug) {
            for (name, round) in &state.last_committed {
                debug!("Latest commit of {}: Round {}", name, round);
            }
        }

        // Output the sequence in the right order.
        for certificate in sequence {
            #[cfg(not(feature = "benchmark"))]
            info!("Committed {}", certificate.header);

            #[cfg(feature = "benchmark")]
            for digest in certificate.header.payload.keys() {
                // NOTE: This log entry is used to compute performance.
                info!("Committed {} -> {:?}", certificate.header, digest);
            }

            self.tx_primary
                .send(certificate.clone())
                .await
                .expect("Failed to send certificate to primary");

            if let Err(e) = self.tx_output.send(certificate).await {
                warn!("Failed to output certificate: {}", e);
            }
        }
    }
    /// Returns the certificate (and the certificate's digest) originated by the leader of the
    /// specified round (if any).
    fn leader<'a>(&self, round: Round,beacon:u128, dag: &'a Dag) -> Option<&'a (Digest0, Certificate)> {
        // TODO: We should elect the leader of round r-2 using the common coin revealed at round r.
        // At this stage, we are guaranteed to have 2f+1 certificates from round r (which is enough to
        // compute the coin). We currently just use round-robin.
        // #[cfg(test)]
        // let coin = 0;
        // #[cfg(not(test))]
        // let coin = round;

        // Elect the leader.
        let mut keys: Vec<_> = self.committee.authorities.keys().cloned().collect();
        keys.sort();
        let leader = keys[beacon as usize % self.committee.size()].clone();

        // Return its certificate and the certificate's digest.
        dag.get(&round).map(|x| x.get(&leader)).flatten()
    }

    /// Order the past leaders that we didn't already commit.
    fn order_leaders(&self, leader: &Certificate,beacon:u128, state: &State) -> Vec<Certificate> {
        let mut to_commit = vec![leader.clone()];
        let mut leader = leader;
        for r in (state.last_committed_round + 2..=leader.round() - 2)
            .rev()
            .step_by(2)
        {
            // Get the certificate proposed by the previous leader.
            let (_, prev_leader) = match self.leader(r,beacon, &state.dag) {
                Some(x) => x,
                None => continue,
            };

            // Check whether there is a path between the last two leaders.
            if self.linked(leader, prev_leader, &state.dag) {
                to_commit.push(prev_leader.clone());
                leader = prev_leader;
            }
        }
        to_commit
    }

    /// Checks if there is a path between two leaders.
    fn linked(&self, leader: &Certificate, prev_leader: &Certificate, dag: &Dag) -> bool {
        let mut parents = vec![leader];
        for r in (prev_leader.round()..leader.round()).rev() {
            parents = dag
                .get(&(r))
                .expect("We should have the whole history by now")
                .values()
                .filter(|(digest, _)| parents.iter().any(|x| x.header.parents.contains(digest)))
                .map(|(_, certificate)| certificate)
                .collect();
        }
        parents.contains(&prev_leader)
    }

    /// Flatten the dag referenced by the input certificate. This is a classic depth-first search (pre-order):
    /// https://en.wikipedia.org/wiki/Tree_traversal#Pre-order
    fn order_dag(&self, leader: &Certificate, state: &State) -> Vec<Certificate> {
        debug!("Processing sub-dag of {:?}", leader);
        let mut ordered = Vec::new();
        let mut already_ordered = HashSet::new();

        let mut buffer = vec![leader];
        while let Some(x) = buffer.pop() {
            debug!("Sequencing {:?}", x);
            ordered.push(x.clone());
            for parent in &x.header.parents {
                let (digest, certificate) = match state
                    .dag
                    .get(&(x.round() - 1))
                    .map(|x| x.values().find(|(x, _)| x == parent))
                    .flatten()
                {
                    Some(x) => x,
                    None => continue, // We already ordered or GC up to here.
                };

                // We skip the certificate if we (1) already processed it or (2) we reached a round that we already
                // committed for this authority.
                let mut skip = already_ordered.contains(&digest);
                skip |= state
                    .last_committed
                    .get(&certificate.origin())
                    .map_or_else(|| false, |r| r == &certificate.round());
                if !skip {
                    buffer.push(certificate);
                    already_ordered.insert(digest);
                }
            }
        }

        // Ensure we do not commit garbage collected certificates.
        ordered.retain(|x| x.round() + self.gc_depth >= state.last_committed_round);

        // Ordering the output by round is not really necessary but it makes the commit sequence prettier.
        ordered.sort_by_key(|x| x.round());
        ordered
    }
}
