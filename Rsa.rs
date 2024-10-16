use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

const POOL_SIZE: usize = 3;
const TIMEOUT_INTERVAL: u64 = 15; // Maximal dispute time is 3 * TIMEOUT_INTERVAL

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Phase {
    None,
    Creation,
    Executing,
    ChallengeExecutor,
    ChallengeWatchdog,
    Crashed,
}

#[derive(Debug)]
struct Operator {
    initialized: bool,
    tee_signature_address: String, 
    tee_encryption_key: Vec<u8>,
}

#[derive(Debug)]
struct ContractInfo {
    phase: Phase,
    incremental_tx_hash: Vec<u8>, 
    pool_address: Option<String>,  
    creation_operator: String,     
    operators: [Option<String>; POOL_SIZE], 
    executive_operator: usize,  
    code_hash: [u8; 32],          
    fallback_phase: Phase,        
    watchdogs_challenged: u8,      
    exec_challenge_hash: Vec<u8>, 
    watchdog_challenge_hash: Vec<u8>, 
    challenged_watchdogs: [u8; POOL_SIZE], 
    deadline: u64,                
}

struct ManagerRSA {
    operators: HashMap<String, Operator>,
    operator_list: Vec<String>,
    operator_incremental_hash: Vec<u8>,
    contracts: HashMap<u32, ContractInfo>,
}

impl ManagerRSA {
    pub fn new() -> Self {
        Self {
            operators: HashMap::new(),
            operator_list: Vec::new(),
            operator_incremental_hash: vec![],
            contracts: HashMap::new(),
        }
    }

    pub fn register(
        &mut self,
        operator_address: String,
        tee_signature_address: String,
        tee_encryption_key: Vec<u8>,
        attestation_signature: Vec<u8>,
    ) {
        if self.operators.get(&operator_address).is_some() {
            panic!("Operator already registered!");
        }

        self.verify_attestation(&tee_signature_address, &tee_encryption_key, &attestation_signature);

        let operator = Operator {
            initialized: true,
            tee_signature_address,
            tee_encryption_key,
        };

        self.operators.insert(operator_address.clone(), operator);
        self.operator_list.push(operator_address.clone());

        self.operator_incremental_hash = self.hash_incremental(self.operator_incremental_hash.clone(), operator_address);
    }

    pub fn init_creation(&mut self, creation_operator: String, code_hash: [u8; 32], free_id: u32) {
        if self.contracts.get(&free_id).is_some() {
            panic!("Contract with this ID already exists!");
        }

        if !self.operators.contains_key(&creation_operator) {
            panic!("Creation operator does not exist!");
        }

        let contract = ContractInfo {
            phase: Phase::Creation,
            incremental_tx_hash: self.operator_incremental_hash.clone(),
            pool_address: None,
            creation_operator,
            operators: [None; POOL_SIZE],
            executive_operator: 0,
            code_hash,
            fallback_phase: Phase::None,
            watchdogs_challenged: 0,
            exec_challenge_hash: vec![],
            watchdog_challenge_hash: vec![],
            challenged_watchdogs: [0; POOL_SIZE],
            deadline: current_timestamp() + TIMEOUT_INTERVAL,
        };

        self.contracts.insert(free_id, contract);
    }

    pub fn finalize_creation(
        &mut self,
        id: u32,
        pool_address: String,
        pool_operators: [String; POOL_SIZE],
        signature: Vec<u8>,
    ) {
        let contract = self.contracts.get_mut(&id).unwrap();
        let signed_hash = self.create_signed_hash(
            "Creation-Attest",
            id,
            &contract.incremental_tx_hash,
            &pool_address,
            &contract.code_hash,
            &pool_operators,
        );

        let creation_operator_addr = contract.creation_operator.clone();
        let creation_operator = self.operators.get(&creation_operator_addr).unwrap();
        if !self.verify_signature(&signed_hash, &signature, &creation_operator.tee_signature_address) {
            panic!("Wrong signature for creation!");
        }

        contract.pool_address = Some(pool_address);
        contract.phase = Phase::Executing;
        contract.operators = pool_operators.map(Some);
    }

    pub fn deposit_to_contract(&mut self, id: u32, value: u64) {
        let contract = self.contracts.get_mut(&id).unwrap();
        if contract.phase != Phase::Executing {
            panic!("Contract is not in phase EXECUTING!");
        }

        // Forward the money (this is simulated in Rust)
        println!(
            "Deposited {} units to pool address: {:?}",
            value, contract.pool_address
        );
    }

    pub fn withdraw(&mut self, id: u32, blocknumber: u64, receiver: String, value: u64) {
        let contract = self.contracts.get_mut(&id).unwrap();
        if contract.pool_address.as_ref().unwrap() != &receiver {
            panic!("Sender is not the pool address!");
        }

        println!("Withdrawing {} units to {}", value, receiver);
    }

    pub fn challenge_executor(&mut self, id: u32, message: Vec<u8>) {
        let contract = self.contracts.get_mut(&id).unwrap();
        if contract.phase != Phase::Executing {
            panic!("Contract is not in phase EXECUTING!");
        }

        contract.phase = Phase::ChallengeExecutor;
        contract.deadline = current_timestamp() + TIMEOUT_INTERVAL;
        contract.watchdogs_challenged = 0;
        contract.exec_challenge_hash = self.hash_message(&message);
    }

    pub fn executor_response(
        &mut self,
        id: u32,
        response: Vec<u8>,
        signature: Vec<u8>,
    ) {
        let contract = self.contracts.get_mut(&id).unwrap();
        if contract.phase != Phase::ChallengeExecutor {
            panic!("Challenge can only be answered if unresolved!");
        }
        if contract.deadline < current_timestamp() {
            panic!("Response deadline has expired!");
        }

        let signed_hash = self.create_signed_hash(
            "Challenge-Response",
            id,
            &contract.incremental_tx_hash,
            &response,
        );

        let exec_operator_addr = contract.operators[contract.executive_operator].clone().unwrap();
        let exec_operator = self.operators.get(&exec_operator_addr).unwrap();
        if !self.verify_signature(&signed_hash, &signature, &exec_operator.tee_signature_address) {
            panic!("Wrong signature for executor response!");
        }

        contract.phase = Phase::Executing;
    }

    fn verify_attestation(&self, tee_signature_address: &str, tee_encryption_key: &[u8], attestation_signature: &[u8]) {
        // Simulated verification of attestation
        println!("Attestation verified: {} {:?}", tee_signature_address, tee_encryption_key);
    }

    fn hash_incremental(&self, previous_hash: Vec<u8>, operator_address: String) -> Vec<u8> {
        // Placeholder hash calculation (use a real hash function)
        let mut new_hash = previous_hash.clone();
        new_hash.extend(operator_address.into_bytes());
        new_hash
    }

    fn hash_message(&self, message: &[u8]) -> Vec<u8> {
        // Placeholder hash calculation for messages (use real hash function)
        let mut new_hash = vec![];
        new_hash.extend(message);
        new_hash
    }

    fn create_signed_hash(
        &self,
        tag: &str,
        id: u32,
        incremental_hash: &[u8],
        pool_address: &str,
        code_hash: &[u8; 32],
        pool_operators: &[String; POOL_SIZE],
    ) -> Vec<u8> {
        // Simulates hashing the input (replace with a proper cryptographic function)
        let mut result = Vec::new();
        result.extend(tag.as_bytes());
        result.extend(&id.to_le_bytes());
        result.extend(incremental_hash);
        result.extend(pool_address.as_bytes());
        result.extend(code_hash);
        for operator in pool_operators {
            result.extend(operator.as_bytes());
        }
        result
    }

    fn verify_signature(&self, signed_hash: &[u8], signature: &[u8], signer_address: &str) -> bool {
        // Simulated signature verification (use real crypto in production)
        println!("Verifying signature: {:?}", signature);
        true
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn main() {
    let mut manager = ManagerRSA::new();

    // Register operators
    manager.register(
        "operator1".to_string(),
        "tee_signature_address1".to_string(),
        vec![0u8; 64],
        vec![0u8; 128],
    );

    // Initialize contract creation
    manager.init_creation(
        "operator1".to_string(),
        [0
