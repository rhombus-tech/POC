use std::collections::HashMap;
use sha2::{Sha256, Digest};

// Constants
const POOL_SIZE: usize = 3;
const TIMEOUT_INTERVAL: u64 = 15;  // Maximal dispute time is 3 * TIMEOUT_INTERVAL

// Enums for different phases of the contract
#[derive(Debug, PartialEq, Eq, Clone)]
enum Phase {
    None,
    Creation,
    Executing,
    ChallengeExecutor,
    ChallengeWatchdog,
    Crashed,
}

// Structure to hold information about the contract
#[derive(Debug)]
struct Contract {
    phase: Phase,
    incremental_tx_hash: Vec<u8>,
    pool_address: Option<String>,
    creation_operator: String,
    operators: [Option<String>; POOL_SIZE],
    executive_operator: usize,
    code_hash: Vec<u8>,
    fallback_phase: Phase,
    watchdogs_challenged: u8,
    exec_challenge_hash: Vec<u8>,
    watchdog_challenge_hash: Vec<u8>,
    challenged_watchdogs: [u8; POOL_SIZE],
    deadline: u64,
}

// Structure to hold operator information
#[derive(Debug)]
struct Operator {
    initialized: bool,
    tee_signature_address: String,
    tee_encryption_key: Vec<u8>,
}

// Manager manages contracts and operators
struct Manager {
    contracts: HashMap<u128, Contract>,
    operators: HashMap<String, Operator>,
    operator_incremental_hash: Vec<u8>,
}

impl Manager {
    pub fn new() -> Self {
        Manager {
            contracts: HashMap::new(),
            operators: HashMap::new(),
            operator_incremental_hash: vec![0u8; 32],  // Initialize with a 32-byte 0 hash
        }
    }

    pub fn init_creation(
        &mut self,
        id: u128,
        creation_operator: String,
        code_hash: Vec<u8>,
        pool_operators: [String; POOL_SIZE],
    ) {
        let contract = Contract {
            phase: Phase::Creation,
            incremental_tx_hash: self.operator_incremental_hash.clone(),
            pool_address: None,
            creation_operator: creation_operator.clone(),
            operators: pool_operators.map(Some),
            executive_operator: 0,
            code_hash,
            fallback_phase: Phase::None,
            watchdogs_challenged: 0,
            exec_challenge_hash: vec![],
            watchdog_challenge_hash: vec![],
            challenged_watchdogs: [0; POOL_SIZE],
            deadline: Self::get_current_time() + TIMEOUT_INTERVAL,
        };

        self.contracts.insert(id, contract);
    }

    pub fn finalize_creation(
        &mut self,
        id: u128,
        pool_address: String,
        pool_operators: [String; POOL_SIZE],
        signature: Vec<u8>,
    ) {
        let contract = self.contracts.get_mut(&id).expect("Contract not found");

        // Check contract is in the right phase and within the deadline
        if contract.phase != Phase::Creation {
            panic!("Contract is not in the creation phase!");
        }
        if contract.deadline < Self::get_current_time() {
            panic!("The creation deadline has expired!");
        }

        let signed_hash = self.calculate_signed_hash(id, &contract.incremental_tx_hash, &pool_address, &contract.code_hash, &pool_operators);

        // Check the signature (dummy function in this example)
        if !self.verify_signature(&signed_hash, &signature, &contract.creation_operator) {
            panic!("Wrong signature for creation!");
        }

        // Update state
        contract.pool_address = Some(pool_address);
        contract.phase = Phase::Executing;
        contract.operators = pool_operators.map(Some);

        // Notify clients (emit event, here we just print a message)
        println!("Contract {} created successfully!", id);
    }

    pub fn deposit_to_contract(&mut self, id: u128, amount: u64) {
        let contract = self.contracts.get_mut(&id).expect("Contract not found");

        // Ensure contract is in the Executing phase
        if contract.phase != Phase::Executing {
            panic!("Contract is not in the executing phase!");
        }

        // Forward the funds to the pool address (simulation)
        println!("Deposited {} to pool address {}", amount, contract.pool_address.clone().unwrap());
    }

    pub fn withdraw(&mut self, id: u128, receiver: String, amount: u64) {
        let contract = self.contracts.get_mut(&id).expect("Contract not found");

        // Ensure the sender is the pool and the contract is in the right phase
        if receiver != contract.pool_address.clone().unwrap() {
            panic!("Sender is not the pool address!");
        }

        // Forward funds to the receiver (simulation)
        println!("Withdrawn {} to receiver {}", amount, receiver);
    }

    pub fn challenge_executor(&mut self, id: u128, message: Vec<u8>) {
        let contract = self.contracts.get_mut(&id).expect("Contract not found");

        // Ensure the contract is in the executing phase
        if contract.phase != Phase::Executing {
            panic!("Contract is not in the executing phase!");
        }

        // Update state to executor challenge phase
        contract.phase = Phase::ChallengeExecutor;
        contract.deadline = Self::get_current_time() + TIMEOUT_INTERVAL;
        contract.exec_challenge_hash = Self::hash_message(&message);

        // Notify clients
        println!("Executor challenged on contract {}!", id);
    }

    pub fn executor_response(&mut self, id: u128, response: Vec<u8>, signature: Vec<u8>) {
        let contract = self.contracts.get_mut(&id).expect("Contract not found");

        // Ensure the contract is in the challenge phase and within the deadline
        if contract.phase != Phase::ChallengeExecutor {
            panic!("No active challenge to respond to!");
        }
        if contract.deadline < Self::get_current_time() {
            panic!("Response deadline has expired!");
        }

        let signed_hash = Self::calculate_executor_signed_hash(id, &contract.incremental_tx_hash, &response);

        // Check signature (dummy function here)
        if !self.verify_signature(&signed_hash, &signature, &contract.operators[contract.executive_operator].clone().unwrap()) {
            panic!("Wrong signature for executor response!");
        }

        // Return to Executing phase
        contract.phase = Phase::Executing;

        // Notify clients
        println!("Executor responded on contract {}!", id);
    }

    // Internal helper functions
    fn calculate_signed_hash(
        &self,
        id: u128,
        incremental_tx_hash: &Vec<u8>,
        pool_address: &String,
        code_hash: &Vec<u8>,
        pool_operators: &[String; POOL_SIZE],
    ) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update("Creation-Attest");
        hasher.update(id.to_le_bytes());
        hasher.update(incremental_tx_hash);
        hasher.update(pool_address.as_bytes());
        hasher.update(code_hash);
        for operator in pool_operators {
            hasher.update(operator.as_bytes());
        }
        hasher.finalize().to_vec()
    }

    fn calculate_executor_signed_hash(id: u128, incremental_tx_hash: &Vec<u8>, response: &Vec<u8>) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update("Challenge-Response");
        hasher.update(id.to_le_bytes());
        hasher.update(incremental_tx_hash);
        hasher.update(response);
        hasher.finalize().to_vec()
    }

    fn verify_signature(&self, _hash: &Vec<u8>, _signature: &Vec<u8>, _operator: &String) -> bool {
        // Placeholder for real signature verification logic
        true
    }

    fn hash_message(message: &Vec<u8>) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(message);
        hasher.finalize().to_vec()
    }

    fn get_current_time() -> u64 {
        // Placeholder for getting the current time in seconds
        1000000
    }
}

fn main() {
    let mut manager = Manager::new();

    // Example usage
    let id = 1;
    let creation_operator = String::from("operator1");
    let code_hash = vec![0x12, 0x34];
    let pool_operators = [String::from("op1"), String::from("op2"), String::from("op3")];

    manager.init_creation(id, creation_operator.clone(), code_hash.clone(), pool_operators);

    let pool_address = String::from("pool_address_1");
    let signature = vec![0xAA, 0xBB, 0xCC];
    manager.finalize_creation(id, pool_address.clone(), pool_operators, signature.clone());

    let deposit_amount = 100;
    manager.deposit_to_contract(id, deposit_amount);

    let receiver = String::from("receiver1");
    manager.withdraw(id, receiver.clone(), 50);

    let challenge_message = vec![0x01, 0x02, 0x03];
    manager.challenge_executor(id, challenge_message.clone());

    let response_message = vec![0x04, 0x05];
    manager.executor_response(id, response_message.clone(), signature);
}
