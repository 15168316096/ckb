# CKB Security Knowledge Base

This document accumulates known attack vectors, vulnerability categories, and defense strategies specific to the CKB (Common Knowledge Base) ecosystem. It serves as a reference for security researchers, developers, and auditors working on CKB.

## Table of Contents

- [1. Consensus Layer Attacks](#1-consensus-layer-attacks)
- [2. Transaction Verification Attacks](#2-transaction-verification-attacks)
- [3. P2P Network Attacks](#3-p2p-network-attacks)
- [4. Script/VM Attacks](#4-scriptvm-attacks)
- [5. Transaction Pool Attacks](#5-transaction-pool-attacks)
- [6. DAO-Related Attacks](#6-dao-related-attacks)
- [7. Sync Protocol Attacks](#7-sync-protocol-attacks)
- [8. Defense Strategies](#8-defense-strategies)
- [9. Regression Test Coverage](#9-regression-test-coverage)

---

## 1. Consensus Layer Attacks

### 1.1 Block Timestamp Manipulation

**Description:** Miners may attempt to set block timestamps far into the future to manipulate time-dependent logic such as `since` locks.

**CKB Mitigation:** The `ALLOWED_FUTURE_BLOCKTIME` constant (15 seconds) limits how far ahead a block timestamp can be from the current time. The `TimestampVerifier` enforces this check (`BlockTimeTooNew` / `BlockTimeTooOld`).

**Related Tests:** `verification/src/tests/header_verifier.rs` — `test_timestamp_too_new`, `test_timestamp_too_old`

### 1.2 Epoch Manipulation

**Description:** Attackers attempt to create blocks with malformed or non-continuous epoch values to bypass epoch-based validation.

**CKB Mitigation:** The `EpochVerifier` checks that epoch values are well-formed and continuous relative to the parent block.

**Related Tests:** `verification/src/tests/header_verifier.rs` — `test_epoch`

### 1.3 Invalid Proof of Work

**Description:** Submitting blocks with invalid nonces that do not satisfy the PoW difficulty target.

**CKB Mitigation:** `PowVerifier` validates the nonce against the Eaglesong PoW algorithm.

**Related Tests:** `verification/src/tests/header_verifier.rs` — `test_pow_verifier`

---

## 2. Transaction Verification Attacks

### 2.1 Capacity Overflow

**Description:** Crafting transactions where the sum of output capacities exceeds the sum of input capacities, effectively creating CKB tokens from nothing.

**CKB Mitigation:** `CapacityVerifier` checks that `inputs_sum >= outputs_sum`. Additionally, each output must have sufficient capacity to cover its occupied space.

**Related Tests:** `verification/src/tests/transaction_verifier.rs` — `test_capacity_invalid`, `test_capacity_out_of_bound`

### 2.2 Duplicate Dependencies

**Description:** Including duplicate cell dependencies or header dependencies to confuse script execution or exploit indexing logic.

**CKB Mitigation:** `DuplicateDepsVerifier` rejects transactions with duplicate cell deps or header deps.

**Related Tests:** `verification/src/tests/transaction_verifier.rs` — `test_duplicate_cell_deps`, `test_duplicate_header_deps`

### 2.3 Cellbase Maturity Bypass

**Description:** Attempting to spend cellbase outputs before the maturity period to access mining rewards early.

**CKB Mitigation:** `MaturityVerifier` enforces the `cellbase_maturity` epoch requirement for both inputs and cell deps.

**Related Tests:** `verification/src/tests/transaction_verifier.rs` — `test_inputs_cellbase_maturity`, `test_deps_cellbase_maturity`

### 2.4 Since Lock Bypass

**Description:** Crafting transactions that attempt to bypass the `since` time-lock mechanism using invalid flag combinations or overflow values.

**CKB Mitigation:** `SinceVerifier` validates since flags, extracts metrics correctly, and checks both absolute and relative lock conditions.

**Related Tests:** `verification/src/tests/transaction_verifier.rs` — `test_since`, `test_invalid_since_verify`, `test_since_overflow`

### 2.5 Outputs Data Length Mismatch

**Description:** Creating transactions where the number of outputs does not match the number of output data entries.

**CKB Mitigation:** `OutputsDataVerifier` ensures `outputs.len() == outputs_data.len()`.

**Related Tests:** `verification/src/tests/transaction_verifier.rs` — `test_outputs_data_length_mismatch`

### 2.6 Invalid Script Hash Type

**Description:** Using unsupported or future script hash types in transaction outputs to potentially bypass validation.

**CKB Mitigation:** `ScriptHashTypeVerifier` checks that all script hash types in outputs are within the enabled set.

**Related Tests:** `verification/src/tests/transaction_verifier.rs` — `test_unknown_hash_type_output_lock`, `test_not_enabled_hash_type_output_lock`

---

## 3. P2P Network Attacks

### 3.1 Malformed Message Flooding

**Description:** Sending malformed or oversized protocol messages to crash nodes or consume excessive resources.

**CKB Mitigation:** Protocol message parsing with strict size limits and validation. Malformed messages result in peer disconnection.

**Related Tests:** `test/src/specs/p2p/malformed_message.rs`

### 3.2 Eclipse Attack

**Description:** An attacker monopolizes all of a node's peer connections, isolating it from the honest network.

**CKB Mitigation:** Peer discovery mechanisms, connection limits, and whitelist configurations.

**Related Tests:** `test/src/specs/p2p/` — discovery and whitelist tests

### 3.3 Sybil Attack on Peer Discovery

**Description:** Creating large numbers of fake nodes to dominate the peer network.

**CKB Mitigation:** Connection limits, peer scoring, and configurable maximum connections.

---

## 4. Script/VM Attacks

### 4.1 Cycle Exhaustion

**Description:** Submitting transactions with scripts that consume excessive VM cycles, potentially causing denial of service.

**CKB Mitigation:** Hard cycle limits per transaction (`max_cycles`). Scripts exceeding the limit are rejected.

**Related Tests:** `test/src/specs/tx_pool/` — cycle-related tests

### 4.2 VM Syscall Exploitation

**Description:** Attempting to exploit CKB-VM syscalls (spawn, exec) with malicious inputs to escape the sandbox or corrupt state.

**CKB Mitigation:** Strict syscall interface validation. Fuzzing coverage for syscall handlers.

**Related Tests:** `script/fuzz/fuzz_targets/syscall_spawn.rs`, `script/fuzz/fuzz_targets/syscall_exec.rs`

### 4.3 Script Data Corruption

**Description:** Providing corrupted or carefully crafted binary data to transaction scripts to trigger unexpected behavior.

**CKB Mitigation:** Fuzzing coverage via libfuzzer targets for transaction script verification.

**Related Tests:** `script/fuzz/fuzz_targets/transaction_scripts_verifier_data*.rs`

---

## 5. Transaction Pool Attacks

### 5.1 Transaction Pool Flooding (DoS)

**Description:** Flooding the transaction pool with many low-fee transactions to prevent legitimate transactions from being processed.

**CKB Mitigation:** Transaction pool size limits, fee-based prioritization, and rate limiting.

### 5.2 Dead Cell Reference

**Description:** Submitting transactions that reference already-consumed cells to probe pool state or cause errors.

**CKB Mitigation:** Cell liveness checking during transaction pool admission.

**Related Tests:** `test/src/specs/tx_pool/dead_cell_deps.rs`

### 5.3 Orphan Transaction Exploitation

**Description:** Sending transactions whose parent transactions are not yet known, potentially filling up orphan pools.

**CKB Mitigation:** Limited orphan pool size with eviction policies.

**Related Tests:** `test/src/specs/tx_pool/orphan_tx.rs`

### 5.4 Transaction Collision

**Description:** Submitting transactions that conflict with each other (spending the same cells) to exploit race conditions.

**CKB Mitigation:** Conflict detection in the transaction pool.

**Related Tests:** `test/src/specs/tx_pool/collision.rs`

---

## 6. DAO-Related Attacks

### 6.1 DAO Lock Script Size Manipulation

**Description:** Changing the lock script size during DAO withdrawal to potentially extract more capacity than deposited.

**CKB Mitigation:** `DaoScriptSizeVerifier` enforces that DAO withdrawal lock script sizes match between deposit and withdrawal phases (after the limiting block number).

**Related Tests:** `verification/src/tests/transaction_verifier.rs` — `test_dao_disables_different_lock_script_size`

### 6.2 DAO Capacity Bypass

**Description:** Attempting to bypass DAO capacity checks to withdraw more than deposited.

**CKB Mitigation:** DAO capacity is verified via dedicated type scripts and the `DaoCalculator`.

**Related Tests:** `verification/src/tests/transaction_verifier.rs` — `test_skip_dao_capacity_check`

---

## 7. Sync Protocol Attacks

### 7.1 Invalid Block Propagation

**Description:** Broadcasting invalid blocks to waste peers' verification resources or cause chain splits.

**CKB Mitigation:** Full block verification before acceptance. Invalid blocks result in peer penalties.

**Related Tests:** `test/src/specs/sync/invalid_block.rs`

### 7.2 Chain Fork Attacks

**Description:** Maintaining a secret longer chain and releasing it to cause a reorganization, potentially enabling double-spend.

**CKB Mitigation:** NC-Max consensus protocol with orphan rate adjustment. Block verification depth limits.

**Related Tests:** `test/src/specs/sync/` — fork and reorganization tests

---

## 8. Defense Strategies

### 8.1 Multi-Layer Verification

CKB employs a layered verification architecture:
- **Non-contextual verification**: Checks that can be performed without chain context (format, size limits, duplicate detection)
- **Contextual verification**: Checks requiring chain state (capacity, maturity, since locks)
- **Script verification**: CKB-VM execution of lock/type scripts

### 8.2 Continuous Fuzzing

Fuzzing targets in `script/fuzz/` provide ongoing coverage for:
- Transaction script verification with arbitrary binary data
- VM syscall handling (spawn, exec)
- Edge cases in script execution

### 8.3 Automated Security Audits

- Daily `cargo deny` checks for known vulnerabilities in dependencies (`.github/workflows/scheduled_audit.yaml`)
- Regression test workflow for core verification modules (`.github/workflows/ci_regression_tests.yaml`)

### 8.4 Peer Scoring and Banning

Peers that send invalid data or exhibit malicious behavior are scored and eventually banned, protecting nodes from persistent attackers.

---

## 9. Regression Test Coverage

The following modules have dedicated regression tests to prevent security regressions:

| Module | Test Location | Key Attack Vectors Covered |
|--------|--------------|---------------------------|
| Block Verification | `verification/src/tests/block_verifier.rs` | Cellbase manipulation, duplicates, merkle root, size limits |
| Transaction Verification | `verification/src/tests/transaction_verifier.rs` | Capacity overflow, since bypass, maturity bypass, hash type attacks |
| Header Verification | `verification/src/tests/header_verifier.rs` | Timestamp manipulation, epoch manipulation, PoW attacks |
| Genesis Verification | `verification/src/tests/genesis_verifier.rs` | Genesis block integrity |
| P2P Protocol | `test/src/specs/p2p/` | Malformed messages, discovery attacks |
| Transaction Pool | `test/src/specs/tx_pool/` | Flooding, orphans, collisions, dead cells |
| Sync Protocol | `test/src/specs/sync/` | Invalid blocks, fork attacks |
| Script Execution | `script/fuzz/` | VM syscall exploitation, data corruption |

---

## Contributing

When discovering new attack vectors or vulnerabilities:

1. Follow the [security policy](../SECURITY.md) for responsible disclosure
2. Add regression tests to the appropriate test module
3. Update this knowledge base with the new attack vector and mitigation
4. Ensure the regression test workflow covers the new test cases
