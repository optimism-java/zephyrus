const std = @import("std");
const primitives = @import("../../primitives/types.zig");
const consensus = @import("../../consensus/types.zig");
const configs = @import("../../configs/config.zig");
const constants = @import("../../primitives/constants.zig");
const preset = @import("../../presets/preset.zig");
const phase0 = @import("../../consensus/phase0/types.zig");
const altair = @import("../../consensus/altair/types.zig");
const bellatrix = @import("../../consensus/bellatrix/types.zig");
const capella = @import("../../consensus/capella/types.zig");
const electra = @import("../../consensus/electra/types.zig");
const deneb = @import("../../consensus/deneb/types.zig");
const validator_helper = @import("../../consensus/helpers/validator.zig");
const ssz = @import("../../ssz/ssz.zig");

pub fn isValidGenesisState(state: *const consensus.BeaconState, allocator: std.mem.Allocator) !bool {
    if (state.genesisTime() < configs.ActiveConfig.get().MIN_GENESIS_TIME) {
        return false;
    }
    const indices = try validator_helper.getActiveValidatorIndices(state, constants.GENESIS_EPOCH, allocator);
    if (indices.len < configs.ActiveConfig.get().MIN_GENESIS_ACTIVE_VALIDATOR_COUNT) {
        return false;
    }
    return true;
}

pub fn initializeBeaconStateFromEth1(
    fork_type: primitives.ForkType,
    eth1_block_hash: primitives.Hash32,
    eth1_timestamp: u64,
    deposits: []const consensus.Deposit,
    execution_payload_header: ?consensus.ExecutionPayloadHeader,
    allocator: std.mem.Allocator,
) !consensus.BeaconState {
    if (execution_payload_header == null) {}
    const fork = switch (fork_type) {
        .phase0 => consensus.Fork{
            .previous_version = configs.ActiveConfig.get().GENESIS_FORK_VERSION,
            .current_version = configs.ActiveConfig.get().GENESIS_FORK_VERSION,
            .epoch = constants.GENESIS_EPOCH,
        },
        .altair => consensus.Fork{
            .previous_version = configs.ActiveConfig.get().ALTAIR_FORK_VERSION,
            .current_version = configs.ActiveConfig.get().ALTAIR_FORK_VERSION,
            .epoch = constants.GENESIS_EPOCH,
        },
        .bellatrix => consensus.Fork{
            .previous_version = configs.ActiveConfig.get().BELLATRIX_FORK_VERSION,
            .current_version = configs.ActiveConfig.get().BELLATRIX_FORK_VERSION,
            .epoch = constants.GENESIS_EPOCH,
        },
        .capella => consensus.Fork{
            .previous_version = configs.ActiveConfig.get().CAPELLA_FORK_VERSION,
            .current_version = configs.ActiveConfig.get().CAPELLA_FORK_VERSION,
            .epoch = constants.GENESIS_EPOCH,
        },
        .deneb => consensus.Fork{
            .previous_version = configs.ActiveConfig.get().DENEB_FORK_VERSION,
            .current_version = configs.ActiveConfig.get().DENEB_FORK_VERSION,
            .epoch = constants.GENESIS_EPOCH,
        },
        .electra => consensus.Fork{
            .previous_version = configs.ActiveConfig.get().ELECTRA_FORK_VERSION,
            .current_version = configs.ActiveConfig.get().ELECTRA_FORK_VERSION,
            .epoch = constants.GENESIS_EPOCH,
        },
    };

    const beacon_block_body = switch (fork_type) {
        .phase0 => consensus.BeaconBlockBody{
            .phase0 = std.mem.zeroes(phase0.BeaconBlockBody),
        },
        .altair => consensus.BeaconBlockBody{
            .altair = std.mem.zeroInit(altair.BeaconBlockBody, .{
                .sync_aggregate = undefined,
            }),
        },
        .bellatrix => consensus.BeaconBlockBody{
            .bellatrix = std.mem.zeroInit(bellatrix.BeaconBlockBody, .{
                .sync_aggregate = undefined,
                .execution_payload = undefined,
            }),
        },
        .capella => consensus.BeaconBlockBody{
            .capella = std.mem.zeroInit(capella.BeaconBlockBody, .{
                .sync_aggregate = undefined,
                .execution_payload = undefined,
            }),
        },
        .deneb, .electra => consensus.BeaconBlockBody{
            .deneb = std.mem.zeroInit(deneb.BeaconBlockBody, .{
                .sync_aggregate = undefined,
                .execution_payload = undefined,
            }),
        },
    };

    var body_root: primitives.Root = undefined;
    try ssz.hashTreeRoot(beacon_block_body, &body_root, allocator);

    const randao_mixes_slice = try allocator.alloc(primitives.Bytes32, preset.ActivePreset.get().EPOCHS_PER_HISTORICAL_VECTOR);
    @memset(randao_mixes_slice, eth1_block_hash);
    const state = switch (fork_type) {
        .phase0 => consensus.BeaconState{
            .phase0 = phase0.BeaconState{
                .genesis_time = eth1_timestamp + configs.ActiveConfig.get().GENESIS_DELAY,
                .fork = fork,
                .eth1_data = consensus.Eth1Data{
                    .block_hash = eth1_block_hash,
                    .deposit_count = @as(u64, deposits.len),
                    .deposit_root = undefined,
                },
                .latest_block_header = consensus.BeaconBlockHeader{
                    .body_root = body_root,
                    .parent_root = undefined,
                    .state_root = undefined,
                    .proposer_index = 0,
                    .slot = 0,
                },
                .randao_mixes = randao_mixes_slice,
                .genesis_validators_root = undefined,
                .slot = 0,
                .block_roots = undefined,
                .state_roots = undefined,
                .historical_roots = undefined,
                .eth1_data_votes = undefined,
                .eth1_deposit_index = undefined,
                .validators = undefined,
                .balances = undefined,
                .slashings = undefined,
                .previous_epoch_attestations = undefined,
                .current_epoch_attestations = undefined,
                .justification_bits = undefined,
                .previous_justified_checkpoint = undefined,
                .current_justified_checkpoint = undefined,
                .finalized_checkpoint = undefined,
            },
        },
        .altair => consensus.BeaconState{
            .altair = altair.BeaconState{
                .genesis_time = eth1_timestamp + configs.ActiveConfig.get().GENESIS_DELAY,
                .fork = fork,
                .eth1_data = consensus.Eth1Data{
                    .block_hash = eth1_block_hash,
                    .deposit_count = @as(u64, deposits.len),
                    .deposit_root = undefined,
                },
                .latest_block_header = consensus.BeaconBlockHeader{
                    .body_root = body_root,
                    .parent_root = undefined,
                    .state_root = undefined,
                    .proposer_index = 0,
                    .slot = 0,
                },
                .randao_mixes = randao_mixes_slice,
                .genesis_validators_root = undefined,
                .slot = 0,
                .block_roots = undefined,
                .state_roots = undefined,
                .historical_roots = undefined,
                .eth1_data_votes = undefined,
                .eth1_deposit_index = undefined,
                .validators = undefined,
                .balances = undefined,
                .slashings = undefined,
                .previous_epoch_attestations = undefined,
                .current_epoch_attestations = undefined,
                .justification_bits = undefined,
                .previous_justified_checkpoint = undefined,
                .current_justified_checkpoint = undefined,
                .finalized_checkpoint = undefined,
                .inactivity_scores = undefined,
                .current_sync_committee = undefined,
                .next_sync_committee = undefined,
            },
        },
        .bellatrix => consensus.BeaconState{
            .bellatrix = bellatrix.BeaconState{
                .genesis_time = eth1_timestamp + configs.ActiveConfig.get().GENESIS_DELAY,
                .fork = fork,
                .eth1_data = consensus.Eth1Data{
                    .block_hash = eth1_block_hash,
                    .deposit_count = @as(u64, deposits.len),
                    .deposit_root = undefined,
                },
                .latest_block_header = consensus.BeaconBlockHeader{
                    .body_root = body_root,
                    .parent_root = undefined,
                    .state_root = undefined,
                    .proposer_index = 0,
                    .slot = 0,
                },
                .randao_mixes = randao_mixes_slice,
                .genesis_validators_root = undefined,
                .slot = 0,
                .block_roots = undefined,
                .state_roots = undefined,
                .historical_roots = undefined,
                .eth1_data_votes = undefined,
                .eth1_deposit_index = undefined,
                .validators = undefined,
                .balances = undefined,
                .slashings = undefined,
                .previous_epoch_attestations = undefined,
                .current_epoch_attestations = undefined,
                .justification_bits = undefined,
                .previous_justified_checkpoint = undefined,
                .current_justified_checkpoint = undefined,
                .finalized_checkpoint = undefined,
                .inactivity_scores = undefined,
                .current_sync_committee = undefined,
                .next_sync_committee = undefined,
                .latest_execution_payload_header = undefined,
            },
        },
        .capella => consensus.BeaconState{
            .capella = capella.BeaconState{
                .genesis_time = eth1_timestamp + configs.ActiveConfig.get().GENESIS_DELAY,
                .fork = fork,
                .eth1_data = consensus.Eth1Data{
                    .block_hash = eth1_block_hash,
                    .deposit_count = @as(u64, deposits.len),
                    .deposit_root = undefined,
                },
                .latest_block_header = consensus.BeaconBlockHeader{
                    .body_root = body_root,
                    .parent_root = undefined,
                    .state_root = undefined,
                    .proposer_index = 0,
                    .slot = 0,
                },
                .randao_mixes = randao_mixes_slice,
                .genesis_validators_root = undefined,
                .slot = 0,
                .block_roots = undefined,
                .state_roots = undefined,
                .historical_roots = undefined,
                .eth1_data_votes = undefined,
                .eth1_deposit_index = undefined,
                .validators = undefined,
                .balances = undefined,
                .slashings = undefined,
                .previous_epoch_attestations = undefined,
                .current_epoch_attestations = undefined,
                .justification_bits = undefined,
                .previous_justified_checkpoint = undefined,
                .current_justified_checkpoint = undefined,
                .finalized_checkpoint = undefined,
                .inactivity_scores = undefined,
                .current_sync_committee = undefined,
                .next_sync_committee = undefined,
                .latest_execution_payload_header = undefined,
                .historical_summaries = undefined,
            },
        },
        .deneb => consensus.BeaconState{
            .deneb = capella.BeaconState{
                .genesis_time = eth1_timestamp + configs.ActiveConfig.get().GENESIS_DELAY,
                .fork = fork,
                .eth1_data = consensus.Eth1Data{
                    .block_hash = eth1_block_hash,
                    .deposit_count = @as(u64, deposits.len),
                    .deposit_root = undefined,
                },
                .latest_block_header = consensus.BeaconBlockHeader{
                    .body_root = body_root,
                    .parent_root = undefined,
                    .state_root = undefined,
                    .proposer_index = 0,
                    .slot = 0,
                },
                .randao_mixes = randao_mixes_slice,
                .genesis_validators_root = undefined,
                .slot = 0,
                .block_roots = undefined,
                .state_roots = undefined,
                .historical_roots = undefined,
                .eth1_data_votes = undefined,
                .eth1_deposit_index = undefined,
                .validators = undefined,
                .balances = undefined,
                .slashings = undefined,
                .previous_epoch_attestations = undefined,
                .current_epoch_attestations = undefined,
                .justification_bits = undefined,
                .previous_justified_checkpoint = undefined,
                .current_justified_checkpoint = undefined,
                .finalized_checkpoint = undefined,
                .inactivity_scores = undefined,
                .current_sync_committee = undefined,
                .next_sync_committee = undefined,
                .latest_execution_payload_header = undefined,
                .historical_summaries = undefined,
            },
        },
        .electra => consensus.BeaconState{
            .electra = electra.BeaconState{
                .genesis_time = eth1_timestamp + configs.ActiveConfig.get().GENESIS_DELAY,
                .fork = fork,
                .eth1_data = consensus.Eth1Data{
                    .block_hash = eth1_block_hash,
                    .deposit_count = @as(u64, deposits.len),
                    .deposit_root = undefined,
                },
                .latest_block_header = consensus.BeaconBlockHeader{
                    .body_root = body_root,
                    .parent_root = undefined,
                    .state_root = undefined,
                    .proposer_index = 0,
                    .slot = 0,
                },
                .randao_mixes = randao_mixes_slice,
                .genesis_validators_root = undefined,
                .slot = 0,
                .block_roots = undefined,
                .state_roots = undefined,
                .historical_roots = undefined,
                .eth1_data_votes = undefined,
                .eth1_deposit_index = undefined,
                .validators = undefined,
                .balances = undefined,
                .slashings = undefined,
                .previous_epoch_attestations = undefined,
                .current_epoch_attestations = undefined,
                .justification_bits = undefined,
                .previous_justified_checkpoint = undefined,
                .current_justified_checkpoint = undefined,
                .finalized_checkpoint = undefined,
                .inactivity_scores = undefined,
                .current_sync_committee = undefined,
                .next_sync_committee = undefined,
                .latest_execution_payload_header = undefined,
                .historical_summaries = undefined,
                .pending_balance_deposits = undefined,
                .pending_partial_withdrawals = undefined,
                .pending_consolidations = undefined,
                .deposit_requests_start_index = constants.UNSET_DEPOSIT_REQUESTS_START_INDEX,
            },
        },
    };

    //
    // // Process deposits
    // var leaves = try std.ArrayList(DepositData).initCapacity(std.heap.page_allocator, deposits.len);
    // defer leaves.deinit();
    //
    // for (deposits, 0..) |deposit, index| {
    //     try leaves.append(deposit.data);
    //     var deposit_data_list = try std.ArrayList(DepositData).initCapacity(std.heap.page_allocator, DEPOSIT_CONTRACT_TREE_DEPTH);
    //     defer deposit_data_list.deinit();
    //     try deposit_data_list.appendSlice(leaves.items[0..index + 1]);
    //     state.eth1_data.deposit_root = try hash_tree_root(deposit_data_list.items);
    //     try process_deposit(&state, deposit);
    // }
    //
    // // Process deposit balance updates
    // for (state.pending_balance_deposits) |deposit| {
    //     try increase_balance(&state, deposit.index, deposit.amount);
    // }
    // state.pending_balance_deposits.clearRetainingCapacity();
    //
    // // Process activations
    // for (state.validators) |*validator, index| {
    //     const balance = state.balances[index];
    //     validator.effective_balance = @min(
    //         balance - balance % EFFECTIVE_BALANCE_INCREMENT,
    //         try get_max_effective_balance(validator),
    //     );
    //     if (validator.effective_balance >= MIN_ACTIVATION_BALANCE) {
    //         validator.activation_eligibility_epoch = GENESIS_EPOCH;
    //         validator.activation_epoch = GENESIS_EPOCH;
    //     }
    // }
    //
    // // Set genesis validators root for domain separation and chain versioning
    // state.genesis_validators_root = try hash_tree_root(state.validators);
    //
    // // Fill in sync committees
    // state.current_sync_committee = try get_next_sync_committee(&state);
    // state.next_sync_committee = try get_next_sync_committee(&state);
    //
    // // Initialize the execution payload header
    // state.latest_execution_payload_header = execution_payload_header;

    return state;
}
