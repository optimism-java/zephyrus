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
const balance_helper = @import("../../consensus/helpers/balance.zig");
const committee_helper = @import("../../consensus/helpers/committee.zig");
const ssz = @import("../../ssz/ssz.zig");

/// isValidGenesisState verifies the validity of a genesis state.
/// @param state - The state.
/// @param allocator - The allocator.
/// @returns True if the state is valid, false otherwise.
/// Spec pseudocode definition:
/// def is_valid_genesis_state(state: BeaconState) -> bool:
///    if state.genesis_time < config.MIN_GENESIS_TIME:
///        return False
///    if len(get_active_validator_indices(state, GENESIS_EPOCH)) < config.MIN_GENESIS_ACTIVE_VALIDATOR_COUNT:
///       return False
///    return True
pub fn isValidGenesisState(state: *consensus.BeaconState, allocator: std.mem.Allocator) !bool {
    if (state.genesisTime() < configs.ActiveConfig.get().MIN_GENESIS_TIME) {
        return false;
    }
    const indices = try validator_helper.getActiveValidatorIndices(state, constants.GENESIS_EPOCH, allocator);
    defer allocator.free(indices);
    if (indices.len < configs.ActiveConfig.get().MIN_GENESIS_ACTIVE_VALIDATOR_COUNT) {
        return false;
    }
    return true;
}

/// initializeBeaconStateFromEth1 initializes the beacon state from the eth1 block hash, timestamp, and deposits.
/// @param fork_type - The fork type.
/// @param eth1_block_hash - The eth1 block hash.
/// @param eth1_timestamp - The eth1 timestamp.
/// @param deposits - The deposits.
/// @param execution_payload_header - The execution payload header.
/// @param allocator - The allocator.
/// @returns The initialized beacon state.
/// Spec pseudocode definition:
/// def initialize_beacon_state_from_eth1(eth1_block_hash: Hash32,
///                                       eth1_timestamp: uint64,
///                                       deposits: Sequence[Deposit],
///                                       execution_payload_header: ExecutionPayloadHeader=ExecutionPayloadHeader()
///                                       ) -> BeaconState:
///     fork = Fork(
///         previous_version=config.ELECTRA_FORK_VERSION,  # [Modified in Electra:EIP6110] for testing only
///         current_version=config.ELECTRA_FORK_VERSION,  # [Modified in Electra:EIP6110]
///         epoch=GENESIS_EPOCH,
///     )
///    state = BeaconState(
///        genesis_time=eth1_timestamp + config.GENESIS_DELAY,
///        fork=fork,
///        eth1_data=Eth1Data(block_hash=eth1_block_hash, deposit_count=uint64(len(deposits))),
///        latest_block_header=BeaconBlockHeader(body_root=hash_tree_root(BeaconBlockBody())),
///        randao_mixes=[eth1_block_hash] * EPOCHS_PER_HISTORICAL_VECTOR,  # Seed RANDAO with Eth1 entropy
///        deposit_requests_start_index=UNSET_DEPOSIT_REQUESTS_START_INDEX,  # [New in Electra:EIP6110]
///    )
///
///    # Process deposits
///    leaves = list(map(lambda deposit: deposit.data, deposits))
///    for index, deposit in enumerate(deposits):
///        deposit_data_list = List[DepositData, 2**DEPOSIT_CONTRACT_TREE_DEPTH](*leaves[:index + 1])
///        state.eth1_data.deposit_root = hash_tree_root(deposit_data_list)
///        process_deposit(state, deposit)
///
///    # Process deposit balance updates
///    for deposit in state.pending_balance_deposits:
///        increase_balance(state, deposit.index, deposit.amount)
///    state.pending_balance_deposits = []
///
///    # Process activations
///    for index, validator in enumerate(state.validators):
///        balance = state.balances[index]
///        # [Modified in Electra:EIP7251]
///        validator.effective_balance = min(
///           balance - balance % EFFECTIVE_BALANCE_INCREMENT, get_max_effective_balance(validator))
///        if validator.effective_balance >= MIN_ACTIVATION_BALANCE:
///            validator.activation_eligibility_epoch = GENESIS_EPOCH
///            validator.activation_epoch = GENESIS_EPOCH
///
///    # Set genesis validators root for domain separation and chain versioning
///    state.genesis_validators_root = hash_tree_root(state.validators)
///
///    # Fill in sync committees
///    # Note: A duplicate committee is assigned for the current and next committee at genesis
///    state.current_sync_committee = get_next_sync_committee(state)
///    state.next_sync_committee = get_next_sync_committee(state)
///
///    # Initialize the execution payload header
///    state.latest_execution_payload_header = execution_payload_header
///
///    return state
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

    var state = switch (fork_type) {
        .phase0 => consensus.BeaconState{
            .phase0 = std.mem.zeroInit(phase0.BeaconState, .{
                .genesis_time = eth1_timestamp + configs.ActiveConfig.get().GENESIS_DELAY,
                .fork = fork,
                .eth1_data = consensus.Eth1Data{
                    .block_hash = eth1_block_hash,
                    .deposit_count = @as(u64, deposits.len),
                    .deposit_root = undefined,
                },
                .latest_block_header = std.mem.zeroInit(consensus.BeaconBlockHeader, .{
                    .body_root = body_root,
                }),
                .randao_mixes = randao_mixes_slice,
            }),
        },
        .altair => consensus.BeaconState{
            .altair = std.mem.zeroInit(altair.BeaconState, .{
                .genesis_time = eth1_timestamp + configs.ActiveConfig.get().GENESIS_DELAY,
                .fork = fork,
                .eth1_data = consensus.Eth1Data{
                    .block_hash = eth1_block_hash,
                    .deposit_count = @as(u64, deposits.len),
                    .deposit_root = undefined,
                },
                .latest_block_header = std.mem.zeroInit(consensus.BeaconBlockHeader, .{
                    .body_root = body_root,
                }),
                .randao_mixes = randao_mixes_slice,
                .current_sync_committee = undefined,
                .next_sync_committee = undefined,
            }),
        },
        .bellatrix => consensus.BeaconState{
            .bellatrix = std.mem.zeroInit(bellatrix.BeaconState, .{
                .genesis_time = eth1_timestamp + configs.ActiveConfig.get().GENESIS_DELAY,
                .fork = fork,
                .eth1_data = consensus.Eth1Data{
                    .block_hash = eth1_block_hash,
                    .deposit_count = @as(u64, deposits.len),
                    .deposit_root = undefined,
                },
                .latest_block_header = std.mem.zeroInit(consensus.BeaconBlockHeader, .{
                    .body_root = body_root,
                }),
                .randao_mixes = randao_mixes_slice,
                .current_sync_committee = undefined,
                .next_sync_committee = undefined,
                .latest_execution_payload_header = undefined,
            }),
        },
        .capella => consensus.BeaconState{
            .capella = std.mem.zeroInit(capella.BeaconState, .{
                .genesis_time = eth1_timestamp + configs.ActiveConfig.get().GENESIS_DELAY,
                .fork = fork,
                .eth1_data = consensus.Eth1Data{
                    .block_hash = eth1_block_hash,
                    .deposit_count = @as(u64, deposits.len),
                    .deposit_root = undefined,
                },
                .latest_block_header = std.mem.zeroInit(consensus.BeaconBlockHeader, .{
                    .body_root = body_root,
                }),
                .randao_mixes = randao_mixes_slice,
                .current_sync_committee = undefined,
                .next_sync_committee = undefined,
                .latest_execution_payload_header = undefined,
            }),
        },
        .deneb => consensus.BeaconState{
            .deneb = std.mem.zeroInit(capella.BeaconState, .{
                .genesis_time = eth1_timestamp + configs.ActiveConfig.get().GENESIS_DELAY,
                .fork = fork,
                .eth1_data = consensus.Eth1Data{
                    .block_hash = eth1_block_hash,
                    .deposit_count = @as(u64, deposits.len),
                    .deposit_root = undefined,
                },
                .latest_block_header = std.mem.zeroInit(consensus.BeaconBlockHeader, .{
                    .body_root = body_root,
                }),
                .randao_mixes = randao_mixes_slice,
                .current_sync_committee = undefined,
                .next_sync_committee = undefined,
                .latest_execution_payload_header = undefined,
            }),
        },
        .electra => consensus.BeaconState{
            .electra = std.mem.zeroInit(electra.BeaconState, .{
                .genesis_time = eth1_timestamp + configs.ActiveConfig.get().GENESIS_DELAY,
                .fork = fork,
                .eth1_data = consensus.Eth1Data{
                    .block_hash = eth1_block_hash,
                    .deposit_count = @as(u64, deposits.len),
                    .deposit_root = undefined,
                },
                .latest_block_header = std.mem.zeroInit(consensus.BeaconBlockHeader, .{
                    .body_root = body_root,
                }),
                .randao_mixes = randao_mixes_slice,
                .current_sync_committee = undefined,
                .next_sync_committee = undefined,
                .latest_execution_payload_header = undefined,
                .deposit_requests_start_index = constants.UNSET_DEPOSIT_REQUESTS_START_INDEX,
            }),
        },
    };

    // Process deposits
    var leaves = try std.ArrayList(consensus.DepositData).initCapacity(allocator, deposits.len);
    defer leaves.deinit();

    for (deposits, 0..) |deposit, index| {
        try leaves.append(deposit.data);
        var deposit_data_list = try std.ArrayList(consensus.DepositData).initCapacity(allocator, index + 1);
        defer deposit_data_list.deinit();
        try deposit_data_list.appendSlice(leaves.items[0 .. index + 1]);
        try ssz.hashTreeRoot(deposit_data_list.items, &state.eth1Data().deposit_root, allocator);
        processDeposit(&state, &deposit);
    }

    // Process deposit balance updates
    if (state == .electra) {
        for (state.electra.pending_balance_deposits) |deposit| {
            balance_helper.increaseBalance(&state, deposit.electra.index, deposit.electra.amount);
        }
        state.electra.pending_balance_deposits.len = 0;
    }

    // Process activations
    for (state.validators(), 0..) |*validator, index| {
        const balance = state.balances()[index];
        const max_balance = if (state == .electra)
            balance_helper.getMaxEffectiveBalance(validator)
        else
            preset.ActivePreset.get().MAX_EFFECTIVE_BALANCE;
        validator.effective_balance = @min(
            balance - @mod(balance, preset.ActivePreset.get().EFFECTIVE_BALANCE_INCREMENT),
            max_balance,
        );
        if (validator.effective_balance >= preset.ActivePreset.get().MIN_ACTIVATION_BALANCE) {
            validator.activation_eligibility_epoch = constants.GENESIS_EPOCH;
            validator.activation_epoch = constants.GENESIS_EPOCH;
        }
    }

    // Set genesis validators root for domain separation and chain versioning
    try ssz.hashTreeRoot(state.validators(), state.genesisValidatorsRootPtr(), allocator);

    // Fill in sync committees
    state.setCurrentSyncCommittee(try committee_helper.getNextSyncCommittee(&state, allocator));
    state.setNextSyncCommittee(try committee_helper.getNextSyncCommittee(&state, allocator));

    if (execution_payload_header != null) {
        // Initialize the execution payload header
        state.setLatestExecutionPayloadHeader(execution_payload_header.?);
    }

    return state;
}

fn processDeposit(state: *consensus.BeaconState, deposit: *const consensus.Deposit) void {
    const a = state.eth1Data();
    std.debug.print("Deposit data: {}\n", .{deposit.data});
    std.debug.print("State data: {}\n", .{a});
}
