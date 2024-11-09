const std = @import("std");
const primitives = @import("../primitives/types.zig");
const consensus = @import("../consensus/types.zig");
const constants = @import("../primitives/constants.zig");
const preset = @import("../presets/preset.zig");
const testing = std.testing;

const ForkChoiceError = error{
    UnknownParent,
    InvalidNodeIndex,
    InvalidBestDescendant,
    JustifiedNodeUnknown,
    DeltaOverflow,
    DeltaUnderflow,
    InvalidDeltaLen,
    FinalizedNodeUnknown,
    PruningFromOutdatedFinalizedRoot,
};
// Core types
pub const BlockId = struct {
    slot: primitives.Slot,
    root: primitives.Root,
};

pub const Checkpoint = consensus.Checkpoint;

pub const FinalityCheckpoints = struct {
    justified: Checkpoint,
    finalized: Checkpoint,
};

pub const ProtoNode = struct {
    bid: BlockId,
    parent: ?usize,
    checkpoints: FinalityCheckpoints,
    weight: i64,
    invalid: bool,
    best_child: ?usize,
    best_descendant: ?usize,
    shared_finalized_epoch: u64,
};

pub const ProtoArray = struct {
    nodes: std.ArrayList(ProtoNode),
    indices: std.AutoHashMap(primitives.Root, usize),
    checkpoints: FinalityCheckpoints,
    current_epoch: u64,
    previous_proposer_boost_root: primitives.Root,
    previous_proposer_boost_score: u64,
    offset: usize,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, checkpoints: FinalityCheckpoints) ProtoArray {
        return ProtoArray{
            .nodes = std.ArrayList(ProtoNode).init(allocator),
            .indices = std.AutoHashMap(primitives.Root, usize).init(allocator),
            .checkpoints = checkpoints,
            .current_epoch = 0,
            .previous_proposer_boost_root = [_]u8{0} ** 32,
            .previous_proposer_boost_score = 0,
            .offset = 0,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ProtoArray) void {
        self.nodes.deinit();
        self.indices.deinit();
    }

    pub fn onBlock(self: *ProtoArray, bid: BlockId, parent: *const primitives.Root, checkpoints: *const FinalityCheckpoints) !void {
        // Skip if block already known
        if (self.indices.contains(bid.root)) return;

        // Special case for genesis block
        const parent_idx = if (std.mem.eql(u8, &bid.root, &parent.*))
            0 // Genesis block is its own parent
        else
            self.indices.get(parent.*) orelse return ForkChoiceError.UnknownParent;

        const node_idx = self.nodes.items.len;
        try self.nodes.append(.{
            .bid = bid,
            .parent = parent_idx,
            .checkpoints = checkpoints.*,
            .weight = 0,
            .invalid = false,
            .best_child = null,
            .best_descendant = null,
            .shared_finalized_epoch = 0,
        });

        try self.indices.put(bid.root, node_idx);
        try self.maybeUpdateBestChildAndDescendant(parent_idx, node_idx);
    }

    pub fn findHead(self: *ProtoArray, justified_root: *const primitives.Root) !primitives.Root {
        const justified_idx = self.indices.get(justified_root.*) orelse
            return ForkChoiceError.JustifiedNodeUnknown;

        const justified_node = self.nodes.items[justified_idx];
        const best_descendant_idx = justified_node.best_descendant orelse justified_idx;
        const best_node = self.nodes.items[best_descendant_idx];

        if (!self.nodeIsViableForHead(&best_node, best_descendant_idx)) {
            return ForkChoiceError.InvalidBestDescendant;
        }

        return best_node.bid.root;
    }

    pub fn applyScoreChanges(self: *ProtoArray, deltas: []const i64, proposer_boost_root: *const primitives.Root) !void {
        if (deltas.len != self.nodes.items.len) {
            return ForkChoiceError.InvalidDeltaLen;
        }

        var proposer_boost_score: u64 = 0;
        std.debug.print("Applying score changes\n", .{}); // DEBUG
        // Apply deltas and handle proposer boost
        for (self.nodes.items, 0..) |*node, i| {
            std.debug.print("Node {}: weight {} + delta {}\n", .{ node.bid.root[0], node.weight, deltas[i] }); // DEBUG
            var node_delta = deltas[i];

            // Remove previous proposer boost
            if (std.mem.eql(u8, &self.previous_proposer_boost_root, &node.bid.root)) {
                node_delta -= @intCast(self.previous_proposer_boost_score);
            }

            // Apply new proposer boost
            if (std.mem.eql(u8, &proposer_boost_root.*, &node.bid.root)) {
                proposer_boost_score = 100;
                // proposer_boost_score = calculateProposerBoost(self.justified_total_active_balance);
                node_delta += @intCast(proposer_boost_score);
            }

            // Update weight with overflow checks
            const result = @addWithOverflow(node.weight, node_delta);
            if (result[1] != 0) {
                return ForkChoiceError.DeltaOverflow;
            }
            const new_weight = result[0];
            if (new_weight < 0) return ForkChoiceError.DeltaUnderflow;
            node.weight = new_weight;
        }

        // Update proposer boost tracking
        self.previous_proposer_boost_root = proposer_boost_root.*;
        self.previous_proposer_boost_score = proposer_boost_score;

        // Update best child and descendant relationships
        var i = self.nodes.items.len;
        while (i > 0) {
            i -= 1;
            if (self.nodes.items[i].parent) |parent_idx| {
                std.debug.print("i: {}, parent_idx: {}\n", .{ i, parent_idx });
                try self.maybeUpdateBestChildAndDescendant(parent_idx, i);
            }
        }
    }

    fn nodeIsViableForHead(self: *ProtoArray, node: *const ProtoNode, node_idx: usize) bool {
        if (node.invalid) return false;

        const correct_justified =
            self.checkpoints.justified.epoch == constants.GENESIS_EPOCH or
            node.checkpoints.justified.epoch == self.checkpoints.justified.epoch;

        if (!correct_justified) {
            const justified_within_two_epochs =
                node.checkpoints.justified.epoch + 2 >= self.current_epoch;
            if (!justified_within_two_epochs) return false;
        }

        if (self.checkpoints.finalized.epoch == constants.GENESIS_EPOCH) return true;

        if (node.shared_finalized_epoch == self.checkpoints.finalized.epoch) return true;

        // Check node ancestry for finalization
        const finalized_slot = self.checkpoints.finalized.epoch * preset.ActivePreset.get().SLOTS_PER_EPOCH;
        var current_node = node;
        var current_idx = node_idx;

        while (current_node.bid.slot > finalized_slot and
            current_node.shared_finalized_epoch != self.checkpoints.finalized.epoch)
        {
            if (current_node.parent) |parent_idx| {
                current_idx = parent_idx;
                current_node = &self.nodes.items[current_idx];
            } else break;
        }

        return current_node.shared_finalized_epoch == self.checkpoints.finalized.epoch;
    }

    fn maybeUpdateBestChildAndDescendant(self: *ProtoArray, parent_idx: usize, child_idx: usize) !void {
        const child = &self.nodes.items[child_idx];
        var parent = &self.nodes.items[parent_idx];

        const child_leads_to_viable_head = try self.nodeLeadsToViableHead(child, child_idx);

        if (parent.best_child) |best_child_idx| {
            if (best_child_idx == child_idx) {
                if (!child_leads_to_viable_head) {
                    // Change to none
                    parent.best_child = null;
                    parent.best_descendant = null;
                } else {
                    // Change to child
                    parent.best_child = child_idx;
                    parent.best_descendant = child.best_descendant orelse child_idx;
                }
            } else {
                const best_child = &self.nodes.items[best_child_idx];
                const best_child_leads_to_viable_head = try self.nodeLeadsToViableHead(best_child, best_child_idx);

                if (child_leads_to_viable_head and !best_child_leads_to_viable_head) {
                    // Change to child
                    parent.best_child = child_idx;
                    parent.best_descendant = child.best_descendant orelse child_idx;
                } else if (!child_leads_to_viable_head and best_child_leads_to_viable_head) {
                    // No change
                } else if (child.weight == best_child.weight) {
                    if (tiebreak(&child.bid.root, &best_child.bid.root)) {
                        // Change to child
                        parent.best_child = child_idx;
                        parent.best_descendant = child.best_descendant orelse child_idx;
                    }
                    // else no change
                } else if (child.weight >= best_child.weight) {
                    // Change to child
                    parent.best_child = child_idx;
                    parent.best_descendant = child.best_descendant orelse child_idx;
                }
                // else no change
            }
        } else if (child_leads_to_viable_head) {
            // Change to child
            parent.best_child = child_idx;
            parent.best_descendant = child.best_descendant orelse child_idx;
        }
    }

    pub fn prune(self: *ProtoArray, finalized_root: *const [32]u8) !void {
        const finalized_idx = self.indices.get(finalized_root.*) orelse
            return ForkChoiceError.FinalizedNodeUnknown;

        if (finalized_idx == self.offset) {
            return;
        }

        if (finalized_idx < self.offset) {
            return ForkChoiceError.PruningFromOutdatedFinalizedRoot;
        }

        const final_physical_idx = finalized_idx - self.offset;

        // Remove indices for pruned nodes
        var i: usize = 0;
        while (i < final_physical_idx) : (i += 1) {
            _ = self.indices.remove(self.nodes.items[i].bid.root);
        }

        // Create temp buffer and copy remaining nodes
        const tail = self.nodes.items.len - final_physical_idx;
        const new_nodes = try self.allocator.alloc(ProtoNode, tail);
        defer self.allocator.free(new_nodes);

        @memcpy(new_nodes, self.nodes.items[final_physical_idx..]);

        // Clear and copy back
        self.nodes.clearRetainingCapacity();
        try self.nodes.appendSlice(new_nodes);

        self.offset = finalized_idx;
    }

    pub fn propagateInvalidity(self: *ProtoArray, start_physical_idx: usize) void {
        var node_physical_idx: usize = start_physical_idx + 1;
        while (node_physical_idx < self.nodes.items.len) : (node_physical_idx += 1) {
            const node = &self.nodes.items[node_physical_idx];
            if (node.parent == null) {
                continue;
            }

            const parent_logical_idx = node.parent.?;
            const parent_physical_idx = parent_logical_idx - self.offset;

            if (parent_physical_idx < 0 or parent_physical_idx >= self.nodes.items.len) {
                continue;
            }

            if (self.nodes.items[parent_physical_idx].invalid) {
                node.invalid = true;
            }
        }
    }

    fn nodeLeadsToViableHead(self: *ProtoArray, node: *const ProtoNode, node_idx: usize) !bool {
        const best_descendant_viable = if (node.best_descendant) |best_descendant_idx| {
            const best_descendant = self.nodes.items[best_descendant_idx];
            return self.nodeIsViableForHead(&best_descendant, best_descendant_idx);
        } else false;

        return best_descendant_viable or self.nodeIsViableForHead(node, node_idx);
    }
};

// pub const ProtoArrayIterator = struct {
//     proto_array: *const ProtoArray,
//     index: usize,
//
//     pub fn next(self: *ProtoArrayIterator) ?ProtoArrayItem {
//         while (self.index < self.proto_array.nodes.items.len) {
//             const node = self.proto_array.nodes.items[self.index];
//             self.index += 1;
//
//             return ProtoArrayItem{
//                 .bid = node.bid,
//                 .parent = if (node.parent) |p|
//                     self.proto_array.nodes.items[p].bid.root
//                 else
//                     [_]u8{0} ** 32,
//                 .checkpoints = node.checkpoints,
//                 .weight = node.weight,
//                 .invalid = node.invalid,
//                 .best_child = if (node.best_child) |c|
//                     self.proto_array.nodes.items[c].bid.root
//                 else
//                     [_]u8{0} ** 32,
//                 .best_descendant = if (node.best_descendant) |d|
//                     self.proto_array.nodes.items[d].bid.root
//                 else
//                     [_]u8{0} ** 32,
//             };
//         }
//         return null;
//     }
// };

fn makeRoot(value: u8) primitives.Root {
    var root = [_]u8{0} ** 32;
    root[0] = value;
    return root;
}

fn getParentRoot(block: BlockId) [32]u8 {
    // For test blocks, parent root is one less than current block's first byte
    var parent_root = [_]u8{0} ** 32;
    parent_root[0] = block.root[0] - 1;
    return parent_root;
}

fn tiebreak(a: *const primitives.Root, b: *const primitives.Root) bool {
    for (a.*, 0..) |byte, i| {
        if (byte < b.*[i]) return false;
        if (byte > b.*[i]) return true;
    }
    return true;
}

fn initTestProtoArray(allocator: std.mem.Allocator) ProtoArray {
    const genesis_checkpoint = Checkpoint{
        .epoch = constants.GENESIS_EPOCH,
        .root = [_]u8{0} ** 32,
    };

    return ProtoArray.init(allocator, .{
        .justified = genesis_checkpoint,
        .finalized = genesis_checkpoint,
    });
}

fn getCheckpoints(block: BlockId) FinalityCheckpoints {
    const epoch = block.slot / preset.ActivePreset.get().SLOTS_PER_EPOCH;
    return FinalityCheckpoints{
        .justified = Checkpoint{
            .epoch = epoch,
            .root = block.root,
        },
        .finalized = Checkpoint{
            .epoch = if (epoch > 0) epoch - 1 else 0,
            .root = makeRoot(0),
        },
    };
}

test "Proto Array - basic operations" {
    // Block structure:
    //     0
    //     |
    //     1
    preset.ActivePreset.set(preset.Presets.minimal);
    defer preset.ActivePreset.reset();
    const allocator = std.testing.allocator;

    var proto_array = initTestProtoArray(allocator);
    defer proto_array.deinit();

    const blocks = [_]BlockId{
        .{ .slot = 0, .root = makeRoot(0) },
        .{ .slot = 1, .root = makeRoot(1) },
    };

    for (blocks) |block| {
        const parent_root = if (block.root[0] == 0)
            block.root
        else
            makeRoot(block.root[0] - 1);
        try proto_array.onBlock(block, &parent_root, &getCheckpoints(block));
    }

    const head = try proto_array.findHead(&blocks[0].root);
    try testing.expectEqualSlices(u8, &blocks[1].root, &head);
}

test "Proto Array - weight updates and head selection" {
    // Block structure:
    //          0
    //         / \
    //        1   2
    //        |   |
    //        3   4
    //
    // Weights:
    //          0
    //         / \
    //       10  20
    //        |   |
    //       30  40
    preset.ActivePreset.set(preset.Presets.minimal);
    defer preset.ActivePreset.reset();
    const allocator = testing.allocator;

    var proto_array = initTestProtoArray(allocator);
    defer proto_array.deinit();

    const blocks = [_]BlockId{
        .{ .slot = 0, .root = makeRoot(0) },
        .{ .slot = 1, .root = makeRoot(1) },
        .{ .slot = 1, .root = makeRoot(2) },
        .{ .slot = 2, .root = makeRoot(3) },
        .{ .slot = 2, .root = makeRoot(4) },
    };

    for (blocks) |block| {
        const parent_root = if (block.root[0] == 0)
            block.root
        else if (block.root[0] <= 2)
            makeRoot(0)
        else if (block.root[0] == 3)
            makeRoot(1)
        else
            makeRoot(2);
        try proto_array.onBlock(block, &parent_root, &getCheckpoints(block));
    }

    var deltas = [_]i64{0} ** blocks.len;
    deltas[1] = 10;
    deltas[2] = 20;
    deltas[3] = 30;
    deltas[4] = 40;

    try proto_array.applyScoreChanges(&deltas, &[_]u8{0} ** 32);
    const head = try proto_array.findHead(&blocks[0].root);
    try testing.expectEqualSlices(u8, &blocks[4].root, &head);
}

test "Proto Array - pruning and invalidity" {
    // Block structure:
    //          0
    //         / \
    //        1   2
    //       /|   |
    //      3 4   5
    //      |     |
    //      6     7
    preset.ActivePreset.set(preset.Presets.minimal);
    defer preset.ActivePreset.reset();
    const allocator = testing.allocator;

    var proto_array = initTestProtoArray(allocator);
    defer proto_array.deinit();

    const blocks = [_]BlockId{
        .{ .slot = 0, .root = makeRoot(0) },
        .{ .slot = 1, .root = makeRoot(1) },
        .{ .slot = 1, .root = makeRoot(2) },
        .{ .slot = 2, .root = makeRoot(3) },
        .{ .slot = 2, .root = makeRoot(4) },
        .{ .slot = 2, .root = makeRoot(5) },
        .{ .slot = 3, .root = makeRoot(6) },
        .{ .slot = 3, .root = makeRoot(7) },
    };

    for (blocks) |block| {
        const parent_root = switch (block.root[0]) {
            0 => block.root,
            1, 2 => makeRoot(0),
            3, 4 => makeRoot(1),
            5 => makeRoot(2),
            6 => makeRoot(3),
            7 => makeRoot(5),
            else => unreachable,
        };
        try proto_array.onBlock(block, &parent_root, &getCheckpoints(block));
    }

    // Print initial state after building tree
    std.debug.print("\nInitial state:\n", .{});
    for (proto_array.nodes.items, 0..) |node, i| {
        std.debug.print("Node {}: root {}, parent {?}\n", .{ i, node.bid.root[0], node.parent });
    }

    // Mark invalid and propagate
    proto_array.nodes.items[0].invalid = true;
    proto_array.propagateInvalidity(0);
    try testing.expect(proto_array.nodes.items[1].invalid);
    std.debug.print("\nAfter invalidity:\n", .{});
    for (proto_array.nodes.items, 0..) |node, i| {
        std.debug.print("Node {}: root {}, invalid {}\n", .{ i, node.bid.root[0], node.invalid });
    }

    try proto_array.prune(&blocks[2].root);
    std.debug.print("\nAfter pruning:\n", .{});
    std.debug.print("Nodes len: {}, offset: {}\n", .{ proto_array.nodes.items.len, proto_array.offset });
    for (proto_array.nodes.items, 0..) |node, i| {
        std.debug.print("Node {}: root {}\n", .{ i, node.bid.root[0] });
    }
    // Verify post-pruning state
    try testing.expectEqual(@as(usize, 3), proto_array.nodes.items.len); // Only nodes 2,5,7 remain
    try testing.expectEqual(@as(usize, 2), proto_array.offset); // Offset should be at node 2
    try testing.expect(proto_array.indices.contains(blocks[2].root)); // Root 2 should exist
    try testing.expect(proto_array.indices.contains(blocks[5].root)); // Root 5 should exist
    try testing.expect(proto_array.indices.contains(blocks[7].root)); // Root 7 should exist
}
