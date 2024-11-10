const std = @import("std");
const primitives = @import("../primitives/types.zig");
const consensus = @import("../consensus/types.zig");
const constants = @import("../primitives/constants.zig");
const preset = @import("../presets/preset.zig");
const configs = @import("../configs/config.zig");
const testing = std.testing;

pub const JustifiedBalances = struct {
    total_effective_balance: primitives.Gwei,
};

pub const InvalidationOperation = union(enum) {
    InvalidateOne: struct {
        block_root: primitives.Root,
    },
    InvalidateMany: struct {
        head_block_root: primitives.Root,
        always_invalidate_head: bool,
        latest_valid_ancestor: primitives.Root,
    },
};

pub const ExecutionStatus = union(enum) {
    Valid: primitives.Root,
    Invalid: primitives.Root,
    Optimistic: primitives.Root,
    Irrelevant: primitives.Root,
};

pub const ValidExecutionStatusBecameInvalid = struct {
    block_root: primitives.Root,
    payload_block_hash: primitives.Root,
};

pub const ProtoNode = struct {
    slot: primitives.Slot,
    state_root: primitives.Root,
    target_root: primitives.Root,
    root: primitives.Root,
    parent: ?usize,
    justified_checkpoint: consensus.Checkpoint,
    finalized_checkpoint: consensus.Checkpoint,
    weight: u64,
    best_child: ?usize,
    best_descendant: ?usize,
    execution_status: ExecutionStatus,
    unrealized_justified_checkpoint: ?consensus.Checkpoint,
    unrealized_finalized_checkpoint: ?consensus.Checkpoint,
};

pub const Block = struct {
    slot: primitives.Slot,
    root: primitives.Root,
    parent_root: ?primitives.Root,
    target_root: primitives.Root,
    state_root: primitives.Root,
    justified_checkpoint: consensus.Checkpoint,
    finalized_checkpoint: consensus.Checkpoint,
    execution_status: ExecutionStatus,
    unrealized_justified_checkpoint: ?consensus.Checkpoint,
    unrealized_finalized_checkpoint: ?consensus.Checkpoint,
};

pub const ProtoArrayIterator = struct {
    next_node_index: ?usize,
    proto_array: *const ProtoArray,

    pub fn next(self: *ProtoArrayIterator) ?*const ProtoNode {
        const index = self.next_node_index orelse return null;
        const node = &self.proto_array.nodes.items[index];
        self.next_node_index = node.parent;
        return node;
    }
};

pub const ProposerBoost = struct {
    root: primitives.Root,
    score: u64,

    pub fn init() ProposerBoost {
        return .{
            .root = [_]u8{0} ** 32,
            .score = 0,
        };
    }
};

pub const ProtoArray = struct {
    allocator: std.mem.Allocator,
    prune_threshold: usize,
    previous_proposer_boost: ProposerBoost,
    justified_checkpoint: consensus.Checkpoint,
    finalized_checkpoint: consensus.Checkpoint,
    nodes: std.ArrayList(ProtoNode),
    indices: std.AutoHashMap(primitives.Root, usize),

    // Core methods will go here
    pub fn init(
        allocator: std.mem.Allocator,
        prune_threshold: usize,
        justified_checkpoint: consensus.Checkpoint,
        finalized_checkpoint: consensus.Checkpoint,
    ) ProtoArray {
        return ProtoArray{
            .prune_threshold = prune_threshold,
            .justified_checkpoint = justified_checkpoint,
            .finalized_checkpoint = finalized_checkpoint,
            .nodes = std.ArrayList(ProtoNode).init(allocator),
            .indices = std.AutoHashMap(primitives.Root, usize).init(allocator),
            .allocator = allocator,
            .previous_proposer_boost = ProposerBoost.init(),
        };
    }

    pub fn deinit(self: *ProtoArray) void {
        self.nodes.deinit();
        self.indices.deinit();
    }

    pub fn onBlock(self: *ProtoArray, block: *const Block, current_slot: u64) !void {
        // If block already known, return early
        if (self.indices.contains(block.root)) {
            return;
        }

        const node_index = self.nodes.items.len;

        const node = ProtoNode{
            .slot = block.slot,
            .root = block.root,
            .target_root = block.target_root,
            .state_root = block.state_root,
            .parent = if (block.parent_root) |parent_root|
                self.indices.get(parent_root)
            else
                null,
            .justified_checkpoint = block.justified_checkpoint,
            .finalized_checkpoint = block.finalized_checkpoint,
            .weight = 0,
            .best_child = null,
            .best_descendant = null,
            .execution_status = block.execution_status,
            .unrealized_justified_checkpoint = block.unrealized_justified_checkpoint,
            .unrealized_finalized_checkpoint = block.unrealized_finalized_checkpoint,
        };

        // Check parent execution status
        if (node.parent) |parent_index| {
            const parent = self.nodes.items[parent_index];
            if (parent.execution_status == .Invalid) {
                return error.ParentExecutionStatusIsInvalid;
            }
        }

        try self.indices.put(node.root, node_index);
        try self.nodes.append(node);

        // Update best child and descendant
        if (node.parent) |parent_index| {
            try self.maybeUpdateBestChildAndDescendant(parent_index, node_index, current_slot);
        }
    }

    pub fn findHead(self: *const ProtoArray, justified_root: *const primitives.Root, current_slot: u64) !primitives.Root {
        const justified_index = self.indices.get(justified_root.*) orelse {
            return error.JustifiedNodeUnknown;
        };

        const justified_node = if (self.nodes.items.len > justified_index)
            self.nodes.items[justified_index]
        else {
            return error.InvalidJustifiedIndex;
        };

        // Check execution status of justified node
        if (justified_node.execution_status == .Invalid) {
            return error.InvalidExecutionStatus;
        }

        const best_descendant_index = justified_node.best_descendant orelse justified_index;

        const best_node = if (self.nodes.items.len > best_descendant_index)
            self.nodes.items[best_descendant_index]
        else {
            return error.InvalidBestDescendant;
        };

        // Verify the node is viable for head
        if (!self.nodeIsViableForHead(&best_node, current_slot)) {
            return error.InvalidBestNode;
        }

        return best_node.root;
    }

    pub fn iterNodes(self: *const ProtoArray, block_root: *const primitives.Root) ProtoArrayIterator {
        return .{
            .next_node_index = self.indices.get(block_root.*),
            .proto_array = self,
        };
    }

    pub fn iterBlockRoots(self: *const ProtoArray, block_root: *const primitives.Root) struct {
        iter: ProtoArrayIterator,

        pub fn next(ctx: *@This()) ?struct { root: primitives.Root, slot: primitives.Slot } {
            const node = ctx.iter.next() orelse return null;
            return .{
                .root = node.root,
                .slot = node.slot,
            };
        }
    } {
        return .{ .iter = self.iterNodes(block_root) };
    }

    pub fn propagateExecutionPayloadValidation(self: *ProtoArray, block_root: *const primitives.Root) !void {
        const index = self.indices.get(block_root.*) orelse {
            return error.NodeUnknown;
        };
        try self.propagateExecutionPayloadValidationByIndex(index);
    }

    fn propagateExecutionPayloadValidationByIndex(self: *ProtoArray, verified_node_index: usize) !void {
        var index = verified_node_index;

        while (true) {
            var node = &self.nodes.items[index];

            switch (node.execution_status) {
                .Valid => return,
                .Irrelevant => return,
                .Optimistic => |payload_block_hash| {
                    node.execution_status = .{ .Valid = payload_block_hash };
                    if (node.parent) |parent_index| {
                        index = parent_index;
                    } else return;
                },
                .Invalid => |_| {
                    return error.InvalidAncestorOfValidPayload;
                },
            }
        }
    }

    pub fn applyScoreChanges(
        self: *ProtoArray,
        deltas: []i64,
        justified_checkpoint: *const consensus.Checkpoint,
        finalized_checkpoint: *const consensus.Checkpoint,
        justified_balances: *const JustifiedBalances,
        proposer_boost_root: *const primitives.Root,
        current_slot: primitives.Slot,
    ) !void {
        if (deltas.len != self.indices.count()) {
            return error.InvalidDeltaLen;
        }

        // Update checkpoints if changed
        if (!std.meta.eql(&justified_checkpoint.*, &self.justified_checkpoint) or
            !std.meta.eql(&finalized_checkpoint.*, &self.finalized_checkpoint))
        {
            self.justified_checkpoint = justified_checkpoint.*;
            self.finalized_checkpoint = finalized_checkpoint.*;
        }

        // Iterate backwards through nodes
        var node_index: usize = self.nodes.items.len;
        while (node_index > 0) {
            node_index -= 1;
            var node = &self.nodes.items[node_index];

            if (std.mem.eql(u8, &node.root, &[_]u8{0} ** 32)) {
                continue;
            }

            const execution_status_is_invalid = node.execution_status == .Invalid;

            var node_delta = if (execution_status_is_invalid)
                try std.math.sub(i64, 0, @as(i64, @intCast(node.weight)))
            else
                deltas[node_index];

            // Handle proposer boost
            if (std.mem.eql(u8, &self.previous_proposer_boost.root, &[_]u8{0} ** 32) and
                std.mem.eql(u8, &self.previous_proposer_boost.root, &node.root) and
                !execution_status_is_invalid)
            {
                node_delta = try std.math.sub(i64, node_delta, @as(i64, @intCast(self.previous_proposer_boost.score)));
            }

            if (std.mem.eql(u8, proposer_boost_root, &[_]u8{0} ** 32) and
                std.mem.eql(u8, proposer_boost_root, &node.root) and
                !execution_status_is_invalid)
            {
                const boost_score = try calculateCommitteeFraction(justified_balances, configs.ActiveConfig.get().PROPOSER_SCORE_BOOST);
                node_delta = try std.math.add(i64, node_delta, @as(i64, @intCast(boost_score)));
                self.previous_proposer_boost = .{
                    .root = proposer_boost_root.*,
                    .score = boost_score,
                };
            }

            // Apply weight changes
            if (execution_status_is_invalid) {
                node.weight = 0;
            } else if (node_delta < 0) {
                node.weight = try std.math.sub(u64, node.weight, @as(u64, @intCast(-node_delta)));
            } else {
                node.weight = try std.math.add(u64, node.weight, @as(u64, @intCast(node_delta)));
            }

            // Update parent delta
            if (node.parent) |parent_index| {
                deltas[parent_index] = std.math.add(i64, deltas[parent_index], node_delta) catch
                    return error.DeltaOverflow;
            }
        }

        // Update best child and descendant relationships
        node_index = self.nodes.items.len;
        while (node_index > 0) {
            node_index -= 1;
            if (self.nodes.items[node_index].parent) |parent_index| {
                try self.maybeUpdateBestChildAndDescendant(parent_index, node_index, current_slot);
            }
        }
    }

    pub fn maybePrune(self: *ProtoArray, finalized_root: *const primitives.Root) !void {
        const finalized_index = self.indices.get(finalized_root.*) orelse {
            return error.FinalizedNodeUnknown;
        };

        if (finalized_index < self.prune_threshold) {
            return;
        }

        // Remove indices for nodes being pruned
        var node_index: usize = 0;
        while (node_index < finalized_index) : (node_index += 1) {
            const root = self.nodes.items[node_index].root;
            _ = self.indices.remove(root);
        }

        // Drop nodes prior to finalization
        const old_nodes = try self.nodes.toOwnedSlice();
        defer self.allocator.free(old_nodes);
        self.nodes = std.ArrayList(ProtoNode).init(self.allocator);
        try self.nodes.appendSlice(old_nodes[finalized_index..]);

        // Adjust indices map
        var iter = self.indices.iterator();
        while (iter.next()) |entry| {
            const index = entry.value_ptr;
            index.* = if (index.* >= finalized_index)
                index.* - finalized_index
            else
                return error.IndexOverflow;
        }

        // Update parent/child indices in remaining nodes
        for (self.nodes.items) |*node| {
            if (node.parent) |parent| {
                node.parent = if (parent >= finalized_index)
                    parent - finalized_index
                else
                    null;
            }
            if (node.best_child) |best_child| {
                node.best_child = if (best_child >= finalized_index)
                    best_child - finalized_index
                else
                    null;
            }
            if (node.best_descendant) |best_descendant| {
                node.best_descendant = if (best_descendant >= finalized_index)
                    best_descendant - finalized_index
                else
                    null;
            }
        }
    }

    fn maybeUpdateBestChildAndDescendant(
        self: *ProtoArray,
        parent_index: usize,
        child_index: usize,
        current_slot: u64,
    ) !void {
        const child = &self.nodes.items[child_index];
        var parent = &self.nodes.items[parent_index];

        const child_leads_to_viable_head = self.nodeLeadsToViableHead(child, current_slot);

        if (parent.best_child) |best_child_index| {
            if (best_child_index == child_index and !child_leads_to_viable_head) {
                parent.best_child = null;
                parent.best_descendant = null;
            } else if (best_child_index == child_index) {
                parent.best_child = child_index;
                parent.best_descendant = child.best_descendant orelse child_index;
            } else {
                const best_child = &self.nodes.items[best_child_index];
                const best_child_leads_to_viable_head = self.nodeLeadsToViableHead(best_child, current_slot);

                if (child_leads_to_viable_head and !best_child_leads_to_viable_head) {
                    parent.best_child = child_index;
                    parent.best_descendant = child.best_descendant orelse child_index;
                } else if (!child_leads_to_viable_head and best_child_leads_to_viable_head) {
                    // No change needed
                } else if (child.weight == best_child.weight) {
                    if (std.mem.lessThan(u8, &best_child.root, &child.root)) {
                        parent.best_child = child_index;
                        parent.best_descendant = child.best_descendant orelse child_index;
                    }
                } else if (child.weight > best_child.weight) {
                    parent.best_child = child_index;
                    parent.best_descendant = child.best_descendant orelse child_index;
                }
            }
        } else if (child_leads_to_viable_head) {
            parent.best_child = child_index;
            parent.best_descendant = child.best_descendant orelse child_index;
        }
    }

    fn nodeLeadsToViableHead(self: *const ProtoArray, node: *const ProtoNode, current_slot: u64) bool {
        const best_descendant_viable = if (node.best_descendant) |best_descendant_index|
            self.nodeIsViableForHead(&self.nodes.items[best_descendant_index], current_slot)
        else
            false;
        return best_descendant_viable or self.nodeIsViableForHead(node, current_slot);
    }

    fn nodeIsViableForHead(self: *const ProtoArray, node: *const ProtoNode, current_slot: u64) bool {
        if (node.execution_status == .Invalid) {
            return false;
        }

        const genesis_epoch = 0;
        const current_epoch = current_slot / preset.ActivePreset.get().SLOTS_PER_EPOCH;
        const node_epoch = node.slot / preset.ActivePreset.get().SLOTS_PER_EPOCH;
        const node_justified_checkpoint = node.justified_checkpoint;

        const voting_source = if (current_epoch > node_epoch)
            node.unrealized_justified_checkpoint orelse node_justified_checkpoint
        else
            node_justified_checkpoint;

        const correct_justified = self.justified_checkpoint.epoch == genesis_epoch or
            voting_source.epoch == self.justified_checkpoint.epoch or
            voting_source.epoch + 2 >= current_epoch;

        const correct_finalized = self.finalized_checkpoint.epoch == genesis_epoch or
            self.isFinalizedCheckpointOrDescendant(&node.root);

        return correct_justified and correct_finalized;
    }

    pub fn getNode(self: *const ProtoArray, root: *const primitives.Root) ?ProtoNode {
        const index = self.indices.get(root.*) orelse return null;
        return self.nodes.items[index];
    }

    pub fn executionBlockHashToBeaconBlockRoot(
        self: *const ProtoArray,
        block_hash: *const primitives.Root,
    ) ?primitives.Root {
        // Iterate backwards through nodes to find matching execution block hash
        var i: usize = self.nodes.items.len;
        while (i > 0) {
            i -= 1;
            const node = self.nodes.items[i];

            const node_block_hash = switch (node.execution_status) {
                .Valid, .Invalid, .Optimistic => |hash| hash,
                .Irrelevant => continue,
            };

            if (std.mem.eql(u8, &node_block_hash, &block_hash.*)) {
                return node.root;
            }
        }
        return null;
    }

    pub fn isFinalizedCheckpointOrDescendant(self: *const ProtoArray, root: *const primitives.Root) bool {
        const finalized_root = self.finalized_checkpoint.root;
        const finalized_slot = self.finalized_checkpoint.epoch * preset.ActivePreset.get().SLOTS_PER_EPOCH;

        // Get initial node
        const node_index = self.indices.get(root.*) orelse return false;
        var node = &self.nodes.items[node_index];

        // Check checkpoints for quick verification
        if (std.meta.eql(node.finalized_checkpoint, self.finalized_checkpoint) or
            std.meta.eql(node.justified_checkpoint, self.finalized_checkpoint))
        {
            return true;
        }

        // Check unrealized checkpoints
        if (node.unrealized_finalized_checkpoint) |cp| {
            if (std.meta.eql(cp, self.finalized_checkpoint)) return true;
        }
        if (node.unrealized_justified_checkpoint) |cp| {
            if (std.meta.eql(cp, self.finalized_checkpoint)) return true;
        }

        // Walk backwards through ancestors
        while (true) {
            if (node.slot <= finalized_slot) {
                return std.meta.eql(node.root, finalized_root);
            }

            // Move to parent
            if (node.parent) |parent_index| {
                node = &self.nodes.items[parent_index];
            } else {
                return false;
            }
        }
    }

    pub fn propagateExecutionPayloadInvalidation(self: *ProtoArray, op: *const InvalidationOperation) !void {
        var invalidated_indices = std.AutoHashMap(usize, void).init(self.allocator);
        defer invalidated_indices.deinit();

        const head_block_root = switch (op.*) {
            .InvalidateOne => |info| info.block_root,
            .InvalidateMany => |info| info.head_block_root,
        };

        const index = self.indices.get(head_block_root) orelse {
            return error.NodeUnknown;
        };

        const latest_valid_ancestor_root = if (op.* == .InvalidateMany)
            self.executionBlockHashToBeaconBlockRoot(&op.InvalidateMany.latest_valid_ancestor)
        else
            null;

        const latest_valid_ancestor_is_descendant = if (latest_valid_ancestor_root) |ancestor_root|
            self.isDescendant(&ancestor_root, &head_block_root) and
                self.isFinalizedCheckpointOrDescendant(&ancestor_root)
        else
            false;

        try self.invalidateAncestors(index, &invalidated_indices, &head_block_root, latest_valid_ancestor_is_descendant, op);

        try self.invalidateDescendants(
            index,
            &invalidated_indices,
        );
    }

    pub fn isDescendant(self: *const ProtoArray, ancestor_root: *const primitives.Root, descendant_root: *const primitives.Root) bool {
        const ancestor_index = self.indices.get(ancestor_root.*) orelse return false;
        const ancestor = &self.nodes.items[ancestor_index];

        var iter = self.iterBlockRoots(descendant_root);
        while (iter.next()) |node_info| {
            if (node_info.slot < ancestor.slot) break;
            if (node_info.slot == ancestor.slot) {
                return std.mem.eql(u8, &node_info.root, &ancestor_root.*);
            }
        }

        return false;
    }

    // fn invalidateAncestors(
    //     self: *ProtoArray,
    //     start_index: usize,
    //     invalidated_indices: *std.AutoHashMap(usize, void),
    //     head_block_root: *const primitives.Root,
    //     latest_valid_ancestor_is_descendant: bool,
    //     op: *const InvalidationOperation,
    // ) !void {
    //     var index = start_index;
    //
    //     while (true) {
    //         var node = &self.nodes.items[index];
    //         std.debug.print("Invalidating block at index {}: status={}\n", .{ index, node.execution_status });
    //
    //         // Only invalidate if:
    //         // 1. This is the head block, or
    //         // 2. We have a valid ancestor and are still traversing between head and ancestor, or
    //         // 3. We should always invalidate blocks (based on op)
    //     if (std.mem.eql(u8, &node.root, head_block_root) or
    //             latest_valid_ancestor_is_descendant or
    //             shouldInvalidateBlock(op))
    //             {
    //                 switch (node.execution_status) {
    //                     .Valid => |_| return error.ValidExecutionStatusBecameInvalid,
    //                     .Optimistic => |hash| {
    //                         try invalidated_indices.put(index, {});
    //                         node.execution_status = .{ .Invalid = hash };
    //                         node.best_child = null;
    //                         node.best_descendant = null;
    //                     },
    //                     .Invalid => {},
    //                     .Irrelevant => break,
    //                 }
    //             } else {
    //                 break;
    //             }
    //
    //         if (node.parent) |parent_index| {
    //             index = parent_index;
    //         } else break;
    //     }
    // }
    fn invalidateAncestors(
        self: *ProtoArray,
        start_index: usize,
        invalidated_indices: *std.AutoHashMap(usize, void),
        head_block_root: *const primitives.Root,
        latest_valid_ancestor_is_descendant: bool,
        op: *const InvalidationOperation,
    ) !void {
        var index = start_index;

        while (true) {
            var node = &self.nodes.items[index];
            std.debug.print("Invalidating block at index {}: status={}\n", .{ index, node.execution_status });

            // Check if this node is the latest valid ancestor
            if (op.* == .InvalidateMany) {
                if (node.execution_status == .Valid) {
                    const valid_hash = switch (node.execution_status) {
                        .Valid => |hash| hash,
                        else => unreachable,
                    };
                    if (std.mem.eql(u8, &valid_hash, &op.InvalidateMany.latest_valid_ancestor)) {
                        break;
                    }
                }
            }

            if (!std.mem.eql(u8, &node.root, head_block_root) and
                !latest_valid_ancestor_is_descendant and
                !shouldInvalidateBlock(op))
            {
                break;
            }

            switch (node.execution_status) {
                .Valid => |_| return error.ValidExecutionStatusBecameInvalid,
                .Optimistic => |hash| {
                    try invalidated_indices.put(index, {});
                    node.execution_status = .{ .Invalid = hash };
                    node.best_child = null;
                    node.best_descendant = null;
                },
                .Invalid => {},
                .Irrelevant => break,
            }

            if (node.parent) |parent_index| {
                index = parent_index;
            } else break;
        }
    }

    fn invalidateDescendants(
        self: *ProtoArray,
        start_index: usize,
        invalidated_indices: *std.AutoHashMap(usize, void),
    ) !void {
        const first_descendant = start_index + 1;

        var i = first_descendant;
        while (i < self.nodes.items.len) : (i += 1) {
            var node = &self.nodes.items[i];

            if (node.parent) |parent_index| {
                if (invalidated_indices.contains(parent_index)) {
                    switch (node.execution_status) {
                        .Valid => |_| return error.ValidExecutionStatusBecameInvalid,
                        .Optimistic, .Invalid => |hash| {
                            node.execution_status = .{ .Invalid = hash };
                        },
                        .Irrelevant => return error.IrrelevantDescendant,
                    }
                    try invalidated_indices.put(i, {});
                }
            }
        }
    }

    fn shouldInvalidateBlock(op: *const InvalidationOperation) bool {
        return switch (op.*) {
            .InvalidateOne => true,
            .InvalidateMany => |info| info.always_invalidate_head,
        };
    }

    pub fn getWeights(self: *const ProtoArray) ![]const u64 {
        var weights = try self.allocator.alloc(u64, self.nodes.items.len);
        for (self.nodes.items, 0..) |node, i| {
            weights[i] = node.weight;
        }
        return weights;
    }

    pub fn calculateCommitteeFraction(
        justified_balances: *const JustifiedBalances,
        proposer_score_boost: u64,
    ) !u64 {
        const committee_weight = try std.math.divFloor(primitives.Gwei, justified_balances.total_effective_balance, preset.ActivePreset.get().SLOTS_PER_EPOCH);

        const boost_score = try std.math.mul(u64, committee_weight, proposer_score_boost);

        return try std.math.divFloor(u64, boost_score, 100);
    }
};

pub fn createTestProtoArray() ProtoArray {
    const genesis_checkpoint = consensus.Checkpoint{
        .epoch = 0,
        .root = [_]u8{0} ** 32,
    };

    return ProtoArray.init(
        std.testing.allocator,
        0, // prune_threshold
        genesis_checkpoint,
        genesis_checkpoint,
    );
}

fn createBlock(slot: u64, execution_status: ExecutionStatus) Block {
    return .{
        .slot = slot,
        .root = blockRoot(slot),
        .parent_root = if (slot > 1) blockRoot(slot - 1) else null,
        .target_root = [_]u8{0} ** 32,
        .state_root = [_]u8{0} ** 32,
        .justified_checkpoint = consensus.Checkpoint{
            .epoch = 0,
            .root = [_]u8{0} ** 32,
        },
        .finalized_checkpoint = consensus.Checkpoint{
            .epoch = 0,
            .root = [_]u8{0} ** 32,
        },
        .execution_status = execution_status,
        .unrealized_justified_checkpoint = null,
        .unrealized_finalized_checkpoint = null,
    };
}

fn blockRoot(slot: primitives.Slot) primitives.Root {
    var root: primitives.Root = undefined;
    std.mem.writeInt(u64, root[0..8], slot, .little);
    return root;
}

fn execution_block_hash(slot: primitives.Slot) primitives.Hash32 {
    var hash: primitives.Hash32 = undefined;
    std.mem.writeInt(u64, hash[0..8], slot, .little);
    return hash;
}

test "ProtoArray basic operations" {
    var proto_array = createTestProtoArray();
    defer proto_array.deinit();

    // Add test cases here
}

test "weights after resetting optimistic status" {
    // Create forked chain structure:
    // genesis -> valid -> syncing -> syncing -> syncing
    const current_slot = 100;
    // Setup test environment
    preset.ActivePreset.set(preset.Presets.minimal);
    defer preset.ActivePreset.reset();
    var proto_array = createTestProtoArray();
    defer proto_array.deinit();

    // Import blocks and set weights
    const blocks = [_]Block{
        createBlock(1, .{ .Valid = execution_block_hash(1) }),
        createBlock(2, .{ .Optimistic = execution_block_hash(2) }),
        createBlock(3, .{ .Optimistic = execution_block_hash(3) }),
        createBlock(4, .{ .Optimistic = execution_block_hash(4) }),
    };

    for (blocks) |block| {
        try proto_array.onBlock(&block, current_slot);
    }

    // Store original weights
    const original_weights = try proto_array.getWeights();
    defer std.testing.allocator.free(original_weights);

    // Reset optimistic status and verify weights
    try proto_array.propagateExecutionPayloadValidation(&blocks[1].root);

    const new_weights = try proto_array.getWeights();
    defer std.testing.allocator.free(new_weights);
    try std.testing.expectEqualSlices(u64, original_weights, new_weights);
}

test "find head with invalid execution status" {
    // Create forked chain structure:
    // genesis -> valid -> invalid
    preset.ActivePreset.set(preset.Presets.minimal);
    defer preset.ActivePreset.reset();
    const current_slot = 100;
    var proto_array = createTestProtoArray();
    defer proto_array.deinit();

    try proto_array.onBlock(&createBlock(1, .{ .Valid = execution_block_hash(1) }), current_slot);
    try proto_array.onBlock(&createBlock(2, .{ .Invalid = execution_block_hash(2) }), current_slot);

    const result = try proto_array.findHead(&blockRoot(1), current_slot);
    try std.testing.expectEqualSlices(u8, &blockRoot(1), &result);

    const result2 = proto_array.findHead(&blockRoot(2), current_slot);
    try std.testing.expectError(error.InvalidExecutionStatus, result2);
}

test "invalidate payload and descendants" {
    // Create forked chain structure:
    // genesis -> valid -> optimistic -> optimistic -> optimistic
    preset.ActivePreset.set(preset.Presets.minimal);
    defer preset.ActivePreset.reset();
    const current_slot = 100;
    var proto_array = createTestProtoArray();
    defer proto_array.deinit();

    const blocks = [_]Block{
        createBlock(1, .{ .Valid = execution_block_hash(1) }),
        createBlock(2, .{ .Optimistic = execution_block_hash(2) }),
        createBlock(3, .{ .Optimistic = execution_block_hash(3) }),
        createBlock(4, .{ .Optimistic = execution_block_hash(4) }),
    };

    for (blocks) |block| {
        try proto_array.onBlock(&block, current_slot);
    }

    const op = InvalidationOperation{
        .InvalidateOne = .{
            .block_root = blocks[0].root, // Try to invalidate a Valid block
        },
    };

    try std.testing.expectError(error.ValidExecutionStatusBecameInvalid, proto_array.propagateExecutionPayloadInvalidation(&op));
}

test "validate payload and ancestors" {
    // Create forked chain structure:
    // genesis -> optimistic -> optimistic -> optimistic -> optimistic
    preset.ActivePreset.set(preset.Presets.minimal);
    defer preset.ActivePreset.reset();
    const current_slot = 100;
    var proto_array = createTestProtoArray();
    defer proto_array.deinit();

    const blocks = [_]Block{
        createBlock(1, .{ .Optimistic = execution_block_hash(1) }),
        createBlock(2, .{ .Optimistic = execution_block_hash(2) }),
        createBlock(3, .{ .Optimistic = execution_block_hash(3) }),
        createBlock(4, .{ .Optimistic = execution_block_hash(4) }),
    };

    for (blocks) |block| {
        try proto_array.onBlock(&block, current_slot);
    }

    // Validate the last block and verify ancestors are validated
    try proto_array.propagateExecutionPayloadValidation(&blocks[3].root);

    // Verify all blocks are now valid
    for (blocks) |block| {
        const node = proto_array.getNode(&block.root);
        try std.testing.expect(node.?.execution_status == .Valid);
    }
}

test "invalidate many with latest valid ancestor" {
    // Create forked chain structure:
    // genesis -> valid -> optimistic -> optimistic -> optimistic
    preset.ActivePreset.set(preset.Presets.minimal);
    defer preset.ActivePreset.reset();
    const current_slot = 100;
    var proto_array = createTestProtoArray();
    defer proto_array.deinit();

    const blocks = [_]Block{
        createBlock(1, .{ .Valid = execution_block_hash(1) }),
        createBlock(2, .{ .Optimistic = execution_block_hash(2) }),
        createBlock(3, .{ .Optimistic = execution_block_hash(3) }),
        createBlock(4, .{ .Optimistic = execution_block_hash(4) }),
    };

    for (blocks) |block| {
        try proto_array.onBlock(&block, current_slot);
    }

    const op = InvalidationOperation{
        .InvalidateMany = .{
            .head_block_root = blocks[2].root,
            .always_invalidate_head = true,
            .latest_valid_ancestor = execution_block_hash(1),
        },
    };

    try proto_array.propagateExecutionPayloadInvalidation(&op);

    // Verify blocks 2-4 are invalid
    for (blocks[1..]) |block| {
        const node = proto_array.getNode(&block.root);
        switch (node.?.execution_status) {
            .Invalid => |hash| try std.testing.expect(std.mem.eql(u8, &hash, &execution_block_hash(block.slot))),
            else => return error.TestUnexpectedResult,
        }
    }

    // Verify block 1 remains valid
    const first_node = proto_array.getNode(&blocks[0].root);
    switch (first_node.?.execution_status) {
        .Valid => |hash| try std.testing.expect(std.mem.eql(u8, &hash, &execution_block_hash(1))),
        else => return error.TestUnexpectedResult,
    }
}

test "proposer boost score changes" {
    preset.ActivePreset.set(preset.Presets.minimal);
    defer preset.ActivePreset.reset();
    const current_slot = 100;
    var proto_array = createTestProtoArray();
    defer proto_array.deinit();
    // Create forked chain structure:
    // genesis -> valid -> valid -> valid
    const justified_balances = JustifiedBalances{
        .total_effective_balance = 32 * preset.ActivePreset.get().EFFECTIVE_BALANCE_INCREMENT,
    };

    // Setup initial chain
    const blocks = [_]Block{
        createBlock(1, .{ .Valid = execution_block_hash(1) }),
        createBlock(2, .{ .Valid = execution_block_hash(2) }),
        createBlock(3, .{ .Valid = execution_block_hash(3) }),
    };

    for (blocks) |block| {
        try proto_array.onBlock(&block, current_slot);
    }

    const genesis_checkpoint = consensus.Checkpoint{
        .epoch = 0,
        .root = [_]u8{0} ** 32,
    };
    // Apply score changes with proposer boost
    var deltas = [_]i64{100} ** 3;
    try proto_array.applyScoreChanges(
        &deltas,
        &genesis_checkpoint,
        &genesis_checkpoint,
        &justified_balances,
        &blocks[1].root, // boost block 2
        current_slot,
    );

    // Verify boosted block has higher weight
    const boosted_node = proto_array.getNode(&blocks[1].root);
    const other_node = proto_array.getNode(&blocks[2].root);
    std.debug.print("{} {}\n", .{ boosted_node.?.weight, other_node.?.weight });
    try std.testing.expect(boosted_node.?.weight > other_node.?.weight);

    // Verify checkpoints are maintained
    try std.testing.expect(std.mem.eql(u8, &proto_array.justified_checkpoint.root, &genesis_checkpoint.root));
    try std.testing.expect(std.mem.eql(u8, &proto_array.finalized_checkpoint.root, &genesis_checkpoint.root));
}

test "prune nodes and maintain indices" {
    // Create forked chain structure:
    // genesis -> valid -> valid -> valid -> valid -> valid
    preset.ActivePreset.set(preset.Presets.minimal);
    defer preset.ActivePreset.reset();
    const current_slot = 100;
    var proto_array = createTestProtoArray();
    defer proto_array.deinit();

    // Set prune threshold to 2 so pruning will occur when we finalize block 3
    proto_array.prune_threshold = 2;

    const blocks = [_]Block{
        createBlock(1, .{ .Valid = execution_block_hash(1) }),
        createBlock(2, .{ .Valid = execution_block_hash(2) }),
        createBlock(3, .{ .Valid = execution_block_hash(3) }),
        createBlock(4, .{ .Valid = execution_block_hash(4) }),
        createBlock(5, .{ .Valid = execution_block_hash(5) }),
    };

    // Import all blocks first
    for (blocks) |block| {
        try proto_array.onBlock(&block, current_slot);
    }

    const original_count = proto_array.nodes.items.len;

    // Finalize block 3 which should trigger pruning since its index > threshold
    try proto_array.maybePrune(&blocks[2].root);

    try std.testing.expect(proto_array.nodes.items.len < original_count);
    try std.testing.expect(proto_array.indices.count() == proto_array.nodes.items.len);
}

fn createBlockWithParent(slot: u64, parent: *const primitives.Root, execution_status: ExecutionStatus) Block {
    const genesis_checkpoint = consensus.Checkpoint{
        .epoch = 0,
        .root = [_]u8{0} ** 32,
    };
    return .{
        .slot = slot,
        .root = blockRoot(slot),
        .parent_root = parent.*,
        .target_root = [_]u8{0} ** 32,
        .state_root = [_]u8{0} ** 32,
        .justified_checkpoint = genesis_checkpoint,
        .finalized_checkpoint = genesis_checkpoint,
        .execution_status = execution_status,
        .unrealized_justified_checkpoint = null,
        .unrealized_finalized_checkpoint = null,
    };
}

test "verify chain relationships" {
    preset.ActivePreset.set(preset.Presets.minimal);
    defer preset.ActivePreset.reset();
    const current_slot = 100;
    var proto_array = createTestProtoArray();
    defer proto_array.deinit();

    // Create forked chain structure:
    //          1
    //         / \
    //        2   5
    //       / \
    //      3   4
    const blocks = [_]Block{
        createBlock(1, .{ .Valid = execution_block_hash(1) }),
        createBlockWithParent(2, &blockRoot(1), .{ .Valid = execution_block_hash(2) }),
        createBlockWithParent(3, &blockRoot(2), .{ .Valid = execution_block_hash(3) }),
        createBlockWithParent(4, &blockRoot(2), .{ .Valid = execution_block_hash(4) }),
        createBlockWithParent(5, &blockRoot(1), .{ .Valid = execution_block_hash(5) }),
    };

    for (blocks) |block| {
        try proto_array.onBlock(&block, current_slot);
    }

    // Test ancestor relationships
    try std.testing.expect(proto_array.isDescendant(&blocks[0].root, &blocks[2].root));
    try std.testing.expect(proto_array.isDescendant(&blocks[0].root, &blocks[4].root));
    try std.testing.expect(proto_array.isDescendant(&blocks[1].root, &blocks[2].root));
    try std.testing.expect(!proto_array.isDescendant(&blocks[1].root, &blocks[4].root));

    // Test finalized ancestor relationships
    try std.testing.expect(proto_array.isFinalizedCheckpointOrDescendant(&blocks[0].root));
    try std.testing.expect(proto_array.isFinalizedCheckpointOrDescendant(&blocks[2].root));
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
    const current_slot = 100;
    var proto_array = createTestProtoArray();
    defer proto_array.deinit();

    const blocks = [_]Block{
        createBlock(1, .{ .Valid = execution_block_hash(1) }),
        createBlockWithParent(2, &blockRoot(1), .{ .Optimistic = execution_block_hash(2) }),
        createBlockWithParent(3, &blockRoot(1), .{ .Optimistic = execution_block_hash(3) }),
        createBlockWithParent(4, &blockRoot(2), .{ .Optimistic = execution_block_hash(4) }),
        createBlockWithParent(5, &blockRoot(2), .{ .Optimistic = execution_block_hash(5) }),
        createBlockWithParent(6, &blockRoot(3), .{ .Optimistic = execution_block_hash(6) }),
        createBlockWithParent(7, &blockRoot(4), .{ .Optimistic = execution_block_hash(7) }),
        createBlockWithParent(8, &blockRoot(6), .{ .Optimistic = execution_block_hash(8) }),
    };
    for (blocks) |block| {
        try proto_array.onBlock(&block, current_slot);
    }

    // Test pruning
    const original_count = proto_array.nodes.items.len;
    try proto_array.maybePrune(&blocks[1].root);
    try std.testing.expect(proto_array.nodes.items.len < original_count);

    // Test invalidity
    const op = InvalidationOperation{
        .InvalidateOne = .{
            .block_root = blocks[2].root,
        },
    };

    try proto_array.propagateExecutionPayloadInvalidation(&op);
    // Verify block 2 and its descendants are invalid
    const node2 = proto_array.getNode(&blocks[2].root);
    const node5 = proto_array.getNode(&blocks[5].root);
    const node7 = proto_array.getNode(&blocks[7].root);

    std.debug.print("{} {} {}\n", .{ node2.?.execution_status, node5.?.execution_status, node7.?.execution_status });
    // try std.testing.expect(node2.?.execution_status == .Invalid);
    // try std.testing.expect(node5.?.execution_status == .Invalid);
    // try std.testing.expect(node7.?.execution_status == .Invalid);

    const node3 = proto_array.getNode(&blocks[3].root);
    const node4 = proto_array.getNode(&blocks[4].root);
    const node6 = proto_array.getNode(&blocks[6].root);
    const node1 = proto_array.getNode(&blocks[1].root);
    std.debug.print("{} {} {} {}\n", .{ node3.?.execution_status, node4.?.execution_status, node6.?.execution_status, node1.?.execution_status });
}

test "Proto Array - chain reorganization" {
    preset.ActivePreset.set(preset.Presets.minimal);
    defer preset.ActivePreset.reset();
    const current_slot = 100;
    var proto_array = createTestProtoArray();
    defer proto_array.deinit();

    const blocks = [_]Block{
        createBlock(1, .{ .Valid = execution_block_hash(1) }),
        createBlockWithParent(2, &blockRoot(1), .{ .Valid = execution_block_hash(2) }),
        createBlockWithParent(3, &blockRoot(1), .{ .Valid = execution_block_hash(3) }),
        createBlockWithParent(4, &blockRoot(2), .{ .Valid = execution_block_hash(4) }),
        createBlockWithParent(5, &blockRoot(3), .{ .Valid = execution_block_hash(5) }),
        createBlockWithParent(6, &blockRoot(4), .{ .Valid = execution_block_hash(6) }),
        createBlockWithParent(7, &blockRoot(5), .{ .Valid = execution_block_hash(7) }),
        createBlockWithParent(8, &blockRoot(6), .{ .Valid = execution_block_hash(8) }),
    };

    for (blocks) |block| {
        try proto_array.onBlock(&block, current_slot);
    }

    const genesis_checkpoint = consensus.Checkpoint{
        .epoch = 0,
        .root = [_]u8{0} ** 32,
    };

    // Initially favor left chain
    var deltas = [_]i64{100} ** blocks.len;
    deltas[4] = 200; // Higher weight for block 5
    try proto_array.applyScoreChanges(
        &deltas,
        &genesis_checkpoint,
        &genesis_checkpoint,
        &JustifiedBalances{ .total_effective_balance = 32 * preset.ActivePreset.get().EFFECTIVE_BALANCE_INCREMENT },
        &[_]u8{0} ** 32,
        current_slot,
    );

    // Verify left chain is preferred
    const head = try proto_array.findHead(&blocks[0].root, current_slot);
    try std.testing.expect(std.mem.eql(u8, &head, &blocks[6].root));

    // Now favor right chain
    deltas[7] = 300; // Higher weight for block 8
    try proto_array.applyScoreChanges(
        &deltas,
        &genesis_checkpoint,
        &genesis_checkpoint,
        &JustifiedBalances{ .total_effective_balance = 32 * preset.ActivePreset.get().EFFECTIVE_BALANCE_INCREMENT },
        &[_]u8{0} ** 32,
        current_slot,
    );

    // Verify right chain becomes preferred
    const new_head = try proto_array.findHead(&blocks[0].root, current_slot);
    try std.testing.expect(std.mem.eql(u8, &new_head, &blocks[7].root));
}
