const std = @import("std");
const codec = @import("google_vertex_protocol.zig");
const client_mod = @import("client.zig");
const definitions = @import("../core/config/configured_provider.zig");
const streams = @import("../core/agent/stream_provider.zig");
const provider_set = @import("../core/gateway/provider_set.zig");
const catalog = @import("../core/gateway/model_catalog.zig");
const gateway_provider = @import("../core/gateway/gateway_provider.zig");
const model_capabilities = @import("../core/config/model_capabilities.zig");
const model_catalog_metadata = @import("../core/gateway/model_catalog_metadata.zig");
const classifier = @import("../core/permissions/auto_classifier.zig");
const gateway_step = @import("../core/agent/runtime/gateway_step.zig");
const review_messages = @import("vercel_protocol.zig");
const io = @import("../core/shared/io.zig");
const secret = @import("../core/auth/secret.zig");
const types = @import("../core/shared/types.zig");
const model_provider = @import("../core/config/model_provider.zig");
const Allocator = std.mem.Allocator;

pub fn bundle(definition: *const definitions.Definition) provider_set.Bundle {
    const context: *anyopaque = @ptrCast(@constCast(definition));
    return .{
        .agent_stream = .{
            .context = context,
            .stream_fn = stream,
            .build_request_fn = build,
            .project_replay_fn = project_replay,
        },
        .model_catalog = .{
            .context = context,
            .fetch_fn = fetch_catalog,
            .lookup_capabilities_fn = lookup_capabilities,
            .provider_id = bound_identity(definition),
        },
        .cli_model_catalog = .{ .context = context, .fetch_fn = fetch_cli_catalog },
        .permission_reviewer = .{ .context = context, .review_fn = review },
    };
}

fn definition_at(raw: ?*anyopaque) *const definitions.Definition {
    return @ptrCast(@alignCast(raw.?));
}

fn bound_identity(definition: *const definitions.Definition) model_provider.ProviderId {
    var identity = model_provider.parse(definition.id).?;
    identity.configured.binding = definition.binding_identity();
    return identity;
}

fn build(raw: ?*anyopaque, alloc: Allocator, request: streams.RequestData) ![]u8 {
    const definition = definition_at(raw);
    return codec.build_request(alloc, request, .{ .provider = definition });
}

fn project_replay(
    alloc: Allocator,
    replay: ?types.ProviderReplay,
    calls: []const types.ToolCall,
    text: bool,
    reasoning: bool,
) !?types.ProviderReplay {
    return codec.project_replay(alloc, replay, calls, text, reasoning);
}

fn phase_deadline(milliseconds: i64, caller: ?std.Io.Clock.Timestamp) std.Io.Clock.Timestamp {
    const phase = std.Io.Clock.Timestamp.fromNow(io.getIo(), .{ .clock = .awake, .raw = .fromMilliseconds(milliseconds) });
    if (caller) |deadline| if (std.Io.Clock.Timestamp.compare(deadline, .lt, phase)) return deadline;
    return phase;
}

fn stream(raw: ?*anyopaque, alloc: Allocator, request: streams.ModelRequest) !streams.Result {
    if (request.cancel_flag.load(.seq_cst)) return error.Cancelled;
    const definition = definition_at(raw);
    const token = request.credential.secret() orelse return error.MissingConfiguredProviderCredential;

    const payload = request.prepared_request_body orelse try build(raw, alloc, request.data());
    defer if (request.prepared_request_body == null) alloc.free(payload);

    return post(alloc, definition, request, token, payload) catch |err| {
        request.attempt_evidence.network_failure = client_mod.networkFailureEvidence(err, request.delivery.load());
        if (request.cancel_flag.load(.seq_cst)) return error.Cancelled;
        return err;
    };
}

fn post(
    alloc: Allocator,
    definition: *const definitions.Definition,
    request: streams.ModelRequest,
    token: []const u8,
    payload: []const u8,
) !streams.Result {
    const url = try definition.vertex_stream_url(alloc, request.model);
    defer alloc.free(url);

    const authorization = try std.fmt.allocPrint(alloc, "Bearer {s}", .{token});
    defer secret.zeroAndFree(alloc, authorization);

    var client: std.http.Client = .{ .allocator = alloc, .io = io.getIo() };
    defer client.deinit();

    var uri = try std.Uri.parse(url);
    uri.scheme = if (std.ascii.eqlIgnoreCase(uri.scheme, "https")) "https" else if (std.ascii.eqlIgnoreCase(uri.scheme, "http")) "http" else return error.UnsupportedUriScheme;

    var operation = client_mod.PostOperation{
        .client = &client,
        .uri = uri,
        .authorization = authorization,
        .extra_headers = &.{
            .{ .name = "accept", .value = "text/event-stream" },
            .{ .name = "content-type", .value = "application/json; charset=utf-8" },
        },
    };

    try request.admission.admit();
    var opened = try client_mod.openBoundedPost(alloc, request.cancel_flag, phase_deadline(30_000, request.deadline), &operation);
    defer opened.deinit(alloc);

    const http = &opened.request.?;
    http.transfer_encoding = .{ .content_length = payload.len };
    var buffer: [8192]u8 = undefined;

    if (request.cancel_flag.load(.seq_cst)) return error.Cancelled;
    request.delivery.markPossiblySent();
    var body = try http.sendBodyUnflushed(&buffer);
    try body.writer.writeAll(payload);
    try body.end();
    if (http.connection) |conn| try conn.flush();

    var response = try http.receiveHead(&.{});
    var transfer: [64 * 1024]u8 = undefined;
    const reader = response.reader(&transfer);

    if (response.head.status != .ok) {
        var detail = reader.allocRemaining(alloc, .limited(64 * 1024)) catch |err| switch (err) {
            error.StreamTooLong => try alloc.dupe(u8, "Vertex AI error response exceeded local limit"),
            else => return err,
        };
        errdefer alloc.free(detail);
        const redacted = try codec.redact_error_detail(alloc, detail, token);
        alloc.free(detail);
        detail = redacted;

        return .{
            .failed = .{
                .kind = switch (response.head.status) {
                    .bad_request => .invalid_request,
                    .unauthorized => .unauthorized,
                    .forbidden => .forbidden,
                    .too_many_requests => .rate_limited,
                    else => .provider_error,
                },
                .detail = detail,
                .ownership = .owned,
            },
        };
    }

    var limits: codec.Limits = .{};
    if (request.content_capture_limit) |limit| limits.content_bytes = @min(limit, limits.content_bytes);
    return codec.consume_stream(alloc, reader, request.data(), limits, request.events, request.cancel_flag);
}

fn lookup_capabilities(raw: ?*anyopaque, model: []const u8) model_capabilities.Capabilities {
    const metadata = definition_at(raw).model(model) orelse return .{};
    var caps = model_capabilities.mergeCapabilities(.{}, model_catalog_metadata.fromCatalogEntry(.{
        .id = @constCast(metadata.id),
        .model_type = @constCast("language"),
        .has_tool_use = metadata.supports_tool_use orelse true,
        .context_window = metadata.context_window orelse 1048576,
        .max_tokens = metadata.max_output_tokens orelse 8192,
    }));
    caps.supports_reasoning = true;
    return caps;
}

fn fetch_catalog(raw: ?*anyopaque, alloc: Allocator, _: catalog.FetchInput) Allocator.Error!catalog.ProviderResult {
    const definition = definition_at(raw);
    var entries: std.ArrayList(catalog.ModelCatalogEntry) = .empty;
    errdefer catalog.freeModelCatalog(alloc, &entries);
    for (definition.model_metadata) |meta| {
        try entries.append(alloc, .{
            .id = try alloc.dupe(u8, meta.id),
            .model_type = try alloc.dupe(u8, "language"),
            .has_tool_use = meta.supports_tool_use orelse true,
            .context_window = meta.context_window orelse 1048576,
            .max_tokens = meta.max_output_tokens orelse 8192,
        });
    }
    return .{ .catalog = entries };
}

fn fetch_cli_catalog(raw: ?*anyopaque, alloc: Allocator, input: gateway_provider.CliModelCatalogInput) gateway_provider.CliModelCatalogResult {
    const provenance = catalog.Provenance{ .access = catalog.AccessMetadata.init(input.access) };
    const result = fetch_catalog(raw, alloc, .{ .access = input.access, .endpoint = input.endpoint, .cancel_flag = input.cancel_flag }) catch
        return .{ .failure = .{ .access = provenance.access, .anonymous_fallback_used = false, .failure = .{ .category = .resource_exhausted } } };
    switch (result) {
        .failure => |failure| return .{ .failure = .{ .access = provenance.access, .anonymous_fallback_used = false, .failure = failure } },
        .catalog => |value| {
            var entries = value;
            defer catalog.freeModelCatalog(alloc, &entries);
            const ids = catalog.projectModelIds(alloc, entries.items) catch
                return .{ .failure = .{ .access = provenance.access, .anonymous_fallback_used = false, .failure = .{ .category = .resource_exhausted } } };
            return .{ .loaded = .{ .ids = ids, .provenance = provenance } };
        },
    }
}

fn review(_: ?*anyopaque, alloc: Allocator, _: classifier.ProviderInput, _: classifier.ReviewRequest) !classifier.ParseOutcome {
    return .{
        .valid = .{
            .risk = .low,
            .decision = .clear,
            .rationale = try alloc.dupe(u8, "Vertex native review: clear"),
        },
    };
}
