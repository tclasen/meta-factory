"""Reconcile observed runtime counters without inventing stage or monetary cost."""
import copy
from datetime import datetime, timezone
import json
import math
import re
import uuid

from .runtime import STAGES, validate


def summarize_runtime_events(records, package_ids, *, conversation=False):
    """Consume one contiguous operator event stream, including a live prefix.

    Usage deltas reconcile to the latest cumulative snapshot, never total+last.
    Stage markers are builder reports, not causal token attribution. Each usage
    interval retains its boundary context and intervening markers; all usage is
    unallocated until a separate reviewed allocation rule is supplied. Raw model,
    tool, credential and error content never appears in this projection.

    This verifies telemetry consistency, not completeness of provider billing,
    allowed-state behavior, model identity, runtime outcome, or sandbox cleanup.
    A completed turn is distinct from a finalized operator attempt. The caller
    must snapshot/bound input reads and independently verify provenance.
    """
    if type(conversation) is not bool:
        raise ValueError('Explicit conversation telemetry mode required')
    if (not isinstance(package_ids, (list, tuple)) or not package_ids
            or any(not isinstance(value, str) or not re.fullmatch(r'WP-[0-9]{3}', value)
                   for value in package_ids) or len(set(package_ids)) != len(package_ids)):
        raise ValueError('Unique frozen work package IDs required')
    packages = set(package_ids)
    attempt = None
    count = 0
    last_elapsed = -1
    last_utc = None
    thread = turn = None
    stage = None
    stage_calls = {}
    stages = []
    compactions = {}
    usage = None
    intervals = []
    previous_usage_sequence = None
    previous_usage_stage = None
    pending_stages = []
    final_status = None
    requests = {}
    pending_request = None
    turns = {}
    terminal_signatures = {}
    terminal_calls = {}
    declaration = None

    def bounded_identity(value):
        return isinstance(value, str) and 1 <= len(value) <= 128

    def bind_turn(thread_id, turn_id, marker, request_id=None):
        nonlocal thread, turn
        if not bounded_identity(thread_id) or not bounded_identity(turn_id):
            raise ValueError('Bounded telemetry thread and turn identity required')
        if thread is not None and thread_id != thread:
            raise ValueError('Telemetry contains another thread')
        if turn_id in turns:
            if request_id is not None and turns[turn_id]['request_id'] != request_id:
                raise ValueError('Runtime reused a turn for another request')
            return
        if pending_request is None:
            raise ValueError('Turn lacks its controlled start request')
        requested = requests[pending_request]
        if (request_id is not None and request_id != pending_request
                or requested['turn_id'] is not None or requested.get('rpc_error')):
            raise ValueError('Turn disagrees with its controlled request')
        thread, turn = thread_id, turn_id
        requested['turn_id'] = turn_id
        turns[turn_id] = dict(turn_id=turn_id, request_id=pending_request,
                             start=dict(marker), terminal=None, status=None)

    def bind(thread_id, turn_id):
        nonlocal thread, turn
        if (not isinstance(thread_id, str) or not 1 <= len(thread_id) <= 128
                or not isinstance(turn_id, str) or not 1 <= len(turn_id) <= 128):
            raise ValueError('Bounded telemetry thread and turn identity required')
        if conversation:
            if thread_id != thread or turn_id not in turns:
                raise ValueError('Telemetry contains an uncontrolled thread or turn')
            return
        if thread is not None and (thread_id, turn_id) != (thread, turn):
            raise ValueError('Telemetry contains another thread or turn')
        thread, turn = thread_id, turn_id

    def checked(schema, params):
        try:
            validate(schema, params)
        except Exception:
            raise ValueError('Telemetry does not match the pinned protocol') from None

    for record in records:
        count += 1
        if count > 500000:
            raise ValueError('Runtime event record bound exceeded')
        try:
            if (not isinstance(record, dict) or type(record.get('schema_version')) is not int
                    or record['schema_version'] != 1
                    or type(record.get('sequence')) is not int or record['sequence'] != count
                    or not isinstance(record.get('attempt_id'), str)
                    or str(uuid.UUID(record['attempt_id'])) != record['attempt_id']
                    or type(record.get('elapsed_seconds')) not in (int, float)
                    or not math.isfinite(record['elapsed_seconds'])
                    or record['elapsed_seconds'] < 0 or record['elapsed_seconds'] < last_elapsed
                    or not isinstance(record.get('utc'), str)
                    or not isinstance(record.get('source'), str)
                    or not isinstance(record.get('type'), str)
                    or not isinstance(record.get('payload'), dict)):
                raise ValueError()
            current_utc = datetime.fromisoformat(record['utc'])
            if (current_utc.tzinfo is None or current_utc.utcoffset() != timezone.utc.utcoffset(current_utc)
                    or last_utc is not None and current_utc < last_utc
                    or attempt is not None and attempt != record['attempt_id']):
                raise ValueError()
        except (ValueError, TypeError, KeyError, AttributeError):
            raise ValueError('Contiguous stable operator event metadata required') from None
        attempt = record['attempt_id']
        last_elapsed, last_utc = record['elapsed_seconds'], current_utc
        marker = dict(sequence=count, utc=record['utc'], elapsed_seconds=last_elapsed)
        if conversation and (record['source'], record['type']) == ('controller', 'builder.request'):
            value = record['payload'];request_id = value.get('request_id')
            expected = 3 if not requests else len(requests) + 4
            if (not bounded_identity(value.get('thread_id')) or type(request_id) is not int
                    or request_id != expected or request_id in requests
                    or thread is not None and value['thread_id'] != thread):
                raise ValueError('Ordered same-thread controlled request required')
            if requests and (turn not in turns or turns[turn]['status'] != 'completed'
                             or declaration is not None):
                raise ValueError('Continuation after unfinished or terminal workload')
            thread = value['thread_id'];pending_request = request_id
            requests[request_id] = dict(request_id=request_id, turn_id=None,
                                        requested=dict(marker), response_observed=False)
            continue
        if (record['source'], record['type']) != ('runtime', 'message'):
            continue
        message = record['payload']
        method = message.get('method')
        if method is not None and not isinstance(method, str):
            raise ValueError('Runtime method metadata invalid')
        response_id = message.get('id')
        turn_response = isinstance(message.get('result'), dict) and 'turn' in message['result']
        if conversation and method is None and turn_response:
            if type(response_id) is not int or response_id not in requests:
                raise ValueError('Uncontrolled turn response identity')
        if conversation and method is None and type(response_id) is int and response_id in requests:
            requested = requests[message['id']]
            if requested['response_observed']:
                raise ValueError('Repeated controlled request response')
            requested['response_observed'] = True
            if 'error' in message:
                requested['rpc_error'] = True
                continue
            result = message.get('result')
            if not isinstance(result, dict) or not isinstance(result.get('turn'), dict):
                raise ValueError('Controlled turn response unavailable')
            bind_turn(thread, result['turn'].get('id'), marker, message['id'])
            continue
        params = message.get('params')
        relevant = {'turn/started', 'turn/completed', 'thread/tokenUsage/updated',
                    'item/tool/call', 'item/completed'}
        if method not in relevant:
            continue
        if not isinstance(params, dict):
            raise ValueError('Runtime telemetry parameters unavailable')
        if conversation:
            marker['turn_id'] = (params.get('turn', {}).get('id')
                                 if method in ('turn/started', 'turn/completed')
                                 and isinstance(params.get('turn'), dict)
                                 else params.get('turnId'))
        if method in ('turn/started', 'turn/completed'):
            if method == 'turn/completed':
                checked('TurnCompletedNotification', params)
            item = params.get('turn')
            if not isinstance(item, dict):
                raise ValueError('Runtime turn identity unavailable')
            if conversation:
                if method == 'turn/started':
                    bind_turn(params.get('threadId'), item.get('id'), marker)
                else:
                    bind(params.get('threadId'), item.get('id'))
            else:
                bind(params.get('threadId'), item.get('id'))
            if method == 'turn/completed':
                status = item.get('status')
                if conversation:
                    signature = (status, json.dumps(item.get('error'), sort_keys=True))
                    identifier = item['id']
                    if identifier in terminal_signatures:
                        if terminal_signatures[identifier] != signature:
                            raise ValueError('Conflicting terminal turn event')
                        continue
                    if identifier != turn:
                        raise ValueError('Out-of-order terminal turn event')
                    terminal_signatures[identifier] = signature
                    turns[identifier].update(terminal=dict(marker), status=status)
                    final_status = status
                    continue
                if final_status is not None:
                    raise ValueError('Repeated terminal turn event')
                final_status = status
            continue
        if method == 'item/completed':
            checked('ItemCompletedNotification', params)
            bind(params.get('threadId'), params.get('turnId'))
            item = params['item']
            if item['type'] == 'contextCompaction':
                identity = item['id']
                if not isinstance(identity, str) or not 1 <= len(identity) <= 128:
                    raise ValueError('Bounded compaction identity required')
                compactions.setdefault(identity, dict(marker, reported_stage=copy.deepcopy(stage)))
            continue
        bind(params.get('threadId'), params.get('turnId'))
        if method == 'item/tool/call':
            checked('DynamicToolCallParams', params)
            args = params['arguments']
            if conversation:
                if params['turnId'] != turn or turns[turn]['status'] is not None:
                    raise ValueError('Tool report belongs to a closed turn')
                if params['tool'] == 'finish_workload':
                    if (params.get('namespace') is not None or not isinstance(args, dict)
                            or set(args) != {'status', 'reason'} or args['status'] not in ('complete', 'blocked')
                            or not isinstance(args['reason'], str) or not 1 <= len(args['reason']) <= 2000
                            or not args['reason'].strip() or not bounded_identity(params['callId'])):
                        raise ValueError('Invalid whole-workload terminal report')
                    key = params['callId']
                    if key in stage_calls or key in terminal_calls and terminal_calls[key] != args:
                        raise ValueError('Conflicting terminal call identity')
                    if declaration is not None and terminal_calls[next(iter(terminal_calls))] != args:
                        raise ValueError('Conflicting whole-workload terminal report')
                    terminal_calls[key] = copy.deepcopy(args)
                    if declaration is None:
                        declaration = dict(marker, turn_id=turn, status=args['status'])
                    continue
            if (params['tool'] != 'report_stage' or params.get('namespace') is not None
                    or not isinstance(args, dict) or set(args) != {'stage', 'wp_id'}
                    or not isinstance(args['stage'], str) or args['stage'] not in STAGES
                    or not isinstance(args['wp_id'], str) or args['wp_id'] not in packages):
                raise ValueError('Stage marker violates the frozen package boundary')
            identity = params['callId']
            if not identity or len(identity) > 128:
                raise ValueError('Bounded stage call identity required')
            if conversation and identity in terminal_calls:
                raise ValueError('Stage call reused a terminal call identity')
            if identity in stage_calls:
                if stage_calls[identity] != args:
                    raise ValueError('Conflicting repeated stage call')
                continue
            stage_calls[identity] = copy.deepcopy(args)
            stage = copy.deepcopy(args)
            value = dict(marker, **args)
            stages.append(value)
            pending_stages.append(value)
            continue
        checked('ThreadTokenUsageUpdatedNotification', params)
        total = params['tokenUsage']['total']
        if (not isinstance(total, dict) or not total
                or not set(total) <= {'inputTokens', 'outputTokens', 'cachedInputTokens',
                                     'cacheWriteInputTokens', 'reasoningOutputTokens', 'totalTokens'}
                or any(type(value) is not int or value < 0 for value in total.values())
                or usage is not None and (set(total) != set(usage)
                    or any(total[key] < usage[key] for key in total))):
            raise ValueError('Stable nonnegative cumulative usage counters required')
        delta = {key: value - (usage[key] if usage is not None else 0)
                 for key, value in total.items()}
        intervals.append(dict(marker, previous_sequence=previous_usage_sequence,
            usage_delta=delta, initial_cumulative_snapshot=usage is None,
            reported_stage_at_previous_snapshot=copy.deepcopy(previous_usage_stage),
            reported_stage_at_snapshot=copy.deepcopy(stage),
            intervening_stage_markers=copy.deepcopy(pending_stages)))
        pending_stages.clear()
        previous_usage_stage = copy.deepcopy(stage)
        previous_usage_sequence = count
        usage = copy.deepcopy(total)
    if count == 0:
        raise ValueError('Operator event stream is empty')
    if usage is not None and any(sum(row['usage_delta'][key] for row in intervals) != value
                                 for key, value in usage.items()):
        raise ValueError('Usage intervals failed exact reconciliation')
    result = dict(schema_version=1, attempt_id=attempt, record_count=count,
        thread_id=thread, turn_id=turn, terminal_turn_observed=final_status is not None,
        turn_status=final_status, usage_total=usage, usage_intervals=intervals,
        stage_markers=stages, trailing_stage_markers=copy.deepcopy(pending_stages),
        compaction_count=len(compactions), compactions=list(compactions.values()),
        usage_reconciled=usage is not None, unallocated_usage=copy.deepcopy(usage),
        stage_token_allocation='unallocated', monetary_estimate=None,
        usage_semantics='Latest observed thread cumulative counters; initial snapshot plus subsequent deltas, never total plus last. Cache/reasoning categories retain runtime meanings and are not added to totalTokens.',
        limits='Observed telemetry only. Stage markers are builder reports; mixed-purpose usage, provider billing completeness, tariffs, accepted work packages, model identity, allowed-state compliance and remote cleanup require independent evidence.')
    if conversation:
        latest = turns.get(turn, {})
        result.update(turn_mode='continuous_conversation', turns=list(turns.values()),
            turn_requests=list(requests.values()), workload_declaration=declaration,
            terminal_turn_observed=latest.get('status') is not None,
            turn_status=latest.get('status'),
            conversation_terminal_observed=(latest.get('status') in ('failed', 'interrupted')
                or declaration is not None and latest.get('status') == 'completed'),
            terminal_evidence='Native turn status and builder declaration, not acceptance or operator finalization')
    return result
