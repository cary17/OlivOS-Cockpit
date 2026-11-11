"""客户端可读的有界原始 SDK 事件快照。

返回值只包含原生 JSON 副本；凭据字段名保留在缓存里，由唯一出站边界
按 allow_fields / 关闭脱敏策略统一处理。读取先按 limit 选最新记录，再有界复制。
"""

from . import raw
from .contracts import Outcome, ToolSpec, object_schema

MAX_RETURN_RECORDS = raw.MAX_RETURN_RECORDS


def _read(ctx, args):
    limit = args.get('limit', MAX_RETURN_RECORDS)
    if type(limit) is not int or not 1 <= limit <= MAX_RETURN_RECORDS:
        limit = MAX_RETURN_RECORDS
    snapshot = raw.read(ctx, limit=limit)
    snapshot['returned_limit'] = limit
    return Outcome(snapshot, truncated=bool(snapshot.get('truncated')))


TOOLS = (
    ToolSpec(
        name='cockpit_raw_events',
        description=(
            'Read bounded native SDK payloads observed before OlivOS API.Event conversion. '
            'Credential-named fields are kept in the copy and redacted only at the outbound boundary. '
            'Coverage excludes adapter-discarded frames, control/WebUI traffic, and plugin outbound calls.'
        ),
        schema=object_schema({
            'limit': {'type': 'integer', 'minimum': 1, 'maximum': MAX_RETURN_RECORDS},
        }),
        handler=_read,
    ),
)
