"""Lite 的静态只读能力与虚拟终端输入；真实账号读取仍需本地授权。"""

from .account_tools import TOOLS as ACCOUNT_TOOLS
from .files import TOOLS as FILE_TOOLS
from .host import TOOLS as HOST_TOOLS
from .raw_tools import TOOLS as RAW_TOOLS
from .read_tools import TOOLS as READ_TOOLS
from .terminal import TOOLS as TERMINAL_TOOLS

MODE = 'lite'
TOOLS = tuple(sorted(
    FILE_TOOLS + HOST_TOOLS + RAW_TOOLS + READ_TOOLS + ACCOUNT_TOOLS + TERMINAL_TOOLS,
    key=lambda tool: tool.name,
))
