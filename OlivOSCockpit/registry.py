"""Full 的静态执行表；未完成安全绑定的接口仅保留在 interfaces.json。"""

from . import intercept
from .account_tools import TOOLS as ACCOUNT_TOOLS
from .account_write import TOOLS as ACCOUNT_WRITE_TOOLS
from .adapter_tools import TOOLS as ADAPTER_TOOLS
from .file_write import TOOLS as FILE_WRITE_TOOLS
from .files import TOOLS as FILE_TOOLS
from .full_only import TOOLS as FULL_TOOLS
from .host import TOOLS as HOST_TOOLS
from .raw_tools import TOOLS as RAW_TOOLS
from .read_tools import TOOLS as READ_TOOLS
from .terminal import TOOLS as TERMINAL_TOOLS

MODE = 'full'
TOOLS = tuple(sorted(
    FILE_TOOLS + HOST_TOOLS + FULL_TOOLS + ADAPTER_TOOLS + RAW_TOOLS + TERMINAL_TOOLS
    + READ_TOOLS + FILE_WRITE_TOOLS + ACCOUNT_TOOLS + ACCOUNT_WRITE_TOOLS + intercept.TOOLS,
    key=lambda tool: tool.name,
))


def attach(context):
    return intercept.install(context)


def detach(context):
    return intercept.uninstall(context)
