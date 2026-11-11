"""Full 的静态执行表；未完成安全绑定的接口仅保留在 interfaces.json。"""

from . import intercept, plugin_install
from .account_tools import TOOLS as ACCOUNT_TOOLS
from .account_write import TOOLS as ACCOUNT_WRITE_TOOLS
from .adapter_tools import TOOLS as ADAPTER_TOOLS
from .file_write import TOOLS as FILE_WRITE_TOOLS
from .files import TOOLS as FILE_TOOLS
from .full_only import TOOLS as FULL_TOOLS
from .host import TOOLS as HOST_TOOLS
from .plugin_install import TOOLS as INSTALL_TOOLS
from .raw_tools import TOOLS as RAW_TOOLS
from .read_tools import TOOLS as READ_TOOLS
from .terminal import TOOLS as TERMINAL_TOOLS

MODE = 'full'
TOOLS = tuple(sorted(
    FILE_TOOLS + HOST_TOOLS + FULL_TOOLS + ADAPTER_TOOLS + RAW_TOOLS + TERMINAL_TOOLS
    + READ_TOOLS + FILE_WRITE_TOOLS + ACCOUNT_TOOLS + ACCOUNT_WRITE_TOOLS + intercept.TOOLS
    + INSTALL_TOOLS,
    key=lambda tool: tool.name,
))


def tick(context):
    """监督 tick 的可选 Full 钩子：清除过期/撤权/换 owner 的待上传包。"""
    return plugin_install.sweep(context)


def attach(context):
    # 新 owner 建立时清除旧 owner 的残留上传；若拦截器安装失败也不影响该清理。
    plugin_install.sweep(context)
    return intercept.install(context)


def detach(context):
    # 即使拦截器卸载抛错，也必须在前后清掉安装器持有的内存状态。
    plugin_install.detach(context)
    try:
        return intercept.uninstall(context)
    finally:
        plugin_install.detach(context)
