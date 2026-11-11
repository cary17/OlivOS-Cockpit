"""静态阅读台账与实际执行表的一致性；不导入或运行上游源码。"""

import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from OlivOSCockpit import adapter_tools, registry  # noqa: E402
from OlivOSCockpit.contracts import MAX_RESPONSE  # noqa: E402


class InventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inventory = json.loads((ROOT / 'interfaces.json').read_text('utf-8'))
        spec = importlib.util.spec_from_file_location(
            'OlivOSCockpit._lite_test_registry', ROOT / 'profiles/lite_registry.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cls.lite_tools = module.TOOLS

    def test_complete_unique_static_inventory_and_baseline(self):
        inventory = self.inventory
        self.assertEqual(inventory['source']['commit'],
                         'c6a99fc2a3b4cc7dd1ea8e7b6fe762b7bee7c7d4')
        self.assertEqual(len(inventory['files']), 227)
        self.assertEqual(len({row['path'] for row in inventory['files']}), 227)
        self.assertTrue(all(row['reviewed'] for row in inventory['files']))
        self.assertEqual(len(inventory['interfaces']), 3355)
        self.assertEqual(len({row['id'] for row in inventory['interfaces']}), 3355)
        self.assertEqual(len(inventory['extra_interfaces']), 75)

    def test_dynamic_declarations_are_not_lost_during_merge(self):
        groups = self.inventory['dynamic_interfaces']['adapters']
        expected = {'http_endpoints': 2, 'websocket_endpoints': 12, 'registries': 7,
                    'milky_api_actions': 64, 'platform_conditional_imports': 2}
        self.assertEqual({name: len(rows) for name, rows in groups.items()}, expected)
        self.assertEqual(self.inventory['summary']['dynamic_entries_by_part']['adapters'], expected)

    def test_every_published_tool_has_real_handler_and_test_mapping(self):
        bindings = self.inventory['tool_bindings']
        full = {tool.name: tool for tool in registry.TOOLS}
        lite = {tool.name for tool in self.lite_tools}
        self.assertEqual(set(bindings), set(full))
        self.assertLessEqual(lite, set(full))
        self.assertEqual(self.inventory['summary']['published_tools'],
                         {'full': len(full), 'lite': len(lite)})
        for name, tool in full.items():
            with self.subTest(tool=name):
                binding = bindings[name]
                self.assertTrue(callable(tool.handler))
                self.assertEqual(binding['handler'],
                                 tool.handler.__module__ + '.' + tool.handler.__qualname__)
                self.assertEqual(binding['handler_line'], tool.handler.__code__.co_firstlineno)
                self.assertEqual(binding['required_permission'],
                                 tool.required_permission or tool.capability)
                self.assertEqual('lite' in binding['profiles'], name in lite)
                self.assertTrue((ROOT / binding['handler_file']).is_file())
                self.assertTrue(binding['tests'])
                self.assertTrue(all((ROOT / path).is_file() for path in binding['tests']))

    def test_unsafe_and_unbound_entries_have_no_public_invocation(self):
        names = set(self.inventory['tool_bindings'])
        for row in self.inventory['interfaces']:
            if row['exposure'] == 'bound':
                self.assertEqual(row['disposition'], 'candidate')
                self.assertIn(row['tool_name'], names)
                self.assertTrue(row['handler'])
                self.assertTrue(row['tests'])
            else:
                self.assertEqual(row['exposure'], 'withheld')
        withheld = {f'cockpit_{row[0]}_{row[1]}' for row in adapter_tools.WITHHELD_ENTRIES}
        self.assertFalse(names & withheld)
        self.assertFalse(any(tool.handler.__module__.endswith('catalog_tools')
                             for tool in registry.TOOLS + self.lite_tools))

    def test_profiles_are_sorted_unique_and_definitions_fit_one_response(self):
        for tools in (registry.TOOLS, self.lite_tools):
            names = [tool.name for tool in tools]
            self.assertEqual(names, sorted(set(names)))
            self.assertTrue(all(name.startswith('cockpit_') for name in names))
            payload = json.dumps([tool.definition() for tool in tools],
                                 ensure_ascii=True, allow_nan=False).encode('utf-8')
            self.assertLess(len(payload), MAX_RESPONSE // 2)
        self.assertEqual({tool.name for tool in self.lite_tools if not tool.read_only},
                         {'cockpit_terminal_input'})

    def test_readme_counts_match_registries(self):
        readme = (ROOT / 'README.md').read_text('utf-8')
        self.assertIn(f'| `OlivOSCockpit-<version>.opk` | {len(registry.TOOLS)} |', readme)
        self.assertIn(f'| `OlivOSCockpitLite-<version>.opk` | {len(self.lite_tools)} |', readme)


if __name__ == '__main__':
    unittest.main()
