import ast
import pathlib
import unittest


class LinuxReviewedIpGuardTests(unittest.TestCase):
    def test_windows_only_rules_are_rejected_before_linux_initialization(self):
        path = (pathlib.Path(__file__).resolve().parents[1] /
                'fakenet' / 'diverters' / 'linux.py')
        source = path.read_text(encoding='utf-8')
        tree = ast.parse(source, filename=str(path))
        diverter = next(
            node for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == 'Diverter')
        initializer = next(
            node for node in diverter.body
            if isinstance(node, ast.FunctionDef) and node.name == '__init__')
        statements = [ast.get_source_segment(source, node) or ''
                      for node in initializer.body]
        guard_index = next(
            index for index, text in enumerate(statements)
            if 'ExternalAllowedIPv4Rules' in text and
            'raise ValueError' in text)
        linux_mixin_index = next(
            index for index, text in enumerate(statements)
            if 'self.init_linux_mixin()' in text)
        linux_diverter_index = next(
            index for index, text in enumerate(statements)
            if 'self.init_diverter_linux()' in text)

        self.assertLess(guard_index, linux_mixin_index)
        self.assertLess(guard_index, linux_diverter_index)

    def test_process_redirect_is_rejected_before_linux_initialization(self):
        path = (pathlib.Path(__file__).resolve().parents[1] /
                'fakenet' / 'diverters' / 'linux.py')
        source = path.read_text(encoding='utf-8')
        tree = ast.parse(source, filename=str(path))
        diverter = next(
            node for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == 'Diverter')
        initializer = next(
            node for node in diverter.body
            if isinstance(node, ast.FunctionDef) and node.name == '__init__')
        statements = [ast.get_source_segment(source, node) or ''
                      for node in initializer.body]
        guard_index = next(
            index for index, text in enumerate(statements)
            if 'ExternalProcessRedirectEnabled' in text and
            'raise ValueError' in text)
        linux_mixin_index = next(
            index for index, text in enumerate(statements)
            if 'self.init_linux_mixin()' in text)

        self.assertLess(guard_index, linux_mixin_index)


if __name__ == '__main__':
    unittest.main()
