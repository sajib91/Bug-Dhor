from bugdhor_ast.detection import BugDhorDetectionEngine


ENGINE = BugDhorDetectionEngine()


def diagnostics(source, rule_id):
    result = ENGINE.analyze_source(
        source, "python", rule_ids=[rule_id]
    )
    assert result.has_syntax_errors is False
    return result.diagnostics


def messages(source, rule_id):
    return [item.message for item in diagnostics(source, rule_id)]


def test_py001_undefined_variable():
    found = diagnostics(
        "def f():\n    return missing_name\n", "PY001"
    )

    assert len(found) == 1
    assert found[0].line == 2
    assert found[0].severity == "error"
    assert "missing_name" in found[0].message
    assert found[0].suggestion


def test_py001_repeated_use_is_reported_once():
    found = diagnostics(
        "def f():\n    print(missing, missing)\n", "PY001"
    )

    assert len(found) == 1
    assert "missing" in found[0].message


def test_py001_ignores_declarations_attributes_builtins_and_scopes():
    source = """
class Thing:
    pass

obj = Thing()
value = 1

def f(arg):
    print(value, arg, len([1]))
    print(obj.attr)
    f(kw=1)

def outer():
    outer_var = 1
    def inner():
        return outer_var
    return inner()
"""

    assert messages(source, "PY001") == []


def test_py002_unused_local_variables():
    source = """
def f():
    first, second = 1, 2
    used = 3
    print(used)
    _ignored = 4
x = 5
"""

    found = messages(source, "PY002")

    assert len(found) == 2
    assert any("'first'" in message for message in found)
    assert any("'second'" in message for message in found)
    assert not any("'used'" in message for message in found)
    assert not any("_ignored" in message for message in found)
    assert not any("'x'" in message for message in found)


def test_py002_counts_uses_in_nested_functions():
    source = """
def outer():
    captured = 1
    def inner():
        return captured
    return inner()
"""

    assert messages(source, "PY002") == []


def test_py003_unreachable_code_after_terminator():
    source = """
def f():
    return 1
    print("dead")
    print("also dead")

def g():
    if True:
        return 1
    print("alive")
"""

    found = diagnostics(source, "PY003")

    assert len(found) == 1
    assert found[0].line == 4
    assert "unreachable" in found[0].message.lower()


def test_py004_duplicate_annotations_only():
    source = """
def f():
    x = 1
    x = 2

def g():
    y: int = 1

def h():
    z: int = 1
    z: int = 2
"""

    found = diagnostics(source, "PY004")

    assert len(found) == 1
    assert found[0].line == 11
    assert "z" in found[0].message


def test_py005_unused_imports_and_aliases():
    source = """
import os
import json as j
from math import sqrt, ceil as c
from pathlib import *
print(j, sqrt)
"""

    found = diagnostics(source, "PY005")

    assert len(found) == 2
    assert "'os'" in found[0].message
    assert "'c'" in found[1].message
    assert {item.line for item in found} == {2, 4}


def test_py005_ignores_used_imports_and_wildcards():
    source = """
import os
from math import sqrt
from pathlib import *
print(os, sqrt)
"""

    assert messages(source, "PY005") == []


def test_py006_unused_parameters():
    source = """
def f(a, b, self, _ignored):
    def inner():
        return a
    return inner()
"""

    found = diagnostics(source, "PY006")

    assert len(found) == 1
    assert "b" in found[0].message


def test_py006_ignores_used_parameters_and_special_names():
    source = """
def f(self, cls, value):
    return value
"""

    assert messages(source, "PY006") == []


def test_py007_none_access_without_guard():
    source = """
def f():
    item = None
    print(item.field)
"""

    found = diagnostics(source, "PY007")

    assert len(found) == 1
    assert "item" in found[0].message
    assert found[0].severity == "warning"


def test_py007_ignores_guards_and_reassignments():
    source = """
def f():
    safe = None
    if safe is not None:
        print(safe.field)
    changed = None
    changed = 1
    print(changed.field)
"""

    assert messages(source, "PY007") == []


def test_py008_empty_exception_handler():
    source = """
try:
    pass
except ValueError:
    pass
"""

    found = diagnostics(source, "PY008")

    assert len(found) == 1
    assert found[0].line == 4


def test_py008_ignores_handlers_with_statements():
    source = """
try:
    pass
except TypeError:
    print("handled")
"""

    assert messages(source, "PY008") == []


def test_py009_suspicious_calls():
    source = """
value = input("prompt")
code = compile("1", "example", "eval")
eval("1")
"""

    found = messages(source, "PY009")

    assert len(found) == 2
    assert any("input" in message for message in found)
    assert any("compile" in message for message in found)
    assert not any("eval" in message for message in found)


def test_py010_dangerous_calls():
    source = """
import subprocess
eval("1")
os.system("ls")
subprocess.run(command)
subprocess.run(command, shell=True)
subprocess.run(command, shell=False)
yaml.load(data)
yaml.load(data, Loader=yaml.SafeLoader)
"""

    found = diagnostics(source, "PY010")

    assert len(found) == 4
    assert any("'eval'" in item.message for item in found)
    assert any("'os.system'" in item.message for item in found)
    assert any("'subprocess.run'" in item.message for item in found)
    assert any("'yaml.load'" in item.message for item in found)
    assert all(item.severity == "error" for item in found)


def test_py010_ignores_safe_variants():
    source = """
subprocess.run(command)
subprocess.run(command, shell=False)
yaml.load(data, Loader=yaml.SafeLoader)
"""

    assert messages(source, "PY010") == []


def test_python_common_patterns_do_not_produce_false_positives():
    source = """
import os

class UserManager:
    def __init__(self, username):
        self.username = username

    def get_user(self):
        return self.username

def authenticate(username, password):
    user = UserManager(username)
    if password == "admin123":
        return user.get_user()
    return None

print(os.name)
result = authenticate("admin", "admin123")
print(result)
"""

    result = ENGINE.analyze_source(source, "python")

    assert result.has_syntax_errors is False
    assert result.diagnostics == []
