from bugdhor_ast.detection import BugDhorDetectionEngine


ENGINE = BugDhorDetectionEngine()


def diagnostics(source, rule_id):
    result = ENGINE.analyze_source(
        source, "javascript", rule_ids=[rule_id]
    )
    assert result.has_syntax_errors is False
    return result.diagnostics


def messages(source, rule_id):
    return [item.message for item in diagnostics(source, rule_id)]


def test_js001_undefined_variable():
    found = diagnostics(
        "function f() { return missingName; }\n", "JS001"
    )

    assert len(found) == 1
    assert found[0].line == 1
    assert found[0].severity == "error"
    assert "missingName" in found[0].message
    assert found[0].suggestion


def test_js001_ignores_declarations_attributes_globals_and_scopes():
    source = """
const value = 1;
function f(arg) { console.log(value, arg, obj.prop); }
const obj = {};
function g() { return 1; }
g({key: 1});
function outer() {
  const outerVar = 1;
  return function inner() { return outerVar; };
}
"""

    assert messages(source, "JS001") == []


def test_js002_unused_variables():
    source = """
function f() {
  const [a, b] = [1, 2];
  const used = 3;
  console.log(used);
  const _ignored = 4;
}
const moduleUnused = 5;
"""

    found = messages(source, "JS002")

    assert len(found) == 3
    assert any("'a'" in message for message in found)
    assert any("'b'" in message for message in found)
    assert any("'moduleUnused'" in message for message in found)
    assert not any("'used'" in message for message in found)
    assert not any("'_ignored'" in message for message in found)


def test_js002_ignores_exported_bindings():
    source = """
export const exported = 1;
const plain = 2;
"""

    found = messages(source, "JS002")

    assert len(found) == 1
    assert "'plain'" in found[0]
    assert not any("'exported'" in message for message in found)


def test_js003_unreachable_code_after_terminator():
    source = """
function f() {
  return 1;
  console.log("dead");
  console.log("also dead");
}
function g() {
  if (true) { return 1; }
  return 2;
}
"""

    found = diagnostics(source, "JS003")

    assert len(found) == 1
    assert found[0].line == 4
    assert "unreachable" in found[0].message.lower()


def test_js004_duplicate_declarations_in_same_scope_only():
    source = """
function f() {
  let x = 1;
  let x = 2;
  return x;
}
function g() {
  let x = 1;
  if (true) {
    let x = 2;
    console.log(x);
  }
}
"""

    found = diagnostics(source, "JS004")

    assert len(found) == 1
    assert found[0].line == 4
    assert "'x'" in found[0].message


def test_js005_unused_imports():
    source = """
import fs from 'fs';
import {used as u, unused} from 'pkg';
import * as ns from 'ns';
import 'side-effect';
console.log(u);
"""

    found = diagnostics(source, "JS005")

    assert len(found) == 3
    assert {item.line for item in found} == {2, 3, 4}
    assert any("'fs'" in item.message for item in found)
    assert any("'unused'" in item.message for item in found)
    assert any("'ns'" in item.message for item in found)


def test_js005_ignores_used_imports_and_side_effect_imports():
    source = """
import fs from 'fs';
import {read as r} from 'pkg';
import 'side-effect';
console.log(fs, r);
"""

    assert messages(source, "JS005") == []


def test_js006_unused_parameters():
    source = """
function outer(a, b, _ignored) {
  return function inner(c) { return a; };
}
"""

    found = diagnostics(source, "JS006")

    assert len(found) == 2
    assert any("'b'" in item.message for item in found)
    assert any("'c'" in item.message for item in found)
    assert not any("'_ignored'" in item.message for item in found)


def test_js006_count_nested_uses():
    source = """
function outer(value) {
  return function inner() { return value; };
}
"""

    assert messages(source, "JS006") == []


def test_js007_null_access_without_guard():
    source = """
function f() {
  let item = null;
  console.log(item.name);
}
"""

    found = diagnostics(source, "JS007")

    assert len(found) == 1
    assert "item" in found[0].message
    assert found[0].severity == "warning"


def test_js007_ignores_guards_optional_chaining_and_reassignments():
    source = """
function f() {
  let safe = null;
  if (safe !== null) { console.log(safe.name); }
  let other = null;
  if (other != null) { console.log(other.name); }
  let opt = null;
  console.log(opt?.name);
  let changed = null;
  changed = {};
  console.log(changed.name);
}
"""

    assert messages(source, "JS007") == []


def test_js008_empty_exception_handler():
    source = """
try { run(); } catch (err) { /* ignored */ }
"""

    found = diagnostics(source, "JS008")

    assert len(found) == 1
    assert found[0].line == 2


def test_js008_ignores_handlers_with_statements():
    source = """
try { run(); } catch (err) { console.log("handled"); }
"""

    assert messages(source, "JS008") == []


def test_js009_suspicious_calls():
    source = """
eval("1");
document.write("x");
setTimeout("code()", 10);
setTimeout(fn, 10);
"""

    found = messages(source, "JS009")

    assert len(found) == 2
    assert any("document.write" in message for message in found)
    assert any("setTimeout" in message for message in found)
    assert not any("eval" in message for message in found)


def test_js010_dangerous_calls():
    source = """
eval("1");
new Function("return 1")();
child_process.exec("ls");
exec("ls");
new ProcessBuilder("ls");
"""

    found = diagnostics(source, "JS010")

    assert len(found) == 4
    assert any("'eval'" in item.message for item in found)
    assert any("'Function'" in item.message for item in found)
    assert any("'child_process.exec'" in item.message for item in found)
    assert any("'exec'" in item.message for item in found)
    assert all(item.severity == "error" for item in found)


def test_js010_ignores_safe_timer_calls():
    source = """
setTimeout(fn, 10);
console.log("safe");
"""

    assert messages(source, "JS010") == []


def test_javascript_common_patterns_do_not_produce_false_positives():
    source = """
import fs from "fs";

class UserService {
  getUser(id) {
    return id;
  }
}

function authenticate(username, password) {
  const user = new UserService();
  if (password === "admin123") {
    return user.getUser(username);
  }
  return null;
}

console.log(fs.existsSync("file"));
const result = authenticate("admin", "admin123");
console.log(result);
"""

    result = ENGINE.analyze_source(source, "javascript")

    assert result.has_syntax_errors is False
    assert result.diagnostics == []
