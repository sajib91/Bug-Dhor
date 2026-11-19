
import pytest

from bugdhor_ast.engine import BugDhorASTEngine


engine = BugDhorASTEngine()


def test_python_ast():
    source = """
import os

class UserManager:
    def get_user(self):
        return self.username

def authenticate(username):
    user = UserManager()
    result = user.get_user()
    return result
"""

    result = engine.analyze_source(source, "python")

    assert result["has_syntax_errors"] is False
    assert result["summary"]["functions"] == 2
    assert result["summary"]["classes"] == 1
    assert result["summary"]["variables"] == 3

    variable_names = {
        item["name"] for item in result["variables"]
    }

    assert {"username", "user", "result"} <= variable_names
    assert "self" not in variable_names
    assert "self.username" not in variable_names


def test_python_function_calls():
    source = """
def authenticate():
    user = UserManager()
    print(user)
"""

    result = engine.analyze_source(source, "python")

    call_names = {
        item["name"] for item in result["function_calls"]
    }

    assert "UserManager" in call_names
    assert "print" in call_names


def test_python_annotated_and_multiple_assignments():
    source = """
def f(alpha: int, beta=2):
    x: str = "a"
    y: int
    p = q = 0
    first, second = (1, 2)
    [third, fourth] = [3, 4]
"""

    result = engine.analyze_source(source, "python")
    variable_names = {
        item["name"] for item in result["variables"]
    }

    assert result["has_syntax_errors"] is False
    assert result["summary"]["variables"] == 10
    assert variable_names == {
        "alpha",
        "beta",
        "x",
        "y",
        "p",
        "q",
        "first",
        "second",
        "third",
        "fourth",
    }
    assert all(
        {
            "type",
            "start_line",
            "end_line",
            "start_column",
            "end_column",
            "name",
            "source",
        } <= set(item)
        for item in result["variables"]
    )


def test_python_nested_functions_and_classes():
    source = """
class Outer:
    class_value = 1

    def method(self, flag):
        self.value = flag
        local = 2

        def inner(cls, item):
            nested = item

        class Inner:
            inner_value = 3
"""

    result = engine.analyze_source(source, "python")
    variable_names = {
        item["name"] for item in result["variables"]
    }

    assert result["has_syntax_errors"] is False
    assert result["summary"]["variables"] == 6
    assert variable_names == {
        "class_value",
        "flag",
        "local",
        "item",
        "nested",
        "inner_value",
    }
    assert "self" not in variable_names
    assert "cls" not in variable_names
    assert "self.value" not in variable_names


def test_python_parameter_forms_and_no_duplicate_variables():
    source = """
def f(a: int, b: str = "x", *args, c=1, **kwargs):
    a = 2
    b += 1
    (d, *rest) = (1, 2)
"""

    result = engine.analyze_source(source, "python")
    variable_names = [
        item["name"] for item in result["variables"]
    ]

    assert result["has_syntax_errors"] is False
    assert result["summary"]["variables"] == 7
    assert variable_names == [
        "a",
        "b",
        "args",
        "c",
        "kwargs",
        "d",
        "rest",
    ]


def test_python_lambda_parameters():
    source = """
callback = lambda q, r=1: q + r
"""

    result = engine.analyze_source(source, "python")
    variable_names = {
        item["name"] for item in result["variables"]
    }

    assert result["has_syntax_errors"] is False
    assert variable_names == {"callback", "q", "r"}
    assert result["summary"]["variables"] == 3


def test_python_attribute_and_walrus_targets():
    source = """
def f(obj):
    obj.field = 1
    obj.items[0] = 2
    obj.a, b = 1, 2
    (capture := obj.field)
"""

    result = engine.analyze_source(source, "python")
    variable_names = {
        item["name"] for item in result["variables"]
    }

    assert result["has_syntax_errors"] is False
    assert result["summary"]["variables"] == 3
    assert variable_names == {"obj", "b", "capture"}
    assert "obj.field" not in variable_names
    assert "obj.items" not in variable_names
    assert "obj.a" not in variable_names


def test_javascript_ast():
    source = """
import fs from "fs";

class UserService {
    getUser(id) {
        return id;
    }
}

function authenticate() {
    const user = new UserService();
    const result = user.getUser(1);
    return result;
}
"""

    result = engine.analyze_source(source, "javascript")

    assert result["has_syntax_errors"] is False
    assert result["summary"]["functions"] == 2
    assert result["summary"]["classes"] == 1
    assert result["summary"]["variables"] == 2

    function_names = {
        item["name"] for item in result["functions"]
    }

    assert {"getUser", "authenticate"} <= function_names


def test_javascript_function_calls():
    source = """
function test() {
    console.log("hello");
    authenticate();
}
"""

    result = engine.analyze_source(source, "javascript")

    call_names = {
        item["name"] for item in result["function_calls"]
    }

    assert "console.log" in call_names
    assert "authenticate" in call_names


def test_java_ast():
    source = """
import java.util.Scanner;

class UserManager {
    public String getUser() {
        return "admin";
    }

    public static void main(String[] args) {
        UserManager manager = new UserManager();
        String user = manager.getUser();
    }
}
"""

    result = engine.analyze_source(source, "java")

    assert result["has_syntax_errors"] is False
    assert result["summary"]["functions"] == 2
    assert result["summary"]["classes"] == 1
    assert result["summary"]["variables"] == 2

    variable_names = {
        item["name"] for item in result["variables"]
    }

    assert {"manager", "user"} <= variable_names


def test_java_method_calls():
    source = """
class Example {
    void test() {
        System.out.println("hello");
    }
}
"""

    result = engine.analyze_source(source, "java")

    call_names = {
        item["name"] for item in result["function_calls"]
    }

    assert "println" in call_names


def test_invalid_syntax():
    source = """
def broken(
    print("hello")
"""

    result = engine.analyze_source(source, "python")

    assert result["has_syntax_errors"] is True
    assert result["summary"]["syntax_errors"] >= 1


def test_empty_source():
    result = engine.analyze_source("", "python")

    assert result["has_syntax_errors"] is False
    assert all(
        count == 0 for count in result["summary"].values()
    )
    assert result["functions"] == []
    assert result["classes"] == []
    assert result["variables"] == []
    assert result["function_calls"] == []
    assert result["imports"] == []
    assert result["syntax_errors"] == []


def test_unsupported_language_raises_value_error():
    with pytest.raises(
        ValueError, match="Unsupported language: ruby"
    ):
        engine.analyze_source("puts 'hello'\n", "ruby")


def test_analyze_file_adds_file_metadata(tmp_path):
    source_file = tmp_path / "module.py"
    source_file.write_text("value = 1\n", encoding="utf-8")

    result = engine.analyze_file(source_file)

    assert result["file"] == str(source_file)
    assert result["language"] == "python"
    assert result["summary"]["variables"] == 1


def test_python_positional_and_keyword_only_parameters():
    source = """
def f(a, /, b, *, c=1, **kwargs):
    return a + b + c
"""

    result = engine.analyze_source(source, "python")

    assert result["has_syntax_errors"] is False
    assert {
        item["name"] for item in result["variables"]
    } == {"a", "b", "c", "kwargs"}


def test_python_complex_expressions_and_imports():
    source = """
from os import path as p
import json as j

@decorator(arg)
async def fetch(url: str):
    payload = j.loads(await read(p.join(url)))
    return [item for item in payload if item] if payload else None
"""

    result = engine.analyze_source(source, "python")

    assert result["has_syntax_errors"] is False
    assert result["summary"]["functions"] == 1
    assert result["summary"]["imports"] == 2
    assert result["summary"]["function_calls"] == 4
    assert result["summary"]["variables"] == 2
    assert {
        item["name"] for item in result["variables"]
    } == {"url", "payload"}
    assert [item["name"] for item in result["imports"]] == [
        "path as p",
        "json as j",
    ]


def test_python_missing_syntax_node():
    result = engine.analyze_source(
        "def f(:\n    pass\n", "python"
    )

    assert result["has_syntax_errors"] is True
    assert len(result["syntax_errors"]) == 1
    assert (
        result["syntax_errors"][0]["message"]
        == "Missing syntax node"
    )


def test_go_variable_declarations():
    source = """package main

var x int
var (
    y = 1
)

func main() {
    z := x + y
}
"""

    result = engine.analyze_source(source, "go")

    assert result["has_syntax_errors"] is False
    assert result["summary"]["functions"] == 1
    assert {
        item["name"] for item in result["variables"]
    } == {"x", "y", "z"}


def test_c_pointer_declarators():
    result = engine.analyze_source(
        "int *p = 0;\nchar **q = 0;\n", "c"
    )

    assert result["has_syntax_errors"] is False
    assert {
        item["name"] for item in result["variables"]
    } == {"p", "q"}


def test_javascript_arrow_function_and_import():
    source = """
import fs from "fs";
const handler = (event) => event;
"""

    result = engine.analyze_source(source, "javascript")

    assert result["has_syntax_errors"] is False
    assert result["summary"]["functions"] == 1
    assert result["summary"]["imports"] == 1
    assert result["summary"]["variables"] == 1
    assert result["variables"][0]["name"] == "handler"
    assert result["imports"][0]["name"] == '"fs"'


def test_java_field_declaration():
    source = """
class Counter {
    int total;

    Counter(int start) {
        this.total = start;
    }
}
"""

    result = engine.analyze_source(source, "java")

    assert result["has_syntax_errors"] is False
    assert result["summary"]["variables"] == 1
    assert result["variables"][0]["name"] == "total"
