from bugdhor_ast.detection import BugDhorDetectionEngine


ENGINE = BugDhorDetectionEngine()


def diagnostics(source, rule_id):
    result = ENGINE.analyze_source(
        source, "java", rule_ids=[rule_id]
    )
    assert result.has_syntax_errors is False
    return result.diagnostics


def messages(source, rule_id):
    return [item.message for item in diagnostics(source, rule_id)]


def test_java001_undefined_variable():
    found = diagnostics(
        """
class Demo {
    void f() {
        System.out.println(missing);
    }
}
""",
        "JAVA001",
    )

    assert len(found) == 1
    assert found[0].severity == "error"
    assert "missing" in found[0].message
    assert found[0].suggestion


def test_java001_ignores_fields_parameters_types_and_jdk_names():
    source = """
class Demo {
    int field = 1;
    void f(int param) {
        String local = "x";
        UnknownType value = null;
        System.out.println(field + param + local + "text");
    }
}
"""

    assert messages(source, "JAVA001") == []


def test_java002_unused_local_variables():
    source = """
class Demo {
    int field = 1;
    void f() {
        int a = 1, b = 2;
        int used = 3;
        System.out.println(used);
        field = 4;
    }
}
"""

    found = messages(source, "JAVA002")

    assert len(found) == 2
    assert any("'a'" in message for message in found)
    assert any("'b'" in message for message in found)
    assert not any("'used'" in message for message in found)
    assert not any("'field'" in message for message in found)


def test_java003_unreachable_code_after_terminator():
    source = """
class Demo {
    void f() {
        return;
        System.out.println("dead");
        System.out.println("also dead");
    }
    int g() {
        if (true) { return 1; }
        return 2;
    }
}
"""

    found = diagnostics(source, "JAVA003")

    assert len(found) == 1
    assert found[0].line == 5
    assert "unreachable" in found[0].message.lower()


def test_java004_duplicate_local_declarations():
    source = """
class Demo {
    int field = 1;
    void f() {
        int x = 1;
        int x = 2;
    }
    void g() {
        int x = 1;
        if (true) {
            int x = 2;
            System.out.println(x);
        }
    }
}
"""

    found = diagnostics(source, "JAVA004")

    assert len(found) == 1
    assert found[0].line == 6
    assert "'x'" in found[0].message


def test_java005_unused_imports():
    source = """
import java.util.List;
import java.io.File;
class Demo {
    void f(List<String> items) {
        System.out.println(items);
    }
}
"""

    found = diagnostics(source, "JAVA005")

    assert len(found) == 1
    assert found[0].line == 3
    assert "'File'" in found[0].message


def test_java005_ignores_wildcard_and_static_imports():
    source = """
import java.util.*;
import static java.lang.Math.PI;
import java.util.List;
class Demo {
    void f(List<String> items) {
        System.out.println(items);
    }
}
"""

    assert messages(source, "JAVA005") == []


def test_java006_unused_parameters():
    source = """
class Demo {
    void f(int used, int unused, int _ignored) {
        System.out.println(used);
    }
}
"""

    found = diagnostics(source, "JAVA006")

    assert len(found) == 1
    assert "'unused'" in found[0].message
    assert not any("'_ignored'" in item.message for item in found)


def test_java007_null_access_without_guard():
    source = """
class Demo {
    void f() {
        String item = null;
        System.out.println(item.length());
    }
}
"""

    found = diagnostics(source, "JAVA007")

    assert len(found) == 1
    assert "item" in found[0].message
    assert found[0].severity == "warning"


def test_java007_ignores_guards():
    source = """
class Demo {
    void f() {
        String safe = null;
        if (safe != null) {
            System.out.println(safe.length());
        }
        String other = null;
        Objects.requireNonNull(other);
        System.out.println(other.length());
    }
}
"""

    assert messages(source, "JAVA007") == []


def test_java008_empty_exception_handler():
    source = """
class Demo {
    void f() {
        try { run(); } catch (Exception e) { /* ignored */ }
    }
}
"""

    found = diagnostics(source, "JAVA008")

    assert len(found) == 1
    assert "Exception" in found[0].message


def test_java008_ignores_handlers_with_statements():
    source = """
class Demo {
    void f() {
        try { run(); } catch (Exception e) { handle(); }
    }
}
"""

    assert messages(source, "JAVA008") == []


def test_java009_suspicious_calls():
    source = """
class Demo {
    void f(Exception error) {
        System.exit(1);
        error.printStackTrace();
        System.out.println("safe");
    }
}
"""

    found = diagnostics(source, "JAVA009")

    assert len(found) == 2
    assert any("System.exit" in item.message for item in found)
    assert any("printStackTrace" in item.message for item in found)
    assert all(item.severity == "warning" for item in found)


def test_java010_dangerous_calls():
    source = """
import java.io.ObjectInputStream;
class Demo {
    void f() throws Exception {
        Runtime.getRuntime().exec("ls");
        new ProcessBuilder("ls");
        ObjectInputStream in = null;
        in.readObject();
        Class.forName("Example");
    }
}
"""

    found = diagnostics(source, "JAVA010")

    assert len(found) == 4
    assert any("exec" in item.message for item in found)
    assert any("ProcessBuilder" in item.message for item in found)
    assert any("readObject" in item.message for item in found)
    assert any("Class.forName" in item.message for item in found)
    assert all(item.severity == "error" for item in found)


def test_java010_ignores_safe_calls():
    source = """
class Demo {
    void f() {
        System.out.println("safe");
        new StringBuilder();
    }
}
"""

    assert messages(source, "JAVA010") == []


def test_java_common_patterns_do_not_produce_false_positives():
    source = """
import java.util.List;

class UserManager {
    private String username;

    public UserManager(String username) {
        this.username = username;
    }

    public String getUser(List<String> names) {
        if (names.isEmpty()) {
            return username;
        }
        return names.get(0);
    }

    public static void main(String[] args) {
        System.out.println(args.length);
    }
}
"""

    result = ENGINE.analyze_source(source, "java")

    assert result.has_syntax_errors is False
    assert result.diagnostics == []
