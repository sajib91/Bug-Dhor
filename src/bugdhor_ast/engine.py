
from pathlib import Path
from tree_sitter import Parser

from .languages import detect_language, get_language


FUNCTION_TYPES = {
    "function_definition",
    "function_declaration",
    "function_item",
    "method_declaration",
    "method_definition",
    "function_expression",
    "arrow_function",
}

CLASS_TYPES = {
    "class_definition",
    "class_declaration",
    "class_specifier",
}

# Only collect actual variable-bearing nodes.
VARIABLE_TYPES = {
    # Python
    "assignment",
    "augmented_assignment",
    "named_expression",

    # JavaScript
    "variable_declarator",

    # Java
    "variable_declarator",

    # C / C++
    "init_declarator",

    # Go
    "short_var_declaration",
    "var_spec",
}

# Python-specific variable-bearing nodes. Function parameters live in a
# ``parameters`` container instead of in a variable-declaration node, so they
# need their own handling.
PYTHON_VARIABLE_TYPES = {
    "assignment",
    "augmented_assignment",
    "named_expression",
    "parameters",
    "lambda_parameters",
}

# ``self`` and ``cls`` are implicit receiver parameters, not variable
# declarations. Attribute and subscript targets are writes to an existing
# object, so they are not declarations either.
PYTHON_IMPLICIT_PARAMETERS = {"self", "cls"}
PYTHON_NON_VARIABLE_TARGETS = {"attribute", "subscript"}

PYTHON_PARAMETER_TYPES = {
    "identifier",
    "typed_parameter",
    "default_parameter",
    "typed_default_parameter",
    "list_splat_pattern",
    "dictionary_splat_pattern",
}

PYTHON_TARGET_PATTERNS = {
    "pattern_list",
    "tuple_pattern",
    "list_pattern",
    "list_splat_pattern",
    "dictionary_splat_pattern",
}

CALL_TYPES = {
    "call",
    "call_expression",
    "method_invocation",
}

IMPORT_TYPES = {
    "import_statement",
    "import_from_statement",
    "import_declaration",
}


class BugDhorASTEngine:

    def __init__(self):
        self.parsers = {}

    def get_parser(self, language_name):
        if language_name not in self.parsers:
            self.parsers[language_name] = Parser(
                get_language(language_name)
            )

        return self.parsers[language_name]

    @staticmethod
    def get_node_text(node, source):
        return source[
            node.start_byte:node.end_byte
        ].decode("utf-8", errors="replace")

    def get_field_text(self, node, field, source):
        child = node.child_by_field_name(field)

        if child is None:
            return None

        return self.get_node_text(child, source)

    def first_identifier(self, node, source):
        """Find the first identifier inside a declarator."""

        if node is None:
            return None

        if node.type in {
            "identifier",
            "field_identifier",
        }:
            return self.get_node_text(node, source)

        for child in node.children:
            result = self.first_identifier(child, source)

            if result is not None:
                return result

        return None

    def get_function_name(self, node, source):
        return (
            self.get_field_text(node, "name", source)
            or self.get_field_text(node, "declarator", source)
        )

    def get_class_name(self, node, source):
        return (
            self.get_field_text(node, "name", source)
            or self.get_field_text(node, "declarator", source)
        )

    def get_variable_name(self, node, source):

        node_type = node.type

        if node_type in {
            "assignment",
            "augmented_assignment",
            "named_expression",
        }:
            return self.get_field_text(
                node, "left", source
            )

        if node_type == "short_var_declaration":
            return self.get_field_text(
                node, "left", source
            )

        if node_type == "var_spec":
            return (
                self.get_field_text(node, "name", source)
                or self.first_identifier(node, source)
            )

        if node_type in {
            "variable_declarator",
            "init_declarator",
        }:
            name_node = node.child_by_field_name("name")

            if name_node is not None:
                return self.get_node_text(name_node, source)

            declarator = node.child_by_field_name(
                "declarator"
            )

            if declarator is not None:
                return self.first_identifier(
                    declarator, source
                )

            return self.first_identifier(node, source)

        return None

    @staticmethod
    def python_name_node(node):
        """Return the identifier node that declares a Python parameter."""

        if node is None:
            return None

        if node.type == "identifier":
            return node

        name_node = node.child_by_field_name("name")

        if name_node is not None and name_node.type == "identifier":
            return name_node

        for child in node.named_children:
            if child.type == "identifier":
                return child

        return None

    def get_python_parameter_names(self, node, source):
        """Collect parameter identifiers without their annotations/defaults."""

        names = []

        for child in node.named_children:
            if child.type not in PYTHON_PARAMETER_TYPES:
                continue

            name_node = self.python_name_node(child)

            if name_node is not None:
                names.append((name_node, self.get_node_text(
                    name_node, source
                )))

        return names

    def get_python_target_names(self, node, source):
        """Collect declared names from the left side of an assignment."""

        if node is None:
            return []

        if node.type in PYTHON_NON_VARIABLE_TARGETS:
            return []

        if node.type == "identifier":
            return [(node, self.get_node_text(node, source))]

        if node.type in PYTHON_TARGET_PATTERNS:
            names = []

            for child in node.named_children:
                names.extend(
                    self.get_python_target_names(child, source)
                )

            return names

        return []

    def get_python_variable_names(self, node, source):
        """Return ``(name_node, name)`` pairs declared by a Python node."""

        if node.type in {
            "parameters",
            "lambda_parameters",
        }:
            return self.get_python_parameter_names(node, source)

        if node.type in {
            "assignment",
            "augmented_assignment",
        }:
            return self.get_python_target_names(
                node.child_by_field_name("left"), source
            )

        if node.type == "named_expression":
            name_node = (
                node.child_by_field_name("name")
                or node.child_by_field_name("left")
            )
            return self.get_python_target_names(name_node, source)

        return []

    def get_call_name(self, node, source):

        if node.type == "method_invocation":
            return self.get_field_text(
                node, "name", source
            )

        function_node = node.child_by_field_name(
            "function"
        )

        if function_node is not None:
            return self.get_node_text(
                function_node, source
            )

        return None

    def get_import_name(self, node, source):

        # Python: import os / from os import path
        name = self.get_field_text(
            node, "name", source
        )

        if name is not None:
            return name

        # JavaScript: import fs from "fs"
        import_source = self.get_field_text(
            node, "source", source
        )

        if import_source is not None:
            return import_source

        # Java: import java.util.Scanner;
        for child in node.children:
            if child.type not in {
                "import",
                ";",
                "static",
            }:
                return self.get_node_text(
                    child, source
                )

        return None

    @staticmethod
    def make_item(node):
        return {
            "type": node.type,
            "start_line": node.start_point.row + 1,
            "end_line": node.end_point.row + 1,
            "start_column": node.start_point.column + 1,
            "end_column": node.end_point.column + 1,
        }

    def analyze_source(self, source_code, language_name):

        if language_name not in {
            "python",
            "javascript",
            "java",
            "c",
            "cpp",
            "go",
        }:
            raise ValueError(
                f"Unsupported language: {language_name}"
            )

        parser = self.get_parser(language_name)
        source = source_code.encode("utf-8")

        tree = parser.parse(source)
        root = tree.root_node

        functions = []
        classes = []
        variables = []
        seen_variables = set()
        calls = []
        imports = []
        syntax_errors = []

        def visit(node):

            node_type = node.type
            item = self.make_item(node)

            if node_type in FUNCTION_TYPES:
                item["name"] = self.get_function_name(
                    node, source
                )
                functions.append(item)

            elif node_type in CLASS_TYPES:
                item["name"] = self.get_class_name(
                    node, source
                )
                classes.append(item)

            elif (
                language_name == "python"
                and node_type in PYTHON_VARIABLE_TYPES
            ):
                for name_node, name in self.get_python_variable_names(
                    node, source
                ):
                    if (
                        name in PYTHON_IMPLICIT_PARAMETERS
                        or name in seen_variables
                    ):
                        continue

                    seen_variables.add(name)

                    is_parameter = node_type in {
                        "parameters",
                        "lambda_parameters",
                    }
                    variable_node = name_node if is_parameter else node

                    variable_item = self.make_item(variable_node)
                    variable_item["name"] = name
                    variable_item["source"] = self.get_node_text(
                        variable_node, source
                    )
                    variables.append(variable_item)

            elif node_type in VARIABLE_TYPES:
                item["name"] = self.get_variable_name(
                    node, source
                )
                item["source"] = self.get_node_text(
                    node, source
                )
                variables.append(item)

            elif node_type in CALL_TYPES:
                item["name"] = self.get_call_name(
                    node, source
                )
                item["source"] = self.get_node_text(
                    node, source
                )
                calls.append(item)

            elif node_type in IMPORT_TYPES:
                item["name"] = self.get_import_name(
                    node, source
                )
                item["source"] = self.get_node_text(
                    node, source
                )
                imports.append(item)

            if node.type == "ERROR" or node.is_missing:
                syntax_errors.append({
                    **item,
                    "message": (
                        "Syntax error"
                        if node.type == "ERROR"
                        else "Missing syntax node"
                    ),
                })

            for child in node.children:
                visit(child)

        visit(root)

        return {
            "language": language_name,
            "has_syntax_errors": root.has_error,
            "summary": {
                "functions": len(functions),
                "classes": len(classes),
                "variables": len(variables),
                "function_calls": len(calls),
                "imports": len(imports),
                "syntax_errors": len(syntax_errors),
            },
            "functions": functions,
            "classes": classes,
            "variables": variables,
            "function_calls": calls,
            "imports": imports,
            "syntax_errors": syntax_errors,
        }

    def analyze_file(self, file_path):

        path = Path(file_path)

        if not path.is_file():
            raise FileNotFoundError(
                f"File not found: {file_path}"
            )

        language = detect_language(str(path))

        if language is None:
            raise ValueError(
                f"Unsupported file extension: {path.suffix}"
            )

        source_code = path.read_text(
            encoding="utf-8"
        )

        result = self.analyze_source(
            source_code,
            language
        )

        result["file"] = str(path)

        return result
