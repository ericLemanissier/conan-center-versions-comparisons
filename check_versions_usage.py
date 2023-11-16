import sys
import ast
import logging
import os
import yaml


def node_uses_version(root: ast.AST) -> bool:
    for node in ast.walk(root):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "self" and node.attr == "version" and isinstance(node.ctx, ast.Load):
            return True
    return False


def evaluate_expr(compiled, version: str, recipe_class: type) -> bool:
    recipe_obj = recipe_class()
    recipe_obj.version = version
    return eval(
        compiled,
        {
            "Version": __import__("conan").tools.scm.Version,
            "scm": __import__("conan").tools.scm,
            "tools": __import__("conan").tools,
            "self": recipe_obj,
        },
    )


def check_recipe(recipe_file: str, versions: list[str]) -> int:
    with open(recipe_file, encoding='utf-8') as file:
        recipe_lines = file.readlines()
    source = "".join(recipe_lines)

    tree = ast.parse(source)

    recipe_class_name = None

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            if any(isinstance(base, ast.Name) and base.id == "ConanFile" for base in node.bases):
                recipe_class_name = node.name
                break

    assert recipe_class_name

    _globals: dict = {}
    sys.path.append(os.path.dirname(recipe_file))
    try:
        exec(source, _globals)
    except Exception as err:
        logging.debug("skipping %s which is not conan v2 compatible: %s", recipe_file, err)
        return 1
    finally:
        sys.path.remove(os.path.dirname(recipe_file))

    recipe_class = _globals[recipe_class_name]

    recipe_instance = recipe_class()
    if hasattr(recipe_instance, "deprecated") and recipe_instance.deprecated is not None:
        logging.debug("skipping %s which is deprecated:%s", recipe_file, recipe_instance.deprecated)
        return 1

    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        if node_uses_version(node.left) or any(node_uses_version(n) for n in node.comparators):
            compiled = compile(ast.Expression(node), recipe_file, 'eval')
            try:
                results = [evaluate_expr(compiled, v, recipe_class) for v in versions]
                if all(r == results[0] for r in results):
                    print(f"[`{ast.unparse(node)}`](https://github.com/conan-io/conan-center-index/tree/master/recipes/{recipe_file}#L{node.lineno}) is always {results[0]} for versions {versions}")
            except Exception:
                logging.warning("Error in %s:%s, %s skipping the comparison", recipe_file, node.lineno, ast.unparse(node))
    return 0


def main(path: str) -> int:
    if path.endswith('config.yml'):
        path = path[0:-10]
    with open(os.path.join(path, 'config.yml'), encoding='utf-8') as file:
        config = yaml.safe_load(file)
    versions_map: dict[str, list[str]] = {}
    for version, version_data in config['versions'].items():
        folder = version_data['folder']
        if folder in versions_map:
            versions_map[folder].append(version)
        else:
            versions_map[folder] = [version]
    for folder, versions in versions_map.items():
        check_recipe(os.path.join(path, folder, "conanfile.py"), versions)
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 1:
        sys.exit(main('.'))
    if len(sys.argv) == 2:
        sys.exit(main(sys.argv[1]))

    sys.exit(check_recipe(sys.argv[1], sys.argv[2:]))
