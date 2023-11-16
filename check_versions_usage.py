import sys
import ast
import logging
from conan import ConanFile
import yaml
import os


def node_uses_version(root: ast.AST) -> bool:
    for node in ast.walk(root):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "self" and  node.attr == "version" and isinstance(node.ctx,  ast.Load):
            return True
    return False

def evaluate_expr(compiled, version:str) -> bool:
    recipe_obj = ConanFile()
    recipe_obj.version = version
    return eval(compiled,
                {
        'Version': __import__('conan').tools.scm.Version,
        'scm': __import__('conan').tools.scm,
        'tools': __import__('conan').tools,
        'self': recipe_obj})

def check_recipe(recipe_file: str, versions: list[str]) -> None:
    with open(recipe_file, encoding='utf-8') as f:
        recipe_lines = f.readlines()
    source = "".join(recipe_lines)

    tree = ast.parse(source)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for name in node.names:
                if name.name.startswith("conans."):
                    logging.debug("skipping %s which is not conan v2 compatible", recipe_file)
                    return
        if isinstance(node, ast.ImportFrom):
            if node.module.startswith("conans"):
                logging.debug("skipping %s which is not conan v2 compatible", recipe_file)
                return

        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "deprecated":
                    logging.debug("skipping %s which is deprecated", recipe_file)
                    return


    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        if node_uses_version(node.left) or any(node_uses_version(n) for n in node.comparators):
            compiled = compile(ast.Expression(node), recipe_file, 'eval')
            try:
                results = [evaluate_expr(compiled, v) for v in versions]
                if all(r == results[0] for r in results):
                    print(f"[`{ast.unparse(node)}`](https://github.com/conan-io/conan-center-index/tree/master/recipes/{recipe_file}#L{node.lineno}) is always {results[0]} for versions {versions}")
            except Exception:
                logging.warning("Error in %s:%s, %s skipping the comparison", recipe_file, node.lineno, ast.unparse(node))

def main(path: str) -> None:
    if path.endswith('config.yml'):
        path = path[0:-10]
    with open(os.path.join(path, 'config.yml'), 'r') as file:
        config = yaml.safe_load(file)
    d = {}
    for version,v in config['versions'].items():
        folder = v['folder']
        if folder in d:
            d[folder].append(version)
        else:
            d[folder] = [version]
    for folder,versions in d.items():
        check_recipe(os.path.join(path, folder, "conanfile.py"), versions)



if __name__ == "__main__":
    if len(sys.argv) == 1:
        sys.exit(main('.'))
    if len(sys.argv) == 2:
        sys.exit(main(sys.argv[1]))

    sys.exit(check_recipe(sys.argv[1], sys.argv[2:]))
