"""The served OpenAPI document against the routes the server actually registers.

`docs/api.md` points clients at `/api/v1/openapi.json` as the description of
this API, which makes its completeness a promise rather than a nicety. It had
drifted to 16 of 47 routes, and the omissions included `/api/v1/auth/login` —
so a client generated from it could not authenticate to reach the sixteen it
did describe.

Both directions matter. A route missing from the document is invisible to such
a client; a path in the document that no longer exists is worse, because it
reads as supported.
"""
from __future__ import annotations

import inspect
import re

import pytest

from trench.api.server import _OPENAPI, API, APIServer

#: Registered but deliberately absent from the API description, with the reason.
NOT_API = {
    "/": "the console SPA's index, not an API route",
}

_ADD_ROUTE = re.compile(
    r'r\.add_(get|post|put|delete|patch)\(\s*(f?)"([^"]*)",\s*self\.(\w+)\)')


def _registered() -> dict[str, set[str]]:
    """{path: {method}} straight out of `_routes`, as aiohttp would see it."""
    source = inspect.getsource(APIServer._add_routes)
    routes: dict[str, set[str]] = {}
    for method, _f, raw, _handler in _ADD_ROUTE.findall(source):
        path = raw.replace("{API}", API).replace("{{", "{").replace("}}", "}")
        routes.setdefault(path, set()).add(method)
    return routes


def _documented() -> dict[str, set[str]]:
    verbs = {"get", "post", "put", "delete", "patch"}
    return {path: {k for k in item if k in verbs}
            for path, item in _OPENAPI["paths"].items()}


@pytest.fixture(scope="module")
def registered() -> dict[str, set[str]]:
    found = _registered()
    assert len(found) > 40, f"only {len(found)} routes parsed; the matcher has drifted"
    return found


def test_every_route_is_in_the_openapi_document(registered):
    documented = _documented()
    missing = sorted(p for p in registered if p not in documented and p not in NOT_API)
    assert not missing, (
        f"{len(missing)} route(s) absent from the OpenAPI document: {missing}\n"
        "Add a summary, or list the path in NOT_API here with the reason.")


def test_the_openapi_document_describes_no_route_that_does_not_exist(registered):
    phantom = sorted(p for p in _documented() if p not in registered)
    assert not phantom, f"documented but not registered: {phantom}"


def test_the_methods_agree(registered):
    documented = _documented()
    wrong = [f"{p}: documented {sorted(documented[p])}, registered {sorted(registered[p])}"
             for p in sorted(set(documented) & set(registered))
             if documented[p] != registered[p]]
    assert not wrong, "\n  ".join(["method mismatch:", *wrong])


def test_every_summary_says_which_role_it_needs(registered):
    """The document is what a client reads before writing code against a route;
    "403 Forbidden" after the fact is a worse way to learn the role."""
    source = inspect.getsource(APIServer)
    handlers = {}
    for method, _f, raw, handler in _ADD_ROUTE.findall(inspect.getsource(APIServer._add_routes)):
        path = raw.replace("{API}", API).replace("{{", "{").replace("}}", "}")
        handlers[(path, method)] = handler

    missing = []
    for path, item in _OPENAPI["paths"].items():
        for method, spec in item.items():
            handler = handlers.get((path, method))
            if handler is None:
                continue
            body = source[source.index(f"def {handler}(") if f"def {handler}(" in source else 0:]
            body = body[:body.find("\n    async def ", 10) if "\n    async def " in body[10:] else len(body)]
            role = re.search(r'_require\(request,\s*"(\w+)"\)', body)
            if role and f"({role.group(1)})" not in spec.get("summary", ""):
                missing.append(f"{method.upper()} {path} needs {role.group(1)}")
    assert not missing, "summaries that do not name the required role:\n  " + "\n  ".join(missing)


def test_every_operation_meets_what_openapi_requires():
    """OpenAPI 3.0 requires `responses` on each operation and a declared
    parameter for each `{name}` in a path. The document once missed both on
    54 counts, and validating generators rejected it whole."""
    verbs = {"get", "post", "put", "delete", "patch"}
    problems = []
    for path, item in _OPENAPI["paths"].items():
        templated = set(re.findall(r"{(\w+)}", path))
        for verb, op in item.items():
            if verb not in verbs:
                continue
            if not op.get("responses"):
                problems.append(f"{verb.upper()} {path}: no responses")
            declared = {p["name"] for p in op.get("parameters", []) if p.get("in") == "path"}
            if declared != templated:
                problems.append(f"{verb.upper()} {path}: path params {sorted(declared)}"
                                f" != {sorted(templated)}")
    assert not problems, "\n  ".join(["invalid OpenAPI operations:", *problems])
