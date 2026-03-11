from __future__ import annotations

import base64
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import yaml

logger = logging.getLogger(__name__)

STATIC_ASSET_EXTENSIONS = frozenset(
    {".js", ".css", ".png", ".woff", ".woff2", ".svg", ".ico", ".jpg", ".jpeg", ".gif", ".ttf", ".eot", ".map"}
)


@dataclass
class APIEndpoint:
    method: str
    url: str
    path: str
    headers: dict[str, str]
    query_params: dict[str, str]
    body: str | None
    body_type: str
    auth_type: str
    auth_value: str | None
    tags: list[str]
    variables: dict[str, str]
    original_name: str
    test_script: str = ""
    pre_request_script: str = ""


def _resolve_vars(text: str, variables: dict[str, str]) -> str:
    if not text:
        return text
    result = text
    for key, val in variables.items():
        if val is None:
            val = ""
        result = result.replace("{{" + key + "}}", str(val))
    return result


def _extract_path_from_url(url: str) -> str:
    parsed = urlparse(url)
    return parsed.path or "/"


def _query_params_to_dict(url: str) -> dict[str, str]:
    parsed = urlparse(url)
    if not parsed.query:
        return {}
    params: dict[str, str] = {}
    for k, v_list in parse_qs(parsed.query, keep_blank_values=True).items():
        params[k] = v_list[0] if v_list else ""
    return params


def _url_without_query(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))


class EndpointRegistry:
    def __init__(self) -> None:
        self._endpoints: list[APIEndpoint] = []
        self._index: dict[str, APIEndpoint] = {}

    def _dedup_key(self, ep: APIEndpoint) -> str:
        path = ep.path
        method = ep.method.upper()
        param_keys = ",".join(sorted(ep.query_params.keys()))
        return f"{method}|{path}|{param_keys}"

    def add(self, endpoints: list[APIEndpoint]) -> None:
        for ep in endpoints:
            key = self._dedup_key(ep)
            if key not in self._index:
                self._index[key] = ep
                self._endpoints.append(ep)

    def add_from_traffic(self, traffic_data: dict | list) -> None:
        items: list[dict] = []
        if isinstance(traffic_data, list):
            items = traffic_data
        elif isinstance(traffic_data, dict):
            entries = traffic_data.get("entries") or traffic_data.get("requests") or traffic_data.get("items")
            if isinstance(entries, list):
                items = entries
            else:
                items = [traffic_data]

        endpoints: list[APIEndpoint] = []
        for item in items:
            url = item.get("url") or item.get("requestUrl") or item.get("request_url")
            method = (item.get("method") or item.get("requestMethod") or "GET").upper()
            if not url:
                continue

            headers = dict(item.get("headers") or item.get("requestHeaders") or {})
            if isinstance(headers, list):
                headers = {h.get("name", h.get("key", "")): h.get("value", "") for h in headers if h.get("name") or h.get("key")}

            body = item.get("request_body") or item.get("requestBody") or item.get("body")
            if isinstance(body, dict):
                body = json.dumps(body) if body else None
            body = str(body) if body is not None else None

            auth_type = "none"
            auth_value = None
            auth_header = item.get("authorization") or (headers.get("Authorization") if isinstance(headers.get("Authorization"), str) else None)
            if auth_header:
                if auth_header.lower().startswith("bearer "):
                    auth_type = "bearer"
                    auth_value = auth_header[7:].strip()
                elif auth_header.lower().startswith("basic "):
                    auth_type = "basic"
                    auth_value = auth_header[6:].strip()

            parsed = urlparse(url)
            path = parsed.path or "/"
            query_params: dict[str, str] = {}
            if parsed.query:
                for k, v_list in parse_qs(parsed.query, keep_blank_values=True).items():
                    query_params[k] = v_list[0] if v_list else ""

            body_type = "raw"
            if body and headers.get("Content-Type", "").lower().find("json") >= 0:
                body_type = "json"
            elif body and headers.get("Content-Type", "").lower().find("x-www-form-urlencoded") >= 0:
                body_type = "form"
            elif body and headers.get("Content-Type", "").lower().find("xml") >= 0:
                body_type = "xml"
            elif body and headers.get("Content-Type", "").lower().find("graphql") >= 0:
                body_type = "graphql"

            ep = APIEndpoint(
                method=method,
                url=url,
                path=path,
                headers=headers,
                query_params=query_params,
                body=body,
                body_type=body_type,
                auth_type=auth_type,
                auth_value=auth_value,
                tags=["traffic"],
                variables={},
                original_name=item.get("name") or f"{method} {path}",
            )
            endpoints.append(ep)

        self.add(endpoints)

    def get_all(self) -> list[APIEndpoint]:
        return list(self._endpoints)

    def get_by_path(self, path: str) -> list[APIEndpoint]:
        return [ep for ep in self._endpoints if ep.path == path]

    def get_by_tag(self, tag: str) -> list[APIEndpoint]:
        return [ep for ep in self._endpoints if tag in ep.tags]

    def summary(self) -> dict:
        paths = list({ep.path for ep in self._endpoints})
        methods = {}
        for ep in self._endpoints:
            key = ep.path
            if key not in methods:
                methods[key] = []
            if ep.method not in methods[key]:
                methods[key].append(ep.method)
        return {
            "total": len(self._endpoints),
            "unique_paths": len(paths),
            "paths": sorted(paths),
            "methods_by_path": {p: methods.get(p, []) for p in paths},
        }


def _postman_auth_to_unified(auth: dict | None) -> tuple[str, str | None]:
    if not auth or auth.get("type") == "noauth":
        return "none", None
    atype = auth.get("type", "")
    if atype == "bearer":
        for attr in auth.get("bearer", []) or []:
            if attr.get("key") == "token":
                return "bearer", attr.get("value")
        return "bearer", None
    if atype == "basic":
        uname = pwd = ""
        for attr in auth.get("basic", []) or []:
            if attr.get("key") == "username":
                uname = attr.get("value") or ""
            elif attr.get("key") == "password":
                pwd = attr.get("value") or ""
        if uname or pwd:
            import base64 as b64
            creds = b64.b64encode(f"{uname}:{pwd}".encode()).decode()
            return "basic", creds
        return "basic", None
    if atype == "apikey":
        for attr in auth.get("apikey", []) or []:
            if attr.get("key") == "value":
                return "api_key", attr.get("value")
        return "api_key", None
    if atype in ("oauth1", "oauth2", "digest", "awsv4", "hawk", "ntlm", "edgegrid"):
        return "bearer", None
    return "none", None


def _postman_body_to_unified(body: dict | None, variables: dict[str, str]) -> tuple[str | None, str]:
    if not body or body.get("disabled"):
        return None, "raw"
    mode = body.get("mode", "raw")
    if mode == "raw":
        raw = body.get("raw") or ""
        raw = _resolve_vars(raw, variables)
        ctype = body.get("options", {}).get("raw", {}).get("language", "text")
        bt = "json" if "json" in ctype.lower() else "xml" if "xml" in ctype.lower() else "raw"
        return raw or None, bt
    if mode == "urlencoded":
        params = body.get("urlencoded") or []
        pairs = [(p.get("key"), _resolve_vars(str(p.get("value", "")), variables)) for p in params if not p.get("disabled")]
        return urlencode(pairs), "form"
    if mode == "formdata":
        params = body.get("formdata") or []
        parts = []
        for p in params:
            if p.get("disabled"):
                continue
            if p.get("type") == "file":
                continue
            parts.append(f"{p.get('key', '')}={_resolve_vars(str(p.get('value', '')), variables)}")
        return "&".join(parts) if parts else None, "form"
    if mode == "graphql":
        gql = body.get("graphql", {})
        if isinstance(gql, dict):
            query = gql.get("query") or ""
            variables_str = gql.get("variables")
            if variables_str:
                query = _resolve_vars(query, variables)
                try:
                    v = json.loads(variables_str) if isinstance(variables_str, str) else variables_str
                    payload = {"query": query, "variables": v}
                except json.JSONDecodeError:
                    payload = {"query": query}
            else:
                payload = {"query": _resolve_vars(query, variables)}
            return json.dumps(payload), "graphql"
        return None, "graphql"
    return None, "raw"


def _postman_url_to_full(url_obj: Any, variables: dict[str, str]) -> str:
    if isinstance(url_obj, str):
        return _resolve_vars(url_obj, variables)

    extra_query = url_obj.get("query") or []
    extra_qs_parts = []
    for q in extra_query:
        if isinstance(q, dict) and not q.get("disabled"):
            k = _resolve_vars(str(q.get("key", "")), variables)
            v = _resolve_vars(str(q.get("value", "")), variables)
            extra_qs_parts.append(f"{k}={v}")

    raw = url_obj.get("raw")
    if raw:
        resolved = _resolve_vars(raw, variables)
        if extra_qs_parts:
            sep = "&" if "?" in resolved else "?"
            resolved = resolved + sep + "&".join(extra_qs_parts)
        return resolved

    protocol = _resolve_vars(url_obj.get("protocol", "https"), variables)
    host_list = url_obj.get("host") or []
    if isinstance(host_list, str):
        host_list = [host_list]
    host = ".".join(_resolve_vars(str(h), variables) for h in host_list)
    path_list = url_obj.get("path") or []
    if isinstance(path_list, str):
        path_list = [path_list]
    path = "/" + "/".join(_resolve_vars(str(p), variables) for p in path_list).lstrip("/")
    if extra_qs_parts:
        path = f"{path}?{'&'.join(extra_qs_parts)}"
    return f"{protocol}://{host}{path}"


def _traverse_postman_items(
    items: list[dict],
    variables: dict[str, str],
    inherited_auth: dict | None,
    folder_tags: list[str],
) -> list[APIEndpoint]:
    endpoints: list[APIEndpoint] = []
    for it in items:
        if "request" in it:
            req = it["request"]
            if req.get("disabled"):
                continue
            auth = req.get("auth") if req.get("auth") else inherited_auth
            auth_type, auth_value = _postman_auth_to_unified(auth)

            vars_here = dict(variables)
            for v in it.get("variable", []) or []:
                if isinstance(v, dict) and v.get("key") is not None:
                    vars_here[v["key"]] = str(v.get("value", ""))
            for v in req.get("url", {}).get("variable", []) or [] if isinstance(req.get("url"), dict) else []:
                if isinstance(v, dict) and v.get("key") is not None:
                    vars_here[v["key"]] = str(v.get("value", ""))

            url_obj = req.get("url")
            if isinstance(url_obj, str):
                url_obj = {"raw": url_obj}
            full_url = _postman_url_to_full(url_obj or {}, vars_here)
            parsed = urlparse(full_url)
            path = parsed.path or "/"
            query_params = _query_params_to_dict(full_url)

            headers_list = req.get("header") or []
            if isinstance(headers_list, str):
                headers_list = []
            headers: dict[str, str] = {}
            for h in headers_list:
                if isinstance(h, dict) and not h.get("disabled"):
                    key = h.get("key")
                    if key:
                        headers[key] = _resolve_vars(str(h.get("value", "")), vars_here)

            body, body_type = _postman_body_to_unified(req.get("body"), vars_here)

            tags = list(folder_tags)
            if it.get("name"):
                tags.append(it["name"])

            test_script = ""
            pre_request_script = ""
            for ev in it.get("event", []) or []:
                if isinstance(ev, dict):
                    listen = ev.get("listen", "")
                    script = ev.get("script", {})
                    exec_lines = script.get("exec", []) if isinstance(script, dict) else []
                    code = "\n".join(exec_lines) if isinstance(exec_lines, list) else str(exec_lines)
                    if listen == "test":
                        test_script = code
                    elif listen == "prerequest":
                        pre_request_script = code

            ep = APIEndpoint(
                method=(req.get("method") or "GET").upper(),
                url=full_url,
                path=path,
                headers=headers,
                query_params=query_params,
                body=body,
                body_type=body_type,
                auth_type=auth_type,
                auth_value=auth_value,
                tags=tags,
                variables=vars_here,
                original_name=it.get("name") or f"{req.get('method', 'GET')} {path}",
                test_script=test_script,
                pre_request_script=pre_request_script,
            )
            endpoints.append(ep)
        else:
            sub_items = it.get("item", [])
            sub_auth = it.get("auth") if it.get("auth") else inherited_auth
            sub_tags = list(folder_tags)
            if it.get("name"):
                sub_tags.append(it["name"])
            sub_vars = dict(variables)
            for v in it.get("variable", []) or []:
                if isinstance(v, dict) and v.get("key") is not None:
                    sub_vars[v["key"]] = str(v.get("value", ""))
            endpoints.extend(
                _traverse_postman_items(sub_items, sub_vars, sub_auth, sub_tags)
            )
    return endpoints


def parse_postman_collection(filepath: str, env_filepath: str | None = None) -> list[APIEndpoint]:
    path = Path(filepath)
    if not path.exists():
        logger.error("Postman collection file not found: %s", filepath)
        return []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        logger.error("Invalid Postman JSON: %s - %s", filepath, e)
        return []
    except OSError as e:
        logger.error("Cannot read Postman file: %s - %s", filepath, e)
        return []

    variables: dict[str, str] = {}
    for v in data.get("variable", []) or []:
        if isinstance(v, dict) and v.get("key") is not None:
            variables[v["key"]] = str(v.get("value", ""))

    if env_filepath:
        env_path = Path(env_filepath)
        if env_path.exists():
            try:
                env_data = json.loads(env_path.read_text(encoding="utf-8"))
                for v in env_data.get("values", []) or []:
                    if isinstance(v, dict) and v.get("key") is not None:
                        variables[v["key"]] = str(v.get("value", ""))
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("Could not load Postman environment %s: %s", env_filepath, e)

    items = data.get("item", [])
    if not items:
        return []
    auth = data.get("auth")
    return _traverse_postman_items(items, variables, auth, [])


def parse_burp_export(filepath: str) -> list[APIEndpoint]:
    path = Path(filepath)
    if not path.exists():
        logger.error("Burp export file not found: %s", filepath)
        return []

    try:
        from lxml import etree
    except ImportError:
        logger.error("lxml is required for Burp XML parsing")
        return []

    try:
        raw_xml = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.error("Cannot read Burp file: %s - %s", filepath, e)
        return []

    raw_xml = re.sub(
        r"(<request[^>]*>)(.*?)(</request>)",
        lambda m: m.group(1) + "<![CDATA[" + m.group(2) + "]]>" + m.group(3),
        raw_xml,
        flags=re.DOTALL,
    )
    raw_xml = re.sub(
        r"(<response[^>]*>)(.*?)(</response>)",
        lambda m: m.group(1) + "<![CDATA[" + m.group(2) + "]]>" + m.group(3),
        raw_xml,
        flags=re.DOTALL,
    )

    try:
        parser = etree.XMLParser(recover=True, encoding="utf-8")
        root = etree.fromstring(raw_xml.encode("utf-8"), parser)
    except etree.XMLSyntaxError as e:
        logger.error("Invalid Burp XML: %s - %s", filepath, e)
        return []

    def _find(elem, *tags):
        for t in tags:
            found = elem.find(t)
            if found is not None:
                return found
        return None

    items = root.findall(".//item")
    if not items:
        items = root.findall(".//{*}item")
    if not items and root.tag == "item" or (root.tag and root.tag.endswith("}item")):
        items = [root]

    seen: set[str] = set()
    endpoints: list[APIEndpoint] = []

    for item in items:
        url_elem = _find(item, "url", "URL")
        host_elem = _find(item, "host", "Host")
        port_elem = _find(item, "port", "Port")
        protocol_elem = _find(item, "protocol", "Protocol")
        method_elem = _find(item, "method", "Method")
        path_elem = _find(item, "path", "Path")
        request_elem = _find(item, "request", "Request")

        url = ""
        if url_elem is not None and url_elem.text:
            url = url_elem.text.strip()
        elif host_elem is not None and protocol_elem is not None and path_elem is not None:
            proto = protocol_elem.text or "https"
            host = host_elem.text or ""
            port = port_elem.text or ("443" if "https" in proto.lower() else "80")
            path = path_elem.text or "/"
            if port and port not in ("80", "443"):
                url = f"{proto}://{host}:{port}{path}"
            else:
                url = f"{proto}://{host}{path}"

        if not url:
            continue

        ext = ""
        ext_elem = _find(item, "extension", "Extension")
        if ext_elem is not None and ext_elem.text:
            ext = "." + ext_elem.text.strip().lstrip(".")
        elif "." in url:
            ext = "." + url.split(".")[-1].split("?")[0].split("/")[-1]
        if ext.lower() in STATIC_ASSET_EXTENSIONS:
            continue

        method = "GET"
        if method_elem is not None and method_elem.text:
            method = method_elem.text.strip().upper()

        if request_elem is None:
            parsed = urlparse(url)
            path = parsed.path or "/"
            query_params = _query_params_to_dict(url)
            ep = APIEndpoint(
                method=method,
                url=url,
                path=path,
                headers={},
                query_params=query_params,
                body=None,
                body_type="raw",
                auth_type="none",
                auth_value=None,
                tags=["burp"],
                variables={},
                original_name=f"{method} {path}",
            )
            key = f"{method}|{path}|{','.join(sorted(ep.query_params.keys()))}"
            if key not in seen:
                seen.add(key)
                endpoints.append(ep)
            continue

        raw_request = request_elem.text or ""
        is_base64 = request_elem.get("base64", "false")
        if str(is_base64).lower() == "true":
            clean = raw_request.strip()
            try:
                raw_request = base64.b64decode(clean).decode("utf-8", errors="replace")
            except Exception as e:
                logger.debug("Burp base64 decode failed: %s", e)

        raw_request = raw_request.replace("\r\n", "\n").replace("\r", "\n")
        # XML normalization can turn \r\n into \n\n; detect and fix:
        # If the first line (request line) is followed by \n\n instead of \n,
        # it means every \r\n was doubled to \n\n by the XML parser.
        first_nl = raw_request.find("\n")
        if first_nl > 0 and first_nl + 1 < len(raw_request) and raw_request[first_nl + 1] == "\n":
            second_char = raw_request[first_nl + 2:first_nl + 3]
            if second_char and second_char not in ("\n", ""):
                raw_request = re.sub(r"\n\n\n\n", "\x00SEP\x00", raw_request)
                raw_request = raw_request.replace("\n\n", "\n")
                raw_request = raw_request.replace("\x00SEP\x00", "\n\n")
        lines = raw_request.split("\n")
        if not lines:
            continue
        first = lines[0]
        parts = first.split()
        if len(parts) >= 2:
            method = parts[0].upper()
            req_path = parts[1]
        else:
            req_path = urlparse(url).path or "/"

        headers: dict[str, str] = {}
        body_lines: list[str] = []
        in_body = False
        for line in lines[1:]:
            if in_body:
                body_lines.append(line)
                continue
            if line.strip() == "":
                in_body = True
                continue
            if ":" in line:
                idx = line.index(":")
                k = line[:idx].strip()
                v = line[idx + 1 :].strip()
                headers[k] = v

        body = "\n".join(body_lines).strip() or None

        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        if req_path.startswith("http"):
            full_url = req_path
        elif req_path.startswith("/"):
            full_url = base_url + req_path
        else:
            full_url = base_url + "/" + req_path
        path = urlparse(full_url).path or "/"
        query_params = _query_params_to_dict(full_url)

        auth_type = "none"
        auth_value = None
        auth_h = headers.get("Authorization", headers.get("authorization"))
        if auth_h:
            if auth_h.lower().startswith("bearer "):
                auth_type = "bearer"
                auth_value = auth_h[7:].strip()
            elif auth_h.lower().startswith("basic "):
                auth_type = "basic"
                auth_value = auth_h[6:].strip()
        cookie = headers.get("Cookie", headers.get("cookie"))
        if cookie and auth_type == "none":
            auth_type = "cookie"
            auth_value = cookie

        body_type = "raw"
        ct = headers.get("Content-Type", headers.get("content-type", ""))
        if "json" in ct.lower():
            body_type = "json"
        elif "x-www-form-urlencoded" in ct.lower():
            body_type = "form"
        elif "xml" in ct.lower():
            body_type = "xml"
        elif "graphql" in ct.lower():
            body_type = "graphql"

        ep = APIEndpoint(
            method=method,
            url=full_url,
            path=path,
            headers=headers,
            query_params=query_params,
            body=body,
            body_type=body_type,
            auth_type=auth_type,
            auth_value=auth_value,
            tags=["burp"],
            variables={},
            original_name=f"{method} {path}",
        )
        key = f"{method}|{path}|{','.join(sorted(ep.query_params.keys()))}"
        if key not in seen:
            seen.add(key)
            endpoints.append(ep)

    return endpoints


def _example_from_schema(schema: dict | None) -> Any:
    if not schema:
        return None
    if "example" in schema:
        return schema["example"]
    if "examples" in schema and schema["examples"]:
        ex = schema["examples"]
        if isinstance(ex, list) and ex:
            return ex[0]
        if isinstance(ex, dict):
            first = next(iter(ex.values()), None)
            return first.get("value", first) if isinstance(first, dict) else first
    stype = schema.get("type")
    if stype == "string":
        fmt = schema.get("format")
        if fmt == "uuid":
            return "550e8400-e29b-41d4-a716-446655440000"
        if fmt == "email":
            return "user@example.com"
        if fmt == "date":
            return "2024-01-15"
        if fmt == "date-time":
            return "2024-01-15T12:00:00Z"
        return "string"
    if stype == "integer":
        return schema.get("default", 0)
    if stype == "number":
        return schema.get("default", 0.0)
    if stype == "boolean":
        return schema.get("default", False)
    if stype == "array":
        items_schema = schema.get("items")
        if items_schema:
            item_ex = _example_from_schema(items_schema)
            return [item_ex] if item_ex is not None else []
        return []
    if stype == "object" or "properties" in schema:
        props = schema.get("properties")
        if props and isinstance(props, dict):
            obj = {}
            for prop_name, prop_schema in props.items():
                if isinstance(prop_schema, dict):
                    ex = _example_from_schema(prop_schema)
                    obj[prop_name] = ex if ex is not None else ""
            if obj:
                return obj
        return {}
    return None


def _openapi_servers(spec: dict) -> str:
    servers = spec.get("servers") or []
    if servers and isinstance(servers[0], dict):
        url = servers[0].get("url", "")
        if url:
            return url.rstrip("/")
    if "host" in spec:
        host = spec.get("host", "")
        base_path = spec.get("basePath", "")
        schemes = spec.get("schemes", ["https"])
        proto = schemes[0] if schemes else "https"
        return f"{proto}://{host.rstrip('/')}{base_path}"
    return ""


def parse_openapi_spec(filepath: str) -> list[APIEndpoint]:
    path = Path(filepath)
    if not path.exists():
        logger.error("OpenAPI spec file not found: %s", filepath)
        return []

    raw = path.read_text(encoding="utf-8")
    try:
        if path.suffix.lower() in (".yaml", ".yml"):
            spec = yaml.safe_load(raw)
        else:
            spec = json.loads(raw)
    except (yaml.YAMLError, json.JSONDecodeError) as e:
        logger.error("Invalid OpenAPI spec: %s - %s", filepath, e)
        return []
    except OSError as e:
        logger.error("Cannot read OpenAPI file: %s - %s", filepath, e)
        return []

    if not isinstance(spec, dict):
        return []

    base_url = _openapi_servers(spec)
    paths = spec.get("paths") or {}
    if not isinstance(paths, dict):
        return []

    endpoints: list[APIEndpoint] = []
    for path_str, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        path_str = path_str.strip()
        if not path_str.startswith("/"):
            path_str = "/" + path_str
        for method in ("get", "post", "put", "delete", "patch", "head", "options"):
            op = path_item.get(method)
            if not isinstance(op, dict):
                continue
            op_id = op.get("operationId") or f"{method}_{path_str.replace('/', '_')}"
            tags = list(op.get("tags") or [])
            params = list(op.get("parameters") or []) + list(path_item.get("parameters") or [])

            query_params: dict[str, str] = {}
            headers: dict[str, str] = {}
            path_params: dict[str, str] = {}

            for p in params:
                if not isinstance(p, dict):
                    continue
                name = p.get("name")
                if not name:
                    continue
                loc = (p.get("in") or "query").lower()
                ex = p.get("example") or _example_from_schema(p.get("schema"))
                val = str(ex) if ex is not None else ""
                if loc == "query":
                    query_params[name] = val
                elif loc == "path":
                    path_params[name] = val
                elif loc == "header":
                    headers[name] = val
                elif loc == "cookie":
                    headers["Cookie"] = headers.get("Cookie", "") + f"{name}={val}; "

            resolved_path = path_str
            for k, v in path_params.items():
                resolved_path = resolved_path.replace("{" + k + "}", str(v))

            if query_params:
                resolved_path = resolved_path + "?" + urlencode(query_params)

            full_url = base_url + resolved_path if base_url else resolved_path
            parsed = urlparse(full_url)
            path_only = parsed.path or "/"
            qp = _query_params_to_dict(full_url)

            body = None
            body_type = "raw"
            req_body = op.get("requestBody")
            if isinstance(req_body, dict):
                content = req_body.get("content") or {}
                if "application/json" in content:
                    body_type = "json"
                    schema = content["application/json"].get("schema")
                    ex = _example_from_schema(schema)
                    body = json.dumps(ex) if ex is not None else "{}"
                elif "application/x-www-form-urlencoded" in content:
                    body_type = "form"
                    schema = content["application/x-www-form-urlencoded"].get("schema")
                    if schema and schema.get("properties"):
                        props = schema.get("properties", {})
                        pairs = [(k, str(_example_from_schema(v) or "")) for k, v in props.items()]
                        body = urlencode(pairs)
                elif "application/xml" in content or "text/xml" in content:
                    body_type = "xml"
                    body = "<?xml version=\"1.0\"?><root/>"
                elif "application/graphql" in content:
                    body_type = "graphql"
                    body = "{}"

            auth_type = "none"
            auth_value = None
            op_sec = op.get("security")
            if op_sec is not None:
                sec = op_sec
            else:
                sec = spec.get("security") or []
            if sec and isinstance(sec[0], dict):
                all_schemes = {}
                all_schemes.update((spec.get("components") or {}).get("securitySchemes") or {})
                all_schemes.update(spec.get("securityDefinitions") or {})
                for scheme_name in sec[0]:
                    scheme_def = all_schemes.get(scheme_name, {}) if isinstance(all_schemes, dict) else {}
                    if isinstance(scheme_def, dict):
                        stype = scheme_def.get("type", "").lower()
                        if stype == "http" and scheme_def.get("scheme", "").lower() == "bearer":
                            auth_type = "bearer"
                            auth_value = scheme_def.get("bearerFormat") or ""
                        elif stype == "http" and scheme_def.get("scheme", "").lower() == "basic":
                            auth_type = "basic"
                        elif stype in ("apikey", "apikey"):
                            auth_type = "api_key"
                            auth_value = scheme_def.get("name", "")
                        elif stype == "basic":
                            auth_type = "basic"

            ep = APIEndpoint(
                method=method.upper(),
                url=full_url,
                path=path_only,
                headers=headers,
                query_params=qp,
                body=body,
                body_type=body_type,
                auth_type=auth_type,
                auth_value=auth_value,
                tags=tags or ["openapi"],
                variables={},
                original_name=op_id,
            )
            endpoints.append(ep)

    return endpoints
