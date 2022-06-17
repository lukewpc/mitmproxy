import json
import typing
from uuid import uuid4

import mitmproxy.types
from mitmproxy import command
from mitmproxy import http
from mitmproxy import exceptions
from mitmproxy import flow


POSTMAN_SCHEMA = "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"


def cleanup_request(f: flow.Flow) -> http.Request:
    if not getattr(f, "request", None):
        raise exceptions.CommandError("Can't export flow with no request.")
    assert isinstance(f, http.HTTPFlow)
    request = f.request.copy()
    request.decode(strict=False)
    request.headers.pop("content-length")
    return request


class PostmanInfo:
    _postman_id: str
    schema: str
    name: str

    def __init__(self, name) -> None:
        self.name = name
        self.schema = POSTMAN_SCHEMA
        self._postman_id = str(uuid4())


class PostmanHeader:
    key: str
    value: str

    def __init__(self, key, value) -> None:
        self.key = key
        self.value = value


class PostmanQueryParam:
    key: str
    value: str

    def __init__(self, key, value) -> None:
        self.key = key
        self.value = value


class PostmanUrl:
    raw: str
    protocol: str
    host: typing.Sequence[str]
    path: typing.Sequence[str]
    query: typing.Sequence[PostmanQueryParam]

    def __init__(self, url: str) -> None:
        self.raw = url
        url = self.set_protocol(url)
        url = self.set_host(url)
        url = self.set_path(url)
        self.set_query(url)

    def set_protocol(self, url):
        split_prot = url.split("://")
        self.protocol = split_prot.pop(0) if len(split_prot) > 1 else ""
        return "://".join(split_prot)

    def set_host(self, url):
        split_host = url.split("/")
        self.host = split_host.pop(0).split(".")
        return "/".join(split_host)

    def set_path(self, url):
        split_path = url.split("?")
        self.path = split_path.pop(0).split("/")
        return "?".join(split_path)

    def set_query(self, url):
        self.query = [
            PostmanQueryParam(
                a.split("=")[0], a.split("=")[1] if len(a.split("=")) > 1 else ""
            )
            for a in url.split("&")
            if a != ""
        ]

    def pretty(self):
        return ".".join(self.host) + "/" + "/".join(self.path)


class PostmanBody:
    mode: str
    raw: str

    def __init__(self, raw) -> None:
        self.mode = "raw"
        self.raw = raw


class PostmanRequest:
    method: str
    header: typing.Sequence[PostmanHeader]
    url: PostmanUrl
    body: PostmanBody

    def __init__(self, method, header, url, body) -> None:
        self.method = method
        self.header = header
        self.url = url
        self.body = body


class PostmanItem:
    name: str
    request: PostmanRequest
    response = []

    def __init__(self, name, request) -> None:
        self.name = name
        self.request = request


class PostmanCollection:
    info: PostmanInfo
    items: typing.Sequence[PostmanItem]

    def __init__(self, name, items) -> None:
        self.info = PostmanInfo(name)
        self.items = items


class PostmanConfig:
    sort_headers: bool = False
    lower_case_header_names: bool = False

    def __init__(self, conf: str) -> None:
        self.sort_headers = 's' in conf
        self.lower_case_header_names = 'l' in conf


class PostmanEncoder(json.JSONEncoder):
    def default(self, o):
        return o.__dict__


def get_headers(request: http.Request, config: PostmanConfig) -> typing.Sequence[PostmanHeader]:
    headers: typing.Sequence[PostmanHeader] = [
        PostmanHeader(
            k.lower() if config.lower_case_header_names else k, v
        )
        for (k, v) in request.headers.items(multi=True)
    ]
    if config.sort_headers:
        return sorted(headers, key=lambda header: header.key)
    else:
        return headers


def postman(f: flow.Flow, config: PostmanConfig) -> PostmanItem:
    request = cleanup_request(f)
    header = get_headers(request, config)
    url = PostmanUrl(request.url)
    body = PostmanBody(request.get_text(strict=True)) if request.content else None

    postmanReq = PostmanRequest(request.method, header, url, body)
    return PostmanItem(url.pretty(), postmanReq)


class Postman:
    
    @command.command("export.postman")
    def save(
        self, flows: typing.Sequence[flow.Flow], path: mitmproxy.types.Path, config: str
    ) -> None:
        """
        Exports flows to a file as a postman collection.
        """
        collection = PostmanCollection(path, [postman(flow, PostmanConfig(config)) for flow in flows])
        posJ = json.dumps(collection, indent=4, cls=PostmanEncoder)
        try:
            with open(path, "w") as fp:
                fp.write(posJ)
        except OSError as e:
            ctx.log.error(str(e))
