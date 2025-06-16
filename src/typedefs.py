"""select_filtered_request로 return 하는 HTTP 요청 데이터 구조를 정의합니다."""

from typing import List, NotRequired, TypedDict, Optional
from datetime import datetime


class Header(TypedDict):
    """Header는 HTTP 요청의 헤더를 나타냅니다."""

    key: str
    value: str


class QueryParam(TypedDict):
    """QueryParam는 HTTP 요청의 쿼리 파라미터를 나타냅니다."""

    key: str
    value: str
    source: str


class Body(TypedDict):
    """Body는 HTTP 요청의 본문을 나타냅니다."""

    id: int
    request_id: int
    content_type: str
    charset: str
    content_length: int
    content_encoding: str
    body: str


class Meta(TypedDict):
    """Meta는 HTTP 요청의 메타데이터를 나타냅니다."""

    id: int
    is_http: int
    http_version: str
    domain: str
    path: str
    method: str
    timestamp: datetime


class RequestData(TypedDict):
    """RequestData는 HTTP 요청의 전체 데이터를 나타냅니다."""

    meta: Meta
    headers: Optional[List[Header]]
    query_params: Optional[List[QueryParam]]
    body: Optional[Body]
    extra: NotRequired[dict]  # 추가적인 메타데이터를 위한 필드
