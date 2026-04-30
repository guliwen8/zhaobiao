#!/usr/bin/env python3
"""
招标信息监控系统 - 后端服务
依赖安装: pip install -r requirements.txt
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta
from typing import Any, Optional
from urllib.parse import quote, urljoin, urlparse

import requests
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from bs4 import BeautifulSoup, Tag
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse, FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from contextlib import asynccontextmanager
import csv
import io

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

DEFAULT_ALLOWED_ORIGINS = ["null"]
LOCAL_ORIGIN_REGEX = r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$"
CRAWL_TIMEOUT = 20
CRAWL_PROXY = os.getenv("BID_MONITOR_PROXY", "").strip() or None  # 部署到远程服务器时设置代理
CRAWL_VERIFY_SSL = os.getenv("BID_MONITOR_VERIFY_SSL", "").lower() not in {"0", "false", "no"}
USE_ENV_PROXY = os.getenv("BID_MONITOR_USE_ENV_PROXY", "").lower() in {"1", "true", "yes", "on"}
FALLBACK_TITLE_KEYWORDS = ["招标", "采购", "公告", "中标", "挂牌", "竞争性", "谈判"]
PROJECT_STAGES = {"线索", "资格预审", "报名中", "标书编制", "已投标", "澄清答疑", "中标", "未中标", "放弃"}
PROJECT_CLOSED_STAGES = {"中标", "未中标", "放弃"}
TASK_STATUSES = {"待办", "进行中", "已完成", "已取消"}
PRIORITIES = {"高", "中", "低"}
NAVIGATION_TITLES = {
    "首页",
    "上一页",
    "下一页",
    "末页",
    "尾页",
    "更多",
    "更多>>",
    "查看全部",
    "点击查看",
    "详情",
    "详细信息",
    "进入",
    "登录",
    "注册",
    "公告信息",
    "通知公告",
}
DATE_PATTERN = re.compile(
    r"(?P<year>\d{4})[年/\-.](?P<month>\d{1,2})[月/\-.](?P<day>\d{1,2})"
    r"(?:日)?(?:\s+(?P<hour>\d{1,2}):(?P<minute>\d{2})(?::(?P<second>\d{2}))?)?"
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    setup_scheduler()
    if not scheduler.running:
        scheduler.start()
    logger.info("招标监控系统已启动")
    yield
    if scheduler.running:
        scheduler.shutdown(wait=False)

app = FastAPI(title="企业投标管理系统", version="2.0.0", lifespan=lifespan)


@app.get("/")
def serve_index():
    return FileResponse("index.html", media_type="text/html")


allowed_origins_env = os.getenv("BID_MONITOR_ALLOWED_ORIGINS", "")
allowed_origins = [item.strip() for item in allowed_origins_env.split(",") if item.strip()] or DEFAULT_ALLOWED_ORIGINS
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=os.getenv("BID_MONITOR_ALLOWED_ORIGIN_REGEX", LOCAL_ORIGIN_REGEX),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Auth middleware ──
# fmt: off
OPEN_PATHS = frozenset({"/", "/api/health", "/api/auth/register", "/api/auth/login", "/api/auth/logout", "/docs", "/openapi.json"})


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    # 开放路径无需认证
    if path in OPEN_PATHS or path.startswith(("/api/auth/",)):
        return await call_next(request)
    # API 路径需要认证（非 /api/* 如静态文件跳过）
    if path.startswith("/api/"):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse(status_code=401, content={"detail": "请先登录"})
        token = auth[len("Bearer "):]
        user = _get_user_from_token(token)
        if not user:
            return JSONResponse(status_code=401, content={"detail": "登录已过期，请重新登录"})
        request.state.user = user
    return await call_next(request)
# fmt: on


DB_PATH = os.getenv("BID_MONITOR_DB_PATH", "bid_monitor.db")
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Cache-Control": "max-age=0",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}
scheduler = BackgroundScheduler(timezone="Asia/Shanghai")
HTTP_SESSION = requests.Session()
HTTP_SESSION.trust_env = USE_ENV_PROXY
if CRAWL_PROXY:
    HTTP_SESSION.proxies = {"http": CRAWL_PROXY, "https": CRAWL_PROXY}
HTTP_SESSION.verify = CRAWL_VERIFY_SSL

# ── Auth ──
TOKEN_EXPIRE_DAYS = 30
TOKEN_BYTES = 32
PWD_HASH_ITERATIONS = 600_000

# ── Crawl concurrency guard ──
_crawl_lock = threading.Lock()


class BidMonitorError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


@app.exception_handler(BidMonitorError)
def handle_bid_monitor_error(_, exc: BidMonitorError):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.exception_handler(Exception)
def handle_unexpected_exception(_, exc: Exception):
    logger.exception("未处理异常", exc_info=exc)
    return JSONResponse(status_code=500, content={"detail": "系统异常，请稍后重试"})


class SiteCreate(BaseModel):
    name: str
    url: str
    list_selector: Optional[str] = "a"
    title_selector: Optional[str] = ""
    date_selector: Optional[str] = ""
    enabled: Optional[int] = 1
    cron_hour: Optional[int] = 8
    cron_minute: Optional[int] = 0
    crawl_mode: Optional[str] = "auto"
    source_type: Optional[str] = ""


class SiteUpdate(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    list_selector: Optional[str] = None
    title_selector: Optional[str] = None
    date_selector: Optional[str] = None
    enabled: Optional[int] = None
    cron_hour: Optional[int] = None
    cron_minute: Optional[int] = None
    crawl_mode: Optional[str] = None
    source_type: Optional[str] = None


class SitePreviewRequest(BaseModel):
    url: str
    list_selector: Optional[str] = "a"
    title_selector: Optional[str] = ""
    date_selector: Optional[str] = ""


class KeywordCreate(BaseModel):
    word: str


class MarkReadRequest(BaseModel):
    ids: Optional[list[int]] = None
    site_id: Optional[int] = None
    keyword: Optional[str] = None
    is_new: Optional[int] = None
    days: Optional[int] = 0
    date_from: Optional[str] = None
    date_to: Optional[str] = None


class ProjectCreate(BaseModel):
    bid_id: Optional[int] = None
    project_name: str
    client_name: Optional[str] = ""
    bid_no: Optional[str] = ""
    stage: Optional[str] = "线索"
    owner: Optional[str] = ""
    priority: Optional[str] = "中"
    bid_deadline: Optional[str] = ""
    estimated_amount: Optional[float] = 0
    win_probability: Optional[int] = 30
    next_action: Optional[str] = ""
    notes: Optional[str] = ""


class ProjectUpdate(BaseModel):
    bid_id: Optional[int] = None
    project_name: Optional[str] = None
    client_name: Optional[str] = None
    bid_no: Optional[str] = None
    stage: Optional[str] = None
    owner: Optional[str] = None
    priority: Optional[str] = None
    bid_deadline: Optional[str] = None
    estimated_amount: Optional[float] = None
    win_probability: Optional[int] = None
    next_action: Optional[str] = None
    notes: Optional[str] = None


class ProjectFromBidRequest(BaseModel):
    owner: Optional[str] = ""
    priority: Optional[str] = "中"
    bid_deadline: Optional[str] = ""
    notes: Optional[str] = ""


class TaskCreate(BaseModel):
    project_id: int
    title: str
    assignee: Optional[str] = ""
    due_date: Optional[str] = ""
    status: Optional[str] = "待办"
    priority: Optional[str] = "中"
    description: Optional[str] = ""


class TaskUpdate(BaseModel):
    project_id: Optional[int] = None
    title: Optional[str] = None
    assignee: Optional[str] = None
    due_date: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    description: Optional[str] = None


class TemplateCreate(BaseModel):
    title: str
    category: Optional[str] = "通用"
    content: str
    enabled: Optional[int] = 1


class TemplateUpdate(BaseModel):
    title: Optional[str] = None
    category: Optional[str] = None
    content: Optional[str] = None
    enabled: Optional[int] = None


class CompanyProfileUpdate(BaseModel):
    company_name: Optional[str] = ""
    contact_person: Optional[str] = ""
    phone: Optional[str] = ""
    email: Optional[str] = ""
    address: Optional[str] = ""
    qualification: Optional[str] = ""
    core_advantage: Optional[str] = ""
    service_commitment: Optional[str] = ""
    case_studies: Optional[str] = ""


class RegisterRequest(BaseModel):
    username: str
    password: str
    display_name: Optional[str] = ""


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str
    user: dict


class UserInfoResponse(BaseModel):
    id: int
    username: str
    display_name: str
    is_admin: bool


def model_to_dict(model: BaseModel) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db():
    conn = get_conn()
    c = conn.cursor()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            list_selector TEXT DEFAULT 'a',
            title_selector TEXT DEFAULT '',
            date_selector TEXT DEFAULT '',
            enabled INTEGER DEFAULT 1,
            cron_hour INTEGER DEFAULT 8,
            cron_minute INTEGER DEFAULT 0,
            crawl_mode TEXT DEFAULT 'auto',
            source_type TEXT DEFAULT '',
            last_crawl TEXT DEFAULT '',
            last_count INTEGER DEFAULT 0,
            locked INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS bids (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site_id INTEGER NOT NULL,
            site_name TEXT,
            title TEXT NOT NULL,
            url TEXT,
            pub_date TEXT,
            source_type TEXT DEFAULT '',
            crawl_time TEXT DEFAULT (datetime('now','localtime')),
            is_new INTEGER DEFAULT 1,
            UNIQUE(site_id, url)
        );
        CREATE TABLE IF NOT EXISTS keywords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            word TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS crawl_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site_id INTEGER NOT NULL,
            site_name TEXT,
            crawl_time TEXT DEFAULT (datetime('now','localtime')),
            success INTEGER DEFAULT 1,
            new_count INTEGER DEFAULT 0,
            total_count INTEGER DEFAULT 0,
            error_message TEXT DEFAULT '',
            duration_ms INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS bid_projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bid_id INTEGER,
            project_name TEXT NOT NULL,
            client_name TEXT DEFAULT '',
            bid_no TEXT DEFAULT '',
            stage TEXT DEFAULT '线索',
            owner TEXT DEFAULT '',
            priority TEXT DEFAULT '中',
            bid_deadline TEXT DEFAULT '',
            estimated_amount REAL DEFAULT 0,
            win_probability INTEGER DEFAULT 30,
            next_action TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            is_deleted INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now','localtime')),
            updated_at TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS project_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            assignee TEXT DEFAULT '',
            due_date TEXT DEFAULT '',
            status TEXT DEFAULT '待办',
            priority TEXT DEFAULT '中',
            description TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now','localtime')),
            updated_at TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS bid_templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            category TEXT DEFAULT '通用',
            content TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now','localtime')),
            updated_at TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS company_profile (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            company_name TEXT DEFAULT '',
            contact_person TEXT DEFAULT '',
            phone TEXT DEFAULT '',
            email TEXT DEFAULT '',
            address TEXT DEFAULT '',
            qualification TEXT DEFAULT '',
            core_advantage TEXT DEFAULT '',
            service_commitment TEXT DEFAULT '',
            case_studies TEXT DEFAULT '',
            updated_at TEXT DEFAULT (datetime('now','localtime'))
        );
        """
    )

    # ── 迁移：为已有站点表增加锁定列 ──
    try:
        c.execute("ALTER TABLE sites ADD COLUMN locked INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # 列已存在

    # ── 系统配置 ──
    c.execute(
        "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )
    conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('match_mode', 'exact')")
    conn.commit()

    # ── 用户表 ──
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            display_name TEXT DEFAULT '',
            is_admin INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS auth_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
        """
    )

    # ── 数据库索引（提升查询性能）──
    for idx_sql in [
        "CREATE INDEX IF NOT EXISTS idx_bids_crawl_time ON bids(crawl_time DESC)",
        "CREATE INDEX IF NOT EXISTS idx_bids_site_id ON bids(site_id)",
        "CREATE INDEX IF NOT EXISTS idx_bids_is_new ON bids(is_new)",
        "CREATE INDEX IF NOT EXISTS idx_bids_pub_date ON bids(pub_date DESC)",
        "CREATE INDEX IF NOT EXISTS idx_projects_stage ON bid_projects(stage)",
        "CREATE INDEX IF NOT EXISTS idx_projects_deadline ON bid_projects(bid_deadline)",
        "CREATE INDEX IF NOT EXISTS idx_tasks_project ON project_tasks(project_id)",
        "CREATE INDEX IF NOT EXISTS idx_tasks_status ON project_tasks(status)",
        "CREATE INDEX IF NOT EXISTS idx_crawl_logs_site ON crawl_logs(site_id)",
        "CREATE INDEX IF NOT EXISTS idx_crawl_logs_time ON crawl_logs(crawl_time DESC)",
        "CREATE INDEX IF NOT EXISTS idx_auth_tokens_expires ON auth_tokens(expires_at)",
    ]:
        try:
            c.execute(idx_sql)
        except sqlite3.OperationalError:
            pass

    sample_sites = [
        (
            "广东省公共资源交易中心",
            "https://www.gdgpo.gov.cn/queryMoreInfoList.do?channelId=0752f8888169430b8b9acd8b85cfc208",
            ".list-item a, .notice-list a, td a",
            "",
            "",
            1,
            8,
            0,
        ),
        (
            "浙江政府采购网",
            "https://zfcg.czt.zj.gov.cn/topicData/list?topicCode=purchaseAnn",
            ".item-title a, .list a",
            "",
            "",
            1,
            8,
            30,
        ),
        (
            "全国公共资源交易平台",
            "https://deal.mlr.gov.cn/ggjg/index.jhtml",
            ".list-content a, .news-list a",
            "",
            "",
            1,
            9,
            0,
        ),
    ]

    for site in sample_sites:
        exists = conn.execute("SELECT 1 FROM sites WHERE url = ?", (site[1],)).fetchone()
        if not exists:
            c.execute(
                """
                INSERT INTO sites
                    (name, url, list_selector, title_selector, date_selector, enabled, cron_hour, cron_minute)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                site,
            )

    # 迁移：为已有数据库添加 crawl_mode 列
    try:
        conn.execute("ALTER TABLE sites ADD COLUMN crawl_mode TEXT DEFAULT 'auto'")
    except sqlite3.OperationalError:
        pass  # 列已存在
    try:
        conn.execute("ALTER TABLE sites ADD COLUMN enabled INTEGER DEFAULT 1")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE sites ADD COLUMN cron_hour INTEGER DEFAULT 8")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE sites ADD COLUMN cron_minute INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE sites ADD COLUMN last_crawl TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE sites ADD COLUMN last_count INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE bid_projects ADD COLUMN is_deleted INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE sites ADD COLUMN source_type TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE bids ADD COLUMN source_type TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass

    # 已有站点迁移：有真正选择器配置的→manual；无选择器的→auto
    # 注：ALTER TABLE ADD COLUMN DEFAULT 会导致已有行直接获得 'auto'，故这里不能只靠 IS NULL 判断
    conn.execute(
        "UPDATE sites SET crawl_mode = 'manual' "
        "WHERE list_selector NOT IN ('a', '') AND list_selector IS NOT NULL "
        "AND (crawl_mode IS NULL OR crawl_mode = 'auto')"
    )

    normalize_existing_keywords(conn)
    seed_enterprise_defaults(conn)
    conn.commit()
    conn.close()


def normalize_whitespace(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "")).strip()


def normalize_text_block(value: Any) -> str:
    lines = []
    for line in str(value or "").splitlines():
        lines.append(re.sub(r"[ \t]+", " ", line).strip())
    return "\n".join(lines).strip()


def split_keywords(raw_value: Optional[str]) -> list[str]:
    parts = re.split(r"[，,、；;\n]+", raw_value or "")
    words: list[str] = []
    seen: set[str] = set()
    for part in parts:
        word = normalize_whitespace(part)
        if word and word not in seen:
            seen.add(word)
            words.append(word)
    return words


def normalize_existing_keywords(conn: sqlite3.Connection):
    rows = conn.execute("SELECT word FROM keywords ORDER BY id").fetchall()
    normalized: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for word in split_keywords(row["word"]):
            if word not in seen:
                seen.add(word)
                normalized.append(word)
    if [row["word"] for row in rows] == normalized:
        return
    conn.execute("DELETE FROM keywords")
    for word in normalized:
        conn.execute("INSERT OR IGNORE INTO keywords (word) VALUES (?)", (word,))


def seed_enterprise_defaults(conn: sqlite3.Connection):
    conn.execute(
        """
        INSERT OR IGNORE INTO company_profile
            (id, company_name, contact_person, phone, email, address, qualification, core_advantage, service_commitment, case_studies)
        VALUES (1, '', '', '', '', '', '', '', '', '')
        """
    )
    template_count = conn.execute("SELECT COUNT(*) FROM bid_templates").fetchone()[0]
    if template_count:
        return
    templates = [
        (
            "商务响应要点",
            "商务",
            "围绕招标文件的资格条件、付款方式、交付周期、验收方式和服务范围逐项响应，明确我方满足条件及可提供的证明材料。",
            1,
        ),
        (
            "技术方案结构",
            "技术",
            "建议按项目理解、总体架构、实施路径、质量控制、安全保障、进度计划、风险应对七个部分展开，突出与招标需求的逐条对应关系。",
            1,
        ),
        (
            "售后服务承诺",
            "服务",
            "提供项目验收后的持续服务机制，包括响应时限、现场支持、定期巡检、培训交付、问题闭环和文档归档。",
            1,
        ),
    ]
    conn.executemany(
        "INSERT INTO bid_templates (title, category, content, enabled) VALUES (?, ?, ?, ?)",
        templates,
    )


def validate_url(url: str) -> str:
    parsed = urlparse((url or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise BidMonitorError(400, "URL 必须是有效的 http/https 地址")
    return url.strip()


def validate_cron(hour: Any, minute: Any) -> tuple[int, int]:
    try:
        cron_hour = int(hour)
        cron_minute = int(minute)
    except (TypeError, ValueError) as exc:
        raise BidMonitorError(400, "抓取时间必须是有效数字") from exc
    if not 0 <= cron_hour <= 23:
        raise BidMonitorError(400, "小时必须在 0-23 之间")
    if not 0 <= cron_minute <= 59:
        raise BidMonitorError(400, "分钟必须在 0-59 之间")
    return cron_hour, cron_minute


def validate_site_payload(payload: dict[str, Any], partial: bool = False) -> dict[str, Any]:
    data = {key: value for key, value in payload.items() if value is not None}
    normalized: dict[str, Any] = {}

    if not partial or "name" in data:
        name = normalize_whitespace(str(data.get("name", "")))
        if not name:
            raise BidMonitorError(400, "网站名称不能为空")
        normalized["name"] = name

    if not partial or "url" in data:
        normalized["url"] = validate_url(str(data.get("url", "")))

    for field in ("list_selector", "title_selector", "date_selector"):
        if field in data or not partial:
            normalized[field] = normalize_whitespace(str(data.get(field, "")))

    if "enabled" in data or not partial:
        try:
            normalized["enabled"] = 1 if int(data.get("enabled", 1)) else 0
        except (TypeError, ValueError) as exc:
            raise BidMonitorError(400, "启用状态必须为 0 或 1") from exc

    if any(field in data for field in ("cron_hour", "cron_minute")) or not partial:
        hour_value = data.get("cron_hour", 8 if not partial else None)
        minute_value = data.get("cron_minute", 0 if not partial else None)
        if hour_value is None or minute_value is None:
            raise BidMonitorError(400, "抓取时间不能为空")
        cron_hour, cron_minute = validate_cron(hour_value, minute_value)
        normalized["cron_hour"] = cron_hour
        normalized["cron_minute"] = cron_minute

    if "crawl_mode" in data or not partial:
        mode = normalize_whitespace(str(data.get("crawl_mode", "auto")))
        if mode not in ("auto", "manual"):
            raise BidMonitorError(400, "抓取模式必须是 'auto' 或 'manual'")
        normalized["crawl_mode"] = mode

    if "source_type" in data or not partial:
        normalized["source_type"] = normalize_whitespace(str(data.get("source_type", "")))

    return normalized


def validate_pagination(page: int, page_size: int) -> tuple[int, int]:
    if page < 1:
        raise HTTPException(400, "page 必须大于 0")
    if page_size < 1 or page_size > 100:
        raise HTTPException(400, "page_size 必须在 1-100 之间")
    return page, page_size


def validate_choice(value: Any, allowed: set[str], default: str, field_name: str) -> str:
    text = normalize_whitespace(str(value or default))
    if text not in allowed:
        raise BidMonitorError(400, f"{field_name} 必须是: {'、'.join(sorted(allowed))}")
    return text


def validate_date_field(value: Any, field_name: str) -> str:
    text = normalize_whitespace(str(value or ""))
    if not text:
        return ""
    try:
        datetime.strptime(text, "%Y-%m-%d")
    except ValueError as exc:
        raise BidMonitorError(400, f"{field_name} 必须是 YYYY-MM-DD 格式") from exc
    return text


def validate_probability(value: Any) -> int:
    try:
        probability = int(value if value is not None else 0)
    except (TypeError, ValueError) as exc:
        raise BidMonitorError(400, "中标概率必须是 0-100 的整数") from exc
    if not 0 <= probability <= 100:
        raise BidMonitorError(400, "中标概率必须在 0-100 之间")
    return probability


def validate_amount(value: Any) -> float:
    if value in (None, ""):
        return 0
    try:
        amount = float(value)
    except (TypeError, ValueError) as exc:
        raise BidMonitorError(400, "预算金额必须是有效数字") from exc
    if amount < 0:
        raise BidMonitorError(400, "预算金额不能为负数")
    return amount


def validate_enabled(value: Any) -> int:
    try:
        return 1 if int(value if value is not None else 1) else 0
    except (TypeError, ValueError) as exc:
        raise BidMonitorError(400, "启用状态必须为 0 或 1") from exc


# ──────────────────────────────────────────────
# 用户认证
# ──────────────────────────────────────────────
_auth_scheme = HTTPBearer(auto_error=False)


def _hash_password(password: str) -> tuple[str, str]:
    salt = secrets.token_hex(32)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), PWD_HASH_ITERATIONS).hex()
    return salt, pwd_hash


def _verify_password(password: str, salt: str, stored_hash: str) -> bool:
    computed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), PWD_HASH_ITERATIONS).hex()
    return hmac.compare_digest(computed, stored_hash)


def _create_token(user_id: int) -> str:
    token = secrets.token_hex(TOKEN_BYTES)
    expires = (datetime.now() + timedelta(days=TOKEN_EXPIRE_DAYS)).isoformat()
    conn = get_conn()
    conn.execute(
        "INSERT INTO auth_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
        (user_id, token, expires),
    )
    conn.commit()
    conn.close()
    return token


def _get_user_from_token(token: str) -> Optional[dict[str, Any]]:
    conn = get_conn()
    row = conn.execute(
        """
        SELECT u.* FROM users u
        JOIN auth_tokens t ON t.user_id = u.id
        WHERE t.token = ? AND t.expires_at > datetime('now', 'localtime')
        """,
        (token,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


async def optional_auth(credentials: Optional[HTTPAuthorizationCredentials] = Depends(_auth_scheme)):
    if credentials is None:
        return None
    return _get_user_from_token(credentials.credentials)


async def require_auth(user: Optional[dict] = Depends(optional_auth)):
    if user is None:
        raise HTTPException(status_code=401, detail="请先登录")
    return user


def parse_date_string(date_value: Optional[str]) -> Optional[str]:
    if not date_value:
        return None
    normalized = normalize_whitespace(date_value)
    match = DATE_PATTERN.search(normalized)
    if not match:
        return None
    year = int(match.group("year"))
    month = int(match.group("month"))
    day = int(match.group("day"))
    hour = int(match.group("hour") or 0)
    minute = int(match.group("minute") or 0)
    second = int(match.group("second") or 0)
    if match.group("hour") is None:
        return f"{year:04d}-{month:02d}-{day:02d}"
    return f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}"


def extract_date_value(node: Tag, selector: str) -> Optional[str]:
    candidates: list[str] = []
    if selector:
        selected = node.select_one(selector)
        if selected:
            attr_value = selected.get("datetime") or selected.get("content") or ""
            if attr_value:
                candidates.append(attr_value)
            candidates.append(selected.get_text(" ", strip=True))
    candidates.append(node.get_text(" ", strip=True))
    if isinstance(node.parent, Tag):
        candidates.append(node.parent.get_text(" ", strip=True))
    for candidate in candidates:
        parsed = parse_date_string(candidate)
        if parsed:
            return parsed
    return None


def select_title_source(node: Tag, title_selector: str) -> Tag:
    if title_selector:
        selected = node.select_one(title_selector)
        if selected:
            return selected
    if node.name == "a":
        return node
    return node.find("a", href=True) or node


def resolve_link(source: Tag, fallback_node: Tag, base_url: str) -> Optional[str]:
    href = ""
    if source and source.get("href"):
        href = source.get("href", "").strip()
    elif fallback_node.name == "a" and fallback_node.get("href"):
        href = fallback_node.get("href", "").strip()
    elif fallback_node.find("a", href=True):
        href = fallback_node.find("a", href=True).get("href", "").strip()
    if not href:
        return None
    if href.startswith(("#", "javascript:", "mailto:", "tel:")):
        return None
    full_url = urljoin(base_url, href)
    parsed = urlparse(full_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return full_url


def should_skip_title(title: str) -> bool:
    normalized = normalize_whitespace(title)
    if len(normalized) < 4:
        return True
    if normalized in NAVIGATION_TITLES:
        return True
    if normalized.startswith(("上一页", "下一页", "返回")):
        return True
    return False


def build_candidate_entry(node: Tag, site: dict[str, Any]) -> Optional[dict[str, Optional[str]]]:
    source = select_title_source(node, site.get("title_selector", ""))
    title = normalize_whitespace(source.get_text(" ", strip=True))
    if not title:
        title = normalize_whitespace(node.get_text(" ", strip=True))
    if should_skip_title(title):
        return None

    full_url = resolve_link(source, node, site["url"])
    if not full_url:
        return None

    return {
        "title": title,
        "url": full_url,
        "pub_date": extract_date_value(node, site.get("date_selector", "")),
    }


# ──────────────────────────────────────────────
# 智能自动检测引擎 — 无需手动配置 CSS 选择器
# ──────────────────────────────────────────────
AUTO_CONTAINER_PRIORITY = ['ul', 'ol', 'table', 'tbody']
AUTO_CHILD_MAP = {'ul': 'li', 'ol': 'li', 'table': 'tr', 'tbody': 'tr'}
DATE_CLASS_KEYWORDS = ['date', 'time', 'pub', 'publish', 'calendar', 'riqi', 'sj', 'fbrq', 'fabu']

def _is_nav_link(text: str) -> bool:
    """宽松导航链接检测"""
    t = text.strip().lower()
    if len(t) < 4:
        return True
    if t in {x.lower() for x in NAVIGATION_TITLES}:
        return True
    if any(t.startswith(p) for p in ('上一页', '下一页', '返回', '首页', '尾页', '末页', '广告')):
        return True
    # 常见非公告链接
    non_bid_keywords = ['广告', '推广', '友情链接', '问卷调查']
    if any(kw in t for kw in non_bid_keywords):
        return True
    return False

def _auto_score_child(child: Tag) -> int:
    """对单个列表项候选元素打分"""
    links = child.find_all('a', href=True)
    if not links:
        return 0

    score = 0
    best_link_score = 0
    for link in links:
        text = link.get_text(' ', strip=True)
        href = link.get('href', '')
        if len(text) < 4 or href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
            continue
        if _is_nav_link(text):
            continue

        ls = 2  # base score for valid link
        if any(kw in text for kw in FALLBACK_TITLE_KEYWORDS):
            ls += 6
        if len(text) >= 10:
            ls += 3
        if len(text) >= 20:
            ls += 2
        if len(href) > 20:
            ls += 2
        best_link_score = max(best_link_score, ls)

    score += best_link_score
    if best_link_score == 0:
        return 0

    # Bonus for date-like content
    child_text = child.get_text(' ', strip=True)
    if DATE_PATTERN.search(child_text):
        score += 4
    if child.find('time'):
        score += 5
    for tag in child.find_all(True):
        cls = ' '.join(tag.get('class', []))
        if any(dw in cls.lower() for dw in DATE_CLASS_KEYWORDS):
            score += 3
            break

    return score

def _auto_find_best_container(soup: BeautifulSoup) -> tuple[Optional[Tag], list[Tag]]:
    """自动寻找最可能是公告列表的容器，返回 (container, children)"""
    best_container = None
    best_children: list[Tag] = []
    best_score = -1

    def _evaluate(container_el: Tag, children: list[Tag], tag_hint: str = ''):
        nonlocal best_container, best_children, best_score
        if len(children) < 3:
            return
        total_score = 0
        good_count = 0
        for ch in children[:30]:
            s = _auto_score_child(ch)
            total_score += s
            if s > 0:
                good_count += 1
        # 惩罚低密度
        if good_count < 3:
            total_score = max(0, total_score - 40)
        # 奖励高密度
        density = good_count / max(len(children), 1)
        total_score = int(total_score * (0.5 + density * 0.5))
        if total_score > best_score:
            best_score = total_score
            best_container = container_el
            best_children = children

    # 策略1：常见列表标签
    for tag_name in AUTO_CONTAINER_PRIORITY:
        for container in soup.find_all(tag_name):
            children = [c for c in container.children if isinstance(c, Tag) and c.name not in ('script', 'style', 'thead', 'tfoot')]
            _evaluate(container, children, tag_name)

    # 策略2：重复 div 兄弟 — 找有 3+ 个直接子 div 的父容器
    if best_score < 60:
        for parent in soup.find_all('div'):
            children = [c for c in parent.children if isinstance(c, Tag) and c.name == 'div' and c.get('id') != c.parent.get('id')]
            if len(children) >= 3:
                _evaluate(parent, children)

    # 策略3：<dl><dt> 定义列表
    if best_score < 40:
        for dl in soup.find_all('dl'):
            children = [c for c in dl.children if isinstance(c, Tag) and c.name in ('dt', 'dd')]
            if len(children) >= 3:
                _evaluate(dl, children)

    return best_container, best_children

def _auto_find_title_link(item: Tag) -> Optional[Tag]:
    """在列表项中找到最可能是标题的链接"""
    links = item.find_all('a', href=True)
    if not links:
        return None
    best = None
    best_score = -1
    MIN_SCORE = 4  # 低于此分数的视为导航/广告链接
    for link in links:
        text = link.get_text(' ', strip=True)
        href = link.get('href', '')
        if len(text) < 4 or href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
            continue
        score = 0
        if any(kw in text for kw in FALLBACK_TITLE_KEYWORDS):
            score += 10
        if len(text) >= 10:
            score += 5
        if len(text) >= 20:
            score += 3
        if href.startswith('/') or href.startswith('http'):
            score += 2
        if not _is_nav_link(text):
            score += 6
        if len(href) > 30:
            score += 3
        if score > best_score:
            best_score = score
            best = link
    if best and best_score < MIN_SCORE:
        return None
    return best

def _auto_find_date(item: Tag) -> Optional[str]:
    """在列表项中用多策略提取发布日期"""
    # 策略1: <time> 标签
    time_tag = item.find('time')
    if time_tag:
        for attr in ('datetime', 'content'):
            val = time_tag.get(attr, '')
            r = parse_date_string(val)
            if r:
                return r
        r = parse_date_string(time_tag.get_text(' ', strip=True))
        if r:
            return r

    # 策略2: 含有日期关键词 class 的标签
    for kw in DATE_CLASS_KEYWORDS:
        for el in item.find_all(class_=lambda c: c and kw in c.lower() if c else False):
            for attr in ('datetime', 'content', 'data-date'):
                val = el.get(attr, '')
                r = parse_date_string(val)
                if r:
                    return r
            r = parse_date_string(el.get_text(' ', strip=True))
            if r:
                return r

    # 策略3: 常用标签中的文本
    for tag_name in ('span', 'td', 'div', 'p', 'small', 'em'):
        for el in item.find_all(tag_name):
            text = el.get_text(' ', strip=True)
            if len(text) < 6 or len(text) > 40:
                continue
            r = parse_date_string(text)
            if r:
                return r

    # 策略4: 在整个 item 文本中搜
    r = parse_date_string(item.get_text(' ', strip=True))
    if r:
        return r

    return None

def auto_collect_entries(soup: BeautifulSoup, base_url: str, limit: int = 50) -> tuple[list[dict[str, Optional[str]]], int]:
    """全自动采集 — 不依赖任何 CSS 选择器配置"""
    container, children = _auto_find_best_container(soup)
    if not container or not children:
        logger.info("auto-detect: 未找到合适的列表容器，回退到关键词匹配")
        return _fallback_keyword_collect(soup, base_url, limit)

    logger.info("auto-detect: 找到候选容器，子元素 %d 个", len(children))

    entries: list[dict[str, Optional[str]]] = []
    seen_urls: set[str] = set()
    raw_count = 0

    for child in children:
        link = _auto_find_title_link(child)
        if not link:
            continue

        raw_count += 1
        title = normalize_whitespace(link.get_text(' ', strip=True))
        if should_skip_title(title):
            continue

        href = link.get('href', '').strip()
        full_url = urljoin(base_url, href)
        parsed = urlparse(full_url)
        if parsed.scheme not in {'http', 'https'} or not parsed.netloc:
            continue
        if full_url in seen_urls:
            continue
        seen_urls.add(full_url)

        pub_date = _auto_find_date(child)

        entries.append({
            'title': title,
            'url': full_url,
            'pub_date': pub_date,
        })
        if len(entries) >= limit:
            break

    return entries, raw_count

def _fallback_keyword_collect(soup: BeautifulSoup, base_url: str, limit: int) -> tuple[list[dict[str, Optional[str]]], int]:
    """回退策略：在全页面中找含招标关键词的链接"""
    entries: list[dict[str, Optional[str]]] = []
    seen_urls: set[str] = set()
    total = 0
    for anchor in soup.find_all('a', href=True):
        title = normalize_whitespace(anchor.get_text(' ', strip=True))
        if len(title) < 4 or should_skip_title(title):
            continue
        if not any(kw in title for kw in FALLBACK_TITLE_KEYWORDS):
            continue
        total += 1
        href = anchor.get('href', '').strip()
        full_url = urljoin(base_url, href)
        parsed = urlparse(full_url)
        if parsed.scheme not in {'http', 'https'} or not parsed.netloc:
            continue
        if full_url in seen_urls:
            continue
        seen_urls.add(full_url)
        entries.append({'title': title, 'url': full_url, 'pub_date': None})
        if len(entries) >= limit:
            break
    return entries, total

def auto_analyze_site(url: str) -> dict[str, Any]:
    """分析网站结构，返回建议的选择器和预览条目"""
    soup = fetch_soup(url)
    container, children = _auto_find_best_container(soup)
    if not container or not children:
        return {'success': False, 'message': '无法自动识别公告列表结构，请尝试手动配置选择器'}

    # 生成建议的 list_selector
    suggested_list = _build_suggested_selector(container, children)

    # 从 children 中分析 title_selector 和 date_selector
    suggested_title = ''
    suggested_date = ''
    if children:
        first = children[0]
        link = _auto_find_title_link(first)
        if link:
            suggested_title = _build_relative_selector(first, link)
        date_el = _auto_find_date_element(first)
        if date_el:
            suggested_date = _build_relative_selector(first, date_el)

    # 取 5 条预览
    samples, raw_count = auto_collect_entries(soup, url, limit=5)

    return {
        'success': True,
        'suggested_selectors': {
            'list_selector': suggested_list,
            'title_selector': suggested_title,
            'date_selector': suggested_date,
        },
        'matched_count': raw_count,
        'preview_count': len(samples),
        'samples': samples,
    }

def _build_suggested_selector(container: Tag, children: list[Tag]) -> str:
    """为容器元素生成 CSS 选择器"""
    css_classes = ' '.join(container.get('class', []))
    tag_name = container.name
    tag_id = container.get('id', '')
    if tag_id:
        return f'{tag_name}#{tag_id} > {children[0].name}' if children else f'{tag_name}#{tag_id}'
    if css_classes and not any(c.startswith('col-') for c in css_classes.split()):
        class_sel = '.'.join(css_classes.split())
        child_name = children[0].name if children else '*'
        return f'{tag_name}.{class_sel} > {child_name}'
    child_name = children[0].name if children else '*'
    return f'{tag_name} > {child_name}'

def _build_relative_selector(parent: Tag, target: Tag) -> str:
    """在父元素内生成相对于 target 的简单 CSS 选择器"""
    tag = target.name
    css_class = ' '.join(target.get('class', []))
    if css_class:
        return f'{tag}.{css_class.split()[0]}'
    # 用 nth-child
    for i, child in enumerate(parent.find_all(tag, recursive=False) or [c for c in parent.children if isinstance(c, Tag) and c.name == tag], 1):
        if child is target:
            return f'{tag}:nth-child({i})'
    return tag

def _auto_find_date_element(item: Tag) -> Optional[Tag]:
    """返回列表项中最可能是日期的元素（供分析用）"""
    # <time> 优先
    t = item.find('time')
    if t:
        return t
    # 含日期关键词 class
    for kw in DATE_CLASS_KEYWORDS:
        for el in item.find_all(class_=lambda c: c and kw in c.lower() if c else False):
            text = el.get_text(' ', strip=True)
            if DATE_PATTERN.search(text):
                return el
    # 含日期文本的短标签
    for tag_name in ('span', 'td', 'div', 'p', 'small'):
        for el in item.find_all(tag_name):
            text = el.get_text(' ', strip=True)
            if 6 <= len(text) <= 40 and DATE_PATTERN.search(text):
                return el
    return None

# ──────────────────────────────────────────────
# 原有手动选择器逻辑（增强 fallback）
# ──────────────────────────────────────────────

def get_candidate_items(soup: BeautifulSoup, selector: str, site: Optional[dict[str, Any]] = None) -> list[Tag]:
    if selector and selector != 'a':
        try:
            items = list(soup.select(selector))
            if items:
                return items
        except Exception as exc:
            logger.error("CSS 选择器解析失败: %s", selector, exc_info=exc)
            raise BidMonitorError(400, f"CSS 选择器无效: {selector}") from exc
    # 手动选择器为空/无效 → 使用自动检测
    if site:
        logger.info("选择器未配置或未命中，尝试自动检测: %s", site.get('name', ''))
    items = []
    for anchor in soup.find_all("a", href=True):
        title = normalize_whitespace(anchor.get_text(" ", strip=True))
        if len(title) >= 4 and not should_skip_title(title) and any(keyword in title for keyword in FALLBACK_TITLE_KEYWORDS):
            items.append(anchor)
    return items


def _headers_for(url: str) -> dict:
    """为特定 URL 构造请求头，带 Referer 模拟来源"""
    h = dict(HEADERS)
    parsed = urlparse(url)
    h["Referer"] = f"{parsed.scheme}://{parsed.netloc}/"
    return h


def fetch_soup(url: str) -> BeautifulSoup:
    try:
        response = HTTP_SESSION.get(url, headers=_headers_for(url), timeout=CRAWL_TIMEOUT)
        if response.status_code != 200:
            raise BidMonitorError(502, f"网站返回 {response.status_code}，可能被反爬或需代理访问。提示: 设置 BID_MONITOR_PROXY 环境变量")
        response.raise_for_status()
        response.encoding = response.apparent_encoding
    except requests.ConnectionError as exc:
        logger.error("无法连接: %s", url, exc_info=exc)
        raise BidMonitorError(502, f"网络不通，无法访问目标网站。远程部署时可能需要设置代理 BID_MONITOR_PROXY") from exc
    except requests.Timeout as exc:
        logger.error("请求超时: %s", url, exc_info=exc)
        raise BidMonitorError(502, f"请求超时 ({CRAWL_TIMEOUT}s)，网站响应过慢或网络不通") from exc
    except requests.RequestException as exc:
        logger.error("请求失败: %s", url, exc_info=exc)
        status = getattr(exc.response, "status_code", "?") if hasattr(exc, "response") and exc.response is not None else "?"
        if str(status) in ("403", "429", "503"):
            raise BidMonitorError(502, f"网站拒绝访问(HTTP {status})，触发了反爬机制。建议: 1) 设置代理 BID_MONITOR_PROXY 2) 降低抓取频率") from exc
        raise BidMonitorError(502, f"抓取失败(HTTP {status}): {str(exc)[:200]}") from exc
    try:
        return BeautifulSoup(response.text, "lxml")
    except Exception as exc:
        logger.error("页面解析失败: %s", url, exc_info=exc)
        raise BidMonitorError(500, "页面解析失败，请检查目标网站内容或选择器配置") from exc


def collect_site_entries(site: dict[str, Any], limit: int = 50) -> tuple[list[dict[str, Optional[str]]], int]:
    soup = fetch_soup(site["url"])
    crawl_mode = site.get("crawl_mode", "auto")

    if crawl_mode == "auto":
        # 自动模式：直接用智能检测
        logger.info("自动模式抓取: %s", site["name"])
        entries, raw_count = auto_collect_entries(soup, site["url"], limit=limit)
        if entries:
            return entries, raw_count
        # 自动检测失败 → 降级到手动选择器 + 关键词回退
        logger.info("自动检测无结果，降级到手动选择器: %s", site["name"])

    # 手动模式或自动降级：使用配置的选择器
    selector = site.get("list_selector") or "a"
    raw_items = get_candidate_items(soup, selector, site=site)

    entries: list[dict[str, Optional[str]]] = []
    seen_urls: set[str] = set()
    for item in raw_items:
        entry = build_candidate_entry(item, site)
        if not entry:
            continue
        if entry["url"] in seen_urls:
            continue
        seen_urls.add(entry["url"])
        entries.append(entry)
        if len(entries) >= limit:
            break

    # 如果手动选择器也没结果，尝试自动兜底
    if not entries and crawl_mode != "auto":
        logger.info("手动选择器无结果，自动兜底: %s", site["name"])
        entries, raw_count = auto_collect_entries(soup, site["url"], limit=limit)
        return entries, raw_count

    return entries, len(raw_items)


def update_site_crawl_status(site_id: int, new_count: int):
    conn = get_conn()
    conn.execute(
        "UPDATE sites SET last_crawl = ?, last_count = ? WHERE id = ?",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), new_count, site_id),
    )
    conn.commit()
    conn.close()


def crawl_site(site: dict[str, Any], raise_on_error: bool = False, retry_times: int = 3) -> dict[str, Any]:
    """
    抓取单个站点，全量入库（关键词过滤在展示层完成）。
    返回 dict: {success, new_count, total_count, error_message, duration_ms, filtered_count}
    """
    start_time = datetime.now()
    last_error = ""

    for attempt in range(1, retry_times + 1):
        logger.info("开始抓取 [%s] 第 %d 次尝试: %s - %s", site["name"], attempt, site["name"], site["url"])
        try:
            entries, total_raw = collect_site_entries(site, limit=50)
            conn = get_conn()
            cursor = conn.cursor()
            new_count = 0
            try:
                for entry in entries:
                    title = entry.get("title", "") or ""
                    source_type = site.get("source_type", "") or ""
                    cursor.execute(
                        """
                        INSERT OR IGNORE INTO bids (site_id, site_name, title, url, pub_date, source_type)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (site["id"], site["name"], title, entry["url"], entry["pub_date"], source_type),
                    )
                    if cursor.rowcount > 0:
                        new_count += 1
                conn.execute(
                    "UPDATE sites SET last_crawl = ?, last_count = ? WHERE id = ?",
                    (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), new_count, site["id"]),
                )
                conn.commit()
            except sqlite3.Error as exc:
                conn.rollback()
                logger.error("保存抓取结果失败: site=%s", site["name"], exc_info=exc)
                raise BidMonitorError(500, "保存抓取结果失败，请检查数据库状态") from exc
            finally:
                conn.close()

            duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            _log_crawl(site, success=True, new_count=new_count, total_count=total_raw, error_message="", duration_ms=duration_ms)
            logger.info("完成抓取 %s：页面 %d 条，新增 %d 条，耗时 %dms", site["name"], total_raw, new_count, duration_ms)
            return {"success": True, "new_count": new_count, "total_count": total_raw, "error_message": "", "duration_ms": duration_ms, "filtered_count": 0}

        except BidMonitorError as exc:
            last_error = exc.detail
            logger.warning("抓取站点 %s 第 %d 次失败: %s", site["name"], attempt, exc.detail)
            if attempt < retry_times:
                import time
                time.sleep(2 ** attempt)  # 指数退避：2s, 4s
            if raise_on_error and attempt == retry_times:
                duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
                _log_crawl(site, success=False, new_count=0, total_count=0, error_message=last_error, duration_ms=duration_ms)
                raise
        except Exception as exc:
            last_error = str(exc)
            logger.exception("抓取站点 %s 发生未预期异常", site["name"])
            if raise_on_error and attempt == retry_times:
                duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
                _log_crawl(site, success=False, new_count=0, total_count=0, error_message=last_error, duration_ms=duration_ms)
                raise BidMonitorError(502, f"抓取异常: {last_error}") from exc

    duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
    _log_crawl(site, success=False, new_count=0, total_count=0, error_message=last_error, duration_ms=duration_ms)
    update_site_crawl_status(site["id"], 0)
    return {"success": False, "new_count": 0, "total_count": 0, "error_message": last_error, "duration_ms": duration_ms}


def _log_crawl(site: dict[str, Any], success: bool, new_count: int, total_count: int, error_message: str, duration_ms: int):
    """写入抓取日志到 crawl_logs 表"""
    try:
        conn = get_conn()
        conn.execute(
            """
            INSERT INTO crawl_logs (site_id, site_name, success, new_count, total_count, error_message, duration_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (site["id"], site["name"], 1 if success else 0, new_count, total_count, error_message, duration_ms),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass  # 日志失败不影响主流程


def crawl_all_enabled():
    global _crawl_lock
    if not _crawl_lock.acquire(blocking=False):
        logger.warning("已有抓取任务进行中，跳过本次请求")
        return
    try:
        conn = get_conn()
        sites = [dict(row) for row in conn.execute("SELECT * FROM sites WHERE enabled = 1 ORDER BY id").fetchall()]
        conn.close()
        for site in sites:
            crawl_site(site)
    except Exception:
        logger.exception("全量抓取出错")
    finally:
        _crawl_lock.release()


def setup_scheduler():
    scheduler.remove_all_jobs()
    conn = get_conn()
    sites = [dict(row) for row in conn.execute("SELECT * FROM sites WHERE enabled = 1 ORDER BY id").fetchall()]
    conn.close()
    for site in sites:
        snapshot = site.copy()
        scheduler.add_job(
            lambda site_snapshot=snapshot: crawl_site(site_snapshot),
            CronTrigger(hour=snapshot["cron_hour"], minute=snapshot["cron_minute"]),
            id=f"site_{snapshot['id']}",
            name=snapshot["name"],
            replace_existing=True,
        )
    logger.info("已配置 %s 个定时任务", len(sites))


def build_bid_conditions(
    site_id: Optional[int] = None,
    keyword: Optional[str] = None,
    is_new: Optional[int] = None,
    days: Optional[int] = 0,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    ids: Optional[list[int]] = None,
    source_type: Optional[str] = None,
) -> tuple[str, list[Any]]:
    where: list[str] = []
    params: list[Any] = []

    if ids:
        placeholders = ", ".join(["?"] * len(ids))
        where.append(f"id IN ({placeholders})")
        params.extend(ids)

    if site_id:
        where.append("site_id = ?")
        params.append(site_id)

    if source_type:
        where.append("source_type = ?")
        params.append(source_type)

    if is_new is not None:
        where.append("is_new = ?")
        params.append(1 if int(is_new) else 0)

    keywords = split_keywords(keyword)
    if keywords:
        clauses = " OR ".join(["title LIKE ?" for _ in keywords])
        where.append(f"({clauses})")
        params.extend([f"%{word}%" for word in keywords])

    if date_from:
        where.append("crawl_time >= ?")
        params.append(f"{date_from} 00:00:00")
    if date_to:
        where.append("crawl_time <= ?")
        params.append(f"{date_to} 23:59:59")
    elif days and int(days) > 0:
        cutoff = (datetime.now() - timedelta(days=int(days))).strftime("%Y-%m-%d 00:00:00")
        where.append("crawl_time >= ?")
        params.append(cutoff)

    where_sql = f"WHERE {' AND '.join(where)}" if where else ""
    return where_sql, params


def ensure_site_exists(site_id: int) -> dict[str, Any]:
    conn = get_conn()
    row = conn.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "网站不存在")
    return dict(row)


def ensure_bid_exists(bid_id: int) -> dict[str, Any]:
    conn = get_conn()
    row = conn.execute("SELECT * FROM bids WHERE id = ?", (bid_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "公告不存在")
    return dict(row)


def ensure_project_exists(project_id: int) -> dict[str, Any]:
    conn = get_conn()
    row = conn.execute("SELECT * FROM bid_projects WHERE id = ? AND is_deleted = 0", (project_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "投标项目不存在")
    return dict(row)


def ensure_task_exists(task_id: int) -> dict[str, Any]:
    conn = get_conn()
    row = conn.execute("SELECT * FROM project_tasks WHERE id = ?", (task_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "任务不存在")
    return dict(row)


def ensure_template_exists(template_id: int) -> dict[str, Any]:
    conn = get_conn()
    row = conn.execute("SELECT * FROM bid_templates WHERE id = ?", (template_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "模板不存在")
    return dict(row)


def validate_project_payload(payload: dict[str, Any], partial: bool = False) -> dict[str, Any]:
    data = {key: value for key, value in payload.items() if value is not None}
    normalized: dict[str, Any] = {}

    if "bid_id" in data:
        bid_id = int(data["bid_id"]) if data["bid_id"] else None
        if bid_id:
            ensure_bid_exists(bid_id)
        normalized["bid_id"] = bid_id

    if not partial or "project_name" in data:
        name = normalize_whitespace(str(data.get("project_name", "")))
        if not name:
            raise BidMonitorError(400, "项目名称不能为空")
        normalized["project_name"] = name

    for field in ("client_name", "bid_no", "owner", "next_action"):
        if field in data or not partial:
            normalized[field] = normalize_whitespace(str(data.get(field, "")))
    if "notes" in data or not partial:
        normalized["notes"] = normalize_text_block(data.get("notes", ""))

    if "stage" in data or not partial:
        normalized["stage"] = validate_choice(data.get("stage"), PROJECT_STAGES, "线索", "项目阶段")
    if "priority" in data or not partial:
        normalized["priority"] = validate_choice(data.get("priority"), PRIORITIES, "中", "优先级")
    if "bid_deadline" in data or not partial:
        normalized["bid_deadline"] = validate_date_field(data.get("bid_deadline"), "投标截止日期")
    if "estimated_amount" in data or not partial:
        normalized["estimated_amount"] = validate_amount(data.get("estimated_amount", 0))
    if "win_probability" in data or not partial:
        normalized["win_probability"] = validate_probability(data.get("win_probability", 30))

    return normalized


def validate_task_payload(payload: dict[str, Any], partial: bool = False) -> dict[str, Any]:
    data = {key: value for key, value in payload.items() if value is not None}
    normalized: dict[str, Any] = {}

    if "project_id" in data or not partial:
        try:
            project_id = int(data.get("project_id", 0))
        except (TypeError, ValueError) as exc:
            raise BidMonitorError(400, "项目 ID 必须是有效数字") from exc
        ensure_project_exists(project_id)
        normalized["project_id"] = project_id

    if "title" in data or not partial:
        title = normalize_whitespace(str(data.get("title", "")))
        if not title:
            raise BidMonitorError(400, "任务标题不能为空")
        normalized["title"] = title

    if "assignee" in data or not partial:
        normalized["assignee"] = normalize_whitespace(str(data.get("assignee", "")))
    if "description" in data or not partial:
        normalized["description"] = normalize_text_block(data.get("description", ""))

    if "due_date" in data or not partial:
        normalized["due_date"] = validate_date_field(data.get("due_date"), "任务截止日期")
    if "status" in data or not partial:
        normalized["status"] = validate_choice(data.get("status"), TASK_STATUSES, "待办", "任务状态")
    if "priority" in data or not partial:
        normalized["priority"] = validate_choice(data.get("priority"), PRIORITIES, "中", "优先级")

    return normalized


def validate_template_payload(payload: dict[str, Any], partial: bool = False) -> dict[str, Any]:
    data = {key: value for key, value in payload.items() if value is not None}
    normalized: dict[str, Any] = {}
    if "title" in data or not partial:
        title = normalize_whitespace(str(data.get("title", "")))
        if not title:
            raise BidMonitorError(400, "模板标题不能为空")
        normalized["title"] = title
    if "category" in data or not partial:
        normalized["category"] = normalize_whitespace(str(data.get("category", "通用"))) or "通用"
    if "content" in data or not partial:
        content = normalize_text_block(data.get("content", ""))
        if not content:
            raise BidMonitorError(400, "模板内容不能为空")
        normalized["content"] = content
    if "enabled" in data or not partial:
        normalized["enabled"] = validate_enabled(data.get("enabled", 1))
    return normalized


def build_enterprise_dashboard() -> dict[str, Any]:
    conn = get_conn()
    today = datetime.now().strftime("%Y-%m-%d")
    week_later = (datetime.now() + timedelta(days=7)).strftime("%Y-%m-%d")
    active_clause = f"stage NOT IN ({','.join(['?'] * len(PROJECT_CLOSED_STAGES))})"
    closed_params = list(PROJECT_CLOSED_STAGES)
    total_projects = conn.execute("SELECT COUNT(*) FROM bid_projects").fetchone()[0]
    active_projects = conn.execute(f"SELECT COUNT(*) FROM bid_projects WHERE {active_clause}", closed_params).fetchone()[0]
    due_soon = conn.execute(
        f"""
        SELECT COUNT(*) FROM bid_projects
        WHERE {active_clause} AND bid_deadline != '' AND bid_deadline BETWEEN ? AND ?
        """,
        [*closed_params, today, week_later],
    ).fetchone()[0]
    overdue_tasks = conn.execute(
        """
        SELECT COUNT(*) FROM project_tasks
        WHERE status NOT IN ('已完成', '已取消') AND due_date != '' AND due_date < ?
        """,
        (today,),
    ).fetchone()[0]
    templates = conn.execute("SELECT COUNT(*) FROM bid_templates WHERE enabled = 1").fetchone()[0]
    stage_rows = [
        dict(row)
        for row in conn.execute(
            "SELECT stage, COUNT(*) AS count FROM bid_projects GROUP BY stage ORDER BY count DESC"
        ).fetchall()
    ]
    upcoming = [
        dict(row)
        for row in conn.execute(
            f"""
            SELECT id, project_name, client_name, owner, bid_deadline, stage, priority
            FROM bid_projects
            WHERE {active_clause} AND bid_deadline != ''
            ORDER BY bid_deadline ASC
            LIMIT 6
            """,
            closed_params,
        ).fetchall()
    ]
    conn.close()
    return {
        "total_projects": total_projects,
        "active_projects": active_projects,
        "due_soon": due_soon,
        "overdue_tasks": overdue_tasks,
        "enabled_templates": templates,
        "stage_counts": stage_rows,
        "upcoming_projects": upcoming,
    }


def sanitize_filename(value: str) -> str:
    text = re.sub(r"[\\/:*?\"<>|]+", "_", normalize_whitespace(value))
    return text[:80] or "投标方案"


def build_proposal_markdown(project_id: int) -> str:
    conn = get_conn()
    project = conn.execute(
        """
        SELECT p.*, b.title AS source_title, b.url AS source_url, b.site_name AS source_site, b.pub_date AS source_pub_date
        FROM bid_projects p
        LEFT JOIN bids b ON b.id = p.bid_id
        WHERE p.id = ?
        """,
        (project_id,),
    ).fetchone()
    if not project:
        conn.close()
        raise HTTPException(404, "投标项目不存在")
    tasks = [
        dict(row)
        for row in conn.execute(
            "SELECT * FROM project_tasks WHERE project_id = ? ORDER BY due_date ASC, id ASC",
            (project_id,),
        ).fetchall()
    ]
    templates = [
        dict(row)
        for row in conn.execute(
            "SELECT title, category, content FROM bid_templates WHERE enabled = 1 ORDER BY category, id"
        ).fetchall()
    ]
    profile = dict(conn.execute("SELECT * FROM company_profile WHERE id = 1").fetchone())
    conn.close()

    p = dict(project)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        f"# {p['project_name']}投标方案初稿",
        "",
        f"> 生成时间：{generated_at}",
        "",
        "## 一、项目基本信息",
        "",
        f"- 项目名称：{p['project_name']}",
        f"- 招标单位/客户：{p.get('client_name') or '待补充'}",
        f"- 项目编号：{p.get('bid_no') or '待补充'}",
        f"- 当前阶段：{p.get('stage') or '线索'}",
        f"- 负责人：{p.get('owner') or '待指定'}",
        f"- 投标截止日期：{p.get('bid_deadline') or '待确认'}",
        f"- 预算金额：{p.get('estimated_amount') or 0:g}",
        f"- 中标概率：{p.get('win_probability') or 0}%",
        "",
        "## 二、企业概况",
        "",
        profile.get("company_name") or "请在“企业资料”模块补充公司名称、资质能力与服务承诺。",
        "",
    ]
    if profile.get("qualification"):
        lines.extend(["### 资质能力", "", profile["qualification"], ""])
    if profile.get("core_advantage"):
        lines.extend(["### 核心优势", "", profile["core_advantage"], ""])
    if profile.get("case_studies"):
        lines.extend(["### 相关案例", "", profile["case_studies"], ""])

    lines.extend(
        [
            "## 三、项目理解与响应策略",
            "",
            p.get("notes") or "结合招标公告、招标文件和客户需求，补充项目背景、建设目标、范围边界、关键响应点与风险点。",
            "",
            "## 四、投标执行计划",
            "",
        ]
    )
    if tasks:
        lines.append("| 任务 | 负责人 | 截止日期 | 状态 | 优先级 |")
        lines.append("| --- | --- | --- | --- | --- |")
        for task in tasks:
            lines.append(
                f"| {task['title']} | {task.get('assignee') or '待定'} | {task.get('due_date') or '-'} | {task.get('status') or '-'} | {task.get('priority') or '-'} |"
            )
        lines.append("")
    else:
        lines.extend(["暂无任务，请在“任务看板”中拆分资格审查、商务响应、技术方案、报价、盖章装订等工作。", ""])

    section_no = sum(1 for _l in lines if _l.startswith("## ")) + 1  # 动态计算，不硬编码
    for template in templates:
        lines.extend([f"## {section_no}、{template['title']}", "", template["content"], ""])
        section_no += 1

    if profile.get("service_commitment"):
        lines.extend([f"## {section_no}、服务承诺", "", profile["service_commitment"], ""])
        section_no += 1

    lines.extend([f"## {section_no}、后续待补充清单", ""])
    checklist = [
        "招标文件资格条件逐条响应表",
        "商务偏离表/技术偏离表",
        "报价清单与成本测算",
        "企业资质、人员证书、业绩证明扫描件",
        "授权委托书、承诺函、盖章页",
    ]
    lines.extend([f"- {item}" for item in checklist])
    if p.get("source_url"):
        lines.extend(["", "## 来源公告", "", f"- 来源网站：{p.get('source_site') or '-'}", f"- 公告标题：{p.get('source_title') or '-'}", f"- 公告链接：{p.get('source_url')}"])
    return "\n".join(lines) + "\n"


# ──────────────────────────────────────────────
# 认证 API
# ──────────────────────────────────────────────


@app.post("/api/auth/register")
def register_user(body: RegisterRequest):
    username = normalize_whitespace(body.username)
    password = body.password
    if not username:
        raise HTTPException(400, "用户名不能为空")
    if len(password) < 6:
        raise HTTPException(400, "密码至少 6 位")
    # 第一个注册用户自动成为管理员
    conn = get_conn()
    user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    is_admin = user_count == 0
    salt, pwd_hash = _hash_password(password)
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, salt, display_name, is_admin) VALUES (?, ?, ?, ?, ?)",
            (username, pwd_hash, salt, body.display_name or username, 1 if is_admin else 0),
        )
        conn.commit()
        user_id = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()[0]
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(400, "用户名已存在")
    conn.close()
    token = _create_token(user_id)
    return {
        "token": token,
        "user": {"id": user_id, "username": username, "display_name": body.display_name or username, "is_admin": is_admin},
    }


@app.post("/api/auth/login")
def login_user(body: LoginRequest):
    username = normalize_whitespace(body.username)
    conn = get_conn()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(401, "用户名或密码错误")
    user = dict(row)
    if not _verify_password(body.password, user["salt"], user["password_hash"]):
        raise HTTPException(401, "用户名或密码错误")
    token = _create_token(user["id"])
    return {
        "token": token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "display_name": user.get("display_name", user["username"]),
            "is_admin": bool(user.get("is_admin", 0)),
        },
    }


@app.post("/api/auth/logout")
def logout_user(credentials: HTTPAuthorizationCredentials = Depends(_auth_scheme), user: dict = Depends(require_auth)):
    conn = get_conn()
    conn.execute("DELETE FROM auth_tokens WHERE token = ?", (credentials.credentials,))
    conn.commit()
    conn.close()
    return {"message": "已登出"}


@app.get("/api/auth/me")
def auth_me(user: dict = Depends(require_auth)):
    return {
        "id": user["id"],
        "username": user["username"],
        "display_name": user.get("display_name", user["username"]),
        "is_admin": bool(user.get("is_admin", 0)),
    }


@app.get("/api/health")
def health_check():
    conn = get_conn()
    total_sites = conn.execute("SELECT COUNT(*) FROM sites").fetchone()[0]
    enabled_sites = conn.execute("SELECT COUNT(*) FROM sites WHERE enabled = 1").fetchone()[0]
    total_bids = conn.execute("SELECT COUNT(*) FROM bids").fetchone()[0]
    conn.close()
    return {
        "status": "ok",
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "database": {"connected": True, "path": DB_PATH},
        "scheduler": {"running": scheduler.running, "job_count": len(scheduler.get_jobs())},
        "sites": {"total": total_sites, "enabled": enabled_sites},
        "bids": {"total": total_bids},
        "crawl_config": {
            "proxy": CRAWL_PROXY or "(未设置 — 远程部署建议配置)",
            "verify_ssl": CRAWL_VERIFY_SSL,
            "timeout": CRAWL_TIMEOUT,
        },
    }


@app.get("/api/diagnose")
def diagnose_sites():
    """诊断已启用站点的网络连通性，帮助排查远程部署问题"""
    conn = get_conn()
    sites = [dict(r) for r in conn.execute("SELECT id, name, url FROM sites WHERE enabled = 1").fetchall()]
    conn.close()
    results = []
    for site in sites:
        result = {"id": site["id"], "name": site["name"], "url": site["url"], "ok": False, "status": "?", "duration_ms": 0, "body_bytes": 0, "error": ""}
        try:
            import time
            t0 = time.time()
            resp = HTTP_SESSION.get(site["url"], headers=_headers_for(site["url"]), timeout=10)
            duration_ms = int((time.time() - t0) * 1000)
            result["duration_ms"] = duration_ms
            result["status"] = resp.status_code
            result["body_bytes"] = len(resp.content)
            if resp.status_code == 200 and len(resp.content) > 200:
                result["ok"] = True
            else:
                result["error"] = f"状态码 {resp.status_code}，响应体 {len(resp.content)} 字节，可能是反爬或重定向"
        except Exception as e:
            result["error"] = str(e)[:200]
        results.append(result)
    return {"results": results}


@app.get("/api/stats")
def get_stats():
    conn = get_conn()
    total_bids = conn.execute("SELECT COUNT(*) FROM bids").fetchone()[0]
    new_bids = conn.execute("SELECT COUNT(*) FROM bids WHERE is_new = 1").fetchone()[0]
    total_sites = conn.execute("SELECT COUNT(*) FROM sites").fetchone()[0]
    enabled_sites = conn.execute("SELECT COUNT(*) FROM sites WHERE enabled = 1").fetchone()[0]
    today = datetime.now().strftime("%Y-%m-%d")
    today_bids = conn.execute("SELECT COUNT(*) FROM bids WHERE crawl_time LIKE ?", (f"{today}%",)).fetchone()[0]
    conn.close()
    return {
        "total_bids": total_bids,
        "new_bids": new_bids,
        "total_sites": total_sites,
        "enabled_sites": enabled_sites,
        "today_bids": today_bids,
    }


@app.get("/api/sites")
def list_sites():
    conn = get_conn()
    rows = [dict(row) for row in conn.execute("SELECT * FROM sites ORDER BY id").fetchall()]
    conn.close()
    return rows


@app.get("/api/source-types")
def list_source_types():
    """获取所有来源类型列表（用于前端筛选器）"""
    conn = get_conn()
    # 从 sites 表获取已定义的来源类型
    rows = conn.execute(
        "SELECT DISTINCT source_type FROM sites WHERE source_type != '' AND source_type IS NOT NULL ORDER BY source_type"
    ).fetchall()
    site_types = [row["source_type"] for row in rows]
    # 也从 bids 表获取实际数据中的类型
    rows2 = conn.execute(
        "SELECT DISTINCT source_type FROM bids WHERE source_type != '' AND source_type IS NOT NULL ORDER BY source_type"
    ).fetchall()
    bid_types = [row["source_type"] for row in rows2]
    # 合并去重
    types = sorted(set(site_types + bid_types))
    conn.close()
    return types


@app.post("/api/sites/preview")
def preview_site(body: SitePreviewRequest):
    payload = validate_site_payload(model_to_dict(body), partial=True)
    payload["name"] = "预览站点"
    # 如果没传选择器，自动检测
    if not body.list_selector or body.list_selector.strip() in ('', 'a'):
        payload["crawl_mode"] = "auto"
    else:
        payload["crawl_mode"] = "manual"
    entries, raw_count = collect_site_entries(payload, limit=5)
    return {
        "matched_count": raw_count,
        "preview_count": len(entries),
        "samples": entries,
    }


@app.post("/api/sites/analyze")
def analyze_site(body: SitePreviewRequest):
    """智能分析：自动检测网站结构和选择器"""
    payload = model_to_dict(body)
    url = validate_url(str(payload.get("url", "")))
    result = auto_analyze_site(url)
    return result


@app.post("/api/sites")
def create_site(body: SiteCreate):
    payload = validate_site_payload(model_to_dict(body), partial=False)
    conn = get_conn()
    exists = conn.execute("SELECT 1 FROM sites WHERE url = ?", (payload["url"],)).fetchone()
    if exists:
        conn.close()
        raise HTTPException(400, "该网站 URL 已存在")
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO sites (name, url, list_selector, title_selector, date_selector, enabled, cron_hour, cron_minute, crawl_mode, source_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            payload["name"],
            payload["url"],
            payload["list_selector"],
            payload["title_selector"],
            payload["date_selector"],
            payload["enabled"],
            payload["cron_hour"],
            payload["cron_minute"],
            payload.get("crawl_mode", "auto"),
            payload.get("source_type", ""),
        ),
    )
    new_id = cursor.lastrowid
    conn.commit()
    conn.close()
    setup_scheduler()
    return {"id": new_id, "message": "添加成功"}


@app.put("/api/sites/{site_id}")
def update_site(site_id: int, body: SiteUpdate):
    ensure_site_exists(site_id)
    payload = validate_site_payload(model_to_dict(body), partial=True)
    if not payload:
        raise HTTPException(400, "无更新内容")
    if "url" in payload:
        conn = get_conn()
        duplicate = conn.execute("SELECT 1 FROM sites WHERE url = ? AND id != ?", (payload["url"], site_id)).fetchone()
        conn.close()
        if duplicate:
            raise HTTPException(400, "该网站 URL 已存在")
    sets = ", ".join(f"{field} = ?" for field in payload)
    params = list(payload.values()) + [site_id]
    conn = get_conn()
    conn.execute(f"UPDATE sites SET {sets} WHERE id = ?", params)
    conn.commit()
    conn.close()
    setup_scheduler()
    return {"message": "更新成功"}


@app.delete("/api/sites/{site_id}")
def delete_site(site_id: int):
    site = ensure_site_exists(site_id)
    if site.get("locked"):
        raise HTTPException(403, "固定站点不允许删除")
    conn = get_conn()
    conn.execute("DELETE FROM sites WHERE id = ?", (site_id,))
    conn.execute("DELETE FROM bids WHERE site_id = ?", (site_id,))
    conn.commit()
    conn.close()
    setup_scheduler()
    return {"message": "删除成功"}


@app.post("/api/sites/{site_id}/crawl")
def manual_crawl(site_id: int):
    site = ensure_site_exists(site_id)
    result = crawl_site(site, raise_on_error=True)
    return {"message": f"抓取完成，新增 {result['new_count']} 条" if result["success"] else f"抓取失败: {result['error_message']}"}


@app.post("/api/crawl-all")
def crawl_all():
    threading.Thread(target=crawl_all_enabled, daemon=True).start()
    return {"message": "已触发全量抓取，请稍后查看结果"}


@app.get("/api/bids")
def list_bids(
    site_id: Optional[int] = None,
    keyword: Optional[str] = None,
    is_new: Optional[int] = None,
    days: Optional[int] = 0,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    page: int = 1,
    page_size: int = 20,
    source_type: Optional[str] = None,
):
    page, page_size = validate_pagination(page, page_size)
    where_sql, params = build_bid_conditions(
        site_id=site_id,
        keyword=keyword,
        is_new=is_new,
        days=days,
        date_from=date_from,
        date_to=date_to,
        source_type=source_type,
    )
    conn = get_conn()
    total = conn.execute(f"SELECT COUNT(*) FROM bids {where_sql}", params).fetchone()[0]
    offset = (page - 1) * page_size
    rows = [
        dict(row)
        for row in conn.execute(
            f"SELECT * FROM bids {where_sql} ORDER BY crawl_time DESC LIMIT ? OFFSET ?",
            [*params, page_size, offset],
        ).fetchall()
    ]
    conn.close()
    return {"total": total, "page": page, "page_size": page_size, "items": rows}


@app.post("/api/bids/mark-read")
def mark_bids_as_read(body: MarkReadRequest):
    payload = model_to_dict(body)
    ids = [int(item) for item in (payload.get("ids") or []) if int(item) > 0]
    where_sql, params = build_bid_conditions(
        site_id=payload.get("site_id"),
        keyword=payload.get("keyword"),
        is_new=payload.get("is_new"),
        days=payload.get("days"),
        date_from=payload.get("date_from"),
        date_to=payload.get("date_to"),
        ids=ids,
    )
    if not where_sql:
        raise HTTPException(400, "请指定要标记已读的公告范围")
    conn = get_conn()
    cursor = conn.execute(f"UPDATE bids SET is_new = 0 {where_sql}", params)
    conn.commit()
    conn.close()
    return {"message": f"已标记 {cursor.rowcount} 条公告为已读", "updated": cursor.rowcount}


@app.delete("/api/bids/{bid_id}")
def delete_bid(bid_id: int):
    conn = get_conn()
    cursor = conn.execute("DELETE FROM bids WHERE id = ?", (bid_id,))
    conn.commit()
    conn.close()
    if cursor.rowcount == 0:
        raise HTTPException(404, "公告不存在")
    return {"message": "删除成功"}


@app.post("/api/bids/clear")
def clear_all_bids():
    conn = get_conn()
    deleted = conn.execute("SELECT COUNT(*) FROM bids").fetchone()[0]
    conn.execute("DELETE FROM bids")
    conn.execute("DELETE FROM crawl_logs")
    conn.commit()
    conn.close()
    return {"message": f"已清除 {deleted} 条招标记录"}


@app.get("/api/bids/export")
def export_bids(
    site_id: Optional[int] = None,
    keyword: Optional[str] = None,
    is_new: Optional[int] = None,
    days: Optional[int] = 0,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    format: Optional[str] = "csv",
):
    where_sql, params = build_bid_conditions(
        site_id=site_id,
        keyword=keyword,
        is_new=is_new,
        days=days,
        date_from=date_from,
        date_to=date_to,
    )
    conn = get_conn()
    rows = [
        dict(row)
        for row in conn.execute(
            f"SELECT * FROM bids {where_sql} ORDER BY crawl_time DESC",
            params,
        ).fetchall()
    ]
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "标题", "来源网站", "链接", "发布日期", "抓取时间", "未读"])
    for row in rows:
        writer.writerow([
            row["id"],
            row["title"],
            row["site_name"],
            row["url"] or "",
            row["pub_date"] or "",
            row["crawl_time"],
            "是" if row["is_new"] else "否",
        ])

    output.seek(0)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"bids_export_{timestamp}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv; charset=utf-8-sig",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{filename}"},
    )


@app.get("/api/enterprise/dashboard")
def enterprise_dashboard():
    return build_enterprise_dashboard()


@app.get("/api/projects")
def list_projects(stage: Optional[str] = None, keyword: Optional[str] = None, owner: Optional[str] = None, include_deleted: Optional[int] = 0):
    where: list[str] = []
    params: list[Any] = []
    if not include_deleted:
        where.append("p.is_deleted = 0")
    if stage:
        where.append("p.stage = ?")
        params.append(stage)
    if owner:
        where.append("p.owner LIKE ?")
        params.append(f"%{owner}%")
    if keyword:
        words = split_keywords(keyword)
        if words:
            clauses: list[str] = []
            for word in words:
                clauses.append("(p.project_name LIKE ? OR p.client_name LIKE ? OR p.bid_no LIKE ? OR b.title LIKE ?)")
                params.extend([f"%{word}%"] * 4)
            where.append("(" + " OR ".join(clauses) + ")")
    where_sql = f"WHERE {' AND '.join(where)}" if where else ""
    conn = get_conn()
    rows = [
        dict(row)
        for row in conn.execute(
            f"""
            SELECT p.*,
                   b.title AS source_title,
                   b.url AS source_url,
                   b.site_name AS source_site,
                   COUNT(t.id) AS total_tasks,
                   SUM(CASE WHEN t.status='已完成' THEN 1 ELSE 0 END) AS done_tasks,
                   SUM(CASE WHEN t.status NOT IN ('已完成', '已取消')
                             AND t.due_date != ''
                             AND t.due_date < date('now','localtime')
                            THEN 1 ELSE 0 END) AS overdue_tasks
            FROM bid_projects p
            LEFT JOIN bids b ON b.id = p.bid_id
            LEFT JOIN project_tasks t ON t.project_id = p.id
            {where_sql}
            GROUP BY p.id
            ORDER BY
                CASE WHEN p.bid_deadline = '' THEN 1 ELSE 0 END,
                p.bid_deadline ASC,
                p.updated_at DESC
            """,
            params,
        ).fetchall()
    ]
    conn.close()
    return rows


@app.get("/api/projects/{project_id}")
def get_project(project_id: int):
    ensure_project_exists(project_id)
    conn = get_conn()
    project = dict(
        conn.execute(
            """
            SELECT p.*, b.title AS source_title, b.url AS source_url, b.site_name AS source_site
            FROM bid_projects p
            LEFT JOIN bids b ON b.id = p.bid_id
            WHERE p.id = ?
            """,
            (project_id,),
        ).fetchone()
    )
    tasks = [dict(row) for row in conn.execute("SELECT * FROM project_tasks WHERE project_id = ? ORDER BY due_date ASC, id ASC", (project_id,)).fetchall()]
    conn.close()
    project["tasks"] = tasks
    return project


@app.post("/api/projects")
def create_project(body: ProjectCreate):
    payload = validate_project_payload(model_to_dict(body), partial=False)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO bid_projects
            (bid_id, project_name, client_name, bid_no, stage, owner, priority, bid_deadline,
             estimated_amount, win_probability, next_action, notes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            payload.get("bid_id"),
            payload["project_name"],
            payload["client_name"],
            payload["bid_no"],
            payload["stage"],
            payload["owner"],
            payload["priority"],
            payload["bid_deadline"],
            payload["estimated_amount"],
            payload["win_probability"],
            payload["next_action"],
            payload["notes"],
            now,
            now,
        ),
    )
    new_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return {"id": new_id, "message": "投标项目已创建"}


@app.post("/api/projects/from-bid/{bid_id}")
def create_project_from_bid(bid_id: int, body: ProjectFromBidRequest):
    bid = ensure_bid_exists(bid_id)
    payload = validate_project_payload(
        {
            "bid_id": bid_id,
            "project_name": bid["title"],
            "client_name": bid["site_name"] or "",
            "stage": "线索",
            "owner": body.owner,
            "priority": body.priority,
            "bid_deadline": body.bid_deadline,
            "estimated_amount": 0,
            "win_probability": 30,
            "next_action": "下载招标文件并完成资格审查",
            "notes": body.notes or f"来源公告：{bid['url'] or ''}",
        },
        partial=False,
    )
    conn = get_conn()
    existing = conn.execute("SELECT id FROM bid_projects WHERE bid_id = ? ORDER BY id LIMIT 1", (bid_id,)).fetchone()
    if existing:
        conn.close()
        return {"id": existing["id"], "message": "该公告已转入项目库"}
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO bid_projects
            (bid_id, project_name, client_name, bid_no, stage, owner, priority, bid_deadline,
             estimated_amount, win_probability, next_action, notes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            payload["bid_id"],
            payload["project_name"],
            payload["client_name"],
            "",
            payload["stage"],
            payload["owner"],
            payload["priority"],
            payload["bid_deadline"],
            payload["estimated_amount"],
            payload["win_probability"],
            payload["next_action"],
            payload["notes"],
            now,
            now,
        ),
    )
    new_id = cursor.lastrowid
    default_tasks = [
        ("资格条件初审", payload["owner"], payload["bid_deadline"], "待办", "高", "核对资质、业绩、人员、财务及信誉要求。"),
        ("招标文件下载与重点条款摘录", payload["owner"], payload["bid_deadline"], "待办", "高", "整理评分办法、响应文件格式、报价要求和废标条款。"),
        ("标书目录与分工确认", payload["owner"], payload["bid_deadline"], "待办", "中", "拆分商务、技术、报价、盖章装订等责任人。"),
    ]
    conn.executemany(
        """
        INSERT INTO project_tasks (project_id, title, assignee, due_date, status, priority, description, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [(new_id, *task, now, now) for task in default_tasks],
    )
    conn.commit()
    conn.close()
    return {"id": new_id, "message": "已转入投标项目，并生成默认任务"}


@app.put("/api/projects/{project_id}")
def update_project(project_id: int, body: ProjectUpdate):
    ensure_project_exists(project_id)
    payload = validate_project_payload(model_to_dict(body), partial=True)
    if not payload:
        raise HTTPException(400, "无更新内容")
    payload["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sets = ", ".join(f"{field} = ?" for field in payload)
    params = list(payload.values()) + [project_id]
    conn = get_conn()
    conn.execute(f"UPDATE bid_projects SET {sets} WHERE id = ?", params)
    conn.commit()
    conn.close()
    return {"message": "投标项目已更新"}


@app.delete("/api/projects/{project_id}")
def delete_project(project_id: int):
    ensure_project_exists(project_id)
    conn = get_conn()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("UPDATE bid_projects SET is_deleted = 1, updated_at = ? WHERE id = ?", (now, project_id))
    conn.commit()
    conn.close()
    return {"message": "投标项目已删除（可恢复）"}


@app.post("/api/projects/{project_id}/restore")
def restore_project(project_id: int):
    conn = get_conn()
    row = conn.execute("SELECT * FROM bid_projects WHERE id = ? AND is_deleted = 1", (project_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "已删除的投标项目不存在")
    conn = get_conn()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("UPDATE bid_projects SET is_deleted = 0, updated_at = ? WHERE id = ?", (now, project_id))
    conn.commit()
    conn.close()
    return {"message": "投标项目已恢复"}


@app.get("/api/projects/{project_id}/proposal")
def export_project_proposal(project_id: int):
    project = ensure_project_exists(project_id)
    markdown = build_proposal_markdown(project_id)
    filename = f"{sanitize_filename(project['project_name'])}_投标方案初稿.md"
    return StreamingResponse(
        iter([markdown.encode("utf-8-sig")]),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename)}"},
    )


@app.get("/api/tasks")
def list_tasks(project_id: Optional[int] = None, status: Optional[str] = None, assignee: Optional[str] = None):
    where: list[str] = []
    params: list[Any] = []
    if project_id:
        where.append("t.project_id = ?")
        params.append(project_id)
    if status:
        where.append("t.status = ?")
        params.append(status)
    if assignee:
        where.append("t.assignee LIKE ?")
        params.append(f"%{assignee}%")
    where_sql = f"WHERE {' AND '.join(where)}" if where else ""
    conn = get_conn()
    rows = [
        dict(row)
        for row in conn.execute(
            f"""
            SELECT t.*, p.project_name
            FROM project_tasks t
            LEFT JOIN bid_projects p ON p.id = t.project_id
            {where_sql}
            ORDER BY
                CASE WHEN t.status='已完成' THEN 1 ELSE 0 END,
                CASE WHEN t.due_date = '' THEN 1 ELSE 0 END,
                t.due_date ASC,
                t.id DESC
            """,
            params,
        ).fetchall()
    ]
    conn.close()
    return rows


@app.post("/api/tasks")
def create_task(body: TaskCreate):
    payload = validate_task_payload(model_to_dict(body), partial=False)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO project_tasks
            (project_id, title, assignee, due_date, status, priority, description, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            payload["project_id"],
            payload["title"],
            payload["assignee"],
            payload["due_date"],
            payload["status"],
            payload["priority"],
            payload["description"],
            now,
            now,
        ),
    )
    new_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return {"id": new_id, "message": "任务已创建"}


@app.put("/api/tasks/{task_id}")
def update_task(task_id: int, body: TaskUpdate):
    ensure_task_exists(task_id)
    payload = validate_task_payload(model_to_dict(body), partial=True)
    if not payload:
        raise HTTPException(400, "无更新内容")
    payload["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sets = ", ".join(f"{field} = ?" for field in payload)
    params = list(payload.values()) + [task_id]
    conn = get_conn()
    conn.execute(f"UPDATE project_tasks SET {sets} WHERE id = ?", params)
    conn.commit()
    conn.close()
    return {"message": "任务已更新"}


@app.delete("/api/tasks/{task_id}")
def delete_task(task_id: int):
    ensure_task_exists(task_id)
    conn = get_conn()
    conn.execute("DELETE FROM project_tasks WHERE id = ?", (task_id,))
    conn.commit()
    conn.close()
    return {"message": "任务已删除"}


@app.get("/api/templates")
def list_templates():
    conn = get_conn()
    rows = [dict(row) for row in conn.execute("SELECT * FROM bid_templates ORDER BY category, id").fetchall()]
    conn.close()
    return rows


@app.post("/api/templates")
def create_template(body: TemplateCreate):
    payload = validate_template_payload(model_to_dict(body), partial=False)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO bid_templates (title, category, content, enabled, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (payload["title"], payload["category"], payload["content"], payload["enabled"], now, now),
    )
    new_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return {"id": new_id, "message": "模板已创建"}


@app.put("/api/templates/{template_id}")
def update_template(template_id: int, body: TemplateUpdate):
    ensure_template_exists(template_id)
    payload = validate_template_payload(model_to_dict(body), partial=True)
    if not payload:
        raise HTTPException(400, "无更新内容")
    payload["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sets = ", ".join(f"{field} = ?" for field in payload)
    params = list(payload.values()) + [template_id]
    conn = get_conn()
    conn.execute(f"UPDATE bid_templates SET {sets} WHERE id = ?", params)
    conn.commit()
    conn.close()
    return {"message": "模板已更新"}


@app.delete("/api/templates/{template_id}")
def delete_template(template_id: int):
    ensure_template_exists(template_id)
    conn = get_conn()
    conn.execute("DELETE FROM bid_templates WHERE id = ?", (template_id,))
    conn.commit()
    conn.close()
    return {"message": "模板已删除"}


@app.get("/api/company-profile")
def get_company_profile():
    conn = get_conn()
    row = conn.execute("SELECT * FROM company_profile WHERE id = 1").fetchone()
    if not row:
        seed_enterprise_defaults(conn)
        conn.commit()
        row = conn.execute("SELECT * FROM company_profile WHERE id = 1").fetchone()
    conn.close()
    return dict(row)


@app.put("/api/company-profile")
def update_company_profile(body: CompanyProfileUpdate):
    block_fields = {"qualification", "core_advantage", "service_commitment", "case_studies"}
    payload = {}
    for key, value in model_to_dict(body).items():
        payload[key] = normalize_text_block(value) if key in block_fields else normalize_whitespace(str(value or ""))
    payload["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fields = [
        "company_name",
        "contact_person",
        "phone",
        "email",
        "address",
        "qualification",
        "core_advantage",
        "service_commitment",
        "case_studies",
        "updated_at",
    ]
    conn = get_conn()
    seed_enterprise_defaults(conn)
    conn.execute(
        f"UPDATE company_profile SET {', '.join(field + ' = ?' for field in fields)} WHERE id = 1",
        [payload.get(field, "") for field in fields],
    )
    conn.commit()
    conn.close()
    return {"message": "企业资料已保存"}


@app.get("/api/keywords")
def list_keywords():
    conn = get_conn()
    rows = [dict(row) for row in conn.execute("SELECT * FROM keywords ORDER BY id").fetchall()]
    conn.close()
    return rows


@app.post("/api/keywords")
def add_keyword(body: KeywordCreate):
    words = split_keywords(body.word)
    if not words:
        raise HTTPException(400, "关键词不能为空")
    conn = get_conn()
    inserted = 0
    duplicates: list[str] = []
    for word in words:
        try:
            conn.execute("INSERT INTO keywords (word) VALUES (?)", (word,))
            inserted += 1
        except sqlite3.IntegrityError:
            duplicates.append(word)
    conn.commit()
    conn.close()
    if inserted == 0:
        raise HTTPException(400, "关键词已存在")
    message = f"已添加 {inserted} 个关键词"
    if duplicates:
        message += f"，忽略重复项: {', '.join(duplicates)}"
    return {"message": message, "inserted": inserted, "duplicates": duplicates}


@app.delete("/api/keywords/{kid}")
def delete_keyword(kid: int):
    conn = get_conn()
    cursor = conn.execute("DELETE FROM keywords WHERE id = ?", (kid,))
    conn.commit()
    conn.close()
    if cursor.rowcount == 0:
        raise HTTPException(404, "关键词不存在")
    return {"message": "删除成功"}


@app.get("/api/scheduler/status")
def scheduler_status():
    conn = get_conn()
    site_map = {row["id"]: row["name"] for row in conn.execute("SELECT id, name FROM sites").fetchall()}
    conn.close()
    jobs = []
    for job in scheduler.get_jobs():
        site_id = None
        if job.id.startswith("site_"):
            try:
                site_id = int(job.id.split("_", 1)[1])
            except ValueError:
                site_id = None
        jobs.append(
            {
                "id": job.id,
                "site_id": site_id,
                "site_name": site_map.get(site_id) or job.name,
                "next_run": str(job.next_run_time) if job.next_run_time else "",
            }
        )
    return {"running": scheduler.running, "jobs": jobs}


@app.get("/api/crawl-logs")
def list_crawl_logs(site_id: Optional[int] = None, limit: int = 50):
    """抓取日志历史，支持按站点筛选"""
    conn = get_conn()
    if site_id:
        rows = conn.execute(
            "SELECT * FROM crawl_logs WHERE site_id = ? ORDER BY crawl_time DESC LIMIT ?",
            (site_id, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM crawl_logs ORDER BY crawl_time DESC LIMIT ?",
            (limit,),
        ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


@app.get("/api/stats/site-stats")
def site_statistics():
    """各站点抓取统计汇总：成功率、失败次数、总新增、平均耗时"""
    conn = get_conn()
    stats = {}
    rows = conn.execute(
        """
        SELECT site_id, site_name,
               COUNT(*) as total_runs,
               SUM(CASE WHEN success=1 THEN 1 ELSE 0 END) as success_count,
               SUM(CASE WHEN success=0 THEN 1 ELSE 0 END) as fail_count,
               SUM(new_count) as total_new,
               AVG(duration_ms) as avg_duration_ms,
               MAX(crawl_time) as last_run
        FROM crawl_logs
        GROUP BY site_id
        ORDER BY last_run DESC
        """
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


@app.get("/api/health/alerts")
def health_alerts():
    """最近抓取失败告警（最近7天失败记录）"""
    conn = get_conn()
    cutoff = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
    rows = conn.execute(
        "SELECT * FROM crawl_logs WHERE success=0 AND crawl_time >= ? ORDER BY crawl_time DESC LIMIT 20"
    , (cutoff,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
