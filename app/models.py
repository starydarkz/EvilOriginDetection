"""
models.py — SQLAlchemy ORM models for Evil Origin Detection.
Tables: iocs, source_results, correlations, scan_history, api_keys
"""
import enum
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean, Float,
    ForeignKey, Enum as SAEnum, Index
)
from sqlalchemy.orm import relationship, DeclarativeBase


class Base(DeclarativeBase):
    pass


# ── Enums ─────────────────────────────────────────────────────────────────────

class IOCType(str, enum.Enum):
    ip     = "ip"
    domain = "domain"
    hash   = "hash"
    url    = "url"
    email  = "email"
    network = "network"   # CIDR range — red=

class Verdict(str, enum.Enum):
    malicious   = "malicious"
    suspicious  = "suspicious"
    clean       = "clean"
    unknown     = "unknown"

class SourceStatus(str, enum.Enum):
    ok       = "ok"
    error    = "error"
    skipped  = "skipped"   # IOC type not supported by this source
    no_key   = "no_key"    # API key not configured
    timeout  = "timeout"

class ScanTrigger(str, enum.Enum):
    auto   = "auto"    # first time seen
    manual = "manual"  # user submitted
    rescan = "rescan"  # forced refresh


# ── Tables ────────────────────────────────────────────────────────────────────

class IOC(Base):
    __tablename__ = "iocs"

    id          = Column(Integer, primary_key=True, index=True)
    value       = Column(String(2048), unique=True, nullable=False, index=True)
    type        = Column(SAEnum(IOCType), nullable=False)
    score       = Column(Integer, nullable=True)            # 0–100
    verdict     = Column(SAEnum(Verdict), default=Verdict.unknown)
    tags        = Column(Text, default="[]")                # JSON list[str]
    metadata_   = Column("metadata", Text, default="{}")   # JSON dict
    first_seen  = Column(DateTime, default=datetime.utcnow)
    last_scan   = Column(DateTime, default=datetime.utcnow)
    cache_until = Column(DateTime, nullable=True)           # now + TTL

    source_results = relationship("SourceResult", back_populates="ioc",
                                  cascade="all, delete-orphan")
    scan_history   = relationship("ScanHistory", back_populates="ioc",
                                  cascade="all, delete-orphan")
    correlations_a = relationship("Correlation",
                                  foreign_keys="Correlation.ioc_a_id",
                                  cascade="all, delete-orphan")
    correlations_b = relationship("Correlation",
                                  foreign_keys="Correlation.ioc_b_id",
                                  cascade="all, delete-orphan")


class SourceResult(Base):
    __tablename__ = "source_results"

    id           = Column(Integer, primary_key=True, index=True)
    ioc_id       = Column(Integer, ForeignKey("iocs.id"), nullable=False)
    source       = Column(String(64), nullable=False)       # e.g. "virustotal"
    status       = Column(SAEnum(SourceStatus), nullable=False)
    raw_json     = Column(Text, default="{}")               # full API response
    normalized   = Column(Text, default="{}")               # normalized fields
    fetched_at   = Column(DateTime, default=datetime.utcnow)

    ioc = relationship("IOC", back_populates="source_results")

    __table_args__ = (
        Index("ix_source_results_ioc_source", "ioc_id", "source"),
    )


class Correlation(Base):
    __tablename__ = "correlations"

    id         = Column(Integer, primary_key=True, index=True)
    ioc_a_id   = Column(Integer, ForeignKey("iocs.id"), nullable=False)
    ioc_b_id   = Column(Integer, ForeignKey("iocs.id"), nullable=False)
    score      = Column(Integer, default=0)                 # 0–100
    reason     = Column(Text, default="[]")                 # JSON list[str]
    created_at = Column(DateTime, default=datetime.utcnow)


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id           = Column(Integer, primary_key=True, index=True)
    ioc_id       = Column(Integer, ForeignKey("iocs.id"), nullable=False)
    score        = Column(Integer, nullable=True)
    verdict      = Column(SAEnum(Verdict), default=Verdict.unknown)
    triggered_by = Column(SAEnum(ScanTrigger), default=ScanTrigger.manual)
    scanned_at   = Column(DateTime, default=datetime.utcnow)

    ioc = relationship("IOC", back_populates="scan_history")


class QueryLog(Base):
    """
    Backend-only query log — never exposed in UI.
    Stores: origin IP, user-agent, IOC queried, timestamp, country (if resolvable).
    """
    __tablename__ = "query_logs"

    id           = Column(Integer, primary_key=True, index=True)
    origin_ip    = Column(String(64), nullable=False, index=True)
    user_agent   = Column(Text, nullable=True)
    ioc_value    = Column(String(2048), nullable=False)
    ioc_type     = Column(String(32), nullable=True)
    forced_rescan= Column(Boolean, default=False)
    response_ms  = Column(Integer, nullable=True)           # latency in ms
    verdict      = Column(String(32), nullable=True)        # result verdict
    created_at   = Column(DateTime, default=datetime.utcnow, index=True)
