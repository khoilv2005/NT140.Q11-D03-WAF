from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from sqlalchemy.sql import func
import os

# --- Cấu hình kết nối ---
# Thay thế bằng thông tin kết nối MySQL của bạn
DB_USER = "waf"
DB_PASSWORD = "wafadmin"
DB_HOST = "127.0.0.1"
DB_NAME = "wafdb"

DATABASE_URL = f"mysql+mysqlconnector://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"

# Tạo Engine kết nối đến DB, sử dụng connection pool
engine = create_engine(DATABASE_URL, pool_recycle=3600)

# Tạo một Session factory đã được cấu hình
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class mà tất cả các model sẽ kế thừa
Base = declarative_base()

# --- Định nghĩa các Model ---

class Rule(Base):
    __tablename__ = "rules"
    id = Column(Integer, primary_key=True)
    enabled = Column(Boolean, nullable=False, default=True)
    description = Column(String(255), nullable=False)
    severity = Column(String(50))
    target = Column(String(100), nullable=False)
    operator = Column(String(50), nullable=False)
    value = Column(Text, nullable=False)
    action = Column(String(50), nullable=False, default="BLOCK")

class IPBlacklist(Base):
    __tablename__ = "ip_blacklist"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(String(45), nullable=False, unique=True)
    triggered_rule_id = Column(Integer, ForeignKey("rules.id", ondelete="SET NULL"))
    notes = Column(String(255))
    timestamp = Column(DateTime, server_default=func.now())
    
    # Tạo mối quan hệ để dễ dàng truy vấn
    triggered_rule = relationship("Rule")

class ActivityLog(Base):
    __tablename__ = "activity_log"
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, server_default=func.now())
    client_ip = Column(String(45), nullable=False)
    request_method = Column(String(10), nullable=False)
    request_path = Column(Text, nullable=False)
    status_code = Column(Integer)
    action_taken = Column(String(50), nullable=False)
    triggered_rule_id = Column(Integer, ForeignKey("rules.id", ondelete="SET NULL"))

    triggered_rule = relationship("Rule")