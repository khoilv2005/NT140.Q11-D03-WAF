from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.sql import func

# Base class mà tất cả các model sẽ kế thừa
Base = declarative_base()

# --- Định nghĩa các Model ---

class Rule(Base):
    """Model cho bảng rules - chứa các luật WAF"""
    __tablename__ = "rules"
    
    id = Column(Integer, primary_key=True)
    enabled = Column(Boolean, nullable=False, default=True)
    description = Column(String(255), nullable=False)
    category = Column(String(50), nullable=False, index=True)  # <-- CỘT MỚI
    severity = Column(String(50))
    target = Column(String(100), nullable=False)
    operator = Column(String(50), nullable=False)
    value = Column(Text, nullable=False)
    action = Column(String(50), nullable=False, default="BLOCK")
    
    def __repr__(self):
        return f"<Rule(id={self.id}, description='{self.description}', enabled={self.enabled})>"
    
    def to_dict(self):
        """Chuyển đổi model thành dictionary"""
        return {
            'id': self.id,
            'enabled': self.enabled,
            'description': self.description,
            'category': self.category,
            'severity': self.severity,
            'target': self.target,
            'operator': self.operator,
            'value': self.value,
            'action': self.action
        }

class IPBlacklist(Base):
    """Model cho bảng ip_blacklist - chứa các IP bị cấm"""
    __tablename__ = "ip_blacklist"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(String(45), nullable=False, unique=True)
    triggered_rule_id = Column(Integer, ForeignKey("rules.id", ondelete="SET NULL"))
    notes = Column(String(255))
    timestamp = Column(DateTime, server_default=func.now())
    
    # Tạo mối quan hệ để dễ dàng truy vấn
    triggered_rule = relationship("Rule")
    
    def __repr__(self):
        return f"<IPBlacklist(id={self.id}, ip_address='{self.ip_address}')>"
    
    def to_dict(self):
        """Chuyển đổi model thành dictionary"""
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'triggered_rule_id': self.triggered_rule_id,
            'notes': self.notes,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }

class ActivityLog(Base):
    """Model cho bảng activity_log - chứa log các hoạt động"""
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
    
    def __repr__(self):
        return f"<ActivityLog(id={self.id}, client_ip='{self.client_ip}', action='{self.action_taken}')>"
    
    def to_dict(self):
        """Chuyển đổi model thành dictionary"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'client_ip': self.client_ip,
            'request_method': self.request_method,
            'request_path': self.request_path,
            'status_code': self.status_code,
            'action_taken': self.action_taken,
            'triggered_rule_id': self.triggered_rule_id
        }