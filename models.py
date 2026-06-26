from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


def _dt(val):
    if val is None:
        return None
    if hasattr(val, "isoformat"):
        return val.isoformat()
    return str(val)


class IOC(db.Model):
    __tablename__ = "iocs"

    id             = db.Column(db.Integer, primary_key=True)
    value          = db.Column(db.String(512), nullable=False, index=True)
    ioc_type       = db.Column(db.String(32), nullable=False)
    source         = db.Column(db.String(64), nullable=False)
    first_seen     = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen      = db.Column(db.DateTime, default=datetime.utcnow)
    severity       = db.Column(db.String(16), default="medium")
    tags           = db.Column(db.Text, default="")
    asn            = db.Column(db.String(32), default="")
    country        = db.Column(db.String(8), default="")
    malware_family = db.Column(db.String(128), default="")
    port           = db.Column(db.Integer, nullable=True)
    uri_pattern    = db.Column(db.String(256), default="")
    raw_context    = db.Column(db.Text, default="")
    campaign_id    = db.Column(db.Integer, db.ForeignKey("campaigns.id"), nullable=True)

    def to_dict(self):
        return {
            "id":             self.id,
            "value":          self.value,
            "ioc_type":       self.ioc_type,
            "source":         self.source,
            "first_seen":     _dt(self.first_seen),
            "last_seen":      _dt(self.last_seen),
            "severity":       self.severity,
            "tags":           self.tags or "",
            "asn":            self.asn or "",
            "country":        self.country or "",
            "malware_family": self.malware_family or "",
            "port":           self.port,
            "uri_pattern":    self.uri_pattern or "",
            "campaign_id":    self.campaign_id,
        }


class Campaign(db.Model):
    __tablename__ = "campaigns"

    id               = db.Column(db.Integer, primary_key=True)
    name             = db.Column(db.String(64), nullable=False, unique=True)
    confidence       = db.Column(db.Float, default=0.0)
    ioc_count        = db.Column(db.Integer, default=0)
    ttps             = db.Column(db.Text, default="")
    sigma_rule       = db.Column(db.Text, default="")
    first_seen       = db.Column(db.DateTime, default=datetime.utcnow)
    last_updated     = db.Column(db.DateTime, default=datetime.utcnow)
    primary_country  = db.Column(db.String(8), default="")
    primary_asn      = db.Column(db.String(32), default="")
    malware_families = db.Column(db.Text, default="")
    basis            = db.Column(db.Text, default="")
    iocs             = db.relationship("IOC", backref="campaign", lazy=True)

    def to_dict(self):
        return {
            "id":               self.id,
            "name":             self.name,
            "confidence":       round(self.confidence or 0.0, 3),
            "ioc_count":        self.ioc_count,
            "ttps":             self.ttps.split(",") if self.ttps else [],
            "sigma_rule":       self.sigma_rule or "",
            "first_seen":       _dt(self.first_seen),
            "last_updated":     _dt(self.last_updated),
            "primary_country":  self.primary_country or "",
            "primary_asn":      self.primary_asn or "",
            "malware_families": self.malware_families.split(",") if self.malware_families else [],
            "basis":            self.basis or "",
            "iocs":             [i.to_dict() for i in self.iocs],
        }


class FeedStatus(db.Model):
    __tablename__ = "feed_status"

    id            = db.Column(db.Integer, primary_key=True)
    source        = db.Column(db.String(64), unique=True, nullable=False)
    last_ingested = db.Column(db.DateTime, nullable=True)
    ioc_count     = db.Column(db.Integer, default=0)
    status        = db.Column(db.String(16), default="pending")

    def to_dict(self):
        return {
            "source":        self.source,
            "last_ingested": _dt(self.last_ingested) or "never",
            "ioc_count":     self.ioc_count,
            "status":        self.status,
        }
