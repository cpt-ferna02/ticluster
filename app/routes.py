from flask import Blueprint, render_template, jsonify, abort
from models import IOC, Campaign, FeedStatus

bp = Blueprint("main", __name__)


@bp.route("/")
def index():
    return render_template("index.html")


@bp.route("/api/iocs")
def api_iocs():
    iocs = IOC.query.order_by(IOC.last_seen.desc()).limit(200).all()
    return jsonify([i.to_dict() for i in iocs])


@bp.route("/api/campaigns")
def api_campaigns():
    campaigns = Campaign.query.order_by(Campaign.confidence.desc()).all()
    # Exclude full IOC list and sigma from the list view — keep payload small
    result = []
    for c in campaigns:
        d = c.to_dict()
        d.pop("iocs", None)
        d.pop("sigma_rule", None)
        result.append(d)
    return jsonify(result)


@bp.route("/api/campaigns/<int:campaign_id>")
def api_campaign_detail(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    d = campaign.to_dict()
    d.pop("sigma_rule", None)   # fetched separately
    return jsonify(d)


@bp.route("/api/campaigns/<int:campaign_id>/sigma")
def api_campaign_sigma(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    if not campaign.sigma_rule:
        abort(404)
    return campaign.sigma_rule, 200, {"Content-Type": "text/plain; charset=utf-8"}


@bp.route("/api/feeds")
def api_feeds():
    feeds = FeedStatus.query.all()
    return jsonify([f.to_dict() for f in feeds])


@bp.route("/api/stats")
def api_stats():
    return jsonify({
        "total_iocs":      IOC.query.count(),
        "total_campaigns": Campaign.query.count(),
        "high_confidence": Campaign.query.filter(Campaign.confidence >= 0.65).count(),
        "noise_iocs":      IOC.query.filter(IOC.campaign_id.is_(None)).count(),
    })