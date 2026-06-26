import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dotenv import load_dotenv
load_dotenv()

from app import create_app
from models import db, FeedStatus

app = create_app()

with app.app_context():
    db.create_all()
    sources = ["abusech_malware", "abusech_url", "feodo", "otx", "cisa_kev"]
    for s in sources:
        if not FeedStatus.query.filter_by(source=s).first():
            db.session.add(FeedStatus(source=s, status="pending"))
    db.session.commit()
    print("✅ Database created at data/ticluster.db")