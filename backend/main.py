import os, re, socket
from datetime import datetime, timezone
import httpx
from fastapi import FastAPI, HTTPException, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, JSON, select
from sqlalchemy.orm import declarative_base, sessionmaker

# Set DATABASE_URL=postgresql://user:pass@localhost/scamdb for PostgreSQL (SQLite fallback for quick dev)
engine = create_engine(os.getenv("DATABASE_URL", "sqlite:///./dev.db"))
Session = sessionmaker(engine)
Base = declarative_base()
now = lambda: datetime.now(timezone.utc)

class Submission(Base):  # offer + analysis result (anonymous client_id, no personal profile stored)
    __tablename__ = "submissions"
    id = Column(Integer, primary_key=True); client_id = Column(String(64), index=True)
    offer_text = Column(Text); score = Column(Integer); label = Column(String(32))
    report = Column(JSON); created_at = Column(DateTime(timezone=True), default=now)

class ScamReport(Base):  # community reports stay 'unverified' until reviewed by a moderator
    __tablename__ = "scam_reports"
    id = Column(Integer, primary_key=True); kind = Column(String(20), index=True)
    value = Column(String(255), index=True); details = Column(Text)
    status = Column(String(20), default="unverified"); created_at = Column(DateTime(timezone=True), default=now)

Base.metadata.create_all(engine)
app = FastAPI(title="Fake-Job and Scam-Offer Detector")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_methods=["*"], allow_headers=["*"])

# (id, regex, weight, reason): each hit returns the matching sentence as evidence
RULES = [
 ("fee", r"(registration|training|security|processing|kit|joining|refundable)\s*(fee|deposit|amount|charges?)|\bdeposit\b|pay\s*(rs\.?|₹|inr)?\s*\d+", 35, "Asks for money from the candidate. Genuine employers do not charge candidates to hire them."),
 ("urgency", r"within\s+\d+\s*(hours?|hrs?|minutes?)|immediately|urgent|last chance|limited seats|today only", 12, "Pressures you to decide fast, a common tactic to stop you from verifying."),
 ("chat_only", r"whats\s*app|telegram", 12, "Moves communication to WhatsApp/Telegram, which is hard to verify or trace."),
 ("no_interview", r"no interview|without (an )?interview|direct (selection|joining)|100% (selection|placement)|guaranteed (job|placement)", 20, "Promises selection without an interview or assessment."),
 ("high_pay", r"(rs\.?|₹|inr)\s*\d[\d,]*\s*(per|/|a)\s*(day|week)|earn\s+(rs\.?|₹)?\s*\d{4,}\s*(daily|per day|weekly)|easy money", 15, "Unusually high or quick earnings are promised."),
 ("sensitive", r"\botp\b|password|\bcvv\b|bank account|aadhaar|pan card|card number|passport", 20, "Requests sensitive personal or financial data, which is not needed at offer stage."),
]
FREE_MAIL = {"gmail.com","yahoo.com","outlook.com","hotmail.com","rediffmail.com","proton.me"}

class AnalyzeIn(BaseModel):
    text: str = Field(min_length=20, max_length=10000)
    company: str | None = Field(None, max_length=200)
    email: str | None = Field(None, max_length=200)
    website: str | None = Field(None, max_length=300)

class ReportIn(BaseModel):
    kind: str = Field(pattern="^(company|email|website|phone|offer)$")
    value: str = Field(min_length=3, max_length=255); details: str = Field("", max_length=2000)

def domain_check(domain):
    out = {"domain": domain, "dns": "unavailable", "registered": "unavailable", "age_days": None}
    try: socket.getaddrinfo(domain, None); out["dns"] = "resolves"
    except socket.gaierror: out["dns"] = "does not resolve"
    except Exception: pass
    try:
        r = httpx.get(f"https://rdap.org/domain/{domain}", timeout=8, follow_redirects=True)
        if r.status_code == 200:
            for ev in r.json().get("events", []):
                if ev.get("eventAction") == "registration":
                    d = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                    out.update(registered=d.date().isoformat(), age_days=(now() - d).days)
        elif r.status_code == 404: out["registered"] = "no RDAP record found"
    except Exception: pass  # stays 'unavailable': never fabricate results
    return out

def analyze(p: AnalyzeIn):
    score, findings, notes = 100, [], []
    sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+|\n+", p.text) if s.strip()]
    for rid, rx, w, why in RULES:
        hits = [s for s in sentences if re.search(rx, s, re.I)]
        if hits:
            score -= w
            findings.append({"rule": rid, "weight": w, "reason": why, "evidence": hits[:3]})
    email_info = web_info = None
    if p.email:
        dom = p.email.split("@")[-1].lower().strip()
        email_info = {"email": p.email, "domain": dom, "free_provider": dom in FREE_MAIL}
        if dom in FREE_MAIL:
            score -= 8; notes.append(f"Recruiter uses a free email provider ({dom}). This alone does not prove fraud, but verify the recruiter independently.")
        else: email_info["check"] = domain_check(dom)
    if p.website:
        host = re.sub(r"^https?://", "", p.website.strip().lower()).split("/")[0]
        web_info = domain_check(host)
        if web_info["dns"] == "does not resolve": score -= 15; notes.append("Company website domain does not resolve in DNS.")
        if web_info["age_days"] is not None and web_info["age_days"] < 180:
            score -= 8; notes.append(f"Domain registered only {web_info['age_days']} days ago. New domains are a weak signal, not proof.")
        if web_info["registered"] == "unavailable": notes.append("Domain registration lookup was unavailable; no conclusion drawn.")
    else: notes.append("No company website provided, so the employer could not be verified.")
    if not p.company: notes.append("No company name provided.")
    score = max(0, min(100, score))
    label = "Lower Risk" if score >= 80 else "Needs Verification" if score >= 50 else "Suspicious" if score >= 25 else "High Risk"
    recs = ["Verify the employer through its official website and independently found contact details.", "Never share OTPs, passwords or banking information."]
    if any(f["rule"] == "fee" for f in findings): recs.insert(0, "Do not pay any fee. If you already paid, contact your bank at once and report it at cybercrime.gov.in (helpline 1930 in India).")
    return {"score": score, "label": label, "findings": findings, "notes": notes, "company": p.company,
            "email": email_info, "website": web_info, "recommendations": recs,
            "disclaimer": "Score reflects risk indicators only. It does not prove an offer is genuine or fraudulent."}

@app.post("/analyze")
def analyze_ep(p: AnalyzeIn, x_client_id: str = Header("anon", max_length=64)):
    rep = analyze(p)
    with Session() as s:
        sub = Submission(client_id=x_client_id, offer_text=p.text, score=rep["score"], label=rep["label"], report=rep)
        s.add(sub); s.commit(); rep["id"] = sub.id
    return rep

@app.get("/history")
def history(x_client_id: str = Header("anon", max_length=64)):
    with Session() as s:
        rows = s.scalars(select(Submission).where(Submission.client_id == x_client_id).order_by(Submission.id.desc()).limit(50))
        return [{"id": r.id, "created_at": r.created_at, "score": r.score, "label": r.label, "snippet": r.offer_text[:120]} for r in rows]

@app.get("/report/{rid}")
def get_report(rid: int, x_client_id: str = Header("anon", max_length=64)):
    with Session() as s:
        r = s.get(Submission, rid)
        if not r or r.client_id != x_client_id: raise HTTPException(404, "Report not found")
        return {**r.report, "id": r.id, "offer_text": r.offer_text, "created_at": r.created_at}

@app.post("/report-scam", status_code=201)
def report_scam(p: ReportIn):
    with Session() as s:
        s.add(ScamReport(kind=p.kind, value=p.value.strip().lower(), details=p.details)); s.commit()
    return {"status": "received", "note": "Report received. It stays 'unverified' until reviewed."}

@app.get("/scam-database")
def scam_db(q: str = Query("", max_length=100)):
    with Session() as s:
        stmt = select(ScamReport).where(ScamReport.value.contains(q.lower())).order_by(ScamReport.id.desc()).limit(50)
        return [{"id": r.id, "kind": r.kind, "value": r.value, "status": r.status, "created_at": r.created_at} for r in s.scalars(stmt)]
