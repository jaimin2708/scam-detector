# Fake-Job and Scam-Offer Detector
Backend: `cd backend && pip install -r requirements.txt && DATABASE_URL=postgresql://user:pass@localhost/scamdb uvicorn main:app --reload`
(omit DATABASE_URL for a local SQLite file during quick dev)
Frontend: `cd frontend && npm install && npm run dev` then open http://localhost:5173
