import { useState, useEffect } from "react";

const T = {
  en: { title: "Fake-Job and Scam-Offer Detector", tag: "Detect fake job offers and internship scams before you lose money or personal information.",
    analyze: "Analyze Job Offer", paste: "Paste the job offer, email or recruiter message here…", home: "Analyze", history: "History", report: "Report Scam", db: "Scam Database", tips: "Safety Tips", about: "About" },
  hi: { title: "फेक-जॉब और स्कैम-ऑफर डिटेक्टर", tag: "पैसे या निजी जानकारी गंवाने से पहले फर्जी नौकरी और इंटर्नशिप ऑफर पहचानें।",
    analyze: "ऑफर का विश्लेषण करें", paste: "यहाँ जॉब ऑफर, ईमेल या रिक्रूटर संदेश पेस्ट करें…", home: "विश्लेषण", history: "इतिहास", report: "स्कैम रिपोर्ट", db: "स्कैम डेटाबेस", tips: "सुरक्षा सुझाव", about: "हमारे बारे में" },
  gu: { title: "ફેક-જોબ અને સ્કેમ-ઓફર ડિટેક્ટર", tag: "પૈસા કે અંગત માહિતી ગુમાવતા પહેલાં નકલી નોકરી અને ઇન્ટર્નશિપ ઓફર ઓળખો.",
    analyze: "ઓફરનું વિશ્લેષણ કરો", paste: "અહીં જોબ ઓફર, ઇમેઇલ અથવા રિક્રૂટર સંદેશ પેસ્ટ કરો…", home: "વિશ્લેષણ", history: "ઇતિહાસ", report: "સ્કેમ રિપોર્ટ", db: "સ્કેમ ડેટાબેઝ", tips: "સુરક્ષા ટિપ્સ", about: "અમારા વિશે" },
};
const cid = (() => { let c = localStorage.getItem("cid"); if (!c) { c = crypto.randomUUID(); localStorage.setItem("cid", c); } return c; })();
const api = async (path, opts = {}) => {
  const r = await fetch("/api" + path, { ...opts, headers: { "Content-Type": "application/json", "X-Client-Id": cid } });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail?.[0]?.msg || "Request failed (" + r.status + ")");
  return r.json();
};
const COLORS = (s) => s >= 80 ? "#34d399" : s >= 50 ? "#fbbf24" : s >= 25 ? "#fb923c" : "#f87171";
const card = "bg-slate-900 border border-slate-800 rounded-xl p-5";
const input = "w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 focus:outline-none focus:border-cyan-400";
const btn = "bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold rounded-lg px-5 py-2.5 disabled:opacity-50";

function Gauge({ score, label }) {
  const r = 52, c = 2 * Math.PI * r;
  return (<div className="flex flex-col items-center"><svg width="140" height="140" viewBox="0 0 140 140">
    <circle cx="70" cy="70" r={r} fill="none" stroke="#1e293b" strokeWidth="12" />
    <circle cx="70" cy="70" r={r} fill="none" stroke={COLORS(score)} strokeWidth="12" strokeLinecap="round" strokeDasharray={c} strokeDashoffset={c * (1 - score / 100)} transform="rotate(-90 70 70)" style={{ transition: "stroke-dashoffset 1s" }} />
    <text x="70" y="78" textAnchor="middle" fill="#fff" fontSize="32" fontWeight="700">{score}</text></svg>
    <span className="font-semibold" style={{ color: COLORS(score) }}>{label}</span></div>);
}

function Domain({ title, d }) {
  if (!d) return null;
  return (<div className="text-sm"><b>{title}:</b> {d.domain} · DNS: {d.dns} · Registered: {d.registered}{d.age_days != null && ` (${d.age_days} days ago)`}</div>);
}

function Result({ r }) {
  return (<div className="space-y-4 mt-6">
    <div className={card + " flex flex-wrap items-center gap-6"}><Gauge score={r.score} label={r.label} />
      <div className="flex-1 min-w-[220px] text-sm text-slate-300"><p className="mb-2">{r.disclaimer}</p>
        {r.company && <div><b>Company (as submitted, unverified):</b> {r.company}</div>}
        {r.email && <div><b>Recruiter email:</b> {r.email.email}</div>}
        <Domain title="Email domain" d={r.email?.check} /><Domain title="Website" d={r.website} /></div></div>
    <div className={card}><h3 className="font-semibold mb-3">Suspicious indicators ({r.findings.length})</h3>
      {r.findings.length === 0 && <p className="text-slate-400 text-sm">No rule-based indicators found. This does not guarantee the offer is genuine.</p>}
      {r.findings.map(f => (<div key={f.rule} className="mb-4 border-l-4 border-orange-400 pl-3">
        <div className="font-medium">{f.reason} <span className="text-xs text-slate-500">(−{f.weight})</span></div>
        {f.evidence.map((e, i) => <p key={i} className="text-sm italic text-amber-200 mt-1">“{e}”</p>)}</div>))}</div>
    {r.notes.length > 0 && <div className={card}><h3 className="font-semibold mb-2">Verification notes</h3><ul className="list-disc ml-5 text-sm text-slate-300 space-y-1">{r.notes.map((n, i) => <li key={i}>{n}</li>)}</ul></div>}
    <div className={card}><h3 className="font-semibold mb-2">Recommendations</h3><ul className="list-disc ml-5 text-sm text-slate-300 space-y-1">{r.recommendations.map((n, i) => <li key={i}>{n}</li>)}</ul>
      <button className={btn + " mt-4 noprint"} onClick={() => window.print()}>Download PDF</button></div></div>);
}

function Analyze({ t }) {
  const [f, setF] = useState({ text: "", company: "", email: "", website: "" }); const [res, setRes] = useState(null); const [busy, setBusy] = useState(false); const [err, setErr] = useState("");
  const go = async () => { setBusy(true); setErr(""); try { const body = Object.fromEntries(Object.entries(f).filter(([, v]) => v)); setRes(await api("/analyze", { method: "POST", body: JSON.stringify(body) })); } catch (e) { setErr(e.message); } setBusy(false); };
  return (<div><section className="text-center py-10"><h1 className="text-3xl md:text-5xl font-bold">{t.title}</h1><p className="text-slate-400 mt-3 max-w-2xl mx-auto">{t.tag}</p></section>
    <div className={card + " space-y-3"}><textarea rows={8} className={input} placeholder={t.paste} value={f.text} onChange={e => setF({ ...f, text: e.target.value })} />
      <div className="grid md:grid-cols-3 gap-3">{[["company", "Company name (optional)"], ["email", "Recruiter email (optional)"], ["website", "Company website (optional)"]].map(([k, p]) => <input key={k} className={input} placeholder={p} value={f[k]} onChange={e => setF({ ...f, [k]: e.target.value })} />)}</div>
      {err && <p className="text-red-400 text-sm">{err}</p>}<button className={btn} disabled={busy || f.text.length < 20} onClick={go}>{busy ? "Analyzing…" : t.analyze}</button></div>
    {res && <Result r={res} />}
    <div className="grid md:grid-cols-3 gap-4 mt-8 text-sm text-slate-300">{["A rule engine scans for fee requests, urgency, chat-only contact and more.", "Domains are checked with live DNS and RDAP lookups. If a service fails, we say “unavailable”.", "The score shows risk indicators only, not proof either way."].map((x, i) => <div key={i} className={card}>{x}</div>)}</div></div>);
}

function History() {
  const [rows, setRows] = useState([]); const [open, setOpen] = useState(null);
  useEffect(() => { api("/history").then(setRows).catch(() => {}); }, []);
  return (<div className="space-y-3">{rows.length === 0 && <p className="text-slate-400">No analyses yet.</p>}
    {rows.map(r => <div key={r.id} className={card + " cursor-pointer"} onClick={async () => setOpen(await api("/report/" + r.id))}>
      <div className="flex justify-between"><span style={{ color: COLORS(r.score) }} className="font-semibold">{r.score} · {r.label}</span><span className="text-xs text-slate-500">{new Date(r.created_at).toLocaleString()}</span></div>
      <p className="text-sm text-slate-400 mt-1">{r.snippet}…</p></div>)}{open && <Result r={open} />}</div>);
}

function Report() {
  const [f, setF] = useState({ kind: "company", value: "", details: "" }); const [msg, setMsg] = useState("");
  const send = async () => { try { const r = await api("/report-scam", { method: "POST", body: JSON.stringify(f) }); setMsg(r.note); setF({ ...f, value: "", details: "" }); } catch (e) { setMsg(e.message); } };
  return (<div className={card + " space-y-3 max-w-xl"}><select className={input} value={f.kind} onChange={e => setF({ ...f, kind: e.target.value })}>{["company", "email", "website", "phone", "offer"].map(k => <option key={k}>{k}</option>)}</select>
    <input className={input} placeholder="Company, email, website, phone…" value={f.value} onChange={e => setF({ ...f, value: e.target.value })} />
    <textarea className={input} rows={4} placeholder="What happened? (don't include your own personal details)" value={f.details} onChange={e => setF({ ...f, details: e.target.value })} />
    <button className={btn} onClick={send} disabled={f.value.length < 3}>Submit report</button>{msg && <p className="text-sm text-cyan-300">{msg}</p>}</div>);
}

function Database() {
  const [q, setQ] = useState(""); const [rows, setRows] = useState([]);
  useEffect(() => { api("/scam-database?q=" + encodeURIComponent(q)).then(setRows).catch(() => {}); }, [q]);
  return (<div><input className={input + " mb-4"} placeholder="Search reported companies, domains, emails…" value={q} onChange={e => setQ(e.target.value)} />
    <p className="text-xs text-slate-500 mb-3">Entries are community reports and remain “unverified” until reviewed. They are not confirmed scams.</p>
    {rows.map(r => <div key={r.id} className={card + " mb-2 flex justify-between"}><span>{r.value} <span className="text-xs text-slate-500">({r.kind})</span></span><span className="text-xs text-amber-300">{r.status}</span></div>)}</div>);
}

const Static = ({ items }) => <div className="space-y-3 max-w-2xl">{items.map((x, i) => <div key={i} className={card + " text-slate-300"}>{x}</div>)}</div>;

export default function App() {
  const [lang, setLang] = useState("en"); const [page, setPage] = useState("home"); const t = T[lang];
  const nav = [["home", t.home], ["history", t.history], ["report", t.report], ["db", t.db], ["tips", t.tips], ["about", t.about]];
  return (<div><nav className="sticky top-0 z-10 bg-slate-950/90 backdrop-blur border-b border-slate-800"><div className="max-w-5xl mx-auto px-4 py-3 flex flex-wrap items-center gap-2">
    <span className="font-bold text-cyan-400 mr-4">🛡 ScamDetector</span>
    {nav.map(([k, l]) => <button key={k} onClick={() => setPage(k)} className={"px-3 py-1 rounded-lg text-sm " + (page === k ? "bg-slate-800 text-cyan-300" : "text-slate-400 hover:text-white")}>{l}</button>)}
    <select className="ml-auto bg-slate-900 border border-slate-700 rounded px-2 py-1 text-sm" value={lang} onChange={e => setLang(e.target.value)}><option value="en">EN</option><option value="hi">हिन्दी</option><option value="gu">ગુજરાતી</option></select></div></nav>
    <main className="max-w-5xl mx-auto px-4 py-6">
      {page === "home" && <Analyze t={t} />}{page === "history" && <History />}{page === "report" && <Report />}{page === "db" && <Database />}
      {page === "tips" && <Static items={["Genuine employers never charge candidates registration, training or security fees.", "Verify the company on its official website and find contact details yourself.", "Be wary of WhatsApp/Telegram-only hiring, urgency, and “no interview” promises.", "Never share OTPs, passwords, card or banking details.", "If you've paid: contact your bank immediately and report at cybercrime.gov.in or call 1930."]} />}
      {page === "about" && <Static items={["Built to protect students and freshers from fake job and internship offers.", "Results are risk indicators, not verdicts. Always verify independently."]} />}</main></div>);
}
