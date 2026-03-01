from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import pickle
from database import init_db, save_analysis, get_all_analyses, get_stats

model = pickle.load(open('models/model.pkl', 'rb'))
scaler = pickle.load(open('models/scaler.pkl', 'rb'))

app = FastAPI(title="AI Threat Guardian")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="frontend"), name="static")

init_db()

class NetworkLog(BaseModel):
    duration: float
    protocol_type: float
    service: float
    flag: float
    src_bytes: float
    dst_bytes: float
    count: float
    srv_count: float
    serror_rate: float
    rerror_rate: float
    same_srv_rate: float
    dst_host_count: float
    dst_host_srv_count: float

@app.get("/")
def home():
    return FileResponse("frontend/index.html")

@app.post("/analyze")
def analyze(log: NetworkLog):
    features = [[
        log.duration, log.protocol_type, log.service, log.flag,
        log.src_bytes, log.dst_bytes, log.count, log.srv_count,
        log.serror_rate, log.rerror_rate, log.same_srv_rate,
        log.dst_host_count, log.dst_host_srv_count
    ]]

    scaled = scaler.transform(features)
    prediction = model.predict(scaled)

    is_threat = bool(prediction[0] == -1)
    score = float(model.score_samples(scaled)[0])
    severity = "ATTAQUE DETECTEE" if is_threat else "Trafic Normal"

    save_analysis(
        log.src_bytes, log.dst_bytes, log.count,
        log.serror_rate, is_threat, severity, score
    )

    return {
        "is_threat": is_threat,
        "severity": severity,
        "score": score
    }

@app.get("/history")
def history():
    rows = get_all_analyses()
    return [
        {
            "id": r[0],
            "timestamp": r[1],
            "src_bytes": r[2],
            "count": r[4],
            "is_threat": bool(r[6]),
            "severity": r[7],
            "score": r[8]
        }
        for r in rows
    ]

@app.get("/stats")
def stats():
    return get_stats()

@app.get("/health")
def health():
    return {"status": "OK", "model": "Loaded"}