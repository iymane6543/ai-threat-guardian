# AI Threat Guardian

> Network Intrusion Detection System powered by Machine Learning

![Python](https://img.shields.io/badge/Python-3.11-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100-green)
![ML](https://img.shields.io/badge/ML-IsolationForest-orange)
![SQLite](https://img.shields.io/badge/Database-SQLite-lightgrey)

## Description

AI Threat Guardian is an intelligent network intrusion detection system that uses Machine Learning to analyze network traffic in real time and automatically detect cyberattacks.

## Features

- Real-time network anomaly detection
- ML model trained on 125,973 real connections (NSL-KDD dataset)
- REST API built with FastAPI
- Interactive web dashboard
- Analysis history stored with SQLite
- Security score for each analyzed connection

## Architecture
```
Network Data → ML Engine → FastAPI → Web Dashboard
                   ↓
                SQLite DB
```

## Technologies

| Layer | Technology |
|-------|------------|
| Machine Learning | Python, Scikit-learn, Isolation Forest |
| Backend API | FastAPI, Uvicorn |
| Database | SQLite |
| Frontend | HTML, CSS, JavaScript |
| Dataset | NSL-KDD (125,973 entries) |

## Installation
```bash
git clone https://github.com/iymane6543/ai-threat-guardian.git
cd ai-threat-guardian
pip install fastapi uvicorn scikit-learn pandas numpy aiofiles
python main.py
uvicorn api:app --reload
```

## Usage

1. Start the API with `uvicorn api:app --reload`
2. Open `http://127.0.0.1:8000` in your browser
3. Enter the network connection parameters
4. Click Analyze to detect threats

## Results

- Dataset : NSL-KDD (125,973 connections)
- Algorithm : Isolation Forest
- Attack types detected : DoS, Probe, R2L, U2R

## Author

**Iymane Bolakhrif** - Computer Science Student, 3rd Year
Project combining Software Engineering 

