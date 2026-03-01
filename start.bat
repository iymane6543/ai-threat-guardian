@echo off
echo Lancement de AI Threat Guardian...
cd C:\Users\Admin\Downloads\backend
call venv\Scripts\activate
start http://127.0.0.1:8000
uvicorn api:app --host 127.0.0.1 --port 8000