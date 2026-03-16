from fastapi import FastAPI

app = FastAPI(title="SentinelAI API", version="1.0.0")

@app.get("/")
async def root():
    return {"message": "Welcome to SentinelAI API"}

@app.get("/health")
async def health():
    return {"status": "healthy"}
