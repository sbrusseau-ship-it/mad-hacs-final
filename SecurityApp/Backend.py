from flask import Flask

app = Flask(__name__)


@app.get("/api/health")
def health():
    return {"status": "ok"}

@app.post("/api/search")
def search():
    return {"message": "Demo request received. No breach lookup was performed."}
    
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
    
    
    