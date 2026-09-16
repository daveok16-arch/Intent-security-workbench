# Vulnerable BOLA Service (Python/FastAPI)
# Target record fetched directly from database without comparing requester identity

from fastapi import FastAPI, HTTPException, Depends
from models import get_db, Document

app = FastAPI()

@app.get("/api/v1/documents/{doc_id}")
def read_document(doc_id: str, db=Depends(get_db)):
    # VULNERABLE: Direct access to document without tenant/ownership validation
    document = db.query(Document).filter(Document.id == doc_id).first()
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
    
    # Missing authorization check: returns document irrespective of requester
    return document
