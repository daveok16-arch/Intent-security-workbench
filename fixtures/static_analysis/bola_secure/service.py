# Secure Service (Python/FastAPI)
# Target record protected by strict owner authorization check

from fastapi import FastAPI, HTTPException, Depends
from models import get_db, Document, get_current_user

app = FastAPI()

@app.get("/api/v1/documents/{doc_id}")
def read_document(doc_id: str, current_user=Depends(get_current_user), db=Depends(get_db)):
    document = db.query(Document).filter(Document.id == doc_id).first()
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
    
    # Secure ownership authorization check
    if document.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Forbidden: Resource belongs to another tenant")
        
    return document
