# Author: OUSSAMA ASLOUJ
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from . import models, database, crypto_utils

# Create tables on startup
models.Base.metadata.create_all(bind=database.engine)

app = FastAPI(title="Project Hades Backend")

# Dependency
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Pydantic Schemas
class MessageCreate(BaseModel):
    role: str
    content: str

class MessageRead(BaseModel):
    id: int
    role: str
    content: str
    created_at: str # Simplification for demo

    class Config:
        orm_mode = True

class ConversationRead(BaseModel):
    id: int
    title: str
    messages: List[MessageRead] = []

    class Config:
        orm_mode = True

class CredentialCreate(BaseModel):
    service_name: str
    api_key: str

@app.get("/")
def read_root():
    return {"message": "Project Hades Backend Operational"}

# --- Conversation Endpoints ---

@app.post("/conversations/", response_model=ConversationRead)
def create_conversation(title: str = "New Chat", db: Session = Depends(get_db)):
    db_conv = models.Conversation(title=title)
    db.add(db_conv)
    db.commit()
    db.refresh(db_conv)
    return db_conv

@app.get("/conversations/", response_model=List[ConversationRead])
def get_conversations(db: Session = Depends(get_db)):
    return db.query(models.Conversation).all()

@app.post("/conversations/{conversation_id}/messages/", response_model=MessageRead)
def add_message(conversation_id: int, message: MessageCreate, db: Session = Depends(get_db)):
    db_conv = db.query(models.Conversation).filter(models.Conversation.id == conversation_id).first()
    if not db_conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
    
    db_msg = models.Message(conversation_id=conversation_id, role=message.role)
    # Crypto handled by model property setter
    db_msg.content = message.content 
    
    db.add(db_msg)
    db.commit()
    db.refresh(db_msg)
    
    return {
        "id": db_msg.id,
        "role": db_msg.role,
        "content": db_msg.content, # Decrypted on access
        "created_at": str(db_msg.created_at)
    }

# --- Credential Endpoints ---

@app.post("/credentials/")
def store_credential(cred: CredentialCreate, db: Session = Depends(get_db)):
    # Check if exists
    existing = db.query(models.Credential).filter(models.Credential.service_name == cred.service_name).first()
    if existing:
        existing.api_key = cred.api_key
    else:
        new_cred = models.Credential(service_name=cred.service_name)
        new_cred.api_key = cred.api_key
        db.add(new_cred)
    
    db.commit()
    return {"status": "success", "service": cred.service_name}

@app.get("/credentials/{service_name}")
def get_credential(service_name: str, db: Session = Depends(get_db)):
    cred = db.query(models.Credential).filter(models.Credential.service_name == service_name).first()
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    
    # In a real app, you might not want to return the raw key via API, 
    # but for internal verification/usage we might need it. 
    # Or just returning mask for now.
    return {"service": service_name, "api_key": cred.api_key[:5] + "***"} 

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
