from backend.database import SessionLocal, engine
from backend import models
import sys

def verify_db():
    print("Initializing Database...")
    models.Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    
    try:
        # Test 1: Credentials Encryption
        print("\n[Test 1] Testing Credential Encryption...")
        service = "test_ai_service"
        key = "sk-1234567890abcdef"
        
        # Cleanup
        db.query(models.Credential).filter(models.Credential.service_name == service).delete()
        
        print(f"Storing key: {key}")
        cred = models.Credential(service_name=service)
        cred.api_key = key
        db.add(cred)
        db.commit()
        
        # Verify it's encrypted in DB (inspecting raw field)
        db.refresh(cred)
        raw_val = cred._api_key
        print(f"Raw DB Value (Encrypted): {raw_val}")
        if raw_val == key:
            print("FAILURE: Key is stored in plaintext!")
            sys.exit(1)
            
        # Verify decryption
        print(f"Decrypted Value: {cred.api_key}")
        if cred.api_key != key:
             print("FAILURE: Decryption mismatch!")
             sys.exit(1)
        print("SUCCESS: Credential encryption passed.")

        # Test 2: Conversation & Messages
        print("\n[Test 2] Testing Chat History...")
        chat = models.Conversation(title="Test Chat")
        db.add(chat)
        db.commit()
        
        msg_content = "Hello, Hades!"
        msg = models.Message(conversation_id=chat.id, role="user")
        msg.content = msg_content
        db.add(msg)
        db.commit()
        
        db.refresh(msg)
        print(f"Stored Message: {msg.content}")
        print(f"Raw Message (Encrypted): {msg._content}")
        
        if msg.content != msg_content:
            print("FAILURE: Message content mismatch!")
            sys.exit(1)
        if msg._content == msg_content:
             print("FAILURE: Message stored in plaintext!")
             sys.exit(1)
             
        print("SUCCESS: Chat history encryption passed.")
        
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)
    finally:
        db.close()

if __name__ == "__main__":
    verify_db()
