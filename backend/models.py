# Author: OUSSAMA ASLOUJ
from sqlalchemy import Column, Integer, String, Text, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base
from .crypto_utils import encrypt, decrypt

class Conversation(Base):
    __tablename__ = "conversations"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, default="New Chat")
    created_at = Column(DateTime, default=datetime.utcnow)
    
    messages = relationship("Message", back_populates="conversation", cascade="all, delete-orphan")

class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    conversation_id = Column(Integer, ForeignKey("conversations.id"))
    role = Column(String)  # 'user' or 'assistant'
    _content = Column("content", Text) # Encrypted content
    created_at = Column(DateTime, default=datetime.utcnow)

    conversation = relationship("Conversation", back_populates="messages")

    @property
    def content(self):
        return decrypt(self._content)

    @content.setter
    def content(self, value):
        self._content = encrypt(value)

class Credential(Base):
    __tablename__ = "credentials"

    id = Column(Integer, primary_key=True, index=True)
    service_name = Column(String, unique=True, index=True) # e.g., 'openai', 'anthropic'
    _api_key = Column("api_key", String) # Encrypted API key

    @property
    def api_key(self):
        return decrypt(self._api_key)

    @api_key.setter
    def api_key(self, value):
        self._api_key = encrypt(value)
