
export interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: number;
  attachment?: {
    data: string; // Base64 encoded (encrypted in storage)
    mimeType: string;
    name: string;
  };
}

export interface ChatSession {
  id: string;
  title: string;
  lastMessage: string;
  messages: Message[];
}
