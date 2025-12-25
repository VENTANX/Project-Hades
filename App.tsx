
// Author: OUSSAMA ASLOUJ
import React, { useState, useEffect, useRef } from 'react';
import {
  Terminal,
  Shield,
  Cpu,
  Send,
  Lock,
  Power,
  UserPlus,
  LogIn,
  Fingerprint,
  Activity,
  ShieldAlert,
  Paperclip,
  FileText,
  X,
  HardDrive,
  Plus,
  Globe,
  Unlock,
  Key,
  EyeOff,
  Menu,
  ChevronRight,
  Database,
  Trash2,
  Flame,
  AlertOctagon
} from 'lucide-react';
import { Message, ChatSession } from './types';
import { getHadesResponse } from './services/geminiService';
import { encryptData, decryptData, hashId, createVerificationHash } from './services/securityService';

type AuthView = 'login' | 'signup' | 'authenticated';

const MatrixBackground: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);
    const characters = 'アカサタナハマヤラワ0123456789ABCDEF';
    const charArray = characters.split('');
    const fontSize = 12;
    const columns = width / fontSize;
    const drops: number[] = Array(Math.floor(columns)).fill(1);
    const draw = () => {
      ctx.fillStyle = 'rgba(10, 10, 10, 0.1)';
      ctx.fillRect(0, 0, width, height);
      ctx.font = `${fontSize}px font-mono`;
      for (let i = 0; i < drops.length; i++) {
        const text = charArray[Math.floor(Math.random() * charArray.length)];
        ctx.fillStyle = Math.random() > 0.98 ? '#fff' : '#ff003c';
        ctx.globalAlpha = Math.random() * 0.2 + 0.05;
        ctx.fillText(text, i * fontSize, drops[i] * fontSize);
        if (drops[i] * fontSize > height && Math.random() > 0.975) drops[i] = 0;
        drops[i]++;
      }
    };
    const interval = setInterval(draw, 40);
    const handleResize = () => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };
    window.addEventListener('resize', handleResize);
    // Fix: clearInterval only accepts 1 argument (the interval ID).
    return () => { clearInterval(interval); window.removeEventListener('resize', handleResize); };
  }, []);
  return <canvas ref={canvasRef} className="fixed inset-0 z-0 pointer-events-none opacity-40" />;
};

const App: React.FC = () => {
  const [authView, setAuthView] = useState<AuthView>('login');
  const [user, setUser] = useState<string | null>(null);
  const [userId, setUserId] = useState<string | null>(null);
  const [userHash, setUserHash] = useState<string | null>(null);
  const [sessionKey, setSessionKey] = useState<string | null>(null);
  const [nexusUrl, setNexusUrl] = useState(localStorage.getItem('hades_nexus_url') || 'http://localhost:5001');

  const [sessions, setSessions] = useState<ChatSession[]>([]);
  const [currentSessionId, setCurrentSessionId] = useState<string | null>(null);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);

  const [isVaultDecrypted, setIsVaultDecrypted] = useState(false);
  const [isPromptingKey, setIsPromptingKey] = useState(false);
  const [isPromptingPurge, setIsPromptingPurge] = useState(false);
  const [purgeConfirmation, setPurgeConfirmation] = useState('');
  const [unlockInput, setUnlockInput] = useState('');
  const [unlockError, setUnlockError] = useState<string | null>(null);

  const [input, setInput] = useState('');
  const [isWaiting, setIsWaiting] = useState(false);
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [decryptedMessages, setDecryptedMessages] = useState<Record<string, string>>({});
  const [decryptedAttachments, setDecryptedAttachments] = useState<Record<string, string>>({});

  const abortControllerRef = useRef<AbortController | null>(null);
  const lastLoadedHash = useRef<string | null>(null);

  const [pendingFile, setPendingFile] = useState<{ data: string, mimeType: string, name: string } | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [stats, setStats] = useState({ cpu: 12, ram: 4.2, gpu: 42 });

  const chatEndRef = useRef<HTMLDivElement>(null);
  const currentSession = sessions.find(s => s.id === currentSessionId);

  useEffect(() => {
    if (userHash) {
      const stored = localStorage.getItem(`hades_vault_${userHash}`);
      if (stored) {
        try {
          const parsed = JSON.parse(stored) as ChatSession[];
          setSessions(parsed);
          if (parsed.length > 0) setCurrentSessionId(parsed[0].id);
          lastLoadedHash.current = userHash;
        } catch (e) {
          console.error("Failed to parse vault data", e);
        }
      } else {
        const initialId = Date.now().toString();
        const initial = { id: initialId, title: 'Nexus Genesis', lastMessage: 'The ritual begins.', messages: [] };
        setSessions([initial]);
        setCurrentSessionId(initialId);
        lastLoadedHash.current = userHash;
      }
    }
  }, [userHash]);

  useEffect(() => {
    if (userHash && sessions.length >= 0 && userHash === lastLoadedHash.current) {
      localStorage.setItem(`hades_vault_${userHash}`, JSON.stringify(sessions));
    }
  }, [sessions, userHash]);

  useEffect(() => {
    const session = sessions.find(s => s.id === currentSessionId);
    setIsVaultDecrypted(session ? session.messages.length === 0 : true);
    setDecryptedMessages({});
    setDecryptedAttachments({});
    setUnlockError(null);
    if (window.innerWidth < 768) setIsSidebarOpen(false);
  }, [currentSessionId]);

  const toggleDecryption = async () => {
    if (isVaultDecrypted) {
      setIsVaultDecrypted(false);
      setDecryptedMessages({});
      setDecryptedAttachments({});
      return;
    }
    setIsPromptingKey(true);
  };

  const handleDecipher = async () => {
    if (!currentSession || !unlockInput) return;
    setUnlockError(null);
    const keyToUse = unlockInput;
    const newCache: Record<string, string> = {};
    const newAttachCache: Record<string, string> = {};

    try {
      if (currentSession.messages.length > 0) {
        const testMsg = currentSession.messages[0];
        const testDec = await decryptData(testMsg.content, keyToUse);
        if (testDec === 'DECRYPTION_ERROR: INVALID_KEY') {
          setUnlockError("CRYPTOGRAPHIC_FAILURE: KEY_MISMATCH");
          return;
        }
      }

      for (const msg of currentSession.messages) {
        if (msg.content) newCache[msg.id] = await decryptData(msg.content, keyToUse);
        if (msg.attachment) newAttachCache[msg.id] = await decryptData(msg.attachment.data, keyToUse);
      }

      setDecryptedMessages(newCache);
      setDecryptedAttachments(newAttachCache);
      setSessionKey(keyToUse);
      setIsVaultDecrypted(true);
      setIsPromptingKey(false);
      setUnlockInput('');
    } catch (e) {
      setUnlockError("ACCESS_VIOLATION: PROTECTION_ENABLED");
    }
  };

  const handlePurge = async (deleteAccount: boolean) => {
    if (!userHash) return;
    if (deleteAccount && purgeConfirmation !== 'PURGE') return;

    localStorage.removeItem(`hades_vault_${userHash}`);
    setSessions([]);
    setCurrentSessionId(null);
    setDecryptedMessages({});
    setDecryptedAttachments({});

    if (deleteAccount && userId) {
      const registry = JSON.parse(localStorage.getItem('hades_registry_v2') || '{}');
      delete registry[userId.toLowerCase().trim()];
      localStorage.setItem('hades_registry_v2', JSON.stringify(registry));

      setUser(null);
      setUserId(null);
      setUserHash(null);
      setSessionKey(null);
      setAuthView('login');
    } else {
      const initialId = Date.now().toString();
      const initial = { id: initialId, title: 'Nexus Genesis', lastMessage: 'The ritual begins.', messages: [] };
      setSessions([initial]);
      setCurrentSessionId(initialId);
      setIsVaultDecrypted(true);
    }

    setIsPromptingPurge(false);
    setPurgeConfirmation('');
  };

  useEffect(() => {
    const interval = setInterval(() => {
      setStats({
        cpu: Math.floor(Math.random() * 15) + 10,
        ram: Number((4.1 + Math.random() * 0.8).toFixed(1)),
        gpu: Math.floor(Math.random() * 10) + 38
      });
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  const [authId, setAuthId] = useState('');
  const [authKey, setAuthKey] = useState('');
  const [authConfirm, setAuthConfirm] = useState('');
  const [authError, setAuthError] = useState<string | null>(null);

  const scrollToBottom = (behavior: ScrollBehavior = 'smooth') => {
    chatEndRef.current?.scrollIntoView({ behavior });
  };

  useEffect(() => {
    if (authView === 'authenticated') scrollToBottom();
  }, [currentSession?.messages, isVaultDecrypted, authView]);

  const startNewSession = () => {
    const id = Date.now().toString();
    const newSession: ChatSession = {
      id,
      title: `Nexus_${id.slice(-4)}`,
      lastMessage: 'Awaiting command...',
      messages: []
    };
    setSessions(prev => [newSession, ...prev]);
    setCurrentSessionId(id);
    setIsVaultDecrypted(true);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (re) => {
        const base64 = (re.target?.result as string).split(',')[1];
        setPendingFile({ data: base64, mimeType: file.type, name: file.name });
      };
      reader.readAsDataURL(file);
    }
  };

  const handleSend = async () => {
    if ((!input.trim() && !pendingFile) || isWaiting || !sessionKey || !currentSessionId) return;

    setIsEncrypting(true);
    const userPromptPlain = input || (pendingFile ? `Analyze artifact: ${pendingFile.name}` : "");
    const userPromptEncrypted = await encryptData(userPromptPlain, sessionKey);

    let encryptedAttachment = null;
    if (pendingFile) {
      const encData = await encryptData(pendingFile.data, sessionKey);
      encryptedAttachment = { data: encData, mimeType: pendingFile.mimeType, name: pendingFile.name };
    }
    setIsEncrypting(false);

    const userMessageId = Date.now().toString();
    const userMessage: Message = {
      id: userMessageId,
      role: 'user',
      content: userPromptEncrypted,
      timestamp: Date.now(),
      attachment: encryptedAttachment || undefined
    };

    setDecryptedMessages(prev => ({ ...prev, [userMessageId]: userPromptPlain }));
    if (pendingFile) setDecryptedAttachments(prev => ({ ...prev, [userMessageId]: pendingFile.data }));

    const assistantPlaceholderId = (Date.now() + 1).toString();
    const assistantPlaceholder: Message = { id: assistantPlaceholderId, role: 'assistant', content: '', timestamp: Date.now() + 1 };

    setSessions(prev => prev.map(s => s.id === currentSessionId
      ? { ...s, messages: [...s.messages, userMessage, assistantPlaceholder], lastMessage: userPromptPlain.slice(0, 30) + '...' }
      : s
    ));

    const currentHistory: { role: string, content: string }[] = [];
    if (currentSession) {
      for (const m of currentSession.messages) {
        currentHistory.push({ role: m.role, content: decryptedMessages[m.id] || "ENCRYPTED_BLOB" });
      }
    }

    setInput('');
    setPendingFile(null);
    setIsWaiting(true);
    abortControllerRef.current = new AbortController();

    try {
      const response = await getHadesResponse(
        nexusUrl,
        [...currentHistory, { role: 'user', content: userPromptPlain }],
        abortControllerRef.current.signal
      );
      setIsWaiting(false);
      const encryptedResponse = await encryptData(response, sessionKey);
      setDecryptedMessages(prev => ({ ...prev, [assistantPlaceholderId]: response }));
      setSessions(prev => prev.map(s =>
        s.id === currentSessionId
          ? { ...s, messages: s.messages.map(m => m.id === assistantPlaceholderId ? { ...m, content: encryptedResponse } : m) }
          : s
      ));
    } catch (err: any) {
      setIsWaiting(false);
      const msg = err.name === 'AbortError' ? "LINK_INTERRUPTED" : `FAULT: ${err.message}`;
      const enc = await encryptData(msg, sessionKey);
      setDecryptedMessages(prev => ({ ...prev, [assistantPlaceholderId]: msg }));
      setSessions(prev => prev.map(s => s.id === currentSessionId
        ? { ...s, messages: s.messages.map(m => m.id === assistantPlaceholderId ? { ...m, content: enc } : m) } : s
      ));
    }
  };

  const handleAuth = async (type: 'login' | 'signup') => {
    setAuthError(null);
    if (!authId || !authKey || !nexusUrl) { setAuthError("CREDENTIALS_REQUIRED"); return; }
    if (type === 'signup' && authKey !== authConfirm) { setAuthError("KEY_MISMATCH"); return; }

    const registry = JSON.parse(localStorage.getItem('hades_registry_v2') || '{}');
    const normalizedId = authId.toLowerCase().trim();

    if (type === 'signup') {
      if (registry[normalizedId]) { setAuthError("ID_ALREADY_EXISTS"); return; }
      registry[normalizedId] = await createVerificationHash(normalizedId, authKey);
      localStorage.setItem('hades_registry_v2', JSON.stringify(registry));
    } else {
      if (!registry[normalizedId] || registry[normalizedId] !== await createVerificationHash(normalizedId, authKey)) {
        setAuthError("ACCESS_DENIED"); return;
      }
    }

    localStorage.setItem('hades_nexus_url', nexusUrl);
    setUserId(normalizedId);
    setUser(authId.toUpperCase());
    setUserHash(await hashId(normalizedId));
    setSessionKey(authKey);
    setAuthView('authenticated');
  };

  if (authView !== 'authenticated') {
    return (
      <div className="flex items-center justify-center min-h-dvh bg-[#0a0a0a] relative overflow-hidden px-4">
        <MatrixBackground />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[300px] md:w-[600px] h-[300px] md:h-[600px] bg-[#ff003c08] blur-[120px] rounded-full pointer-events-none animate-pulse"></div>
        <div className="relative w-full max-w-md z-10 py-10">
          <div className="flex flex-col items-center mb-8 text-center">
            <div className="w-16 h-16 rounded-xl bg-[#ff003c] flex items-center justify-center shadow-[0_0_40px_rgba(255,0,60,0.5)] mb-6">
              <Terminal size={32} className="text-white" />
            </div>
            <h1 className="text-4xl font-black tracking-[0.2em] uppercase text-white font-mono">HADES</h1>
            <p className="text-[10px] text-[#ff003c] tracking-[0.5em] uppercase mt-2 font-mono font-bold">Local Encryption Nexus</p>
          </div>
          <div className="bg-black/60 backdrop-blur-3xl border border-white/5 p-6 md:p-8 rounded-3xl shadow-2xl">
            <h2 className="text-[10px] font-mono tracking-[0.3em] text-zinc-500 uppercase mb-6 flex items-center gap-2">
              <Fingerprint size={14} className="text-[#ff003c]" />
              {authView === 'login' ? 'Nexus Authentication' : 'Identity Creation'}
            </h2>
            <div className="space-y-4">
              <div className="space-y-1">
                <label className="text-[8px] uppercase tracking-widest text-zinc-600 ml-1">Nexus Gateway</label>
                <div className="relative">
                  <Globe size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#ff003c]" />
                  <input type="text" value={nexusUrl} onChange={(e) => setNexusUrl(e.target.value)} className="w-full bg-black/40 border border-zinc-900 focus:border-[#ff003c] rounded-xl py-3 pl-10 text-xs font-mono text-white outline-none transition-all" />
                </div>
              </div>
              <div className="space-y-1">
                <label className="text-[8px] uppercase tracking-widest text-zinc-600 ml-1">Subject Identifier</label>
                <input type="text" value={authId} onChange={(e) => setAuthId(e.target.value)} className="w-full bg-black/40 border border-zinc-900 focus:border-[#ff003c] rounded-xl py-3 px-4 text-xs font-mono text-white outline-none transition-all" placeholder="ID_XXXXX" />
              </div>
              <div className="space-y-1">
                <label className="text-[8px] uppercase tracking-widest text-zinc-600 ml-1">Vault Key</label>
                <input type="password" value={authKey} onChange={(e) => setAuthKey(e.target.value)} className="w-full bg-black/40 border border-zinc-900 focus:border-[#ff003c] rounded-xl py-3 px-4 text-xs font-mono text-white outline-none transition-all" placeholder="••••••••" />
              </div>
              {authView === 'signup' && (
                <div className="space-y-1">
                  <label className="text-[8px] uppercase tracking-widest text-zinc-600 ml-1">Confirm Key</label>
                  <input type="password" value={authConfirm} onChange={(e) => setAuthConfirm(e.target.value)} className="w-full bg-black/40 border border-zinc-900 focus:border-[#ff003c] rounded-xl py-3 px-4 text-xs font-mono text-white outline-none transition-all" placeholder="••••••••" />
                </div>
              )}
              {authError && (
                <div className="text-[9px] font-mono text-[#ff003c] bg-[#ff003c08] p-3 rounded-lg border border-[#ff003c22] text-center uppercase animate-pulse">
                  SYSTEM_ALERT: {authError}
                </div>
              )}
              <button onClick={() => handleAuth(authView as 'login' | 'signup')} className="w-full bg-[#ff003c] py-4 rounded-xl text-xs font-bold uppercase tracking-widest text-white hover:bg-red-600 transition-all shadow-[0_0_20px_rgba(255,0,60,0.3)] flex items-center justify-center gap-2 mt-4">
                {authView === 'login' ? <LogIn size={14} /> : <UserPlus size={14} />} Initialize Link
              </button>
              <button onClick={() => { setAuthView(authView === 'login' ? 'signup' : 'login'); setAuthError(null); }} className="w-full text-[9px] uppercase tracking-[0.2em] text-zinc-600 hover:text-white transition-colors mt-2">
                {authView === 'login' ? 'Register New Identity' : 'Already Linked? Login'}
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-dvh bg-[#0a0a0a] text-zinc-200 font-sans selection:bg-[#ff003c] selection:text-white relative overflow-hidden">
      <MatrixBackground />

      {/* Purge Evidence Modal */}
      {isPromptingPurge && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/90 backdrop-blur-2xl p-4">
          <div className="max-w-md w-full bg-zinc-950 border border-red-500/30 p-8 rounded-[2.5rem] shadow-[0_0_150px_rgba(255,0,60,0.1)] animate-in fade-in zoom-in-95">
            <div className="flex flex-col items-center text-center mb-8">
              <div className="w-20 h-20 rounded-full bg-red-500/10 border border-red-500/20 flex items-center justify-center mb-6 animate-pulse">
                <AlertOctagon size={48} className="text-red-500" />
              </div>
              <h3 className="text-2xl font-black font-mono tracking-[0.2em] uppercase text-white mb-2">Purge Evidence</h3>
              <p className="text-[10px] font-mono text-zinc-500 uppercase tracking-widest leading-relaxed">System-wide data destruction initiated. Choose protocol tier.</p>
            </div>

            <div className="space-y-4 mb-8">
              <button
                onClick={() => handlePurge(false)}
                className="w-full group p-5 border border-zinc-800 rounded-2xl bg-zinc-900/50 hover:bg-zinc-900 transition-all text-left flex items-start gap-4"
              >
                <Trash2 size={24} className="text-red-500 mt-1" />
                <div>
                  <div className="text-xs font-bold font-mono text-white uppercase tracking-widest">Wipe Conversation Shards</div>
                  <div className="text-[9px] text-zinc-600 font-mono uppercase mt-1">Deletes history. Key and ID remain linked.</div>
                </div>
              </button>

              <div className="p-5 border border-red-500/30 rounded-2xl bg-red-500/5 space-y-4">
                <div className="flex items-start gap-4">
                  <Flame size={24} className="text-red-500 mt-1" />
                  <div>
                    <div className="text-xs font-bold font-mono text-red-500 uppercase tracking-widest">Total Nexus Annihilation</div>
                    <div className="text-[9px] text-zinc-400 font-mono uppercase mt-1">Deletes history and identity from registry.</div>
                  </div>
                </div>
                <div className="space-y-2">
                  <label className="text-[8px] font-mono uppercase tracking-widest text-zinc-500">Authorization Code: Type "PURGE"</label>
                  <input
                    type="text"
                    value={purgeConfirmation}
                    onChange={(e) => setPurgeConfirmation(e.target.value.toUpperCase())}
                    className="w-full bg-black border border-red-500/20 py-3 px-4 rounded-xl text-xs font-mono text-white outline-none focus:border-red-500/50 transition-all"
                    placeholder="CONFIRM"
                  />
                  <button
                    disabled={purgeConfirmation !== 'PURGE'}
                    onClick={() => handlePurge(true)}
                    className="w-full py-4 bg-red-600 disabled:bg-zinc-900 disabled:text-zinc-600 text-white rounded-xl text-[10px] font-bold uppercase tracking-[0.2em] transition-all shadow-[0_0_30px_rgba(255,0,0,0.2)]"
                  >
                    Execute Annihilation
                  </button>
                </div>
              </div>
            </div>

            <button
              onClick={() => { setIsPromptingPurge(false); setPurgeConfirmation(''); }}
              className="w-full text-[10px] font-bold uppercase text-zinc-600 hover:text-white transition-colors"
            >
              Abort Protocol
            </button>
          </div>
        </div>
      )}

      {/* Decipher Modal */}
      {isPromptingKey && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 backdrop-blur-xl p-4">
          <div className="max-w-sm w-full bg-[#0d0d0d] border border-[#ff003c33] p-8 rounded-[2rem] shadow-[0_0_100px_rgba(255,0,60,0.1)]">
            <h3 className="text-xl font-bold font-mono tracking-widest uppercase mb-4 text-[#ff003c] flex items-center gap-3">
              <Key size={24} /> Decipher
            </h3>
            <p className="text-[10px] font-mono text-zinc-600 uppercase tracking-widest mb-6">Enter vault key to decrypt shard cluster</p>
            <input
              type="password"
              autoFocus
              value={unlockInput}
              onChange={(e) => setUnlockInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleDecipher()}
              className="w-full bg-black border border-zinc-900 focus:border-[#ff003c] py-4 px-6 text-sm font-mono text-white rounded-2xl mb-6 outline-none transition-all"
              placeholder="••••••••"
            />
            {unlockError && <div className="text-[10px] text-[#ff003c] font-mono uppercase mb-4 text-center">{unlockError}</div>}
            <div className="flex gap-4">
              <button onClick={() => { setIsPromptingKey(false); setUnlockInput(''); }} className="flex-1 py-3 text-[10px] font-bold uppercase border border-zinc-900 rounded-xl hover:bg-white/5">Cancel</button>
              <button onClick={handleDecipher} className="flex-1 py-3 text-[10px] font-bold uppercase bg-[#ff003c] text-white rounded-xl shadow-[0_0_20px_rgba(255,0,60,0.4)]">Unlock</button>
            </div>
          </div>
        </div>
      )}

      {/* Sidebar Mobile Overlay */}
      {isSidebarOpen && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-[45] md:hidden" onClick={() => setIsSidebarOpen(false)} />
      )}

      <aside className={`fixed md:static inset-y-0 left-0 w-72 md:w-80 border-r border-[#ff003c11] bg-[#0a0a0a]/90 md:bg-black/20 backdrop-blur-3xl flex flex-col z-50 transition-transform duration-300 ease-in-out ${isSidebarOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'}`}>
        <div className="p-6 border-b border-[#ff003c11] flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-[#ff003c] flex items-center justify-center shadow-[0_0_15px_rgba(255,0,60,0.4)]"><Terminal size={18} className="text-white" /></div>
            <h1 className="font-black tracking-widest text-lg uppercase text-white font-mono">HADES</h1>
          </div>
          <button onClick={startNewSession} className="p-2 hover:bg-[#ff003c11] rounded-lg text-zinc-500 hover:text-[#ff003c] transition-all"><Plus size={18} /></button>
        </div>

        <div className="p-4 bg-[#ff003c05] border-b border-[#ff003c08]">
          <div className="flex items-center gap-2 text-[9px] font-mono text-[#ff003c] uppercase tracking-widest font-bold">
            <div className="w-1.5 h-1.5 rounded-full bg-[#ff003c] animate-ping" />
            Nexus Online
          </div>
          <div className="mt-1 text-[8px] text-zinc-600 truncate font-mono uppercase">URL: {nexusUrl}</div>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-2 custom-scrollbar">
          {sessions.map(session => (
            <button key={session.id} onClick={() => setCurrentSessionId(session.id)} className={`w-full text-left p-4 rounded-2xl border transition-all ${currentSessionId === session.id ? 'border-[#ff003c55] bg-[#ff003c11] shadow-[inset_0_0_20px_rgba(255,0,60,0.05)]' : 'border-transparent hover:bg-white/5'}`}>
              <div className="text-[11px] font-bold truncate text-white font-mono flex items-center justify-between">
                {session.title}
                {currentSessionId === session.id && <ChevronRight size={12} className="text-[#ff003c]" />}
              </div>
              <div className={`text-[9px] truncate mt-1 font-mono uppercase tracking-tighter ${currentSessionId === session.id && !isVaultDecrypted ? 'text-[#ff003c] opacity-60' : 'text-zinc-600'}`}>
                {currentSessionId === session.id && !isVaultDecrypted ? '[ CIPHERTEXT_LOCK ]' : session.lastMessage}
              </div>
            </button>
          ))}
        </div>

        <div className="p-4 border-t border-[#ff003c11] space-y-4 bg-black/40">
          <div className="grid grid-cols-2 gap-3 text-[9px] uppercase tracking-tighter text-zinc-500 font-mono">
            <div className="flex items-center gap-2"><Activity size={12} className="text-[#ff003c]" /> CPU {stats.cpu}%</div>
            <div className="flex items-center gap-2"><HardDrive size={12} className="text-[#ff003c]" /> RAM {stats.ram}G</div>
            <div className="flex items-center gap-2"><Cpu size={12} className="text-[#ff003c]" /> GPU {stats.gpu}%</div>
            <div className="flex items-center gap-2 text-green-500"><Database size={12} /> SECURE</div>
          </div>

          <div className="flex gap-2">
            <button
              onClick={() => setIsPromptingPurge(true)}
              className="flex-1 py-3 group relative overflow-hidden bg-transparent border border-[#ff003c33] rounded-xl flex items-center justify-center gap-2 text-[9px] uppercase tracking-widest text-[#ff003c] hover:bg-[#ff003c] hover:text-white transition-all font-mono font-bold shadow-[0_0_10px_rgba(255,0,60,0.1)]"
            >
              <Trash2 size={14} /> Purge
              <div className="absolute inset-0 bg-red-500/10 opacity-0 group-hover:opacity-100 animate-pulse pointer-events-none" />
            </button>
            <button onClick={() => window.location.reload()} className="flex-1 py-3 bg-transparent border border-zinc-900 rounded-xl flex items-center justify-center gap-2 text-[9px] uppercase tracking-widest hover:bg-[#ff003c11] hover:border-[#ff003c44] transition-all font-mono font-bold">
              <Power size={14} className="text-zinc-600" /> Kill
            </button>
          </div>
        </div>
      </aside>

      <main className="flex-1 flex flex-col relative z-10">
        <header className="h-16 md:h-20 border-b border-[#ff003c11] flex items-center justify-between px-4 md:px-8 bg-black/40 backdrop-blur-md">
          <div className="flex items-center gap-4">
            <button onClick={() => setIsSidebarOpen(true)} className="md:hidden p-2 text-zinc-400 hover:text-[#ff003c]"><Menu size={20} /></button>
            <div className="hidden md:flex items-center gap-4 text-[10px] font-mono">
              <div className={`border px-4 py-1.5 rounded-full uppercase flex items-center gap-2 transition-all font-bold ${isVaultDecrypted ? 'border-green-500/30 text-green-500 bg-green-500/5' : 'border-[#ff003c44] text-[#ff003c] bg-[#ff003c05]'}`}>
                {isVaultDecrypted ? <Unlock size={14} /> : <Lock size={14} />}
                {isVaultDecrypted ? 'Decrypted' : 'Vault Locked'}
              </div>
              <div className="text-zinc-500 flex items-center gap-2 uppercase font-bold"><UserPlus size={12} className="text-[#ff003c]" /> SUBJECT: {user}</div>
            </div>
          </div>
          <button
            onClick={toggleDecryption}
            className={`flex items-center gap-2 px-4 md:px-6 py-2 rounded-full text-[10px] font-bold uppercase tracking-widest font-mono transition-all border ${isVaultDecrypted
                ? 'bg-[#ff003c11] border-[#ff003c44] text-[#ff003c] hover:bg-[#ff003c] hover:text-white'
                : 'bg-[#ff003c] border-[#ff003c] text-white shadow-[0_0_30px_rgba(255,0,60,0.4)]'
              }`}
          >
            {isVaultDecrypted ? <><EyeOff size={16} /> Encrypt</> : <><Unlock size={16} /> Decrypt</>}
          </button>
        </header>

        <div className="flex-1 overflow-y-auto relative custom-scrollbar">
          {(!currentSession || currentSession.messages.length === 0) ? (
            <div className="h-full flex flex-col items-center justify-center text-center opacity-40 px-6">
              <div className="w-20 h-20 md:w-32 md:h-32 rounded-3xl bg-[#ff003c11] border border-[#ff003c22] flex items-center justify-center mb-8 animate-pulse">
                <Shield size={48} className="text-[#ff003c] md:hidden" />
                <Shield size={64} className="text-[#ff003c] hidden md:block" />
              </div>
              <h2 className="text-2xl md:text-4xl font-black tracking-[0.4em] text-white uppercase font-mono">READY</h2>
              <p className="mt-4 text-[10px] md:text-xs font-mono tracking-[0.2em] uppercase text-[#ff003c] font-bold">Encrypted Shards Syncing. Transmit Command.</p>
            </div>
          ) : (
            <div className="p-4 md:p-10 space-y-10 max-w-4xl mx-auto w-full">
              {currentSession?.messages.map((message) => (
                <div key={message.id} className={`flex flex-col ${message.role === 'user' ? 'items-end' : 'items-start'}`}>
                  <div className="flex items-center gap-2 mb-3 text-[9px] font-mono tracking-widest uppercase font-bold text-zinc-600">
                    {message.role === 'user' ? (
                      <><UserPlus size={10} className="text-[#ff003c]" /> Subject</>
                    ) : (
                      <><Cpu size={10} className="text-[#ff003c]" /> Hades Nexus</>
                    )}
                  </div>
                  <div className={`group relative w-full md:max-w-[90%] p-5 md:p-7 rounded-3xl font-mono text-xs md:text-sm leading-relaxed border backdrop-blur-3xl transition-all duration-500 ${message.role === 'user'
                      ? 'bg-zinc-900/30 border-zinc-800 text-zinc-300'
                      : 'bg-[#ff003c05] border-[#ff003c22] text-white shadow-[0_0_50px_rgba(255,0,60,0.03)] hover:shadow-[0_0_50px_rgba(255,0,60,0.06)]'
                    }`}>
                    {!isVaultDecrypted && message.content !== '' && (
                      <div className="absolute top-3 right-5 flex items-center gap-2 text-[8px] text-[#ff003c] font-bold">
                        <Lock size={10} /> PROTECTED
                      </div>
                    )}

                    {message.attachment && (
                      <div className="mb-6 rounded-2xl overflow-hidden bg-black/40 border border-zinc-800/50">
                        {!isVaultDecrypted ? (
                          <div className="p-10 flex flex-col items-center justify-center text-center gap-4">
                            <ShieldAlert size={40} className="text-[#ff003c] opacity-30" />
                            <div className="text-[10px] text-zinc-600 uppercase tracking-widest">ARTIFACT_ENCRYPTED</div>
                          </div>
                        ) : (
                          message.attachment.mimeType.startsWith('image/') ? (
                            <img src={`data:${message.attachment.mimeType};base64,${decryptedAttachments[message.id]}`} alt="Artifact" className="max-h-96 w-full object-contain" />
                          ) : (
                            <div className="p-6 flex items-center gap-5">
                              <div className="w-12 h-12 rounded-xl bg-[#ff003c11] flex items-center justify-center text-[#ff003c]">
                                <FileText size={24} />
                              </div>
                              <div className="flex-1 min-w-0">
                                <div className="text-[11px] font-bold uppercase truncate text-white">{message.attachment.name}</div>
                                <div className="text-[9px] text-zinc-600 uppercase mt-1 font-mono">{message.attachment.mimeType}</div>
                              </div>
                            </div>
                          )
                        )}
                      </div>
                    )}

                    <div className={`whitespace-pre-wrap transition-all duration-700 ${!isVaultDecrypted ? 'text-[#ff003c]/10 blur-[6px] select-none break-all scale-[0.98]' : 'scale-100 opacity-100'}`}>
                      {isVaultDecrypted ?
                        (decryptedMessages[message.id] || (isWaiting && message.role === 'assistant' ? <span className="inline-block w-2 h-4 bg-[#ff003c] animate-pulse"></span> : "")) :
                        message.content.slice(0, 400)
                      }
                    </div>
                  </div>
                </div>
              ))}
              <div ref={chatEndRef} className="h-10" />
            </div>
          )}
        </div>

        <div className="p-4 md:p-8 pt-0 w-full max-w-4xl mx-auto">
          {pendingFile && (
            <div className="mb-4 p-3 bg-zinc-900/80 border border-zinc-800 rounded-2xl flex items-center justify-between animate-in slide-in-from-bottom-2">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-[#ff003c11] flex items-center justify-center text-[#ff003c]">
                  <Paperclip size={18} />
                </div>
                <div className="text-[10px] font-mono">
                  <div className="text-zinc-300 uppercase font-bold truncate max-w-[150px]">{pendingFile.name}</div>
                  <div className="text-zinc-600 uppercase">{pendingFile.mimeType}</div>
                </div>
              </div>
              <button onClick={() => setPendingFile(null)} className="p-2 text-zinc-500 hover:text-white"><X size={16} /></button>
            </div>
          )}

          <div className="relative group">
            <div className={`relative bg-black/60 backdrop-blur-3xl border transition-all rounded-[1.5rem] flex items-center p-2 shadow-2xl ${!isVaultDecrypted ? 'border-zinc-900 opacity-40 grayscale' : 'border-zinc-800 focus-within:border-[#ff003c44] group-hover:border-[#ff003c22]'
              }`}>
              <button onClick={() => fileInputRef.current?.click()} className="w-12 h-12 flex items-center justify-center text-zinc-600 hover:text-[#ff003c] transition-colors"><Paperclip size={20} /></button>
              <input type="file" ref={fileInputRef} onChange={handleFileChange} className="hidden" />
              <input
                type="text"
                disabled={!isVaultDecrypted || isWaiting}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSend()}
                placeholder={isVaultDecrypted ? "Transmit command..." : "VAULT_LOCKED"}
                className="flex-1 bg-transparent border-none focus:ring-0 px-4 py-4 text-xs md:text-sm font-mono text-white placeholder-zinc-800 outline-none"
              />
              <button
                onClick={handleSend}
                disabled={!isVaultDecrypted || (!input.trim() && !pendingFile) || isWaiting}
                className={`w-12 h-12 rounded-2xl flex items-center justify-center transition-all ${!isVaultDecrypted || isWaiting || (!input.trim() && !pendingFile)
                    ? 'bg-zinc-900/50 text-zinc-700'
                    : 'bg-[#ff003c] text-white shadow-[0_0_25px_rgba(255,0,60,0.4)] hover:scale-105 active:scale-95'
                  }`}
              >
                {isWaiting ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <Send size={20} />}
              </button>
            </div>
          </div>
          <div className="flex justify-between items-center px-4 mt-4">
            <p className="text-[8px] uppercase tracking-[0.3em] text-zinc-700 font-mono flex items-center gap-2">
              <ShieldAlert size={10} className="text-[#ff003c]" /> End-to-End Local Encryption
            </p>
            <p className="text-[8px] uppercase tracking-[0.3em] text-zinc-700 font-mono">Build 0.9.6 // Hades</p>
          </div>
        </div>
      </main>

      <style>{`
        .custom-scrollbar::-webkit-scrollbar { width: 3px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #ff003c22; border-radius: 10px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #ff003c; }
        @keyframes scanline { 0% { top: 0; } 100% { top: 100%; } }
        main::after {
          content: "";
          position: absolute;
          top: 0; left: 0; right: 0; height: 1px;
          background: linear-gradient(90deg, transparent, #ff003c22, transparent);
          animation: scanline 8s linear infinite;
          pointer-events: none;
          z-index: 100;
        }
      `}</style>
    </div>
  );
};

export default App;
