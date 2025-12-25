
/**
 * Project Hades - Nexus Service (KoboldCPP / Local Core)
 * Connects to the user's self-hosted AI engine.
 */

const HADES_SYSTEM_INSTRUCTION = ``;

export const getEndpoint = (baseUrl: string): string => {
  let sanitized = baseUrl.trim();
  sanitized = sanitized.replace(/\/+$/, "");
  
  if (sanitized.endsWith('/v1')) {
    return `${sanitized}/chat/completions`;
  }
  
  if (!sanitized.includes('/v1') && !sanitized.includes('/api')) {
    return `${sanitized}/v1/chat/completions`;
  }
  
  if (sanitized.endsWith('/chat/completions')) {
    return sanitized;
  }

  return `${sanitized}/v1/chat/completions`;
};

export const getHadesResponse = async (
  baseUrl: string,
  history: { role: string, content: string, attachment?: { data: string, mimeType: string, name: string } }[],
  signal?: AbortSignal
) => {
  const endpoint = getEndpoint(baseUrl);

  const messages = [
    { role: "system", content: HADES_SYSTEM_INSTRUCTION },
    ...history.map(h => {
      let finalContent = h.content;
      if (h.attachment) {
        const typeLabel = h.attachment.mimeType.startsWith('image/') ? 'IMAGE_ARTIFACT' : 'DATA_PACK';
        finalContent = `[${typeLabel}: ${h.attachment.name}]\n\n${finalContent}`;
      }
      return {
        role: h.role === 'assistant' ? 'assistant' : 'user',
        content: finalContent
      };
    })
  ];

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      mode: "cors",
      signal: signal, // Attach the abort signal
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
      },
      body: JSON.stringify({
        model: "local-model",
        messages: messages,
        temperature: 0.7,
        max_tokens: 4096,
        stop: ["Mortal:", "Subject:", "USER:", "HADES:"]
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      let parsedError = errorText;
      try {
        const jsonError = JSON.parse(errorText);
        parsedError = jsonError.error?.message || errorText;
      } catch (e) {}
      throw new Error(`NEXUS_REJECTED (${response.status}): ${parsedError || "Is the model loaded?"}`);
    }

    const data = await response.json();
    const content = data.choices?.[0]?.message?.content;

    if (!content) {
      throw new Error("ABYSSAL_SILENCE: Core returned no data.");
    }

    return content;
  } catch (error: any) {
    if (error.name === 'AbortError') {
      throw error; // Let the UI handle the abort
    }
    
    console.error("Hades Nexus Fault:", error);
    
    if (error.name === 'TypeError' && error.message === 'Failed to fetch') {
      return `NEXUS_ACCESS_DENIED: Browser blocked the cross-origin request. \n\nCOMMAND_REQUIRED: \nLaunch KoboldCPP with the flag: --cors *`;
    }

    return `NEXUS_LINK_FAULT: ${error.message || "The local core is unreachable."}`;
  }
};
