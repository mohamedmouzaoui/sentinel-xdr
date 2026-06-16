import { useEffect, useRef, useCallback } from 'react';

export function useWebSocket(onMessage) {
  const wsRef = useRef(null);
  const reconnectTimerRef = useRef(null);
  const token = localStorage.getItem('sentinel_token');

  const connect = useCallback(() => {
    if (!token) return;
    const wsUrl = `${process.env.REACT_APP_WS_URL || 'ws://localhost:8000/ws/stream'}?token=${token}`;
    
    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        console.log('[WS] Connected to Sentinel XDR stream');
      };

      ws.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data);
          onMessage?.(data);
        } catch {}
      };

      ws.onclose = () => {
        // Reconnect after 3s
        reconnectTimerRef.current = setTimeout(connect, 3000);
      };

      ws.onerror = () => {
        ws.close();
      };
    } catch {}
  }, [token, onMessage]);

  useEffect(() => {
    connect();
    return () => {
      clearTimeout(reconnectTimerRef.current);
      wsRef.current?.close();
    };
  }, [connect]);

  const send = useCallback((data) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(typeof data === 'string' ? data : JSON.stringify(data));
    }
  }, []);

  return { send };
}
