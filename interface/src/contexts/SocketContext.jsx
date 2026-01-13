import React, { createContext, useContext, useEffect, useState, useRef } from 'react';
import { io } from 'socket.io-client';
import { WS_URL } from '../config';

const SocketContext = createContext();

export const useSocket = () => {
    return useContext(SocketContext);
};

export const SocketProvider = ({ children }) => {
    const [socket, setSocket] = useState(null);
    const [isConnected, setIsConnected] = useState(false);
    const socketRef = useRef(null);

    useEffect(() => {
        // Initialize socket
        console.log(`[SOCKET_CTX] Connecting to ${WS_URL}...`);
        const newSocket = io(WS_URL, {
            transports: ['websocket', 'polling'], // Prioritize Websocket
            reconnectionAttempts: 10,
        });

        newSocket.on('connect', () => {
            console.log('[SOCKET_CTX] Connected:', newSocket.id);
            setIsConnected(true);
        });

        newSocket.on('disconnect', () => {
            console.log('[SOCKET_CTX] Disconnected');
            setIsConnected(false);
        });

        newSocket.on('connect_error', (err) => {
            console.error('[SOCKET_CTX] Connect Error:', err.message);
        });

        socketRef.current = newSocket;
        setSocket(newSocket);

        // Cleanup
        return () => {
            if (newSocket) newSocket.disconnect();
        };
    }, []);

    const value = {
        socket,
        isConnected
    };

    return (
        <SocketContext.Provider value={value}>
            {children}
        </SocketContext.Provider>
    );
};
