// import { useRef, useState } from "react";
// import { BACKEND_URL } from "../config";
// import init, {
//     parse_notarized,
//     parse_finalized,
//     parse_seed,
// } from "../alto_types/alto_types.js";


// export const wsRef = { current: null };
// export const setErrorMessage = (message: string) => {
//     console.error(message);
// };
// export const setShowError = (show: boolean) => {
//     console.error(show);
// };
// export const setConnectionStatusKnown = (known: boolean) => {
//     console.error(known);
// };

// export const PUBLIC_KEY = "92b050b6fbe80695b5d56835e978918e37c8707a7fad09a01ae782d4c3170c9baa4c2c196b36eac6b78ceb210b287aeb0727ef1c60e48042142f7bcc8b6382305cd50c5a4542c44ec72a4de6640c194f8ef36bea1dbed168ab6fd8681d910d55";

// export const wsRef = useRef<WebSocket | null>(null);

// // Manage WebSocket lifecycle
// export const handleSeedRef = useRef<typeof handleSeed>(null!);
// export const handleNotarizedRef = useRef<typeof handleNotarization>(null!);
// export const handleFinalizedRef = useRef<typeof handleFinalization>(null!);
// export const isInitializedRef = useRef(false);
// export const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
// export const [isLoading, setIsLoading] = useState(true);
// export const [isInMaintenance, setIsInMaintenance] = useState(false);

// export const wsCreationTime = Date.now();
// const protocol = BACKEND_URL.includes(":") ? "ws" : "wss";
// export const ws = new WebSocket(`${protocol}://${BACKEND_URL}/consensus/ws`);
// wsRef.current = ws;
// ws.binaryType = "arraybuffer";

// ws.onopen = () => {
//     console.log("WebSocket connected");
//     setErrorMessage("");
//     setShowError(false);
//     setConnectionStatusKnown(true);
// };

// ws.onmessage = (event) => {
//     const data = new Uint8Array(event.data);
//     const kind = data[0];
//     const payload = data.slice(1);

//     switch (kind) {
//         case 0:
//             const seed = parse_seed(PUBLIC_KEY, payload);
//             if (seed) handleSeedRef.current(seed);
//             break;
//         case 1: // Notarization
//             const notarized = parse_notarized(PUBLIC_KEY, payload);
//             if (notarized) handleNotarizedRef.current(notarized);
//             break;
//         case 2: // Finalization
//             const finalized = parse_finalized(PUBLIC_KEY, payload);
//             if (finalized) handleFinalizedRef.current(finalized);
//             break;
//     }
// };

// export const ws.onerror = (error: any) => {
//     console.error("WebSocket error:", error);
// };

// export const ws.onclose = (event: any) => {
//     console.error(`WebSocket closed with code: ${event.code}`);

//     // Check for potential rate limiting (code 1006 is "Abnormal Closure")
//     if (event.code === 1006) {
//         // If connection closed very quickly, likely rate-limited
//         const timeSinceStarted = Date.now() - wsCreationTime;
//         if (timeSinceStarted < 1000) {
//             setErrorMessage(
//                 "Too many connection attempts from your IP. Try connecting again in an hour."
//             );
//             setShowError(true);

//             // Clear reference to prevent reconnection
//             wsRef.current = null;
//         } else {
//             setErrorMessage("Disconnected from server. Reconnecting...");
//             setShowError(true);
//         }
//     }
//     setConnectionStatusKnown(true);

//     // Only attempt to reconnect if we still have a reference to this websocket (and we didn't detect a rate limit error)
//     if (wsRef.current === ws) {
//         reconnectTimeoutRef.current = setTimeout(() => {
//             reconnectTimeoutRef.current = null;
//             connectWebSocket();
//         }, 11000);
//     }
// };


// const setup = async () => {
//     await init();
//     connectWebSocket();
// };

// setup();

// // Cleanup function when component unmounts
// return () => {
//     // Clear any reconnection timers
//     if (reconnectTimeoutRef.current) {
//         clearTimeout(reconnectTimeoutRef.current);
//         reconnectTimeoutRef.current = null;
//     }

//     // Close and clean up the websocket
//     if (wsRef.current) {
//         const ws = wsRef.current;
//         wsRef.current = null; // Clear reference first to prevent reconnection attempts
//         try {
//             ws.close(1000, "Component unmounting");
//         } catch (err) {
//             console.error("Error closing WebSocket during cleanup:", err);
//         }
//     }
// };
//     }, [isLoading, isInMaintenance]);

export { };