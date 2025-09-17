import { hexToUint8Array } from "./utils";

export const BACKEND_URL = "localhost:7777";
export const PUBLIC_KEY_HEX = "8545391f46812888993b7ad3ddf5384f2a2303c1bb2a3b5259021490b958d09682e527c100ff52c223c6d0fd3150c79211ed3c2bc71e49b455f1b44de956e7f8e735cf4105dee3d72d48e64b61fdd0dc2447a7199322f4ab7d58479396b24f95";
export const LOCATIONS: [[number, number], string][] = [
    [[37.7749, -122.4194], "San Francisco"],
    [[38.8339, -77.3074], "Ashburn"],
    [[53.3498, -6.2603], "Dublin"],
    [[35.6895, 139.6917], "Tokyo"],
];
// Export PUBLIC_KEY as a Uint8Array for use in the application
export const PUBLIC_KEY = hexToUint8Array(PUBLIC_KEY_HEX);

export const SCALE_DURATION = 750; // 750ms
export const TIMEOUT_DURATION = 5000; // 5s
export const HEALTH_CHECK_INTERVAL = 60000; // Check health every minute   