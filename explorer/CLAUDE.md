# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a React TypeScript application called "Quartz Explorer" that provides a real-time visualization of a blockchain consensus protocol. The app displays:

- A world map showing validator locations
- A timeline of consensus views with visual bars showing seeding, notarization, and finalization states
- Real-time statistics about block production and finalization latencies
- Live updates via WebSocket connection to a backend consensus node

## Commands

### Development
- `npm start` - Start development server
- `npm run build` - Build for production

### WASM Types
Before running the app, compile the Rust types to WebAssembly:
```bash
cd ../types
wasm-pack build --release --target web
mv pkg/alto_types.js ../explorer/src/alto_types
mv pkg/alto_types_bg.wasm ../explorer/src/alto_types
cd ../explorer
```

### Production
- `serve -s build` - Serve built app (requires `serve` package)

## Architecture

### Core Components

**App.tsx** (`src/App.tsx:75`) - Main application component that:
- Manages WebSocket connection to consensus backend
- Processes consensus messages (seeds, notarizations, finalizations) 
- Maintains timeline state of consensus views
- Renders map, statistics, and timeline visualization

**Configuration** (`src/config.ts`) - Contains:
- `BACKEND_URL` - WebSocket endpoint for consensus data
- `PUBLIC_KEY_HEX` - Consensus threshold verification key
- `LOCATIONS` - Validator geographic locations (4 validators)

**Types** (`src/types.ts`) - TypeScript interfaces for:
- `ViewData` - Timeline view state with status, timing, block data
- Consensus message types: `SeedJs`, `NotarizedJs`, `FinalizedJs`
- `ViewStatus` - Consensus states: growing, notarized, finalized, timed_out, unknown

### Key Features

**Real-time Updates**: WebSocket connection processes binary consensus messages and updates UI state

**Timeline Visualization**: Interactive bars showing consensus progression with latency measurements

**Geographic Display**: Map overlay showing current validator location based on view rotation

**Error Handling**: Health checks, maintenance mode, connection error notifications with reconnection logic

**Mobile Responsive**: Adaptive layout and timing display for mobile devices

## WASM Integration

The app uses WebAssembly modules generated from Rust types in `../types/` to parse consensus protocol messages. The WASM files must be compiled and placed in `src/alto_types/` before running the application.

## Backend Integration

The explorer connects to a consensus node backend via WebSocket at the configured `BACKEND_URL`. It expects binary messages with:
- Type 0: Seed messages for leader election
- Type 1: Notarization messages when blocks are notarized
- Type 2: Finalization messages when blocks are finalized

Health checks are performed against `/health` endpoint to determine maintenance mode.