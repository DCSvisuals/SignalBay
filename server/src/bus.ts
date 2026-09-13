import { EventEmitter } from "node:events";
import type { WebSocket } from "ws";
import type { WsMessage } from "./types.js";

class Hub extends EventEmitter {
  private clients = new Set<WebSocket>();

  add(socket: WebSocket): void {
    this.clients.add(socket);
    socket.on("close", () => this.clients.delete(socket));
    socket.on("error", () => this.clients.delete(socket));
  }

  broadcast(message: WsMessage): void {
    const data = JSON.stringify(message);
    for (const client of this.clients) {
      if (client.readyState === 1) {
        client.send(data);
      }
    }
    this.emit(message.type, message.payload);
  }

  get size(): number {
    return this.clients.size;
  }
}

export const hub = new Hub();
