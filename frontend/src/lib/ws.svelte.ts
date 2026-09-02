export interface ServerState {
  version: string;
  connect_url: string;
  server_name: string;
  is_running: boolean;
  online_players: string[];
  auto_stop_time: number;
}

export class ServerSocket {
  private _ws: WebSocket | null = null;
  #isConnected = $state(false);
  #serverState = $state<ServerState | null>(null);
  #isConnecting = $state(false);
  #chatHistory = $state("");

  private _reconnectTimeout: number | null = null;

  get isConnected() {
    return this.#isConnected;
  }
  get serverState() {
    return this.#serverState;
  }
  get isConnecting() {
    return this.#isConnecting;
  }
  get chatHistory() {
    return this.#chatHistory;
  }

  constructor() { }

  close() {
    if (this._ws) {
      this._ws.close(1000);
      this.#isConnecting = false;
      if (this._reconnectTimeout) clearTimeout(this._reconnectTimeout);

      console.log("closing cleanely from client");
    }
  }

  connect() {
    if (this._ws !== null) return;

    this.#isConnecting = true;
    this._ws = new WebSocket("/api/ws");
    const ws = this._ws;

    ws.addEventListener("close", (ev) => {
      this.#isConnected = false;
      this.#chatHistory = "";
      this._ws = null;

      if (!ev.wasClean) {
        console.warn("WS closed", ev);
        this.#isConnecting = true;
        this._reconnectTimeout = setTimeout(() => {
          console.log("attempting reconnection");
          this.connect();
        }, 5 * 1000);
      }
    });

    ws.addEventListener("error", console.error);
    ws.addEventListener("message", (message) => {
      const msg = JSON.parse(message.data);

      switch (msg.type) {
        case "state":
          if (this.#serverState?.is_running && !msg.data.is_running)
            this.#chatHistory = "";
          this.#serverState = msg.data;
          break;
        case "chat":
          if (msg.data.length !== 0) this.#chatHistory += msg.data;
          break;
        default:
          console.warn("unknown message type");
          break;
      }
    });
    ws.addEventListener("open", () => {
      this.#isConnected = true;
      this.#isConnecting = false;
      console.log("connected ws");
    });
  }

  startServer() {
    if (this.#serverState?.is_running || !this.#isConnected || !this._ws)
      return;

    this._ws.send("start");
  }
}
