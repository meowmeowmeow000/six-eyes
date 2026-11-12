import { connect } from 'cloudflare:sockets';

const SMUX_VERSION = 1;
const CMD_SYN = 0;
const CMD_FIN = 1;
const CMD_PSH = 2;
const CMD_NOP = 3;
const HEADER_SIZE = 8;

function encodeSmuxFrame(cmd, streamId, payload = new Uint8Array(0)) {
  const frame = new Uint8Array(HEADER_SIZE + payload.byteLength);
  const view = new DataView(frame.buffer);
  view.setUint8(0, SMUX_VERSION);
  view.setUint8(1, cmd);
  view.setUint16(2, payload.byteLength, true);
  view.setUint32(4, streamId, true);
  if (payload.byteLength > 0) {
    frame.set(payload, HEADER_SIZE);
  }
  return frame;
}

function concatUint8(a, b) {
  if (a.byteLength === 0) return b;
  if (b.byteLength === 0) return a;
  const out = new Uint8Array(a.byteLength + b.byteLength);
  out.set(a, 0);
  out.set(b, a.byteLength);
  return out;
}

export default {
  async fetch(request) {
    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
      return new Response('OK', { status: 200 });
    }
    const [client, server] = Object.values(new WebSocketPair());
    server.accept();
    const streams = new Map();
    let rxBuffer = new Uint8Array(0);
    let processingChain = Promise.resolve();
    const textDecoder = new TextDecoder();

    const safeSend = (frame) => {
      try {
        server.send(frame);
      } catch (_) {}
    };

    const closeStream = async (streamId, sendFin = false) => {
      const entry = streams.get(streamId);
      if (!entry) return;
      streams.delete(streamId);
      entry.closed = true;
      try {
        if (entry.writer) await entry.writer.close();
      } catch (_) {}
      try {
        if (entry.socket) await entry.socket.close();
      } catch (_) {}
      if (sendFin) {
        safeSend(encodeSmuxFrame(CMD_FIN, streamId));
      }
    };

    const handleStreamPayload = async (streamId, chunk) => {
      const entry = streams.get(streamId);
      if (!entry || entry.closed) return;
      if (!entry.connected) {
        entry.headerBuf = concatUint8(entry.headerBuf, chunk);
        if (entry.headerBuf.byteLength < 1) return;
        const hostLen = entry.headerBuf[0];
        const totalHeaderLen = 1 + hostLen + 2;
        if (entry.headerBuf.byteLength < totalHeaderLen) return;

        const hostBytes = entry.headerBuf.subarray(1, 1 + hostLen);
        const portView = new DataView(
          entry.headerBuf.buffer,
          entry.headerBuf.byteOffset + 1 + hostLen,
          2
        );
        const hostname = textDecoder.decode(hostBytes);
        const port = portView.getUint16(0, false);
        const remainder = entry.headerBuf.slice(totalHeaderLen);
        entry.headerBuf = new Uint8Array(0);

        try {
          const tcpSocket = connect({ hostname, port });
          const writer = tcpSocket.writable.getWriter();
          entry.socket = tcpSocket;
          entry.writer = writer;
          entry.connected = true;
          if (remainder.byteLength > 0) {
            await writer.write(remainder);
          }
          (async () => {
            const reader = tcpSocket.readable.getReader();
            try {
              while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                if (value && value.byteLength > 0) {
                  const MAX_FRAME = 16384;
                  for (let offset = 0; offset < value.byteLength; offset += MAX_FRAME) {
                    const slice = value.subarray(offset, offset + MAX_FRAME);
                    safeSend(encodeSmuxFrame(CMD_PSH, streamId, slice));
                  }
                }
              }
            } catch (_) {
            } finally {
              await closeStream(streamId, true);
            }
          })();
        } catch (_) {
          await closeStream(streamId, true);
        }
        return;
      }
      if (entry.writer) {
        try {
          await entry.writer.write(chunk);
        } catch (_) {
          await closeStream(streamId, true);
        }
      }
    };

    server.addEventListener('message', (event) => {
      const incoming = event.data instanceof ArrayBuffer
        ? new Uint8Array(event.data)
        : new TextEncoder().encode(String(event.data));
      rxBuffer = concatUint8(rxBuffer, incoming);
      const parsedFrames = [];
      let offset = 0;

      while (rxBuffer.byteLength - offset >= HEADER_SIZE) {
        const view = new DataView(rxBuffer.buffer, rxBuffer.byteOffset + offset, HEADER_SIZE);
        const ver = view.getUint8(0);
        const cmd = view.getUint8(1);
        const length = view.getUint16(2, true);
        const streamId = view.getUint32(4, true);

        if (ver !== SMUX_VERSION) {
          rxBuffer = new Uint8Array(0);
          server.close(1002, 'Invalid SMUX version');
          return;
        }
        if (rxBuffer.byteLength - offset < HEADER_SIZE + length) {
          break;
        }
        const payload = rxBuffer.slice(offset + HEADER_SIZE, offset + HEADER_SIZE + length);
        offset += HEADER_SIZE + length;
        parsedFrames.push({ cmd, streamId, payload });
      }
      if (offset > 0) {
        rxBuffer = rxBuffer.slice(offset);
      }
      if (parsedFrames.length === 0) return;

      processingChain = processingChain.then(async () => {
        for (const frame of parsedFrames) {
          switch (frame.cmd) {
            case CMD_SYN:
              if (!streams.has(frame.streamId)) {
                streams.set(frame.streamId, {
                  connected: false,
                  closed: false,
                  headerBuf: new Uint8Array(0),
                  socket: null,
                  writer: null,
                });
              }
              break;
            case CMD_PSH:
              await handleStreamPayload(frame.streamId, frame.payload);
              break;
            case CMD_FIN:
              await closeStream(frame.streamId, false);
              break;
            case CMD_NOP:
              safeSend(encodeSmuxFrame(CMD_NOP, 0));
              break;
          }
        }
      }).catch(() => {});
    });

    server.addEventListener('close', () => {
      for (const streamId of Array.from(streams.keys())) {
        closeStream(streamId, false);
      }
    });
    return new Response(null, { status: 101, webSocket: client });
  }
};
