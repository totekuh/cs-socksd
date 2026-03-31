#!/usr/bin/env python3
"""socksd-listener -- operator-side reverse listener for socksd.

Accepts one control channel from the agent, then pairs incoming local
SOCKS5 clients with on-demand data channels through the agent.

Protocol (all on the callback port):
  Control:  agent sends 0x01, listener acks 0x01
  Signal:   listener sends 0x01 on control = "open a data channel"
  Data:     agent sends 0x02 on a new connection, listener pairs it
"""

import argparse
import asyncio
import logging
import sys

CHAN_CONTROL = b"\x01"
CHAN_DATA = b"\x02"
SIG_CONNECT = b"\x01"

log = logging.getLogger("socksd-listener")


class Listener:
    def __init__(self, callback_port, socks_port, bind):
        self.callback_port = callback_port
        self.socks_port = socks_port
        self.bind = bind
        self.control = None          # (reader, writer) or None
        self.data_queue = asyncio.Queue(maxsize=64)

    async def run(self):
        cb = await asyncio.start_server(
            self._on_callback, self.bind, self.callback_port)
        sk = await asyncio.start_server(
            self._on_socks, self.bind, self.socks_port)
        log.info("callback  %s:%d", self.bind, self.callback_port)
        log.info("socks5    %s:%d", self.bind, self.socks_port)
        async with cb, sk:
            await asyncio.gather(cb.serve_forever(), sk.serve_forever())

    # -- callback port handlers ----------------------------------------

    async def _on_callback(self, reader, writer):
        try:
            marker = await asyncio.wait_for(reader.readexactly(1), timeout=10)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, OSError):
            await self._safe_close(writer)
            return

        if marker == CHAN_CONTROL:
            await self._accept_control(reader, writer)
        elif marker == CHAN_DATA:
            if self.data_queue.full():
                log.warning("data channel queue full, dropping")
                await self._safe_close(writer)
                return
            await self.data_queue.put((reader, writer))
        else:
            await self._safe_close(writer)

    async def _accept_control(self, reader, writer):
        if self.control:
            log.warning("replacing existing control channel")
            await self._safe_close(self.control[1])
            self._drain_data_queue()
        self.control = (reader, writer)
        writer.write(CHAN_CONTROL)
        await writer.drain()
        log.info("agent connected")
        # block until the control connection drops
        try:
            while True:
                data = await reader.read(1)
                if not data:
                    break
        except (ConnectionError, asyncio.IncompleteReadError, OSError):
            pass
        log.info("agent disconnected")
        if self.control and self.control[1] is writer:
            self.control = None
            self._drain_data_queue()

    # -- socks port handler --------------------------------------------

    async def _on_socks(self, reader, writer):
        if not self.control:
            log.warning("no agent, dropping socks client")
            await self._safe_close(writer)
            return

        ctrl_r, ctrl_w = self.control
        try:
            ctrl_w.write(SIG_CONNECT)
            await ctrl_w.drain()
        except (ConnectionError, OSError):
            log.warning("control channel broken")
            await self._safe_close(writer)
            return

        try:
            dr, dw = await asyncio.wait_for(
                self._dequeue_live_channel(), timeout=30)
        except asyncio.TimeoutError:
            log.warning("timeout waiting for data channel")
            await self._safe_close(writer)
            return

        log.info("paired socks client <-> data channel")
        await self._relay(reader, writer, dr, dw)

    # -- relay ---------------------------------------------------------

    async def _relay(self, sr, sw, dr, dw):
        t1 = asyncio.ensure_future(self._copy(sr, dw))
        t2 = asyncio.ensure_future(self._copy(dr, sw))
        await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
        for t in (t1, t2):
            if not t.done():
                t.cancel()
        await asyncio.gather(t1, t2, return_exceptions=True)
        for w in (sw, dw):
            await self._safe_close(w)

    @staticmethod
    async def _copy(reader, writer):
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except (ConnectionError, BrokenPipeError, OSError,
                asyncio.CancelledError, asyncio.IncompleteReadError):
            pass

    # -- helpers -----------------------------------------------------------

    async def _dequeue_live_channel(self):
        """Pull from data_queue, skipping dead channels."""
        while True:
            dr, dw = await self.data_queue.get()
            try:
                if dw.is_closing():
                    log.debug("discarding stale data channel")
                    await self._safe_close(dw)
                    continue
                return dr, dw
            except asyncio.CancelledError:
                await self._safe_close(dw)
                raise

    def _drain_data_queue(self):
        """Drop all queued data channels (agent gone, they are useless)."""
        dropped = 0
        while not self.data_queue.empty():
            try:
                _r, w = self.data_queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            try:
                w.close()
            except Exception:
                pass
            dropped += 1
        if dropped:
            log.info("drained %d stale data channels", dropped)

    @staticmethod
    async def _safe_close(writer):
        """Close a writer and wait for the socket to shut down."""
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser(
        description="socksd reverse-mode listener (operator side)")
    ap.add_argument("-c", "--callback-port", type=int, default=9001,
                    help="agent callback port (default: 9001)")
    ap.add_argument("-s", "--socks-port", type=int, default=1080,
                    help="local SOCKS5 port (default: 1080)")
    ap.add_argument("-b", "--bind", default="0.0.0.0",
                    help="bind address (default: 0.0.0.0)")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="suppress log output")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(message)s", stream=sys.stderr)

    try:
        asyncio.run(Listener(args.callback_port, args.socks_port, args.bind).run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
