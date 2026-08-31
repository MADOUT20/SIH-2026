import os
import sys
import ssl
import asyncio

async def proxy_stream(reader, writer, target_port):
    try:
        t_reader, t_writer = await asyncio.open_connection("127.0.0.1", target_port)

        # Pipe request from client to target
        async def forward_req():
            try:
                while True:
                    data = await reader.read(8192)
                    if not data:
                        break
                    t_writer.write(data)
                    await t_writer.drain()
            except Exception:
                pass
            finally:
                try:
                    t_writer.write_eof()
                except Exception:
                    pass

        # Pipe response from target to client
        async def forward_resp():
            try:
                while True:
                    data = await t_reader.read(8192)
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
            except Exception:
                pass

        await asyncio.gather(forward_req(), forward_resp())
    except Exception as e:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

async def handle_client(reader, writer):
    # Inspect initial request line for routing
    try:
        data = await reader.readuntil(b"\r\n")
    except Exception:
        writer.close()
        return

    req_line = data.decode("latin1", errors="ignore")
    parts = req_line.split(" ")
    path = parts[1] if len(parts) > 1 else "/"

    if path.startswith("/api") or path == "/health" or path.startswith("/docs") or path.startswith("/openapi"):
        target_port = 8000
    else:
        target_port = 3000

    # Open target connection and pass initial header + rest of stream
    try:
        t_reader, t_writer = await asyncio.open_connection("127.0.0.1", target_port)
        t_writer.write(data)
        await t_writer.drain()

        # Bi-directional stream copy
        async def req_copier():
            try:
                while True:
                    chunk = await reader.read(16384)
                    if not chunk:
                        break
                    t_writer.write(chunk)
                    await t_writer.drain()
            except Exception:
                pass
            finally:
                try:
                    t_writer.write_eof()
                except Exception:
                    pass

        async def resp_copier():
            try:
                while True:
                    chunk = await t_reader.read(16384)
                    if not chunk:
                        break
                    writer.write(chunk)
                    await writer.drain()
            except Exception:
                pass

        await asyncio.gather(req_copier(), resp_copier())
    except Exception as e:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

async def main_async():
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    crt_path = os.path.join(root_dir, "certs", "localhost.crt")
    key_path = os.path.join(root_dir, "certs", "localhost.key")
    port = int(os.getenv("HTTPS_PORT", "443"))

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(certfile=crt_path, keyfile=key_path)

    print(f"Starting Asyncio NetGuard HTTPS Gateway on https://localhost:{port}/...")
    server = await asyncio.start_server(handle_client, "0.0.0.0", port, ssl=ssl_ctx)
    print(f"HTTPS Gateway is LIVE at https://localhost:{port}/")
    async with server:
        await server.serve_forever()

def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("HTTPS Gateway stopped.")

if __name__ == "__main__":
    main()
