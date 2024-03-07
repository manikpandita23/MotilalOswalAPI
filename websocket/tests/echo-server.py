import asyncio
import websockets
import os
LOCAL_WS_SERVER_PORT = os.environ.get('LOCAL_WS_SERVER_PORT', '8765')
async def echo(websocket, path):
    async for message in websocket:
        await websocket.send(message)


async def main():
    async with websockets.serve(echo, "localhost", LOCAL_WS_SERVER_PORT):
        await asyncio.Future()  

asyncio.run(main())
