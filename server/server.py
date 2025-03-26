import asyncio
import websockets
import subprocess

async def handle_client(websocket, path):
    try:
        async for message in websocket:
            if message == "network_scan":
                result = subprocess.run(["python3", "server/NetworkScan.py"], capture_output=True, text=True)
                await websocket.send(f"NetworkScan Output:\n{result.stdout}")

            elif message == "port_scan":
                result = subprocess.run(["python3", "server/PortScan.py"], capture_output=True, text=True)
                await websocket.send(f"PortScan Output:\n{result.stdout}")

    except websockets.exceptions.ConnectionClosed:
        print("Client disconnected")

start_server = websockets.serve(handle_client, "localhost", 8080)

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
