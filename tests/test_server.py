from entities.server import Server

server = Server()

server.initialize()

print()

print("Initialized :", server.initialized)

print("Users :", len(server.users))

print("Devices :", len(server.devices))