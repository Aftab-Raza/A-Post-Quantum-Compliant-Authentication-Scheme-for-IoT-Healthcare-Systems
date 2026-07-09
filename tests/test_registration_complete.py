from entities.server import Server
from entities.user import User
from protocol.registration import RegistrationProtocol

server = Server()

server.initialize()

user = User(
    "vickey",
    "password123"
)

registration = RegistrationProtocol(server)

registration.register(user)

print()

print("=" * 60)

print("REGISTERED :", user.registered)

print("SMART CARD :", user.smartcard.personalized)

print("DATABASE :", server.database.user_exists("vickey"))

print()

print("Lambda :", len(user.smartcard.lambda_value))

print("Eta :", len(user.smartcard.eta))

print("Zeta :", len(user.smartcard.zeta))