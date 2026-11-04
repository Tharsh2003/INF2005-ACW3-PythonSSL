
import socket
import ssl

# Server configuration
HOST = "127.0.0.1"
PORT = 8443

# Create TLS context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

# Load server certificate and private key
context.load_cert_chain(
    certfile="certs/server.crt",
    keyfile="certs/server.key"
)

# Create TCP server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:

    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)

    print(f"TLS server running on {HOST}:{PORT}")
    print("Waiting for client connection...")

    while True:
        connection, address = server.accept()

        try:
            # Establish TLS connection
            with context.wrap_socket(
                connection,
                server_side=True
            ) as tls_connection:

                print("Client connected:", address)
                print("TLS version:", tls_connection.version())

                # Send test response
                tls_connection.sendall(
                    b"TLS connection successful!"
                )

        except ssl.SSLError as error:
            print("TLS error:", error)
        finally:
            connection.close()
