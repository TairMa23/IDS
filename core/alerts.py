def alert(message, packet):
    with open('logs/alerts.log', 'a') as log_file:
        log_file.write(f"{message} | Packet: {packet.summary()}\n")
