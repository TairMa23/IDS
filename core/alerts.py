def alert(message, packet):
    """
    Logs an alert message and the packet summary to a log file.

    Args:
        message (str): The alert message to log.
        packet (scapy.packet.Packet): The network packet associated with the alert.

    This function appends the alert message and a summary of the packet
    to the 'alerts.log' file. Each entry is recorded on a new line, with
    the message and packet details separated by a pipe symbol.
    """
    with open('logs/alerts.log', 'a') as log_file:
        log_file.write(f"{message} | Packet: {packet.summary()}\n")
