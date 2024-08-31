from core.packet_capture import start_sniffing
from app.routes import app
import threading


def run_sniffer():
    """
    Starts the packet sniffing process in a separate thread.

    This function is used to start the packet capture process by calling
    the start_sniffing function from the core.packet_capture module.
    """
    start_sniffing()


if __name__ == "__main__":
    """
    Entry point of the application.

    This block of code is executed when the script is run directly.
    It starts a separate thread for packet sniffing and then starts the
    Flask web server to handle HTTP requests.

    - A daemon thread is created for packet sniffing to run in the background.
    - The Flask application is started on host '0.0.0.0' and port 5000.
    """
    # Create a thread for packet sniffing
    sniffer_thread = threading.Thread(target=run_sniffer)
    sniffer_thread.daemon = True  # Ensure the thread exits when the main program exits
    sniffer_thread.start()

    # Run the Flask web server
    app.run(host="0.0.0.0", port=5000)
