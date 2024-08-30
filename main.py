from core.packet_capture import start_sniffing
from app.routes import app
import threading


def run_sniffer():
    start_sniffing()


if __name__ == "__main__":
    # יצירת ת'רד עבור לכידת חבילות
    sniffer_thread = threading.Thread(target=run_sniffer)
    sniffer_thread.daemon = True
    sniffer_thread.start()

    # הרצת Flask
    app.run(host="0.0.0.0", port=5000)
