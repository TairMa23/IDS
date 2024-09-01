# Intrusion Detection System (IDS)

This project is a network traffic monitoring and alert system built using Flask and Scapy. It captures network packets, analyzes them for suspicious activities, and logs alerts if any anomalies are detected. The application includes a web interface for viewing logs and traffic summaries.

## Features

- **Packet Capturing**: Captures network packets and processes them for various types of network threats.
- **Port Scan Detection**: Identifies potential port scanning activities.
- **SQL Injection Detection**: Detects attempts to exploit SQL injection vulnerabilities.
- **XSS Detection**: Identifies potential Cross-Site Scripting (XSS) attacks.
- **Alert Logging**: Logs detected threats along with packet summaries to a log file.
- **Web Interface**: Provides a web interface to view logs and traffic summaries.

## Installation
**Clone the Repository**
`git clone https://github.com/yourusername/ids_project.git`.
`cd ids_project`

**Set Up a Virtual Environment (Optional but recommended):**
`python -m venv venv`
`source venv/bin/activate`
### On Windows, use `venv\Scripts\activate`

**Install Dependencies:**
`pip install -r requirements.txt`
## Configuration
1. Update Credentials:
- Edit the app/routes.py file to set the ADMIN_USERNAME and ADMIN_PASSWORD as needed.
2. Secret Key:
- Update app.secret_key with a secure key for session management.

## Running the Application
`python main.py`

## Testing
To run the tests for the application, use:
`python -m unittest discover -s tests`
