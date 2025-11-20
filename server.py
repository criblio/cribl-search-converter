#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import http.server
import socketserver
import webbrowser
import threading
import sys
import os
import socket # Imported to check port availability

# --- Server Configuration ---
# We use SimpleHTTPRequestHandler, which automatically serves index.html at the root
# and other files from the directory it's run in.
HANDLER = http.server.SimpleHTTPRequestHandler

def is_port_in_use(port):
    """
    Checks if a given port is already in use on localhost.
    Returns True if in use, False if available.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("localhost", port))
            return False # Port is available
        except OSError:
            return True # Port is in use

def find_available_port():
    """
    Tries to use the default port 42000. If it's in use,
    prompts the user to enter a new port until a free one is found.
    """
    default_port = 42000
    if not is_port_in_use(default_port):
        print(f"Default port {default_port} is available. Using it.")
        return default_port

    print(f"Warning: Default port {default_port} is already in use.")

    while True:
        try:
            port_str = input("Please enter a new port number (1025-65535): ")
            port = int(port_str)

            if not (1025 <= port <= 65535):
                print(f"Warning: Port must be between 1025 and 65535.")
                continue

            if is_port_in_use(port):
                print(f"Warning: Port {port} is also in use. Please try another.")
                continue

            print(f"Port {port} is available. Using it.")
            return port

        except ValueError:
            print(f"Warning: Invalid input. Please enter a number.")
        except KeyboardInterrupt:
            print("\nOperation cancelled by user.")
            sys.exit(0)

def run_server(server_class=http.server.HTTPServer, handler_class=HANDLER, port=42000):
    """
    Starts the HTTP server, changes to the script's directory, 
    and opens the browser.
    """
    
    # Change directory to the script's location
    # This is crucial so the server can find index.html and the /static folder
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    print(f"Serving files from: {script_dir}")
    
    server_address = ('localhost', port)

    try:
        socketserver.TCPServer.allow_reuse_address = True
        httpd = server_class(server_address, handler_class)
    except OSError as e:
        print(f"\nError: Could not start server on port {port}. Is it already in use?")
        print(f"Details: {e}")
        print("Please ensure no other service is using this port and try again.")
        sys.exit(1)
    except Exception as e:
        print(f"\nAn unexpected error occurred during server startup: {e}")
        sys.exit(1)


    print(f"\n--- Cribl KQL Converter ---")
    print(f"Serving at http://{server_address[0]}:{server_address[1]}")
    print("Your browser should open automatically.")
    print("Press Ctrl+C in this terminal to stop the server.")

    # Open the web page in a new browser tab after a short delay
    def open_browser():
        try:
            webbrowser.open(f'http://localhost:{port}')
        except Exception as e:
            print(f"\nWarning: Could not automatically open the browser: {e}")
            print(f"Please manually navigate to http://localhost:{port}")

    threading.Timer(1.25, open_browser).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped gracefully.")
        httpd.server_close()
        sys.exit(0)
    except Exception as e:
        print(f"\nAn unexpected error occurred while the server was running: {e}")
        httpd.server_close()
        sys.exit(1)

if __name__ == '__main__':
    # Print introductory message
    print("\n--- Cribl KQL Search Converter ---")
    print("This script starts a local web server to host the KQL conversion tool.")
    print("It uses the Cribl AI endpoint (https://ai.cribl.cloud/api/kql) to convert")
    print("searches from various vendors (Splunk, Elastic, Loki, etc.) to KQL.")
    print("\nAttempting to start server...")

    PORT = find_available_port() # Use the function to find an available port
    run_server(port=PORT)
