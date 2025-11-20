Cribl Copilot Search Converter
This is a local, self-hosted web tool designed to batch-convert search queries from various vendors (like Splunk, Elastic, and Loki) into the Cribl Search KQL (Kusto Query Language) format.
It uses the official Cribl AI API endpoint and adds a layer of intelligent post-processing to correct common AI conversion errors, especially for complex Splunk stats and timechart commands.

🚀 Core Features
Batch Conversion: Process an entire list of search queries with a single click.

Multiple Input Methods:

Drag & Drop / File Upload: Load a .txt, .spl, .log, or .csv file.
Paste Text: Paste a list of queries directly into the app.
Load from URL: Fetch a text-based query list from a public URL.
Sample Data: Load random sample queries for Security, IT Ops, and Metrics to test the tool.
Intelligent Post-Processing: The tool automatically identifies the source vendor (e.g., Splunk) and applies client-side corrections to the KQL received from the AI. This includes:
Fixing summarize by clauses.
Correcting aggregation function names and aliases (e.g., dc to dcount, avg(foo) as bar).
Optimizing simple Splunk count commands to the more efficient KQL | count syntax.

Interactive UI:
Editable Searches: Modify your loaded searches in a text editor before starting the conversion.
AI Debug Log: A dedicated log panel shows the original AI output vs. the corrected KQL, so you can see exactly what changes the tool made.
Detailed Results: View source, vendor, and converted KQL in a clear table.
Copy & Download: Copy individual KQL queries or download the complete results as a CSV. You can also download the raw console and AI logs.
Dark/Light Mode: For your viewing comfort.

🛠️ How It Works
This tool consists of two parts:
Local Python Server (server.py): A lightweight Python 3 HTTP server that serves the index.html, style.css, and script.js files to your browser. It's only used to host the app locally; it does not process any of your data.
Frontend Application (script.js): All the work happens in your browser.
When you click "Start," the JavaScript client sends each of your search queries, one by one, to the official Cribl AI endpoint (https://ai.cribl.cloud/api/kql).
It receives the KQL response from the AI.
It then runs the KQL through a series of post-processing and correction functions (like replaceKqlByClause, replaceKqlAggAliases, etc.) to improve accuracy.
The final, corrected KQL is displayed in the results table.

📋 Prerequisites
Python 3
A modern web browser
An internet connection (to access the Cribl AI API)

⚡ Getting Started
Ensure server.py is executable, or be prepared to run it with python3.
From your terminal, navigate to the project directory and run the server:

Bash

python3 server.py
(You may also be able to use python server.py or ./server.py)

The script will automatically find an available port (starting with 42000) and open the tool in your default web browser.
Load your search queries using one of the input methods (e.g., paste, upload file).
(Optional) Edit the queries in the "Editable Searches" text area.
Click the 🚀 Start button to begin the conversion.
Review the results in the "Conversion Results" table.
Check the "AI Debug Log" panel to see any corrections that were applied.
Click Download Results to get a CSV file of your conversions.
To stop the server, press Ctrl+C in your terminal.