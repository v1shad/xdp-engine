#!/bin/bash
LOG_FILE="/tmp/fake_access.log"
IP="10.10.0.2"

echo "Appending HTTP Traversal attack..."
echo "$IP - - [10/Oct/2026:13:55:36 +0000] \"GET /../../../etc/passwd HTTP/1.1\" 200 2326 \"-\" \"Mozilla/5.0\"" >> $LOG_FILE
sleep 1

echo "Appending HTTP SQLi attack..."
echo "$IP - - [10/Oct/2026:13:55:37 +0000] \"GET /login?user=' or 1=1 HTTP/1.1\" 200 2326 \"-\" \"Mozilla/5.0\"" >> $LOG_FILE
sleep 1

echo "Appending HTTP Scanner attack..."
echo "$IP - - [10/Oct/2026:13:55:38 +0000] \"GET / HTTP/1.1\" 200 2326 \"-\" \"sqlmap/1.4.12#dev\"" >> $LOG_FILE

echo "HTTP attacks completed."
