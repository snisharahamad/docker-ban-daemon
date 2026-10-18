from flask import Flask, request
import os
app = Flask(__name__)
@app.route('/ping')
def ping():
    ip = request.args.get('ip', '127.0.0.1')
    result = os.popen(f"ping -c 1 {ip}").read()
    return f"<pre>{result}</pre>"
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
