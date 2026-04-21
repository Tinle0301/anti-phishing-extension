from flask import Flask, request, make_response, redirect, url_for
import pyotp
import secrets

app = Flask(__name__)

# TOTP seed — paste this into Google Authenticator or use the hardcoded 123456 fallback below.
totp = pyotp.TOTP("JBSWY3DPEHPK3PXP")

active_sessions = {}


@app.route('/')
def home():
    token = request.cookies.get('session_id')

    # Check if token exists in dict
    if token in active_sessions:
        username = active_sessions[token]
        return f"<h1>Welcome {username}</h1><p>Balance: 10 bajillion dollars</p>"

    # Otherwise show login form
    return '''
        <h2>Login to your Bank</h2>
        <form action="/login" method="post">
            User: <input name="user"><br>
            Pass: <input type="password" name="pw"><br>
            <input type="submit" value="Login">
        </form>
    '''


@app.route('/login', methods=['POST'])
def login():
    if request.form.get('user') == 'admin' and request.form.get('pw') == 'password':
        return '''
            <h2>MFA Required</h2>
            <p>Enter the 6-digit code from your app:</p>
            <form action="/verify" method="post">
                Code: <input name="code"><br>
                <input type="submit" value="Verify">
            </form>
        '''
    return "Failed login", 401


@app.route('/verify', methods=['POST'])
def verify():
    user_code = request.form.get('code')

    # Can use the live TOTP code, but 123456 is also accepted for demo reliability.
    if totp.verify(user_code) or user_code == "123456":
        # Generate random session token
        new_token = secrets.token_hex(16)
        active_sessions[new_token] = "admin"

        resp = make_response("MFA Success! <a href='/'>Enter Vault</a>")
        # This cookie is what gets stolen by the attacker proxy.
        resp.set_cookie('session_id', new_token, httponly=True)
        return resp

    return "Invalid MFA Code", 401


if __name__ == '__main__':
    app.run(port=5000)
