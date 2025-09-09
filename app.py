from flask import Flask, redirect, request, jsonify, render_template, session
import requests
from requests.auth import HTTPBasicAuth
import json
import time
from datetime import datetime
import threading
import os
from urllib.parse import urlencode

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Change this to a fixed secret key in production

# Discord OAuth2 configuration
CLIENT_ID = '1414847487881117746'
CLIENT_SECRET = '6Gt7sYFShJIJCSUgtkiGBGVFmRiVs1fz'
REDIRECT_URI = 'https://prussian-blueeel.onpella.app/callback'
DISCORD_API_URL = 'https://discord.com/api/v10'
BOT_TOKEN = ''  # For making API requests as your bot

# Token storage file
TOKEN_FILE = 'tokens.json'

def load_tokens():
    try:
        with open(TOKEN_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_tokens(tokens):
    with open(TOKEN_FILE, 'w') as f:
        json.dump(tokens, f, indent=2)

def refresh_tokens_loop():
    """Background thread to refresh tokens every 5 minutes"""
    while True:
        time.sleep(300)  # 5 minutes
        refresh_all_tokens()

def refresh_all_tokens():
    """Refresh all access tokens that are about to expire"""
    tokens = load_tokens()
    updated = False
    
    for user_id, token_data in list(tokens.items()):
        if token_data.get('expires_at', 0) <= time.time() + 60:  # Refresh if expires in less than 1 minute
            success, new_tokens = refresh_user_token(token_data['refresh_token'])
            if success:
                tokens[user_id] = {
                    'access_token': new_tokens['access_token'],
                    'refresh_token': new_tokens.get('refresh_token', token_data['refresh_token']),
                    'expires_at': time.time() + new_tokens['expires_in'],
                    'scope': new_tokens['scope']
                }
                updated = True
            else:
                # Remove invalid tokens
                del tokens[user_id]
                updated = True
    
    if updated:
        save_tokens(tokens)

def refresh_user_token(refresh_token):
    """Refresh a single user's access token"""
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    try:
        r = requests.post(f'{DISCORD_API_URL}/oauth2/token', data=data, headers=headers)
        r.raise_for_status()
        return True, r.json()
    except requests.exceptions.RequestException as e:
        print(f"Error refreshing token: {e}")
        return False, None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    # Generate the Discord OAuth2 URL
    params = {
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'response_type': 'code',
        'scope': 'identify guilds.join'
    }
    url = f"https://discord.com/api/oauth2/authorize?{urlencode(params)}"
    return redirect(url)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    if not code:
        return redirect('/error?message=No authorization code provided')
    
    # Exchange the code for an access token
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'scope': 'identify guilds.join'
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    try:
        r = requests.post(f'{DISCORD_API_URL}/oauth2/token', data=data, headers=headers)
        r.raise_for_status()
        tokens = r.json()
    except requests.exceptions.RequestException as e:
        return redirect(f'/error?message=Failed to exchange code: {e}')
    
    # Get user information
    headers = {
        'Authorization': f"Bearer {tokens['access_token']}"
    }
    
    try:
        r = requests.get(f'{DISCORD_API_URL}/users/@me', headers=headers)
        r.raise_for_status()
        user_data = r.json()
    except requests.exceptions.RequestException as e:
        return redirect(f'/error?message=Failed to get user info: {e}')
    
    user_id = user_data['id']
    
    # Store the tokens
    tokens_data = load_tokens()
    tokens_data[user_id] = {
        'access_token': tokens['access_token'],
        'refresh_token': tokens['refresh_token'],
        'expires_at': time.time() + tokens['expires_in'],
        'scope': tokens['scope'],
        'user': user_data
    }
    save_tokens(tokens_data)
    
    # Store user ID in session for success page
    session['user_id'] = user_id
    session['username'] = user_data['username']
    
    return redirect('/success')

@app.route('/success')
def success():
    user_id = session.get('user_id')
    username = session.get('username')
    
    if not user_id or not username:
        return redirect('/')
    
    return render_template('success.html', username=username, user_id=user_id)

@app.route('/error')
def error():
    message = request.args.get('message', 'An unknown error occurred')
    return render_template('error.html', message=message)

@app.route('/tokens')
def get_tokens():
    """Endpoint for the bot to retrieve tokens"""
    return jsonify(load_tokens())

@app.route('/pull/<guild_id>', methods=['POST'])
def pull_members(guild_id):
    """Endpoint for the bot to pull members into a server"""
    # Verify the request is from your bot (simplistic approach)
    auth_header = request.headers.get('Authorization')
    if not auth_header or auth_header != f"Bearer {BOT_TOKEN}":
        return jsonify({'error': 'Unauthorized'}), 401
    
    tokens_data = load_tokens()
    
    # For each user, add them to the guild
    results = {}
    for user_id, token_data in tokens_data.items():
        access_token = token_data['access_token']
        
        # Add member to guild
        headers = {
            'Authorization': f"Bot {BOT_TOKEN}",
            'Content-Type': 'application/json'
        }
        
        data = {
            'access_token': access_token
        }
        
        try:
            r = requests.put(
                f'{DISCORD_API_URL}/guilds/{guild_id}/members/{user_id}',
                headers=headers,
                json=data
            )
            
            if r.status_code in [200, 201]:
                results[user_id] = 'Added successfully'
            elif r.status_code == 204:
                results[user_id] = 'Already in server'
            else:
                results[user_id] = f'Error: {r.status_code} - {r.text}'
        except requests.exceptions.RequestException as e:
            results[user_id] = f'Request error: {e}'
    
    return jsonify(results)

# Start the token refresh thread
refresh_thread = threading.Thread(target=refresh_tokens_loop, daemon=True)
refresh_thread.start()

if __name__ == '__main__':
    app.run(ssl_context='adhoc', host='0.0.0.0', port=5000)
