import os
import json
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
from flask import Flask, redirect, request, url_for, session, render_template, request, jsonify
from google.auth.transport.requests import Request
from classifier import classify_email
import tempfile
# Set up Flask app
app = Flask(__name__)
app.secret_key = '131313'  # Required to keep session secure

# Access the environment variables
client_id = os.getenv('CLIENT_ID')
project_id = os.getenv('PROJECT_ID')
auth_uri = os.getenv('AUTH_URI')
token_uri = os.getenv('TOKEN_URI')
auth_provider_cert_url = os.getenv('AUTH_PROVIDER_CERT_URL')
client_secret = os.getenv('CLIENT_SECRET')
redirect_uri = os.getenv('REDIRECT_URI')

# OAuth 2.0 Client ID and Secret
CLIENT_SECRETS_FILE = {
    "web": {
        "client_id": client_id,
        "project_id": project_id,
        "auth_uri": auth_uri,
        "token_uri": token_uri,
        "auth_provider_x509_cert_url": auth_provider_cert_url,
        "client_secret": client_secret,
        "redirect_uris": [redirect_uri]
    }
}

# OAuth 2.0 scopes
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Redirect URI for OAuth flow
# REDIRECT_URI = 'http://localhost:5000/oauth2callback'  # Ensure this matches Google Cloud Console
REDIRECT_URI = 'https://emailfallacydetector-vf57.onrender.com/oauth2callback'  # Ensure this matches Google Cloud Console

# Google API settings
API_SERVICE_NAME = 'gmail'
API_VERSION = 'v1'

# Index route
@app.route('/')
def index():
    # return 'Welcome to the Spam Classifier! <a href="/authorize">Authorize Gmail</a>'
    return render_template('index.html')

# Authorize route: Start the OAuth flow
@app.route('/authorize')
def authorize():



    with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as tmp:
            json.dump(CLIENT_SECRETS_FILE, tmp)
            tmp_path = tmp.name
    # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        tmp_path, scopes=SCOPES)

    # Set the redirect URI for the authorization response
    flow.redirect_uri = url_for('oauth2callback', _external=True)

    # Generate the authorization URL
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )

    # Store the state in the session to validate the callback later
    session['state'] = state

    return redirect(authorization_url)

# OAuth2 callback route: Handle the redirect back from Google
@app.route('/oauth2callback')
def oauth2callback():
    # Get the state from the session
    state = session.get('state')

    if not state:
        return 'Error: State not found in session. Please try again.'

    with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as tmp:
            json.dump(CLIENT_SECRETS_FILE, tmp)
            tmp_path = tmp.name
    # Recreate the flow instance to continue the OAuth flow
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        tmp_path, scopes=SCOPES, state=state)
    flow.redirect_uri = url_for('oauth2callback', _external=True)

    # Exchange the authorization code for access token
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)

    # Save the credentials in the session
    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)

    return redirect(url_for('list_emails'))

# List emails from Gmail
@app.route('/list_emails')
def list_emails():
    # Check if credentials are in the session
    if 'credentials' not in session:
        return redirect(url_for('authorize'))

    # Load credentials from session
    credentials = google.oauth2.credentials.Credentials(
        **session['credentials'])

    if credentials.expired and credentials.refresh_token:
        credentials.refresh(Request()) 
    
    # Use the Gmail API to list messages
    service = googleapiclient.discovery.build(API_SERVICE_NAME, API_VERSION, credentials=credentials)

    results = service.users().messages().list(userId='me', maxResults=10).execute()
    messages = results.get('messages', [])

    # testing on extracted message
    
    # return render_template('emails.html')


    if not messages:
        return 'No messages found.'

    message_list = '<h2>Recent Emails:</h2>'
    for message in messages:
        msg = service.users().messages().get(userId='me', id=message['id']).execute()
        snippet = msg.get('snippet', '')
        res = classify_email(snippet)
        message_list += f'<p> {snippet} : </p> <span>{res}<span> <hr>'

    return message_list



@app.route('/check_email',methods=['POST'])
def checkemail():
    email = request.form['email'] 
     
    result = classify_email(email)

    if result == "spam":
        message = "Email is classified as SPAM"
    else:
        message = "Email is classified as NOT SPAM"
    
    return render_template('index.html', result=result, message=message)

# Helper function to convert credentials to a dictionary
def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}

# Run Flask app
if __name__ == '__main__':
    app.run(port=5000, debug=True)
