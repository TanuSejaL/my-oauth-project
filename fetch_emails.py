from flask import Flask, jsonify, request, session, redirect
from google.oauth2 import credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
import os
import google.auth.transport.requests
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import base64

app = Flask(__name__)
app.secret_key = "e2f9b0f1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7a8b9"

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/gmail.modify"]
CLIENT_SECRET_FILE = "credentials.json"
REDIRECT_URI = "http://localhost:5000/callback"  # ✅ Use HTTP instead of HTTPS for local development


def get_credentials():
    """
    Gets or refreshes user credentials.
    """
    creds = None
    if os.path.exists('token.json'):
        creds = credentials.Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception as e:
                print(f"Error refreshing credentials: {e}")
                os.remove('token.json')  # Remove the invalid token
                creds = None  # Restart the auth flow
        else:
            flow = Flow.from_client_secrets_file(CLIENT_SECRET_FILE, SCOPES, redirect_uri=REDIRECT_URI)
            auth_url, _ = flow.authorization_url(prompt='consent')
            return redirect(auth_url)

        if creds:
            with open('token.json', 'w') as token:
                token.write(creds.to_json())
    return creds


@app.route('/')
def index():
    """
    Handles the root URL, initiating the authentication flow if necessary.
    """
    creds = get_credentials()
    if isinstance(creds, credentials.Credentials):
        session['credentials'] = creds.to_json()
        return "Authentication Successful! You can now access Gmail."
    else:
        return creds  # Redirect to Google for authentication


@app.route('/callback')
def callback():
    """
    Handles the callback from Google after the user authorizes the application.
    """
    flow = Flow.from_client_secrets_file(CLIENT_SECRET_FILE, scopes=SCOPES, redirect_uri=REDIRECT_URI)
    authorization_response = request.url

    try:
        flow.fetch_token(authorization_response=authorization_response)
        creds = flow.credentials
    except Exception as e:
        return f"Error handling callback: {e}. Try accessing the main page again."

    if creds:
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
        session['credentials'] = creds.to_json()
        return redirect('/')


def get_gmail_service():
    """
    Builds and returns the Gmail API service object.
    """
    creds_json = session.get('credentials')
    if not creds_json:
        raise Exception("Credentials not found in session. Please authenticate first.")
    creds = credentials.Credentials.from_authorized_user_info(creds_json, SCOPES)
    return build('gmail', 'v1', credentials=creds)


def decode_email_body(payload):
    """
    Decodes the email body, handling different encodings and payload structures.
    """
    if not payload:
        return ""

    if 'parts' in payload:
        parts = payload['parts']
        text_parts = [decode_email_body(part) for part in parts if part.get('mimeType') == 'text/plain']
        html_parts = [decode_email_body(part) for part in parts if part.get('mimeType') == 'text/html']
        if text_parts:
            return '\n'.join(text_parts)
        elif html_parts:
            return html_parts[0]
        else:
            return ""
    elif 'data' in payload:
        try:
            decoded_data = base64.urlsafe_b64decode(payload['data'].encode('utf-8')).decode('utf-8')
            return decoded_data
        except Exception as e:
            print(f"Error decoding data: {e}")
            return ""
    return ""


def extract_email_content(message):
    """
    Extracts the email subject and body from a Gmail API message object.
    """
    headers = message.get('payload', {}).get('headers', [])
    subject = next((header['value'] for header in headers if header['name'] == 'Subject'), "")
    body = decode_email_body(message.get('payload', {}))
    return {'subject': subject, 'body': body}


@app.route('/fetch-emails')
def fetch_emails():
    """
    Fetches the latest emails from the user's inbox and returns them as JSON.
    """
    try:
        service = get_gmail_service()
        results = service.users().messages().list(userId='me', maxResults=10).execute()
        messages = results.get('messages', [])

        if not messages:
            return jsonify({'message': 'No new emails found.'})

        emails = []
        for message in messages:
            msg = service.users().messages().get(userId='me', id=message['id'], format='full').execute()
            email_content = extract_email_content(msg)
            emails.append({
                'id': message['id'],
                'subject': email_content['subject'],
                'body': email_content['body']
            })
        return jsonify(emails)

    except HttpError as error:
        return jsonify({'error': f'An error occurred: {error}'}), 500
    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred: {e}'}), 500


if __name__ == '__main__':
    app.run(debug=True, port=5000)  # ✅ Running on HTTP instead of HTTPS
