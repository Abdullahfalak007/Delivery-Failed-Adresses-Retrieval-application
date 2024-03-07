from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import os
import os.path
import pickle
import base64
from email.mime.text import MIMEText
from email.header import decode_header
from datetime import datetime
import csv
import re
import html
import pytz
from google.auth.exceptions import RefreshError
import email.utils  # Import email.utils for parsing email headers

# If modifying these scopes, delete the file token.pickle.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']


def get_message(service, user_id, msg_id):
    try:
        message = service.users().messages().get(userId=user_id, id=msg_id).execute()
        msg_payload = message['payload']
        
        if 'parts' in msg_payload:
            parts = msg_payload['parts']
            email_body = ""
            for part in parts:
                if part['mimeType'] == 'text/plain':
                    data = part['body']['data']
                    decoded_data = base64.urlsafe_b64decode(data).decode('utf-8')
                    email_body += decoded_data
            return email_body
        else:
            return ""
    except Exception as error:
        print('An error occurred while fetching message: %s' % error)
        return ""


def extract_email_address(email_body):
    # Regular expression pattern to match email addresses
    pattern = r'[\w\.-]+@[\w\.-]+'
    matches = re.findall(pattern, email_body)
    if matches:
        return matches[0]  # Return the first match
    else:
        return None


def write_headers(csv_file):
    headers = ["Time Stamp", "Email Addresses"]  # Changed "Time Stamp" to "Date"
    with open(csv_file, 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(headers)


def write_to_csv(csv_file, date_time, email_address):
    with open(csv_file, 'a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        # Format date and time
        date_time_formatted = date_time.strftime('%Y-%m-%d %I:%M %p')
        writer.writerow([date_time_formatted, email_address])



def main():
    try:
        creds = None
        if os.path.exists('token.pickle'):
            with open('token.pickle', 'rb') as token:
                creds = pickle.load(token)
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                except RefreshError as e:
                    print("Failed to refresh credentials:", e)
                    return
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    'credentials.json', SCOPES)
                creds = flow.run_local_server(port=0)
            with open('token.pickle', 'wb') as token:
                pickle.dump(creds, token)

        # Build Gmail service
        service = build('gmail', 'v1', credentials=creds)

        # CSV file handling
        csv_file = 'email_records.csv'
        if not os.path.exists(csv_file):
            write_headers(csv_file)
        
        with open(csv_file, 'r', encoding='utf-8') as file:
            reader = csv.reader(file)
            header_row = next(reader, None)
            if header_row is None or header_row != ["Time Stamp", "Email Addresses"]:  # Changed header check
                write_headers(csv_file)

        # Check if CSV file is writable
        if not os.access(csv_file, os.W_OK):
            os.chmod(csv_file, 0o666)

        existing_addresses = set()
        with open(csv_file, 'r', newline='', encoding='utf-8') as file:
            reader = csv.reader(file)
            next(reader)  # Skip header row
            for row in reader:
                existing_addresses.add(row[1])  # Assuming email address is in the second column

        # Retrieve emails in batches
        page_token = None
        while True:
            results = service.users().messages().list(userId='me', pageToken=page_token).execute()
            messages = results.get('messages', [])

            if not messages:
                print('No more messages found.')
                break
            else:
                for message in messages:
                    msg_id = message['id']
                    email_body = get_message(service, 'me', msg_id)

                    # Extract email address from the email body
                    email_address = extract_email_address(email_body)

                    if email_address and email_address not in existing_addresses:
                        msg = service.users().messages().get(userId='me', id=msg_id).execute()  # Fetch the full message object
                        # Parse headers for date using email.utils
                        headers = msg['payload']['headers']
                        date_str = next(header['value'] for header in headers if header['name'] == 'Date')
                        date_tuple = email.utils.parsedate_tz(date_str)
                        if date_tuple:
                            date_utc = datetime.fromtimestamp(email.utils.mktime_tz(date_tuple), tz=pytz.utc)
                            # Format date in YYYY-MM-DD format
                            date_formatted = date_utc.strftime('%Y-%m-%d')

                            # Write data to CSV file
                            write_to_csv(csv_file, date_utc, email_address)


                            # Add email address to set of existing addresses
                            existing_addresses.add(email_address)

            # Check if there are more pages of results
            page_token = results.get('nextPageToken')
            if not page_token:
                break
    except Exception as e:
        print('An error occurred:', e)


if __name__ == '__main__':
    main()
