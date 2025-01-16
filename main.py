import imaplib
import email
import logging
import requests
import re

# Constants
GMAIL_IMAP_HOST = "imap.gmail.com"
WHITELIST = ["socalgas.com"]
KEYWORDS = ["invoice", "bill", "statement", "payment due"]

logging.basicConfig(filename="inbox_cleanser_unsubscribe.log", level=logging.INFO)

class InboxCleanser:
    def __init__(self, address, app_password):
        """Initialize InboxCleanser with email address and app password."""
        self.host = GMAIL_IMAP_HOST
        self.whitelist = WHITELIST
        self.keywords = KEYWORDS
        self.imap_ssl = None
        self.address = address
        self.app_password = app_password

    def connect_to_imap(self):
        """Connect to the IMAP server."""
        self.imap_ssl = imaplib.IMAP4_SSL(self.host)
        logging.info(f"Connected to {self.host}")

    def login(self):
        """Login to the IMAP server and select the inbox."""
        code, resp = self.imap_ssl.login(self.address, self.app_password)
        self._output_response(code, resp)
        if code == 'OK':
            self.imap_ssl.select("Inbox", readonly=False)
            logging.info(f"Logged in as {self.address}")
        else:
            raise Exception("Failed to login")

    def logout(self):
        """Logout from the IMAP server."""
        self.imap_ssl.close()
        code, resp = self.imap_ssl.logout()
        self._output_response(code, resp)

    def search_emails(self):
        """Search for emails containing 'unsubscribe' in the body."""
        result, data = self.imap_ssl.search(None, '(BODY "unsubscribe")')
        return data[0].split()

    def fetch_email_subjects(self, email_ids):
        """Fetch and return the subjects of the given email IDs."""
        subjects = []
        for email_id in email_ids:
            msg = self._fetch_email_message(email_id)
            subjects.append(msg['subject'])
        return subjects

    def unsubscribe(self, email_ids):
        """Unsubscribe from emails and move them to trash."""
        for email_id in email_ids:
            msg = self._fetch_email_message(email_id)
            sender = email.utils.parseaddr(msg['from'])[1]
            subject = msg['subject']

            if self._is_whitelisted(sender) or self._contains_keyword(subject):
                continue

            unsubscribe_link = self._find_unsubscribe_link(msg)
            if unsubscribe_link:
                self._process_unsubscribe(sender, subject, unsubscribe_link)

            self._move_to_trash(email_id)

    def delete_emails(self):
        """Permanently delete emails marked with the '\\Deleted' flag."""
        result = self.imap_ssl.expunge()
        if result[0] == 'OK':
            logging.info("Expunged deleted emails successfully")
            print("Deleted all marked emails")
        else:
            logging.error("Failed to expunge emails")

    # Private Methods
    def _fetch_email_message(self, email_id):
        """Fetch the raw email message for a given email ID."""
        result, msg_data = self.imap_ssl.fetch(email_id, '(RFC822)')
        return email.message_from_bytes(msg_data[0][1])

    def _find_unsubscribe_link(self, msg):
        """Extract the unsubscribe link from an email message."""
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                body = part.get_payload(decode=True).decode('utf-8')
                return self._extract_unsubscribe_link(body)
        return None

    def _process_unsubscribe(self, sender, subject, unsubscribe_link):
        """Send an HTTP request to unsubscribe using the link."""
        response = requests.get(unsubscribe_link)
        if response.status_code == 200:
            self._log_unsubscribe(sender, subject)
            print(f"Unsubscribed from: {subject}")
        else:
            logging.error(f"Failed to unsubscribe from {subject}: {response.status_code}")

    def _move_to_trash(self, email_id):
        """Move the specified email to Gmail's Trash folder."""
        result, response = self.imap_ssl.copy(email_id, "[Gmail]/Trash")
        if result == 'OK':
            self.imap_ssl.store(email_id, '+FLAGS', '\\Deleted')
            logging.info(f"Email {email_id} moved to Trash")
        else:
            logging.error(f"Failed to move email {email_id} to Trash: {response}")

    def _extract_unsubscribe_link(self, email_body):
        """Extract unsubscribe link from the email body."""
        match = re.search(r'<a\s+[^>]*href="([^"]+)"[^>]*>([^<]*)unsubscribe([^<]*)</a>', email_body, re.IGNORECASE)
        if match:
            return match.group(1)
        match = re.search(r'mailto:([^"]+)', email_body, re.IGNORECASE)
        if match and "unsubscribe" in match.group(1).lower():
            return match.group(0)
        match = re.search(r'https?://[^"\s]+', email_body, re.IGNORECASE)
        if match and "unsubscribe" in match.group(0).lower():
            return match.group(0)
        return None

    def _is_whitelisted(self, email):
        """Check if an email is from a whitelisted domain."""
        return any(domain in email for domain in self.whitelist)

    def _contains_keyword(self, email):
        """Check if an email subject contains any of the keywords."""
        return any(keyword in email.lower() for keyword in self.keywords)

    def _log_unsubscribe(self, sender, subject):
        """Log the unsubscribe action."""
        logging.info(f"Unsubscribed from {sender} with subject: {subject}")

    def _output_response(self, code, resp):
        """Output the response code and message from IMAP commands."""
        print(f"Response Code : {code}")
        print(f"Response      : {resp[0].decode()}\n")

if __name__ == "__main__":
    address = input("Enter email address: ")
    app_password = input("Enter app password: ")
    inbox = InboxCleanser(address, app_password)

    inbox.connect_to_imap()
    inbox.login()
    email_ids = inbox.search_emails()[:10]
    print(inbox.fetch_email_subjects(email_ids))
    inbox.unsubscribe(email_ids)
    inbox.delete_emails()
    inbox.logout()