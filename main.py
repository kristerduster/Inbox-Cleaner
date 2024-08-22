import imaplib
import email
import logging
import requests
import re

GMAIL_IMAP_HOST = "imap.gmail.com"
WHITELIST = ["socalgas.com"]
KEYWORDS = ["invoice", "bill", "statement", "payment due"]

logging.basicConfig(filename = "inbox_cleanser_unsubscribe.log", level = logging.INFO)

class InboxCleanser:
    def __init__(self, address, app_password):
        self.host = GMAIL_IMAP_HOST
        self.whitelist = WHITELIST
        self.keywords = KEYWORDS
        self.imap_ssl = None
        self.address = address
        self.app_password = app_password
        

    def connect_to_imap(self):
        self.imap_ssl = imaplib.IMAP4_SSL(self.host)

    def login(self):
        code, resp = self.imap_ssl.login(self.address, self.app_password)
        self._output_response(code, resp)
        self.imap_ssl.select("Inbox")
        
    def logout(self):
        self.imap_ssl.close()
        code, resp = self.imap_ssl.logout()
        self._output_response(code, resp)

    def search_emails(self):
        result, data = self.imap_ssl.search(None, '(BODY "unsubscribe")')
        return data[0].split()
    
    def fetch_email_subjects(self, email_ids):
        subjects = []
        for email_id in email_ids:
            result, msg_data = self.imap_ssl.fetch(email_id, '(RFC822)')
            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)
            subject = msg['subject']
            subjects.append(subject)
        return subjects
    

    

    def unsubscribe(self, email_ids):
        for email_id in email_ids:
            result, msg_data = self.imap_ssl.fetch(email_id, '(RFC822)')
            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)
            sender = email.utils.parseaddr(msg['from'])[1]
            subject = msg['subject']
            

            if (self._is_whitelisted(sender) or self._contains_keyword(subject)):
                continue

            for part in msg.walk():
                
                if part.get_content_type() == "text/html":
                    body = part.get_payload(decode=True).decode('utf-8')
                    unsubscribe_link = self._extract_unsubscribe_link(body)
                    if unsubscribe_link:
                        response = requests.get(unsubscribe_link)
                        if response.status_code == 200:
                            self._log_unsubscribe(sender, subject)
                            print(f"Unsubscribed from: {subject}")
                        else:
                            logging.error(f"Failed to unsubscribe from {subject}: {response.status_code}")
                    else:
                        logging.warning(f"No unsubscribe link found in {subject} from {sender}")
            
            logging.info(f"Marking email for deletion: {subject} from {sender}")
            self.imap_ssl.store(email_id, '+FLAGS', '\\Deleted')
      

    def delete_emails(self):
        self.imap_ssl.expunge()
        print("Deleted all emails")

    def _output_response(self, code, resp):
        print("Response Code : {}".format(code))
        print("Response      : {}\n".format(resp[0].decode()))

    def _extract_unsubscribe_link(self, email_body):
        # Try to find an anchor tag with "unsubscribe" text
        match = re.search(r'<a\s+[^>]*href="([^"]+)"[^>]*>([^<]*)unsubscribe([^<]*)</a>', email_body, re.IGNORECASE)
        if match:
            return match.group(1)
        
        # Try to find a mailto link with "unsubscribe" in the email address
        match = re.search(r'mailto:([^"]+)', email_body, re.IGNORECASE)
        if match and "unsubscribe" in match.group(1).lower():
            return match.group(0)
        
        # Try to find a plain URL with "unsubscribe" in the text
        match = re.search(r'https?://[^"\s]+', email_body, re.IGNORECASE)
        if match and "unsubscribe" in match.group(0).lower():
            return match.group(0)
        
        return None
    
    def _is_whitelisted(self, email):
        return any(domain in email for domain in self.whitelist)
    
    def _contains_keyword(self, email):
        return any(keyword in email.lower() for keyword in self.keywords)
    
    def _log_unsubscribe(self, sender, subject):
        logging.info(f"Unsubscribed from {sender} with subject: {subject}")


if __name__ == "__main__":
    address = input("Enter email address:")
    app_password = input("Enter app password: ")
    inbox = InboxCleanser(address, app_password)
    inbox.connect_to_imap()
    inbox.login()
    ids = inbox.search_emails()[:10]
    print(inbox.fetch_email_subjects(ids))
    inbox.unsubscribe(ids)
    inbox.delete_emails()
    inbox.logout()

