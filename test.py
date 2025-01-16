import imaplib
import time

GMAIL_IMAP_HOST = "imap.gmail.com"
ADDRESS1 = "kristerduster1@gmail.com"
APP_PASSWORD_K1 = "afvi fgwu flwf tcaj"

def establish_ssl_connection(host, port):
    # start = time.time()
    try:
        imap_ssl = imaplib.IMAP4_SSL(host=host, port=port)
    except Exception as e:
        print("ErrorType : {}, Error : {}".format(type(e).__name__, e))
        imap_ssl = None

    print("Connection Object : {}".format(imap_ssl))
    # print("Total Time Taken  : {:,.2f} Seconds\n".format(time.time() - start))
    return imap_ssl

def login(imap_ssl, address, app_password):
    print("Logging into mailbox...")
    try:
        resp_code, response = imap_ssl.login(address, app_password)
    except Exception as e:
        print("ErrorType : {}, Error : {}".format(type(e).__name__, e))
        resp_code, response = None, None

    print("Response Code : {}".format(resp_code))
    print("Response      : {}\n".format(response[0].decode()))
    return resp_code, response

def logout(imap_ssl):
    print("\nLogging Out....")
    try:
        resp_code, response = imap_ssl.logout()
    except Exception as e:
        print("ErrorType : {}, Error : {}".format(type(e).__name__, e))
        resp_code, response = None, None

    print("Response Code : {}".format(resp_code))
    print("Response      : {}".format(response[0].decode()))
    return resp_code, response


if __name__ == "__main__": 
    imap_ssl = establish_ssl_connection(GMAIL_IMAP_HOST, imaplib.IMAP4_SSL_PORT)
    if imap_ssl:
        print("Connection Established Successfully")
        login(imap_ssl, ADDRESS1, APP_PASSWORD_K1)

        try:
            resp_code, directories = imap_ssl.list()
        except Exception as e:
            print("ErrorType : {}, Error : {}".format(type(e).__name__, e))
            resp_code, directories = None, None

        print("Response Code : {}".format(resp_code))
        print("========= List of Directories =================\n")
        for directory in directories:
            print(directory.decode())

        #################### List Directores #####################
        try:
            resp_code, directories = imap_ssl.list(directory="[Gmail]")
        except Exception as e:
            print("ErrorType : {}, Error : {}".format(type(e).__name__, e))
            resp_code, directories = None, None

        print("Response Code : {}".format(resp_code))
        print("\n========= List of Directories =================\n")
        for directory in directories:
            print(directory.decode())

        logout(imap_ssl)
    else:
        print("Connection Failed")