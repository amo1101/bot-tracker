import requests
import json
import pyzipper
import hashlib
import os
import logging

l = logging.getLogger(name=__name__)

class Bazaar:
    """Malware Bazaar class wrapper for methods and shared values

    Args:
        url (str, optional): URL of malware bazaar. Defaults to 'https://mb-api.abuse.ch/api/v1/'.
        api_key (str, optional): API Key to send requests with; REQUIRED. Defaults to "".

    Attributes:
        url (str): URL of malware bazaar.
        session (:class:`requests.Session`): Requests session
        valid_fields (list): list of valid fields
        valid_selectors (list): list of valid selectors
        valid_types (list): list of valid types
        valid_keys (list): list of valid keys
    """
    def __init__(self, url: str = 'https://mb-api.abuse.ch/api/v1/', api_key: str = "10fec6243baa59a4ca9738022ae7d7e9"):
        self.url = url
        self.valid_fields = ['sha256_hash', 'sha1_hash', 'md5_hash', 'file_name', 'signature', 'imphash']
        self.valid_selectors = ['100', 'time']
        self.valid_types = ["tag", "signature"]
        self.valid_keys = ['urlhaus', 'any_run', 'joe_sandbox', 'malpedia',
            'twitter', 'links', 'dropped_by_md5', 'dropped_by_sha256',
            'dropped_by_malware', 'dropping_md5', 'dropping_sha256',
            'dropping_malware', 'add_tag', 'remove_tag', 'comment'
        ]
        session = requests.Session()
        session.headers = {"API-KEY": api_key}
        self.session = session

    def check_fields(self, field, field_value, options_list):
        if field_value not in options_list:
            raise ValueError("{} must be one of {}".format(field, options_list))

    def upload_file(self, myfile):
        data = {
            'tags': '',
            'delivery_method': 'other'
        }
        files = {
            'json_data': (None, json.dumps(data), 'application/json'),
            'file': (open(myfile,'rb'))
        }
        l.debug(f"Uploading file {myfile}")
        response = self.session.post(self.url, files=files)
        json_data = response.json()
        status = json_data['query_status']

        l.debug("Upload status: " + status)
        if(status == "file_already_known"):
            with open(myfile,"rb") as f:
                file_bytes = f.read()
                hash_sha256 = hashlib.sha256(file_bytes).hexdigest()
                return "https://bazaar.abuse.ch/sample/" + hash_sha256 + "/"

    def check_sha256(self, s):
        if s == "":
            return
        if len(s) != 64:
            raise ValueError("Please use sha256 value instead of '" + s + "'")
        return str(s)

    def bazaar_add_comment(self, hash: str, comment: str):
        """Adds a comment to a malware hash

        Args:
            hash (str): Hash value to add comment to
            comment (str): Comment to add

        Returns:
            dict: Request json response
        """

        data = {
            'query': 'add_comment',
            'sha256_hash': ''+hash+'',
            'comment': u''+comment+''
        }

        response = self.session.post(self.url, data=data, timeout=15)
        return response.json()

    def bazaar_download(self, hash: str, unzip: bool = True, info: bool = False):
        """Downloads malware hash's information

        Args:
            hash (str): Hash value to download
            unzip (bool, optional): Whether to unzip the file returned
            info (bool, optional): Whether to get information as JSON

        Returns:
            dict OR str OR list: Request response, name of zip file written to, or list of names of files unpacked from zip
        """
        if(unzip == True and info == True):
            raise ValueError("Sorry, please select unzip or information display.")
        self.check_sha256(hash)

        ZIP_PASSWORD = "infected"

        if(info == False):
            data = {
                'query': 'get_file',
                'sha256_hash': hash,
            }

            response = self.session.post(self.url, data=data, timeout=15, allow_redirects=True)
            open(hash+'.zip', 'wb').write(response.content)

            if(unzip == True):
                try:
                    with pyzipper.AESZipFile(hash+".zip") as zf:
                        zf.pwd = ZIP_PASSWORD.encode()
                        _ = zf.extractall(".")
                        l.debug("Sample \""+hash+"\" downloaded and unpacked.")
                        os.remove(hash+".zip")
                        return zf.namelist()
                except BaseException as e:
                    l.debug(f'An error occured: {e}')
                    return None
            else:
                l.debug("Sample \""+hash+"\" downloaded.")
                return hash + '.zip'
        else:
            data = {
                'query': 'get_info',
                'hash': hash,
            }
            l.debug(data)
            response = self.session.post(self.url, data=data, timeout=15)
            return response.json()

    def bazaar_get_sample_json(self):
        """Get malware sample to view JSON

        Returns:
            dict: Request response
        """
        data = {'query': 'get_recent', 'selector': "time"}
        response = self.session.post(self.url, data=data, timeout=15)
        json_response = response.content.decode("utf-8", "ignore")
        json_response = json.loads(json_response)

        if(json_response["query_status"] == 'no_results'):
            l.debug(f"No samples found, terminating.")
            return

        for entry in json_response['data']:
            sample_sha256 = entry['sha256_hash']
            if(os.path.isfile(sample_sha256+'.json') == False):
                data = {'query': 'get_info', 'hash': sample_sha256}
                response = self.session.post(self.url, data=data, timeout=15, allow_redirects=True)
                return response.json()

    def bazaar_list_samples(self, selector: str, field: str = None):
        """List samples of malware by count or date

        Args:
            selector (str): List by count or date; valid options are ``100`` or ``time``
            field (str, optional): Field to sort by. Defaults to None. Options are:
                ``sha256_hash``, ``sha1_hash``, ``md5_hash``, ``file_name``, ``signature``, or ``imphash``

        Returns:
            dict OR list: JSON response
        """

        self.check_fields("selector", selector, self.valid_selectors)

        if field:
            self.check_fields("field", field, self.valid_fields)

        data = {
            'query': 'get_recent',
            'selector': str(selector),
        }

        response = self.session.post(self.url, data=data, timeout=15)
        json_response = response.json()

        if(field):
            json_response = [i[field] for i in json_response['data']]

        return json_response

    def bazaar_query(self, type_: str, query: str, limit: str, field: str = None):
        """Query sample information by tag or signature on Malware Bazaar by abuse.ch

        Args:
            type_ (str): type of query to make; valid options are ``tag`` or ``signature``
            query (str): Query value (trickbot, exe, ...)
            field (str, optional): Field to return. Defaults to None. Options are:
                ``sha256_hash``, ``sha1_hash``, ``md5_hash``, ``file_name``, ``signature``, or ``imphash``

        Returns:
            dict OR list: JSON response
        """
        self.check_fields("type_", type_, self.valid_types)
        if field:
            self.check_fields("field", field, self.valid_fields)

        data = {}

        if(type == "tag"):
            data = {
                'query': 'get_taginfo',
                'tag': '' + query + '',
                'limit': '' + limit + ''
            }
        else:
            data = {
                'query': 'get_siginfo',
                'signature': '' + query + '',
                'limit': '' + limit + ''
            }

        response = self.session.post(self.url, data=data, timeout=300)
        l.debug(f'respone:{response}')
        json_response = response.json()

        if(field):
            json_response = [i[field] for i in json_response['data']]

        return json_response

    def bazaar_update(self, hash: str, key: str, value: str):
        """Update a malware sample on Malware Bazaar by abuse.ch. 

        Notice: You can only update your own samples

        Args:
            hash (str): Hash to udate
            key (str): Field to update. Options are:
                ``urlhaus``, ``any_run``, ``joe_sandbox``, ``malpedia``,
                ``twitter``, ``links``, ``dropped_by_md5``, ``dropped_by_sha256``, 
                ``dropped_by_malware``, ``dropping_md5``, ``dropping_sha256``, 
                ``dropping_malware``, ``add_tag``, ``remove_tag``, ``comment``
            value (str): Value to update field with

        Returns:
            dict: JSON response
        """
        self.check_fields("key", key, self.valid_keys)


        data = {
            'query': 'update',
            'sha256_hash': ''+hash+'',
            'key': ''+key+'',
            'value': ''+value+''
        }

        response = self.session.post(self.url, data=data, timeout=15)

        return response.json()

    def bazaar_upload_directory(self, directory: str, file: str = None):
        """Upload malware samples from a folder to MalwareBazaar by abuse.ch

        Args:
            directory (str): Directory name to upload files from
            file (str, optional): File name to upload for single file mode. Defaults to None.

        Raises:
            ValueError: Raised if directory is not valid

        Returns:
            str: File report url
        """
        if(os.path.isdir(directory) == False):
            raise ValueError(f"Error, not a valid directory {directory}")


        l.debug("Folder: " + directory)
        with os.scandir(directory) as root_dir:
            for path in root_dir:
                if path.is_file():
                    myfile = os.path.join(directory, path.name)
                    return self.upload_file(myfile)

    def bazaar_upload(self, file: str, is_email_attachment: bool = False, is_email_link: bool = False):
        """Upload a malware sample to Malware Bazaar by abuse.ch

        Args:
            file (str): File to upload
            is_email_attachment (bool, optional): Whether file was received via email attachment. Defaults to False.
            is_email_link (bool, optional): Whether file was found in email link. Defaults to False.

        Returns:
            dict OR str: JSON response or report url
        """
        extracted_file_extension = os.path.splitext(file)[1].replace(".","")

        tags = []
        tags.append("" + extracted_file_extension + "")

        delivery_method = ""

        if is_email_attachment and is_email_link:
            delivery_method = "multiple"
        elif is_email_attachment:
            delivery_method = "email_attachment"
        elif is_email_link:
            delivery_method = "email_link"
        else:
            delivery_method = "other"

        data = {
            'tags': tags,
            'delivery_method': delivery_method
        }

        files = {
            'json_data': (None, json.dumps(data), 'application/json'),
            'file': (open(file,'rb'))
        }

        response = self.session.post(self.url, files=files)
        json_data = response.json()
        status = json_data['query_status']

        l.debug("Upload status: " + status)
        if(status == "file_already_known"):
            with open(file,"rb") as f:
                file_bytes = f.read()
                hash_sha256 = hashlib.sha256(file_bytes).hexdigest()
                return "https://bazaar.abuse.ch/sample/" + hash_sha256 + "/"

        return json_data
