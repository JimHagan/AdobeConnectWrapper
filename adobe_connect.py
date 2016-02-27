import pytz
import urllib2
from django.conf import settings
from django.utils.http import urlquote
from lxml import etree
from datetime import datetime, timedelta
from dateutil.parser import parse
import string
import random


def iso_date_string_from_datetime(dt):
    """
     Unfortunately we have to massage the date string returned by datetime.isodate in order to comply
     with the expectations of Adobe Connect.
    """
    # 2015-07-15T16:30:29.863808+00:00
    # 2015-07-15T16:30:29-00:00

    dt_string = dt.isoformat()
    date = dt_string[:10]
    time = dt_string[11:19]
    offset = dt_string[26:]

    return "{0}T{1}{2}".format(date, time, "-00:00" if offset == "+00:00" else offset)


def generate_random_id(n_chars=6):
    return ''.join(random.sample((string.ascii_uppercase + string.digits),
                                 n_chars))


def get_breeze_session_id(cookies_list):
    """
    :param cookies_list:
    :return: Just the session id from the BREEZESESSION cookie
    """
    for cookie in cookies_list:
        if "BREEZESESSION" in cookie:
            # return just the session id
            return cookie[14:]
    raise AdobeConnectionError("Breeze session cookie not found in response cookie list.")


class AdobeConnectRecording:

    def __init__(self):
        self.sco_id = None
        self.url = None
        self.duration = None
        self.filename = None

    def from_xml(self, xml):
        xml_tree = etree.fromstring(xml)

        root = xml_tree.xpath("//sco")[0]

        self.sco_id = root.xpath("./@sco-id")

        if len(self.sco_id) > 0:
            self.sco_id = self.sco_id[0]
        else:
            raise AdobeConnectionError("No Sco-Id found for recording.")

        self.url = root.xpath("./url-path/text()")
        if len(self.url) > 0:
            self.url = self.url[0]

        self.duration = root.xpath("./duration/text()")
        if len(self.duration) > 0:
            self.duration = self.duration[0]

        self.filename = root.xpath("./filename/text()")

        if len(self.filename) > 0:
            self.filename = self.filename[0]


class AdobeConnectUserAccount():
    """
     Encapsulates AdobeConnect User Account Information
    """
    def __init__(self):
        self.login = None
        self.name = None
        self.principal_id = None
        self.password = None

    def from_xml(self, xml):
        xml_tree = etree.fromstring(xml)

        root = xml_tree.xpath("//principal")

        if len(root) > 0:
            root = root[0]
        else:
            raise AdobeConnectionError("No 'principal' node found in user "
                                       "account creation response.")

        self.principal_id = root.xpath("./@principal-id")
        if len(self.principal_id) > 0:
            self.principal_id = self.principal_id[0]
        else:
            raise AdobeConnectionError("principal-id not returned during user "
                                       "account creation.")

        self.name = root.xpath("./name/text()")
        if len(self.name) > 0:
            self.name = self.name[0]
        else:
            raise AdobeConnectionError("User's name not returned during user "
                                       "account creation.")

        self.login = root.xpath("./login/text()")
        if len(self.login) > 0:
            self.login = self.login[0]
        else:
            raise AdobeConnectionError("Login (user's email) not returned "
                                       "during user account creation.")

        return self


class AdobeConnectMeetingParticipant(AdobeConnectUserAccount):

    def __init__(self, meeting_sco_id):
        AdobeConnectUserAccount.__init__(self)
        self.role = None
        self.meeting_sco_id = meeting_sco_id

    def from_xml(self, xml):
        xml_tree = etree.fromstring(xml)

        root = xml_tree.xpath("//user")[0]

        self.name = root.xpath("./@name")
        if len(self.name) > 0:
            self.name = self.name[0]
        else:
            self.name = None

        self.principal_id = root.xpath("./@principal_id")
        if len(self.principal_id) > 0:
            self.principal_id = self.principal_id[0]
        else:
            self.principal_id = None

        self.login = root.xpath("./@login")
        if len(self.login) > 0:
            self.login = self.login[0]
        else:
            self.login = None

        self.role = root.xpath("./@permission_id")
        if len(self.role) > 0:
            self.role = self.role[0]
        else:
            self.role = None


class AdobeConnectMeeting():
    """
      Encapsulates AdobeConnect Meeting Information
    """

    def __init__(self, ):
        self.sco_id = None
        self.url = None
        self.description = None
        self.date_created = None
        self.date_end = None
        self.date_modified = None

    def from_xml(self, xml):
        self.__init__()  # Wipe out any previous values
        xml_tree = etree.fromstring(xml)

        root_row = xml_tree.xpath("//row")
        root_sco = xml_tree.xpath("//sco")
        if len(root_row) > 0:
            root = root_row[0]
        elif len(root_sco) > 0:
            root = root_sco[0]
        else:
            raise AdobeConnectionError("No 'row' or 'sco' node found in "
                                       "meeting response.")

        sco_id = root.xpath("./@sco-id")
        if len(sco_id) > 0:
            self.sco_id = sco_id[0]
        else:
            raise AdobeConnectionError("No SCO-ID found in 'get_meeting' "
                                       "results")

        # Get meetings returns xml with "url" create meeting returns "url-path"

        url = root.xpath("./url/text()")
        url_path = root.xpath("./url-path/text()")

        if len(url) > 0:
            self.url = url[0]
        elif len(url_path) > 0:
            self.url = url_path[0]

        self.url = self.url[1:]

        description = root.xpath("./name/text()")
        if len(description) > 0:
            self.description = description[0]

        date_created = root.xpath("./date_created/text()")
        if len(date_created) > 0:
            self.date_created = date_created[0]

        date_end = root.xpath("./date_end/text()")
        if len(date_end) > 0:
            self.date_end = date_end

        date_modified = root.xpath("./date_modified/text()")
        if len(date_modified) > 0:
            self.date_modified = date_modified[0]

        return self


class AdobeConnectionError(Exception):
    pass


class AdobeConnectAPI(object):
    """
    Wrapper for Adobe Connect HTTP API.  Handles the following
    - authentication based upon Flashnotes environment settings
    - serialization and deserialization of XML
    """

    # SCO-ID of default templates
    MEETING_TEMPLATES = \
        {"TUTORING": settings.FN_CONNECT_TUTORING_TEMPLATE,
         "LIVE_QA": settings.FN_CONNECT_LIVE_QA_TEMPLATE,
         "VIDEO_TUTORIAL": settings.FN_CONNECT_VIDEO_TUTORIAL_TEMPLATE,
         "DEMO": settings.FN_CONNECT_DEMO_TEMPLATE}

    # SCO-ID of folder to put new meetings into
    DEFAULT_MEETINGS_FOLDER = settings.FN_CONNECT_DEFAULT_MEETINGS_FOLDER
    DEFAULT_RECORDINGS_FOLDER = settings.FN_CONNECT_DEFAULT_RECORDINGS_FOLDER

    DEFAULT_USER_ACCOUNT_PASSWORD = u"Flash!123"

    # Principal id for named host user group
    GROUP_IDS = \
        {"LIVE_ADMINS": settings.FN_CONNECT_LIVE_ADMINS_GROUP_ID}

    def __init__(self):
        self._auth_cookie = None
        self._last_authentication_datetime = None
        self._is_authenticated = False
        self._authenticate()

    def _authenticate(self):
        """
        Authenticates to the AdobeConnect API server.  If success stores
        the authentication cookie which will be embedded in subsequent requests
        made through this wrapper.

        The cookie string should have the format:

        BREEZESESSION=*session id*

        """
        fn_connect_login_template = u"https://{0}/api/xml?" \
                                    "action=login&login={1}&password={2}"
        fn_connect_login_url = fn_connect_login_template.\
            format(settings.FN_CONNECT_DOMAIN,
                   settings.FN_CONNECT_USER,
                   settings.FN_CONNECT_PASSWORD)

        try:
            response = urllib2.urlopen(fn_connect_login_url)
            cookies_string = response.info()['Set-Cookie']
            response.close()
            cookies_list = cookies_string.split(';')
            self._auth_cookie = "BREEZESESSION={0}".format(get_breeze_session_id(cookies_list))
            self._last_authentication_datetime = datetime.utcnow()
            self._is_authenticated = True
            return True

        except Exception as e:
            raise AdobeConnectionError(str(e))

    def _make_request(self, url):
        if not self._is_authenticated or \
                self._last_authentication_datetime < \
                (datetime.utcnow() - timedelta(minutes=15)):
            self._authenticate()

        try:
            opener = urllib2.build_opener()
            opener.addheaders.append(('Cookie', self._auth_cookie))
            response = opener.open(url)
            xml = response.read()
            response.close()

            # All calls should be accompanied by a status
            # Raise exception if status other than 'ok'
            xml_tree = etree.fromstring(xml)

            root = xml_tree.xpath("//results")
            if len(root) > 0:
                root = root[0]
            else:
                raise AdobeConnectionError("No results returned by request.")

            status_code = root.xpath("./status/@code")[0]
            status_code = status_code.lower()

            if status_code != "ok":
                raise AdobeConnectionError("Request returned status other "
                                           "than 'ok' - status code: {0}\n{1}"
                                           .format(status_code,
                                                   xml))

            return xml

        except Exception as e:
            raise AdobeConnectionError(str(e))

    def get_meetings(self, sco_id_list=None, start_date=None, end_date=None):
        """
        :param sco_id_list: one or more Adobe Connect sco ids (or None)
        :param start_date: datetime string for start_date filter (or None)
        :param end_date: datetime string for end_date_filter (or None)
        :return: list of one or more AdobeConnectMeeting objects
        TBD: sco_id_list filter works. Must determine if date can be used to filter.
        """
        get_meetings_template = \
            u"https://{0}/api/xml?action="\
            "sco-contents&sco-id={1}"
        get_meetings_url = get_meetings_template.\
            format(settings.FN_CONNECT_DOMAIN,
                   self.DEFAULT_MEETINGS_FOLDER)

        if sco_id_list:
            if len(sco_id_list) > 0:
                for sco_id in sco_id_list:
                    fn_filter_sco_id_template = "&filter-sco-id={0}"
                    fn_filter_sco_id_url = fn_filter_sco_id_template.format(sco_id)
                    get_meetings_url += fn_filter_sco_id_url

        meetings = []

        meetings_xml = self._make_request(get_meetings_url)

        # Parse xml into meeting AdobeConnectMeeting objects
        xml_tree = etree.fromstring(meetings_xml)
        scos = xml_tree.xpath("//sco")

        for sco in scos:
            meeting = AdobeConnectMeeting()
            meeting = AdobeConnectMeeting()
            meeting.from_xml(etree.tostring(sco))
            meetings.append(meeting)

        return meetings

    def add_participant_to_meeting(self, principal_id, meeting_sco_id, role):
        """
        :param principal_id: Adobe Connect user account id
        :param meeting_sco_id: Resource id for existing meeting
        :param role: "host", "mini-host" for presenter or "view" for guests (double check)
        :return: TBD (return a data structure)
        """
        fn_add_participant_to_meeting_template = \
            u"https://{0}/api/xml?action=permissions-update" \
            "&principal-id={1}&acl-id={2}&permission-id={3}" \
            "&principal-id=public-access&permission-id=denied"
        fn_add_participant_to_meeting_url = \
            fn_add_participant_to_meeting_template.\
            format(settings.FN_CONNECT_DOMAIN,
                   principal_id,
                   meeting_sco_id,
                   role)

        return self._make_request(fn_add_participant_to_meeting_url)

    def create_meeting(self, meeting_description,
                       template_type="TUTORING",
                       start_date=None, end_date=None,
                       host_user_principal_id=None):
        """
        :param meeting_description: Free text description
        :param template_type: Either "TUTORING", "LIVE_QA" or "VIDEO_TUTORIAL"
        :param start_date: Datetime string for meeting start or ""
        :param end_date: Datetime string for meeting start or ""
        :param host_user_principal_id: Adobe Connect principal id
        :return: AdobeConnectMeeting
        """
        if start_date:
            assert(start_date.tzinfo, "Start date parameter must be timezone aware.")

        if not start_date:
            start_date = pytz.UTC.localize(datetime.utcnow())

        # Check if viable default option
        if not end_date:
            end_date = start_date + timedelta(hours=3)

        template_sco_id = AdobeConnectAPI.MEETING_TEMPLATES[template_type]

        meeting_description = urlquote(meeting_description)

        fn_create_meeting_template = u"https://{0}/api/xml?action=" \
                                     "sco-update&type=meeting" \
                                     "&name={1}&folder-id={2}" \
                                     "&date-begin={3}&date-end={4}" \
                                     "&url-path={5}&source-sco-id={6}"

        fn_create_meeting_url = \
            fn_create_meeting_template.format(settings.FN_CONNECT_DOMAIN,
                                              meeting_description,
                                              self.DEFAULT_MEETINGS_FOLDER,
                                              iso_date_string_from_datetime(start_date),
                                              iso_date_string_from_datetime(end_date),
                                              u"{0}-{1}-{2}-{3}".
                                              format(template_type.lower(),
                                                     template_sco_id,
                                                     host_user_principal_id
                                                     if host_user_principal_id
                                                     else u"fn",
                                                     generate_random_id()),
                                              template_sco_id)

        create_meeting_xml = self._make_request(fn_create_meeting_url)
        meeting = AdobeConnectMeeting().from_xml(create_meeting_xml)
        meeting_sco_id = meeting.sco_id

        if host_user_principal_id:
            self.add_participant_to_meeting(host_user_principal_id,
                                            meeting_sco_id,
                                            u"host")
        return meeting

    def get_meeting_url(self, sco_id, session_id=None):
        """
        :param sco_id: Adobe Connect resource id
        :param session_id Session id for user BREEZESESSION
        :return: valid URL for entering the meeting
        """
        meeting = self.get_meetings([sco_id], None, None)

        if len(meeting) > 0:
            meeting = meeting[0]
        else:
            raise AdobeConnectionError("No meeting exists for sco_id: {0}".format(sco_id))

        fn_meeting_url_for_user_template = "https://{0}/{1}"
        fn_meeting_url_for_user_url = fn_meeting_url_for_user_template.format(settings.FN_CONNECT_DOMAIN,
                                                                              meeting.url)
        if session_id:
            fn_meeting_url_session_id_template = "?session={0}"
            fn_meeting_url_session_id = fn_meeting_url_session_id_template.format(session_id)
            fn_meeting_url_for_user_url += fn_meeting_url_session_id

        return fn_meeting_url_for_user_url

    def create_account_for_user(self, user_first_name,
                                user_last_name, user_email,
                                pwd=DEFAULT_USER_ACCOUNT_PASSWORD):
        """
        :param user_first_name: Given name of user if known
        :param user_last_name: Surname of user if known
        :param user_email: email address of user (must not be used prior)
        :return: AdobeConnectUserAccount
        """
        fn_create_user_template = \
            u"https://{0}/api/xml?action=principal-update" \
            "&first-name={1}&last-name={2}&login={3}&password={4}" \
            "&type=user&send-email=true&has-children=0&email={3}"

        fn_create_user_url = fn_create_user_template.\
            format(settings.FN_CONNECT_DOMAIN,
                   urlquote(user_first_name),
                   urlquote(user_last_name),
                   urlquote(user_email),
                   pwd)

        create_user_xml = self._make_request(fn_create_user_url)
        user = AdobeConnectUserAccount().from_xml(create_user_xml)
        user.password = pwd

        return user

    def get_accounts(self, email_list=None):
        """
        :param email_list: List of users emails

        For email list defined
        :return: Returns all principals in email list
        For email list not defined
        :return: All principals in system
        """

        fn_get_accounts_template = u"https://{0}/api/xml?action=principal-list"
        fn_get_accounts_url = fn_get_accounts_template.format(settings.FN_CONNECT_DOMAIN)

        for email in email_list:
            fn_additional_email_template = "&filter-email={0}"
            fn_additional_email_url = fn_additional_email_template.format(email)
            fn_get_accounts_url += fn_additional_email_url

        get_accounts_xml = self._make_request(fn_get_accounts_url)

        xml_tree = etree.fromstring(get_accounts_xml)
        principals = xml_tree.xpath("//principal-list")
        accounts = []

        for principal in principals:
            account = AdobeConnectUserAccount()
            account = account.from_xml(etree.tostring(principal))
            accounts.append(account)

        return accounts

    def get_participants_for_meeting(self, meeting_sco_id):
        """
        :param meeting_sco_id: Adobe Connect resource id for meeting
        :return: List of one or more AdobeConnectUserAccount
        """
        fn_get_participants_for_meeting_template = "https://{0}/api/xml?" \
                                                   "action=report-event-participants-complete-information" \
                                                   "&sco-id={1}"
        fn_get_participants_for_meeting_url = fn_get_participants_for_meeting_template\
            .format(settings.FN_CONNECT_DOMAIN,
                    meeting_sco_id)

        get_participants_xml = self._make_request(fn_get_participants_for_meeting_url)
        xml_tree = etree.fromstring(get_participants_xml)
        meeting_participants = xml_tree.xpath("//user_list")

        participants = []

        for participant in meeting_participants:
            participant = AdobeConnectMeetingParticipant(meeting_sco_id).from_xml(etree.tostring(participant))
            participants.append(participant)

        return participants

    def delete_meeting_room(self, sco_id):
        fn_delete_meeting_room_template = "https://{0}/api/xml?action=sco-delete&sco-id={1}"
        fn_delete_meeting_room_url = fn_delete_meeting_room_template.format(settings.FN_CONNECT_DOMAIN,
                                                                            sco_id)

        self._make_request(fn_delete_meeting_room_url)

    def authenticate_participant(self, user_login, user_password):
        """
        :param user_email:
        :param user_password:
        :return: BREEZE SESSION COOKIE
        """

        fn_authenticate_participant_template = "https://{0}/api/xml?action=login&login={1}&password={2}"
        fn_authenticate_participant_url = fn_authenticate_participant_template.format(settings.FN_CONNECT_DOMAIN,
                                                                                      user_login,
                                                                                      user_password)
        try:
            response = urllib2.urlopen(fn_authenticate_participant_url)
            cookies_string = response.info()['Set-Cookie']
            response.close()
            cookies_list = cookies_string.split(';')
            cookie = get_breeze_session_id(cookies_list)
            return cookie
        except Exception as e:
            raise AdobeConnectionError(str(e))

    def get_known_groups(self):
        pass

    def update_group_for_user(self, user_principal_id, group_name, remove=False):
        """

        :param user_principal_id: Principal id for the user to be added to the group
        :param group_name: Name of new group to add the user. "LIVE_ADMINS"
        :param remove: Whether the user should be removed or added from the group. True = remove
        :return: True if successful make_request raises exception on failure
        """
        fn_update_group_for_user_template = "https://{0}/api/xml?action=group-membership-update" \
                                            "&group-id={1}" \
                                            "&principal-id={2}" \
                                            "&is-member={3}"
        fn_update_group_for_user_url = fn_update_group_for_user_template.format(settings.FN_CONNECT_DOMAIN,
                                                                                self.GROUP_IDS[group_name],
                                                                                user_principal_id,
                                                                                str(not remove).lower())
        self._make_request(fn_update_group_for_user_url)

        return True

    def get_users_in_group(self, group_name, principal_id_list=None):
        """
        :param group_name:
        :param principal_id_list:
        :return:
        """
        fn_users_in_group_template = "https://{0}/api/xml?action=principal-list" \
                                     "&group-id={1}" \
                                     "&filter-is-member=true"
        fn_users_in_group_url = fn_users_in_group_template.format(settings.FN_CONNECT_DOMAIN,
                                                                  self.GROUP_IDS[group_name])

        if principal_id_list:
            for principal_id in principal_id_list:
                fn_principal_id_template = "&filter-principal-id={0}"
                fn_principal_id_url = fn_principal_id_template.format(principal_id)
                fn_users_in_group_url += fn_principal_id_url

        users_in_group_xml = self._make_request(fn_users_in_group_url)
        xml_tree = etree.fromstring(users_in_group_xml)
        principals = xml_tree.xpath("//principal-list/principal")

        accounts = []

        for principal in principals:
            account = AdobeConnectUserAccount()
            account = account.from_xml(etree.tostring(principal))
            accounts.append(account)

        return accounts

    def get_artifacts_for_meeting(self, meeting_sco_id):
        fn_get_artifacts_for_meeting_template = "https://{0}/api/xml?action=list-recordings&" \
                                                "folder-id={1}"
        fn_get_artifacts_for_meeting_url = fn_get_artifacts_for_meeting_template.format(settings.FN_CONNECT_DOMAIN,
                                                                                        meeting_sco_id)

        artifacts_xml = self._make_request(fn_get_artifacts_for_meeting_url)
        xml_tree = etree.fromstring(artifacts_xml)

        artifacts = xml_tree.xpath("//recordings")

        recordings = []

        for artifact in artifacts:
            recording = AdobeConnectRecording()
            recording.from_xml(etree.tostring(artifact))
            recordings.append(recording)

        return recordings

    def move_artifact(self, artifact_sco_id, destination_folder_sco_id):
        fn_move_artifact_template = "http://{0}/api/xml?action=sco-move&" \
                                    "sco-id={1}&folder-id={2}"
        fn_move_artifact_url = fn_move_artifact_template.format(settings.FN_CONNECT_DOMAIN,
                                                                artifact_sco_id, destination_folder_sco_id)

        self._make_request(fn_move_artifact_url)

        return True

    def grant_permission_to_artifact(self, principal_id, artifact_id, permission="view"):
        fn_grant_permissions_to_artifact_template = "https://{0}/api/xml?action=permissions-update&" \
                                                    "acl-id={1}&principal-id={2}&permission-id={3}"
        fn_grant_permissions_to_artifact_url = fn_grant_permissions_to_artifact_template.\
            format(settings.FN_CONNECT_DOMAIN,
                   artifact_id,
                   principal_id,
                   permission)

        self._make_request(fn_grant_permissions_to_artifact_url)

        return True