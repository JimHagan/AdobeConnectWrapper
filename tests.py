from .meeting_manager import AdobeConnectMeetingManager, AdobeConnectKeyManager,\
    AdobeConnectUser
from .adobe_connect import AdobeConnectAPI, generate_random_id


@skip("Only run these tests on-demand due to resource dependencies i.e., Adobe Connect")
class AdobeConnectTests(TestCase):
    def test_login_to_adobe_connect(self):
        connection = AdobeConnectAPI()
        self.assertTrue(connection._is_authenticated)
        self.assertIsNotNone(connection._auth_cookie)

    def test_get_meetings(self):
        connection = AdobeConnectAPI()
        meeting = connection.create_meeting(meeting_description=
                                            "fn-test-meeting-{0}".
                                            format(generate_random_id()),
                                            start_date=None,
                                            end_date=None)

        meetings = connection.get_meetings(None, None, None)
        self.assertGreater(len(meetings), 0)

        meetings_with_sco_id = connection.get_meetings([meeting.sco_id],
                                                       None, None)
        self.assertGreater(len(meetings_with_sco_id), 0)

    def test_create_meeting(self):
        connection = AdobeConnectAPI()
        meeting = connection.create_meeting(meeting_description=
                                            "fn-test-meeting-{0}".
                                            format(generate_random_id()),
                                            start_date=None,
                                            end_date=None)
        self.assertIsNotNone(meeting.sco_id)

    def test_create_account_for_user(self):
        connection = AdobeConnectAPI()
        email = "create_account_test.{0}{1}".format(generate_random_id(),
                                                    "@flashnotes.com")
        user = connection.create_account_for_user(generate_random_id(),
                                                  generate_random_id(),
                                                  email)
        self.assertEqual(user.login, email)

    def test_add_participants_to_meeting(self):
        connection = AdobeConnectAPI()
        host_email = "add_participants_test.{0}{1}".format(generate_random_id(),
                                                           "@flashnotes.com")
        host_user = connection.create_account_for_user(generate_random_id(),
                                                       generate_random_id(),
                                                       host_email)

        mini_host_email = \
            "add_participants_test.{0}{1}".format(generate_random_id(),
                                                  "@flashnotes.com")
        mini_host_user = \
            connection.create_account_for_user(generate_random_id(),
                                               generate_random_id(),
                                               mini_host_email)

        meeting = connection.create_meeting(meeting_description=
                                            "fn-test-meeting-{0}".
                                            format(generate_random_id()),
                                            start_date=None,
                                            end_date=None)

        connection.add_participant_to_meeting(host_user.principal_id,
                                              meeting.sco_id, "host")
        connection.add_participant_to_meeting(mini_host_user.principal_id,
                                              meeting.sco_id, "mini-host")

    def test_get_participants_from_meeting(self):
        connection = AdobeConnectAPI()
        host_email = "add_participants_test.{0}" + generate_random_id() + "@flashnotes.com"
        host_user = connection.create_account_for_user(generate_random_id(),
                                                       generate_random_id(),
                                                       host_email)

        mini_host_email = "add_participants_test." + generate_random_id() + "@flashnotes.com"
        mini_host_user = \
            connection.create_account_for_user(generate_random_id(),
                                                            generate_random_id(),
                                                            mini_host_email)

        meeting = connection.create_meeting(meeting_description=
                                            "fn-test-meeting-{0}".
                                            format(generate_random_id()),
                                            start_date=None,
                                            end_date=None)

        connection.add_participant_to_meeting(host_user.principal_id,
                                              meeting.sco_id, "host")
        connection.add_participant_to_meeting(mini_host_user.principal_id,
                                              meeting.sco_id, "mini-host")

        self.assertIsNotNone(connection.
                             get_participants_for_meeting(meeting.sco_id))

    def test_get_meeting_url(self):
        connection = AdobeConnectAPI()
        email = "get_meeting_url_test.{0}{1}".format(generate_random_id(),
                                                       "@flashnotes.com")
        user = connection.create_account_for_user(generate_random_id(),
                                                  generate_random_id(),
                                                  email)
        session_cookie = connection.authenticate_participant(user.login,
                                                             "Flash!123")

    def test_delete_meeting_room(self):
        connection = AdobeConnectAPI()
        meeting = connection.create_meeting(meeting_description=
                                            "fn-test-meeting-{0}".
                                            format(generate_random_id()),
                                            start_date=None,
                                            end_date=None)
        connection.delete_meeting_room(meeting.sco_id)

    def test_authenticate_user(self):
        connection = AdobeConnectAPI()
        email = "authenticate_user_test.{0}{1}".format(generate_random_id(),
                                                    "@flashnotes.com")
        user = connection.create_account_for_user(generate_random_id(),
                                                  generate_random_id(),
                                                  email)
        session_cookie = connection.authenticate_participant(user.login,
                                            "Flash!123")

        meeting = connection.create_meeting(meeting_description=
                                            "fn-test-meeting-{0}".
                                            format(generate_random_id()),
                                            start_date=None,
                                            end_date=None)

        connection.add_participant_to_meeting(user.principal_id,
                                              meeting.sco_id, "host")

        self.assertIsNotNone(session_cookie)

    def test_update_group_for_user(self):
        connection = AdobeConnectAPI()
        email = "create_account_test.{0}{1}".format(generate_random_id(),
                                                    "@flashnotes.com")
        user = connection.create_account_for_user(generate_random_id(),
                                                  generate_random_id(),
                                                  email)
        # Add to group LIVE_ADMINS
        connection.update_group_for_user(user.principal_id, "LIVE_ADMINS")

        # Remove from group LIVE_ADMINS
        connection.update_group_for_user(user.principal_id, "LIVE_ADMINS", True)

    def test_get_users_in_group(self):
        connection = AdobeConnectAPI()
        users = connection.get_users_in_group("LIVE_ADMINS")

        self.assertGreater(len(users), 0)

    def test_show_user_in_correct_group(self):
        connection = AdobeConnectAPI()
        host_email = "add_participants_test.{0}{1}".format(generate_random_id(),
                                                           "@flashnotes.com")
        host_user = connection.create_account_for_user(generate_random_id(),
                                                       generate_random_id(),
                                                       host_email)

        mini_host_email = \
            "add_participants_test.{0}{1}".format(generate_random_id(),
                                                  "@flashnotes.com")
        mini_host_user = \
            connection.create_account_for_user(generate_random_id(),
                                               generate_random_id(),
                                               mini_host_email)

        meeting = connection.create_meeting(meeting_description=
                                            "fn-test-meeting-{0}".
                                            format(generate_random_id()),
                                            start_date=None,
                                            end_date=None)

        connection.update_group_for_user(host_user.principal_id, "LIVE_ADMINS")

        connection.add_participant_to_meeting(host_user.principal_id,
                                              meeting.sco_id, "host")
        connection.add_participant_to_meeting(mini_host_user.principal_id,
                                              meeting.sco_id, "mini-host")

        host_session = connection.authenticate_participant(host_user.login,
                                                           "Flash!123")
        mini_host_session = connection.authenticate_participant(mini_host_user.login,
                                                                "Flash!123")

        host_url = connection.get_meeting_url(meeting.sco_id, host_session)
        pres_url = connection.get_meeting_url(meeting.sco_id, mini_host_session)


@skip("Only run these tests on-demand due to Adobe resource dependency.")
class AdobeConnectUserTests(TestCase):
    def setUp(self):
        self.host = factories.User.create(email="testhost@fntest.com")
        self.attendee = factories.User.create(email="testlearner@fntest.com")
        from .models import adobe_connect_api
        self._ac_api = adobe_connect_api

    def test_exercise_user_workflow(self):
        # Register users
        self.host_user = AdobeConnectUser()
        self.host_user.register(self._ac_api, self.host)
        self.host_user._validate_acount()
        self.assertEqual(self.host_user.fn_user_email, self.host.email)
        self.assertEqual(self.host_user.fn_user.id, self.host.id)
        self.assertIsNotNone(self.host_user.pwd)

        self.attendee_user = AdobeConnectUser()
        self.attendee_user.register(self._ac_api, self.attendee)
        self.attendee_user._validate_acount()
        self.assertEqual(self.attendee_user.fn_user_email, self.attendee.email)
        self.assertEqual(self.attendee_user.fn_user.id, self.attendee.id)
        self.assertIsNotNone(self.attendee_user.pwd)

        # Add user to room
        room = self._ac_api.create_meeting(meeting_description=
                                           "fn-test-meeting-{0}".
                                           format(generate_random_id()),
                                           start_date=datetime.utcnow(),
                                           end_date=None)

        # Add participants

        # Host
        self.host_user.add_to_meeting_room(self._ac_api,
                                           room.sco_id, "host")

        # Attendee
        self.attendee_user.add_to_meeting_room(self._ac_api,
                                               room.sco_id, "mini-host")

        # Authenticate and get URL
        # host
        host_url = self.host_user.get_url_for_meeting_room(self._ac_api,
                                                           room.sco_id)
        print host_url

        self.assertIn("https://flashnotes.adobeconnect.com", host_url)

        # attendee
        attendee_url = self.attendee_user.\
            get_url_for_meeting_room(self._ac_api, room.sco_id)
        print attendee_url
        self.assertIn("https://flashnotes.adobeconnect.com", attendee_url)

        # This is to clean up resources.  If you want to test that the
        # host URL will log the user in as HOST you can comment out this line.
        self.host_user.remove_from_hosts_group(self._ac_api)


@skip("Only run these tests on-demand due to Adobe resource dependency.")
class AdobeConnectMeetingManagerTests(TestCase):
    """
    This test will use a Mock class
    """
    class AdobeConnectMeetingManagerMock(AdobeConnectMeetingManager):
        def __init__(self):
            self._adobe_connect_meeting_room = None
            self.host = factories.User.create(email="testhost@fntest.com")
            self.attendee = factories.User.create(email="testlearner@fntest.com")
            self.scheduled_start_time = pytz.UTC.localize(datetime.utcnow() +
                                                          timedelta(minutes=1))

            self.some_other_user = factories.User.create(email="testother@fntest.com".
                                              format(generate_random_id(4)))

        def get_host(self):
            return self.host

        def get_meeting_room_template_type(self):
            return "TUTORING"

        def get_attendees(self):
            from django.contrib.auth.models import User
            return User.objects.filter(id=self.attendee.id)

        def get_adobe_connect_meeting_sco_id(self):
            return self._adobe_connect_meeting_room

        def set_adobe_connect_meeting_sco_id(self, sco_id, save=True):
            self._adobe_connect_meeting_room = sco_id

        def get_scheduled_start_time(self):
            return self.scheduled_start_time

    def test_create_resources_with_adobe_connect_meeting_manager(self):
        from .models import adobe_connect_api
        ac_mock = self.AdobeConnectMeetingManagerMock()
        # Create meeting resources
        ac_mock.create_adobe_session_resources()

        # Should return gracefully on second call (and do nothing)
        ac_mock.create_adobe_session_resources()

        self.assertIsNotNone(ac_mock.get_adobe_connect_meeting_sco_id() )

        with self.assertRaises(Exception):
            ac_mock.authenticate_user_for_adobe_session(self.some_other_user)

        host_url = ac_mock.authenticate_user_for_adobe_session(ac_mock.host)
        print host_url
        self.assertIn("https://flashnotes.adobeconnect.com", host_url)
        attendee_url = \
            ac_mock.authenticate_user_for_adobe_session(ac_mock.attendee)
        print attendee_url
        self.assertIn("https://flashnotes.adobeconnect.com", attendee_url)
        ac_host_user = AdobeConnectUser.objects.get(fn_user_id=ac_mock.host.id)
        self.assertEqual(ac_host_user.last_meeting_room_entered,
                         ac_mock.get_adobe_connect_meeting_sco_id())
        self.assertEqual(ac_host_user.last_meeting_room_role, "host")
        self.assertIsNotNone(ac_host_user.last_meeting_room_entrance_datetime)

        # If you want to do some experimenting with the URLs created above
        # comment out the next two lines.
        ac_host_user.remove_from_hosts_group(adobe_connect_api)
        ac_mock.destroy_adobe_session_resources()


@skip("Only run these tests on-demand due to Adobe resource dependency.")
class AdobeConnectKeyManagerTests(TestCase):
    def test_recycle_keys_1(self):
        from .models import adobe_connect_api
        host1 = factories.User.create(email="testhost@fntest.com")

        three_hours_ago = \
            pytz.UTC.localize(datetime.utcnow() - timedelta(hours=3))
        host1_user = AdobeConnectUser()
        host1_user.register(adobe_connect_api, host1)
        host1_user.add_to_hosts_group(adobe_connect_api)

        # fake some data
        host1_user.last_meeting_room_role = "host"
        host1_user.last_meeting_room_entered = "TESTROOM"
        host1_user.last_meeting_room_entrance_datetime = three_hours_ago
        host1_user.save()
        AdobeConnectKeyManager().recycle_keys(max_age_threshold_minutes=120)
        host1_user = AdobeConnectUser.objects.get(fn_user_id=host1.id)
        self.assertEqual(host1_user.last_meeting_room_role, "revoked")

    def test_recycle_keys_2(self):
        from .models import adobe_connect_api
        host1 = factories.User.create(email="testhost@fntest.com")

        three_hours_ago = \
            pytz.UTC.localize(datetime.utcnow() - timedelta(hours=1))
        host1_user = AdobeConnectUser()
        host1_user.register(adobe_connect_api, host1)
        host1_user.add_to_hosts_group(adobe_connect_api)

        # fake some data
        host1_user.last_meeting_room_role = "host"
        host1_user.last_meeting_room_entered = "TESTROOM"
        host1_user.last_meeting_room_entrance_datetime = three_hours_ago
        host1_user.save()
        AdobeConnectKeyManager().recycle_keys(max_age_threshold_minutes=120)
        host1_user = AdobeConnectUser.objects.get(fn_user_id=host1.id)
        self.assertEqual(host1_user.last_meeting_room_role, "host")

    def test_recycle_keys_3(self):
        from .models import adobe_connect_api
        host1 = factories.User.create(email="testhost@fntest.com")

        three_hours_ago = \
            pytz.UTC.localize(datetime.utcnow() - timedelta(minutes=30))
        host1_user = AdobeConnectUser()
        host1_user.register(adobe_connect_api, host1)
        host1_user.add_to_hosts_group(adobe_connect_api)

        # fake some data
        host1_user.last_meeting_room_role = "host"
        host1_user.last_meeting_room_entered = "TESTROOM"
        host1_user.last_meeting_room_entrance_datetime = three_hours_ago
        host1_user.save()
        AdobeConnectKeyManager().recycle_keys(max_age_threshold_minutes=15)
        host1_user = AdobeConnectUser.objects.get(fn_user_id=host1.id)
        self.assertEqual(host1_user.last_meeting_room_role, "revoked")
