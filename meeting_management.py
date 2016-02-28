# -*- coding: utf-8 -*-
"""
This module defines a number of classes that are meant to provide a higher level integration w/ AdobeConnect.
It is built upon the basic AdobeConnectAPI wrapper defined in adobe_connect.py.  

Class Descriptions:

AdobeConnectUser - Class for mapping a django user to an adobe connect user account id
AdobeConnectKeyLog - Model for storing host key usage for our AdobeConnect account
AdobeConnectKeyManager - Class for recycling keys as needed 
AdobeConnectMeetingManager - Abstract base class for managing all resources associated with a meeting
"""


from flashnotes.apps.learningspace.adobe_connect import AdobeConnectAPI,\
    AdobeConnectionError, generate_random_id

logger = logging.getLogger(__name__)

try:
    adobe_connect_api = AdobeConnectAPI() \
        if settings.FN_CONNECT_ENABLED else None
except AdobeConnectionError:
    logger.exception("Adobe connection error")
    adobe_connect_api = None

class AdobeConnectArtifact(models.Model):
    artifact_id = models.CharField(max_length=255)

class AdobeConnectUser(models.Model):
    """
    This class links the Flashnotes User model to an
    Adobe Connect user account.  An AdobeConnectAPI instance must
    be passed in to most methods.  Interaction with this model
    is primarily managed through AdobeConnectMeetingManager and its
    meeting subclasses.
    """
    date_created = models.DateTimeField(auto_now_add=True)
    login = models.CharField(max_length=128, unique=True)
    pwd = models.CharField(max_length=20)
    principal_id = models.CharField(max_length=20, unique=True)
    fn_user = models.OneToOneField(User, related_name='adobe_connect_user')
    fn_user_email = models.CharField(max_length=128, null=True, blank=True)
    last_meeting_room_entered = models.CharField(max_length=20,
                                                 null=True, blank=True)
    last_meeting_room_entrance_datetime = models.DateTimeField(null=True,
                                                               blank=True)
    last_meeting_room_role = models.CharField(max_length=10,
                                              null=True,
                                              blank=True)

    def _validate_acount(self):
        if not all([self.fn_user, self.login, self.principal_id, self.pwd]):
            raise Exception("Invalid account information!")

        # Adobe Connect does not like '+' in email addresses
        if self.fn_user.email.replace('+', '_pl_') not in self.login:
            logger.warn("user email for {0} may have been updated since the"
                        "corresponding Adobe Connect login was created."
                        "  This is not necessarily a problem."
                        .format(self.fn_user))

    def register(self, ac_api, fn_user):
        if not ac_api:
            raise Exception("Adobe Connect API instance required!")

        if all([self.login, self.principal_id, self.pwd]):
            raise Exception("This instance is already registered to "
                            " user %s" % self.login)

        existing_ac_user_in_db = None
        try:
            existing_ac_user_in_db = \
                AdobeConnectUser.objects.get(fn_user=fn_user)
        except:
            pass

        if existing_ac_user_in_db:
            raise Exception("Another connect user object exists for "
                            "flashnotes user %s." % fn_user)

        # Because we have several test environments we will assume in many
        # cases staff and perhaps beta testers may have registered with connect
        # once before.  To avoid login/email collisions we'll append a unique
        # code to each email before registering.  This has the added benefit
        # of identifying users created from our code vs. users created
        # through the Adobe Connect admin application.
        #
        # Note that since Adobe Connect does not like '+' in email addresses
        # we need to apply a substitution.
        adjusted_email = 'lv-user-{0}-{1}'.format(generate_random_id(3),
                                                  fn_user.email).replace('+',
                                                                         '_pl_')
        adjusted_first_name = fn_user.first_name or fn_user.email.split('@')[0]
        adjusted_last_name = fn_user.last_name or 'none'

        ac_user = ac_api.create_account_for_user(user_first_name=
                                                 adjusted_first_name,
                                                 user_last_name=
                                                 adjusted_last_name,
                                                 user_email=
                                                 adjusted_email,
                                                 pwd=generate_random_id(8))

        self.principal_id = ac_user.principal_id
        self.login = ac_user.login
        self.fn_user = fn_user
        self.fn_user_email = fn_user.email
        self.pwd = ac_user.password

        self.save()

    def add_to_hosts_group(self, ac_api):
        if not ac_api:
            raise Exception("Adobe Connect API instance required!")
        ac_api.update_group_for_user(self.principal_id, "LIVE_ADMINS")

    def remove_from_hosts_group(self, ac_api):
        if not ac_api:
            raise Exception("Adobe Connect API instance required!")
        ac_api.update_group_for_user(self.principal_id,
                                     "LIVE_ADMINS", remove=True)
        if self.last_meeting_room_role == "host":
            self.last_meeting_room_role = "revoked"
            self.save()

    def add_to_meeting_room(self, ac_api, ac_sco_id, ac_role):
        if not ac_api:
            raise Exception("Adobe Connect API instance required!")

        self._validate_acount()

        if ac_role not in ["host", "mini-host"]:
            raise Exception("Invalid role: '{0}'.  Valid types are 'host'"
                            "and 'mini-host'".format(ac_role))

        if ac_role == 'host':
            self.add_to_hosts_group(adobe_connect_api)
        ac_api.add_participant_to_meeting(self.principal_id, ac_sco_id, ac_role)
        self.last_meeting_room_entered = ac_sco_id
        self.last_meeting_room_role = ac_role
        self.last_meeting_room_entrance_datetime = \
            pytz.UTC.localize(datetime.utcnow())
        self.save()

    def get_url_for_meeting_room(self, ac_api, ac_sco_id):
        if not ac_api:
            raise Exception("Adobe Connect API instance required!")

        self._validate_acount()

        session_cookie = ac_api.authenticate_participant(self.login,
                                                         self.pwd)
        return ac_api.get_meeting_url(ac_sco_id, session_cookie)

    def get_url_for_meeting_recording(self, ac_api, ac_meeting_sco_id):
        artifacts = ac_api.get_artifacts_for_meeting(ac_meeting_sco_id)
        if len(artifacts) > 1:
            raise AdobeConnectionError("There should only be a single artifact per session!")

        if not len(artifacts):
            raise AdobeConnectionError("No artifacts found for meeting %s" % ac_meeting_sco_id)

        session_cookie = ac_api.authenticate_participant(self.login,
                                                         self.pwd)

        ac_api.grant_permission_to_artifact(principal_id=self.principal_id,
                                            artifact_id=artifacts[0].sco_id)

        url = "https://{0}{1}?session={2}".format(
            settings.FN_CONNECT_DOMAIN,
            artifacts[0].url,
            session_cookie)
        return url


    def __unicode__(self):
        return u"Adobe Connect User: login=%s, principal_id=%s" % \
               (self.login, self.principal_id)

    def save(self, *args, **kwargs):
        self._validate_acount()
        super(AdobeConnectUser, self).save(*args, **kwargs)


class AdobeConnectKeyLog(models.Model):
    observation_datetime = models.DateTimeField(auto_now_add=True)
    total_keys_used_in_app = models.IntegerField()
    total_keys_for_account = models.IntegerField(default=100)
    total_keys_used_for_account = models.IntegerField(null=True, blank=True)


class AdobeConnectKeyManager(object):
    ASSIGNED_KEY_WARNING_LIMIT = 35

    def recycle_keys(self,
                     max_age_threshold_minutes=
                     settings.FN_CONNECT_MAX_KEY_AGE_MINUTES):

        if not adobe_connect_api:
            raise Exception("Adobe Connect API instance required!")
        age_cutoff = pytz.UTC.localize(datetime.utcnow() -
                                       timedelta(minutes=
                                                 max_age_threshold_minutes))
        users_no_longer_needing_host_group = \
            AdobeConnectUser.objects.filter(last_meeting_room_role="host",
                                            last_meeting_room_entrance_datetime__lte=age_cutoff)

        if users_no_longer_needing_host_group.count() > self.ASSIGNED_KEY_WARNING_LIMIT:
            logger.warn("Currently assigned lession space keys exceed %s "
                        "(not including Luvo staff)!  Recycling should "
                        "resolve this, but monitor usage rates carefully.",
                        self.ASSIGNED_KEY_WARNING_LIMIT)

        for user in users_no_longer_needing_host_group:
            user.remove_from_hosts_group(adobe_connect_api)
            user.save()

        key_log_lookback = \
            pytz.UTC.localize(datetime.utcnow())-timedelta(minutes=60)
        recent_key_logs = AdobeConnectKeyLog.objects.filter(
            observation_datetime__gte=key_log_lookback)
        if not recent_key_logs.exists():
            try:
                total_admins = \
                    len(adobe_connect_api.get_users_in_group("LIVE_ADMINS"))
            except Exception as e:
                print e
                total_admins = None
            keys_still_held = AdobeConnectUser.objects.filter(
                last_meeting_room_role="host").count()
            AdobeConnectKeyLog.objects.create(
                total_keys_used_in_app=keys_still_held,
                total_keys_used_for_account=total_admins)


class AdobeConnectMeetingManager(object):
    """
    Base class for giving adobe meeting management capabilities to
    another class.  The benefit of using this base class is that we can use
    a very simple mock object for testing rather than having to instantiate
    a full AttendedLearningPresentation object.

    Usage:

    create_adobe_session_resources: instantiates a meeting user configuration
                                    for a given meeting.

    authenticate_user_for_adobe_session: authenticate user for an adobe session.
                                         (returns URL)

    destroy_adobe_session_resources: destroys certain meeting resources.  Does
                                    not remove any AdobeConnectUser objects
                                    created during create_adobe_session_resources.

    """
    def get_meeting_room_template_type(self):
        """
        This should be overriden and return one of the following
         - 'TUTORING'
         - 'LIVE_QA'
         - 'VIDEO_TUTORIAL'
         - 'DEMO'
        """
        raise Exception("Abstract method get_host() must be overriden.")

    def get_host(self):
        raise Exception("Abstract method get_meeting_room_template_type() must be overriden.")

    def get_attendees(self):
        raise Exception("Abstract method get_attendees() must be overriden.")

    def get_adobe_connect_meeting_sco_id(self):
        raise Exception("Abstract method get_adobe_connect_meeting_sco_id "
                        "must be overriden.")

    def set_adobe_connect_meeting_sco_id(self, sco_id, save=True):
        raise Exception("Abstract method set_adobe_connect_meeting_sco_id "
                        "must be overriden.")

    def get_scheduled_start_time(self):
        raise Exception("Abstract get_scheduled_start_time must be overriden")

    def create_adobe_session_resources(self):
        if adobe_connect_api is None:
            raise Exception("AdobeConnect API not available.  Check that "
                            "FN_CONNECT_ENABLED is true and that all "
                            "FN_CONNECT* environment variables are correct!")

        if self.get_adobe_connect_meeting_sco_id():
            return

        # Prevent race condition for resource creation.  We need only
        # create resources once.  If the adobe connect id is set
        # this method returns before doing anything.  In some cases
        # there is too much latency if two parties enter around the same
        # time so this lock is needed.
        lock_id = "create-room-{0}-{1}".format(
            self.get_host().username,
            str(self.get_scheduled_start_time())
        )
        if not acquire_lock(lock_id, expires=60):
            logger.warn('Lock already taken for {0}'.format(lock_id))
            for __ in range(10):
                if self.get_adobe_connect_meeting_sco_id():
                    return
                time.sleep(2)

            if not self.get_adobe_connect_meeting_sco_id():
                logger.warn(
                    "Resource creation for meeting may not have "
                    "completed (host={0}, scheduled start={1})".format(
                        self.get_host(), self.get_scheduled_start_time()
                    ))
            return

        # If we think this is a local dev environment let's
        # recycle keys immediately.  Otherwise we'll make this an async
        # job with a scheduled managed in CELERYBEAT_SCHEDULE
        managed_envs = ['fn-prod', 'fn_stage', 'fn_integration']
        if os.environ.get('FN_APP_ENVIRONMENT', None) not in managed_envs:
            AdobeConnectKeyManager().recycle_keys()

        host = self.get_host()

        # Create the meeting room if one doesn't existing
        meeting = \
            adobe_connect_api.create_meeting(meeting_description=
                                             "lv-{0}-{1}-{2}".
                                             format(self.get_meeting_room_template_type().lower(),
                                                    host.username,
                                                    generate_random_id(6)),
                                             template_type=self.get_meeting_room_template_type(),
                                             start_date=
                                             self.get_scheduled_start_time(),
                                             end_date=None)

        if self.get_adobe_connect_meeting_sco_id():
            # A meeting room was created in another process and persisted to
            # the session object already.
            logger.warn(
                "Discarding adobe connect meeting room {0}.  "
                "It seems another one has already been created "
                "for this session (host={1}, scheduled start={2})".format(
                    meeting.sco_id,
                    self.get_host(),
                    self.get_scheduled_start_time()
                ))
            time.sleep(5)
            return

        # Make sure users are registered with AdobeConnect and add them to the
        # meeting.  Start with the host.
        try:
            host_user = AdobeConnectUser.objects.get(fn_user_email=host.email)
        except:
            host_user = AdobeConnectUser()
            host_user.register(adobe_connect_api, host)

        host_user.add_to_meeting_room(adobe_connect_api, meeting.sco_id, 'host')

        # Now we will add the Luvo support team as a second host so that they
        # may enter the meeting if called up for help.
        adobe_connect_api.add_participant_to_meeting(
            settings.FN_CONNECT_SUPPORT_TEAM_PRINCIPAL_ID,
            meeting.sco_id, 'host')

        # Now add the attendees
        for attendee_user in self.get_attendees():
            try:
                ac_attendee_user = AdobeConnectUser.\
                    objects.get(fn_user_email=attendee_user.email)
            except:
                ac_attendee_user = AdobeConnectUser()
                ac_attendee_user.register(adobe_connect_api, attendee_user)

            ac_attendee_user.add_to_meeting_room(adobe_connect_api,
                                                 meeting.sco_id,
                                                 'mini-host')

        self.set_adobe_connect_meeting_sco_id(meeting.sco_id)

    def host_has_entered(self):
        # must be overridden in subclasses
        pass

    def authenticate_user_for_adobe_session(self, user):
        if adobe_connect_api is None:
            raise Exception("AdobeConnect API not available.  Check that "
                            "FN_CONNECT_ENABLED is true and that all "
                            "FN_CONNECT* environment variables are correct!")

        if not self.get_adobe_connect_meeting_sco_id():
            raise Exception("Meeting room has not been created!")

        if user != self.get_host() and user.id not in \
                self.get_attendees().values_list('id', flat=True) \
                and user.email != settings.TUTORING_SUPPORT_EMAIL:
            raise Exception("User {0} not associated with this {1}.".format(
                            user, "AttendedLearningPresentation"))

        if user == self.get_host():
            self.host_has_entered()

        # Get AdobeConnectUser record for this user
        ac_user = AdobeConnectUser.objects.get(fn_user__id=user.id)

        # This learner may have become an attendee after the host has
        # entered and therefore they may have not been added to the meeting
        # during the original creation of resources.
        # Let's add them if necessary
        if user != self.get_host() and ac_user.last_meeting_room_entered !=\
                self.get_adobe_connect_meeting_sco_id():
            ac_user.add_to_meeting_room(adobe_connect_api,
                                        self.get_adobe_connect_meeting_sco_id(),
                                        'mini-host')

        # Let's see if this host has had their host status revoked for some
        # reason.  Perhaps they were booted from the meeting and need to get
        # back in.  They are still associated with this meeting room in the
        # host role so no need to re-add them to the meeting room.
        if ac_user.last_meeting_room_role == "revoked":
            ac_user.add_to_hosts_group(adobe_connect_api)

        return ac_user.\
            get_url_for_meeting_room(adobe_connect_api,
                                     self.get_adobe_connect_meeting_sco_id())

    # TODO integrate this with the celery task for cleaning up old sessions
    def destroy_adobe_session_resources(self):
        if adobe_connect_api is None:
            raise Exception("AdobeConnect API not available.  Check that "
                            "FN_CONNECT_ENABLED is true and that all "
                            "FN_CONNECT* environment variables are correct!")
        adobe_connect_api.\
            delete_meeting_room(self.get_adobe_connect_meeting_sco_id())

    class Meta:
        abstract = True
