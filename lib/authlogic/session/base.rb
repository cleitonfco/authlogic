# frozen_string_literal: true

module Authlogic
  module Session # :nodoc:
    # This is the most important class in Authlogic. You will inherit this class
    # for your own eg. `UserSession`.
    #
    # Ongoing consolidation of modules
    # ================================
    #
    # We are consolidating modules into this class (inlining mixins). When we
    # are done, there will only be this one file. It will be quite large, but it
    # will be easier to trace execution.
    #
    # Once consolidation is complete, we hope to identify and extract
    # collaborating objects. For example, there may be a "session adapter" that
    # connects this class with the existing `ControllerAdapters`. Perhaps a
    # data object or a state machine will reveal itself.
    #
    # Callbacks
    # =========
    #
    # Between these callbacks and the configuration, this is the contract between me and
    # you to safely modify Authlogic's behavior. I will do everything I can to make sure
    # these do not change.
    #
    # Check out the sub modules of Authlogic::Session. They are very concise, clear, and
    # to the point. More importantly they use the same API that you would use to extend
    # Authlogic. That being said, they are great examples of how to extend Authlogic and
    # add / modify behavior to Authlogic. These modules could easily be pulled out into
    # their own plugin and become an "add on" without any change.
    #
    # Now to the point of this module. Just like in ActiveRecord you have before_save,
    # before_validation, etc. You have similar callbacks with Authlogic, see the METHODS
    # constant below. The order of execution is as follows:
    #
    #   before_persisting
    #   persist
    #   after_persisting
    #   [save record if record.has_changes_to_save?]
    #
    #   before_validation
    #   before_validation_on_create
    #   before_validation_on_update
    #   validate
    #   after_validation_on_update
    #   after_validation_on_create
    #   after_validation
    #   [save record if record.has_changes_to_save?]
    #
    #   before_save
    #   before_create
    #   before_update
    #   after_update
    #   after_create
    #   after_save
    #   [save record if record.has_changes_to_save?]
    #
    #   before_destroy
    #   [save record if record.has_changes_to_save?]
    #   after_destroy
    #
    # Notice the "save record if has_changes_to_save" lines above. This helps with performance. If
    # you need to make changes to the associated record, there is no need to save the
    # record, Authlogic will do it for you. This allows multiple modules to modify the
    # record and execute as few queries as possible.
    #
    # **WARNING**: unlike ActiveRecord, these callbacks must be set up on the class level:
    #
    #   class UserSession < Authlogic::Session::Base
    #     before_validation :my_method
    #     validate :another_method
    #     # ..etc
    #   end
    #
    # You can NOT define a "before_validation" method, this is bad practice and does not
    # allow Authlogic to extend properly with multiple extensions. Please ONLY use the
    # method above.
    #
    # Timeout
    # =======
    #
    # Think about financial websites, if you are inactive for a certain period
    # of time you will be asked to log back in on your next request. You can do
    # this with Authlogic easily, there are 2 parts to this:
    #
    # 1. Define the timeout threshold:
    #
    #   acts_as_authentic do |c|
    #     c.logged_in_timeout = 10.minutes # default is 10.minutes
    #   end
    #
    # 2. Enable logging out on timeouts
    #
    #   class UserSession < Authlogic::Session::Base
    #     logout_on_timeout true # default if false
    #   end
    #
    # This will require a user to log back in if they are inactive for more than
    # 10 minutes. In order for this feature to be used you must have a
    # last_request_at datetime column in your table for whatever model you are
    # authenticating with.
    #
    # Params
    # ======
    #
    # This module is responsible for authenticating the user via params, which ultimately
    # allows the user to log in using a URL like the following:
    #
    #   https://www.domain.com?user_credentials=4LiXF7FiGUppIPubBPey
    #
    # Notice the token in the URL, this is a single access token. A single access token is
    # used for single access only, it is not persisted. Meaning the user provides it,
    # Authlogic grants them access, and that's it. If they want access again they need to
    # provide the token again. Authlogic will *NEVER* try to persist the session after
    # authenticating through this method.
    #
    # For added security, this token is *ONLY* allowed for RSS and ATOM requests. You can
    # change this with the configuration. You can also define if it is allowed dynamically
    # by defining a single_access_allowed? method in your controller. For example:
    #
    #   class UsersController < ApplicationController
    #     private
    #       def single_access_allowed?
    #         action_name == "index"
    #       end
    #
    # Also, by default, this token is permanent. Meaning if the user changes their
    # password, this token will remain the same. It will only change when it is explicitly
    # reset.
    #
    # You can modify all of this behavior with the Config sub module.
    class Base
      extend Authlogic::Config
      include ActiveSupport::Callbacks

      E_AC_PARAMETERS = <<~EOS
        Passing an ActionController::Parameters to Authlogic is not allowed.

        In Authlogic 3, especially during the transition of rails to Strong
        Parameters, it was common for Authlogic users to forget to `permit`
        their params. They would pass their params into Authlogic, we'd call
        `to_h`, and they'd be surprised when authentication failed.

        In 2018, people are still making this mistake. We'd like to help them
        and make authlogic a little simpler at the same time, so in Authlogic
        3.7.0, we deprecated the use of ActionController::Parameters. Instead,
        pass a plain Hash. Please replace:

            UserSession.new(user_session_params)
            UserSession.create(user_session_params)

        with

            UserSession.new(user_session_params.to_h)
            UserSession.create(user_session_params.to_h)

        And don't forget to `permit`!

        We discussed this issue thoroughly between late 2016 and early
        2018. Notable discussions include:

        - https://github.com/binarylogic/authlogic/issues/512
        - https://github.com/binarylogic/authlogic/pull/558
        - https://github.com/binarylogic/authlogic/pull/577
      EOS
      VALID_SAME_SITE_VALUES = [nil, "Lax", "Strict"].freeze

      # Callbacks
      # =========

      METHODS = %w[
        before_persisting
        persist
        after_persisting
        before_validation
        before_validation_on_create
        before_validation_on_update
        validate
        after_validation_on_update
        after_validation_on_create
        after_validation
        before_save
        before_create
        before_update
        after_update
        after_create
        after_save
        before_destroy
        after_destroy
      ].freeze

      # Defines the "callback installation methods" used below.
      METHODS.each do |method|
        class_eval <<-EOS, __FILE__, __LINE__ + 1
            def self.#{method}(*filter_list, &block)
              set_callback(:#{method}, *filter_list, &block)
            end
        EOS
      end

      # Defines session life cycle events that support callbacks.
      define_callbacks(
        *METHODS,
        terminator: ->(_target, result_lambda) { result_lambda.call == false }
      )
      define_callbacks(
        "persist",
        terminator: ->(_target, result_lambda) { result_lambda.call == true }
      )

      # Use the "callback installation methods" defined above
      # -----------------------------------------------------

      before_persisting :reset_stale_state

      # `persist` callbacks, in order of priority
      persist :persist_by_params
      persist :persist_by_cookie
      persist :persist_by_session
      persist :persist_by_http_auth, if: :persist_by_http_auth?

      after_persisting :enforce_timeout
      after_persisting :update_session, unless: :single_access?
      after_persisting :set_last_request_at

      before_save :update_info
      before_save :set_last_request_at

      after_save :reset_perishable_token!
      after_save :save_cookie
      after_save :update_session

      after_destroy :destroy_cookie
      after_destroy :update_session

      # `validate` callbacks, in deliberate order. For example,
      # validate_magic_states must run *after* a record is found.
      validate :validate_by_password, if: :authenticating_with_password?
      validate(
        :validate_by_unauthorized_record,
        if: :authenticating_with_unauthorized_record?
      )
      validate :validate_magic_states, unless: :disable_magic_states?
      validate :reset_failed_login_count, if: :reset_failed_login_count?
      validate :validate_failed_logins, if: :being_brute_force_protected?
      validate :increase_failed_login_count

      # Accessors
      # =========

      class << self
        attr_accessor(
          :configured_password_methods,
          :configured_klass_methods
        )
      end
      attr_accessor(
        :new_session,
        :priority_record,
        :record,
        :single_access,
        :stale_record,
        :unauthorized_record
      )
      attr_writer(
        :scope,
        :id
      )

      # Public class methods
      # ====================

      class << self
        # The name of the cookie or the key in the cookies hash. Be sure and use
        # a unique name. If you have multiple sessions and they use the same
        # cookie it will cause problems. Also, if a id is set it will be
        # inserted into the beginning of the string. Example:
        #
        #   session = UserSession.new
        #   session.cookie_key => "user_credentials"
        #
        #   session = UserSession.new(:super_high_secret)
        #   session.cookie_key => "super_high_secret_user_credentials"
        #
        # * <tt>Default:</tt> "#{klass_name.underscore}_credentials"
        # * <tt>Accepts:</tt> String
        def cookie_key(value = nil)
          rw_config(:cookie_key, value, "#{klass_name.underscore}_credentials")
        end
        alias cookie_key= cookie_key

        # If sessions should be remembered by default or not.
        #
        # * <tt>Default:</tt> false
        # * <tt>Accepts:</tt> Boolean
        def remember_me(value = nil)
          rw_config(:remember_me, value, false)
        end
        alias remember_me= remember_me

        # The length of time until the cookie expires.
        #
        # * <tt>Default:</tt> 3.months
        # * <tt>Accepts:</tt> Integer, length of time in seconds, such as 60 or 3.months
        def remember_me_for(value = nil)
          rw_config(:remember_me_for, value, 3.months)
        end
        alias remember_me_for= remember_me_for

        # Should the cookie be set as secure?  If true, the cookie will only be sent over
        # SSL connections
        #
        # * <tt>Default:</tt> true
        # * <tt>Accepts:</tt> Boolean
        def secure(value = nil)
          rw_config(:secure, value, true)
        end
        alias secure= secure

        # Should the cookie be set as httponly?  If true, the cookie will not be
        # accessible from javascript
        #
        # * <tt>Default:</tt> true
        # * <tt>Accepts:</tt> Boolean
        def httponly(value = nil)
          rw_config(:httponly, value, true)
        end
        alias httponly= httponly

        # Should the cookie be prevented from being send along with cross-site
        # requests?
        #
        # * <tt>Default:</tt> nil
        # * <tt>Accepts:</tt> String, one of nil, 'Lax' or 'Strict'
        def same_site(value = nil)
          unless VALID_SAME_SITE_VALUES.include?(value)
            msg = "Invalid same_site value: #{value}. Valid: #{VALID_SAME_SITE_VALUES.inspect}"
            raise ArgumentError, msg
          end
          rw_config(:same_site, value)
        end
        alias same_site= same_site

        # Should the cookie be signed? If the controller adapter supports it, this is a
        # measure against cookie tampering.
        def sign_cookie(value = nil)
          if value && !controller.cookies.respond_to?(:signed)
            raise "Signed cookies not supported with #{controller.class}!"
          end
          rw_config(:sign_cookie, value, false)
        end
        alias sign_cookie= sign_cookie

        # With acts_as_authentic you get a :logged_in_timeout configuration
        # option. If this is set, after this amount of time has passed the user
        # will be marked as logged out. Obviously, since web based apps are on a
        # per request basis, we have to define a time limit threshold that
        # determines when we consider a user to be "logged out". Meaning, if
        # they login and then leave the website, when do mark them as logged
        # out? I recommend just using this as a fun feature on your website or
        # reports, giving you a ballpark number of users logged in and active.
        # This is not meant to be a dead accurate representation of a user's
        # logged in state, since there is really no real way to do this with web
        # based apps. Think about a user that logs in and doesn't log out. There
        # is no action that tells you that the user isn't technically still
        # logged in and active.
        #
        # That being said, you can use that feature to require a new login if
        # their session times out. Similar to how financial sites work. Just set
        # this option to true and if your record returns true for stale? then
        # they will be required to log back in.
        #
        # Lastly, UserSession.find will still return an object if the session is
        # stale, but you will not get a record. This allows you to determine if
        # the user needs to log back in because their session went stale, or
        # because they just aren't logged in. Just call
        # current_user_session.stale? as your flag.
        #
        # * <tt>Default:</tt> false
        # * <tt>Accepts:</tt> Boolean
        def logout_on_timeout(value = nil)
          rw_config(:logout_on_timeout, value, false)
        end
        alias logout_on_timeout= logout_on_timeout

        # Works exactly like cookie_key, but for params. So a user can login via
        # params just like a cookie or a session. Your URL would look like:
        #
        #   http://www.domain.com?user_credentials=my_single_access_key
        #
        # You can change the "user_credentials" key above with this
        # configuration option. Keep in mind, just like cookie_key, if you
        # supply an id the id will be appended to the front. Check out
        # cookie_key for more details. Also checkout the "Single Access /
        # Private Feeds Access" section in the README.
        #
        # * <tt>Default:</tt> cookie_key
        # * <tt>Accepts:</tt> String
        def params_key(value = nil)
          rw_config(:params_key, value, cookie_key)
        end
        alias params_key= params_key

        # Works exactly like cookie_key, but for sessions. See cookie_key for more info.
        #
        # * <tt>Default:</tt> cookie_key
        # * <tt>Accepts:</tt> Symbol or String
        def session_key(value = nil)
          rw_config(:session_key, value, cookie_key)
        end
        alias session_key= session_key

        # Authentication is allowed via a single access token, but maybe this is
        # something you don't want for your application as a whole. Maybe this
        # is something you only want for specific request types. Specify a list
        # of allowed request types and single access authentication will only be
        # allowed for the ones you specify.
        #
        # * <tt>Default:</tt> ["application/rss+xml", "application/atom+xml"]
        # * <tt>Accepts:</tt> String of a request type, or :all or :any to
        #   allow single access authentication for any and all request types
        def single_access_allowed_request_types(value = nil)
          rw_config(
            :single_access_allowed_request_types,
            value,
            ["application/rss+xml", "application/atom+xml"]
          )
        end
        alias single_access_allowed_request_types= single_access_allowed_request_types
      end

      # Public instance methods
      # =======================

      def initialize(*args)
        @id = nil
        self.scope = self.class.scope

        # Creating an alias method for the "record" method based on the klass
        # name, so that we can do:
        #
        #   session.user
        #
        # instead of:
        #
        #   session.record
        unless self.class.configured_klass_methods
          self.class.send(:alias_method, klass_name.demodulize.underscore.to_sym, :record)
          self.class.configured_klass_methods = true
        end

        raise NotActivatedError unless self.class.activated?
        unless self.class.configured_password_methods
          configure_password_methods
          self.class.configured_password_methods = true
        end
        instance_variable_set("@#{password_field}", nil)
        self.credentials = args
      end

      # The credentials you passed to create your session. See credentials= for
      # more info.
      def credentials
        if authenticating_with_unauthorized_record?
          # Returning meaningful credentials
          details = {}
          details[:unauthorized_record] = "<protected>"
          details
        elsif authenticating_with_password?
          # Returns the login_field / password_field credentials combination in
          # hash form.
          details = {}
          details[login_field.to_sym] = send(login_field)
          details[password_field.to_sym] = "<protected>"
          details
        else
          []
        end
      end

      # Set your credentials before you save your session. There are many
      # method signatures.
      #
      # ```
      # # A hash of credentials is most common
      # session.credentials = { login: "foo", password: "bar", remember_me: true }
      #
      # # You must pass an actual Hash, `ActionController::Parameters` is
      # # specifically not allowed.
      #
      # # You can pass an array of objects:
      # session.credentials = [my_user_object, true]
      #
      # # If you need to set an id (see `Authlogic::Session::Id`) pass it
      # # last. It needs be the last item in the array you pass, since the id
      # # is something that you control yourself, it should never be set from
      # # a hash or a form. Examples:
      # session.credentials = [
      #   {:login => "foo", :password => "bar", :remember_me => true},
      #   :my_id
      # ]
      # session.credentials = [my_user_object, true, :my_id]
      #
      # # Finally, there's priority_record
      # [{ priority_record: my_object }, :my_id]
      # ```
      def credentials=(value)
        normalized = Array.wrap(value)
        if normalized.first.class.name == "ActionController::Parameters"
          raise TypeError, E_AC_PARAMETERS
        end

        # Allows you to set the remember_me option when passing credentials.
        values = value.is_a?(Array) ? value : [value]
        case values.first
        when Hash
          if values.first.with_indifferent_access.key?(:remember_me)
            self.remember_me = values.first.with_indifferent_access[:remember_me]
          end
        else
          r = values.find { |val| val.is_a?(TrueClass) || val.is_a?(FalseClass) }
          self.remember_me = r unless r.nil?
        end

        # Accepts the login_field / password_field credentials combination in
        # hash form.
        #
        # You must pass an actual Hash, `ActionController::Parameters` is
        # specifically not allowed.
        #
        # See `Authlogic::Session::Foundation#credentials=` for an overview of
        # all method signatures.
        values = Array.wrap(value)
        if values.first.is_a?(Hash)
          sliced = values
            .first
            .with_indifferent_access
            .slice(login_field, password_field)
          sliced.each do |field, val|
            next if val.blank?
            send("#{field}=", val)
          end
        end

        # Setting the unauthorized record if it exists in the credentials passed.
        values = value.is_a?(Array) ? value : [value]
        self.unauthorized_record = values.first if values.first.class < ::ActiveRecord::Base

        # Setting the id if it is passed in the credentials.
        values = value.is_a?(Array) ? value : [value]
        self.id = values.last if values.last.is_a?(Symbol)

        # Setting priority record if it is passed. The only way it can be passed
        # is through an array:
        #
        #   session.credentials = [real_user_object, priority_user_object]
        values = value.is_a?(Array) ? value : [value]
        self.priority_record = values[1] if values[1].class < ::ActiveRecord::Base
      end

      def inspect
        format(
          "#<%s: %s>",
          self.class.name,
          credentials.blank? ? "no credentials provided" : credentials.inspect
        )
      end

      def save_record(alternate_record = nil)
        r = alternate_record || record
        if r != priority_record
          if r&.has_changes_to_save? && !r.readonly?
            r.save_without_session_maintenance(validate: false)
          end
        end
      end

      # Tells you if the record is stale or not. Meaning the record has timed
      # out. This will only return true if you set logout_on_timeout to true
      # in your configuration. Basically how a bank website works. If you
      # aren't active over a certain period of time your session becomes stale
      # and requires you to log back in.
      def stale?
        if remember_me?
          remember_me_expired?
        else
          !stale_record.nil? || (logout_on_timeout? && record && record.logged_out?)
        end
      end

      # Is the cookie going to expire after the session is over, or will it stick around?
      def remember_me
        return @remember_me if defined?(@remember_me)
        @remember_me = self.class.remember_me
      end

      # Accepts a boolean as a flag to remember the session or not. Basically
      # to expire the cookie at the end of the session or keep it for
      # "remember_me_until".
      def remember_me=(value)
        @remember_me = value
      end

      # See remember_me
      def remember_me?
        remember_me == true || remember_me == "true" || remember_me == "1"
      end

      # How long to remember the user if remember_me is true. This is based on the class
      # level configuration: remember_me_for
      def remember_me_for
        return unless remember_me?
        self.class.remember_me_for
      end

      # When to expire the cookie. See remember_me_for configuration option to change
      # this.
      def remember_me_until
        return unless remember_me?
        remember_me_for.from_now
      end

      # Has the cookie expired due to current time being greater than remember_me_until.
      def remember_me_expired?
        return unless remember_me?
        (Time.parse(cookie_credentials[2]) < Time.now)
      end

      # If the cookie should be marked as secure (SSL only)
      def secure
        return @secure if defined?(@secure)
        @secure = self.class.secure
      end

      # Accepts a boolean as to whether the cookie should be marked as secure.  If true
      # the cookie will only ever be sent over an SSL connection.
      def secure=(value)
        @secure = value
      end

      # See secure
      def secure?
        secure == true || secure == "true" || secure == "1"
      end

      # If the cookie should be marked as httponly (not accessible via javascript)
      def httponly
        return @httponly if defined?(@httponly)
        @httponly = self.class.httponly
      end

      # Accepts a boolean as to whether the cookie should be marked as
      # httponly.  If true, the cookie will not be accessible from javascript
      def httponly=(value)
        @httponly = value
      end

      # See httponly
      def httponly?
        httponly == true || httponly == "true" || httponly == "1"
      end

      # If the cookie should be marked as SameSite with 'Lax' or 'Strict' flag.
      def same_site
        return @same_site if defined?(@same_site)
        @same_site = self.class.same_site(nil)
      end

      # Accepts nil, 'Lax' or 'Strict' as possible flags.
      def same_site=(value)
        unless VALID_SAME_SITE_VALUES.include?(value)
          msg = "Invalid same_site value: #{value}. Valid: #{VALID_SAME_SITE_VALUES.inspect}"
          raise ArgumentError, msg
        end
        @same_site = value
      end

      # If the cookie should be signed
      def sign_cookie
        return @sign_cookie if defined?(@sign_cookie)
        @sign_cookie = self.class.sign_cookie
      end

      # Accepts a boolean as to whether the cookie should be signed.  If true
      # the cookie will be saved and verified using a signature.
      def sign_cookie=(value)
        @sign_cookie = value
      end

      # See sign_cookie
      def sign_cookie?
        sign_cookie == true || sign_cookie == "true" || sign_cookie == "1"
      end

      include HttpAuth
      include Password
      include UnauthorizedRecord
      include MagicStates
      include Activation
      include ActiveRecordTrickery
      include BruteForceProtection
      include Existence
      include Klass
      include MagicColumns
      include PerishableToken
      include Persistence
      include Scopes
      include Id
      include Validation
      include PriorityRecord

      # Private class methods
      # =====================

      # Private instance methods
      # ========================

      private

      # Used for things like cookie_key, session_key, etc.
      # Examples:
      # - user_credentials
      # - ziggity_zack_user_credentials
      #   - ziggity_zack is an "id"
      #   - see persistence_token_test.rb
      def build_key(last_part)
        [id, scope[:id], last_part].compact.join("_")
      end

      def enforce_timeout
        if stale?
          self.stale_record = record
          self.record = nil
        end
      end

      def logout_on_timeout?
        self.class.logout_on_timeout == true
      end

      def params_credentials
        controller.params[params_key]
      end

      def params_enabled?
        if !params_credentials || !klass.column_names.include?("single_access_token")
          return false
        end
        if controller.responds_to_single_access_allowed?
          return controller.single_access_allowed?
        end
        params_enabled_by_allowed_request_types?
      end

      def params_enabled_by_allowed_request_types?
        case single_access_allowed_request_types
        when Array
          single_access_allowed_request_types.include?(controller.request_content_type) ||
            single_access_allowed_request_types.include?(:all)
        else
          %i[all any].include?(single_access_allowed_request_types)
        end
      end

      def params_key
        build_key(self.class.params_key)
      end

      def persist_by_params
        return false unless params_enabled?
        self.unauthorized_record = search_for_record(
          "find_by_single_access_token",
          params_credentials
        )
        self.single_access = valid?
      end

      def reset_stale_state
        self.stale_record = nil
      end

      def single_access?
        single_access == true
      end

      def single_access_allowed_request_types
        self.class.single_access_allowed_request_types
      end

      def cookie_key
        build_key(self.class.cookie_key)
      end

      # Returns an array of cookie elements. See cookie format in
      # `generate_cookie_for_saving`. If no cookie is found, returns nil.
      def cookie_credentials
        cookie = cookie_jar[cookie_key]
        cookie&.split("::")
      end

      # The third element of the cookie indicates whether the user wanted
      # to be remembered (Actually, it's a timestamp, `remember_me_until`)
      # See cookie format in `generate_cookie_for_saving`.
      def cookie_credentials_remember_me?
        !cookie_credentials.nil? && !cookie_credentials[2].nil?
      end

      def cookie_jar
        if self.class.sign_cookie
          controller.cookies.signed
        else
          controller.cookies
        end
      end

      # Tries to validate the session from information in the cookie
      def persist_by_cookie
        persistence_token, record_id = cookie_credentials
        if persistence_token.present?
          record = search_for_record("find_by_#{klass.primary_key}", record_id)
          if record && record.persistence_token == persistence_token
            self.unauthorized_record = record
          end
          valid?
        else
          false
        end
      end

      def save_cookie
        if sign_cookie?
          controller.cookies.signed[cookie_key] = generate_cookie_for_saving
        else
          controller.cookies[cookie_key] = generate_cookie_for_saving
        end
      end

      def generate_cookie_for_saving
        value = format(
          "%s::%s%s",
          record.persistence_token,
          record.send(record.class.primary_key),
          remember_me? ? "::#{remember_me_until.iso8601}" : ""
        )
        {
          value: value,
          expires: remember_me_until,
          secure: secure,
          httponly: httponly,
          same_site: same_site,
          domain: controller.cookie_domain
        }
      end

      def destroy_cookie
        controller.cookies.delete cookie_key, domain: controller.cookie_domain
      end

      # Tries to validate the session from information in the session
      def persist_by_session
        persistence_token, record_id = session_credentials
        if !persistence_token.nil?
          record = persist_by_session_search(persistence_token, record_id)
          if record && record.persistence_token == persistence_token
            self.unauthorized_record = record
          end
          valid?
        else
          false
        end
      end

      # Allow finding by persistence token, because when records are created
      # the session is maintained in a before_save, when there is no id.
      # This is done for performance reasons and to save on queries.
      def persist_by_session_search(persistence_token, record_id)
        if record_id.nil?
          search_for_record("find_by_persistence_token", persistence_token.to_s)
        else
          search_for_record("find_by_#{klass.primary_key}", record_id.to_s)
        end
      end

      # @api private
      # @return [String] - Examples:
      # - user_credentials_id
      # - ziggity_zack_user_credentials_id
      #   - ziggity_zack is an "id", see `Authlogic::Session::Id`
      #   - see persistence_token_test.rb
      def session_compound_key
        "#{session_key}_#{klass.primary_key}"
      end

      def session_credentials
        [
          controller.session[session_key],
          controller.session[session_compound_key]
        ].collect { |i| i.nil? ? i : i.to_s }.compact
      end

      # @return [String] - Examples:
      # - user_credentials
      # - ziggity_zack_user_credentials
      #   - ziggity_zack is an "id", see `Authlogic::Session::Id`
      #   - see persistence_token_test.rb
      def session_key
        build_key(self.class.session_key)
      end

      def update_session
        update_session_set_persistence_token
        update_session_set_primary_key
      end

      # Updates the session, setting the primary key (usually `id`) of the
      # record.
      #
      # @api private
      def update_session_set_primary_key
        compound_key = session_compound_key
        controller.session[compound_key] = record && record.send(record.class.primary_key)
      end

      # Updates the session, setting the `persistence_token` of the record.
      #
      # @api private
      def update_session_set_persistence_token
        controller.session[session_key] = record && record.persistence_token
      end
    end
  end
end
