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

      # Defines the "callback installation methods". Other modules will use
      # these class methods to install their callbacks. Examples:
      #
      # ```
      # # session/timeout.rb, in `included`
      # before_persisting :reset_stale_state
      #
      # # session/password.rb, in `included`
      # validate :validate_by_password, if: :authenticating_with_password?
      # ```
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

      # Public class methods
      # ====================

      class << self
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

      # Included first so that the session resets itself to nil
      before_persisting :reset_stale_state
      after_persisting :enforce_timeout
      attr_accessor :stale_record
      include Timeout

      # The next four modules are included in a specific order so they are
      # tried in this order when persisting

      attr_accessor :single_access
      persist :persist_by_params
      include Params

      persist :persist_by_cookie
      after_save :save_cookie
      after_destroy :destroy_cookie
      include Cookies

      persist :persist_by_session
      after_save :update_session
      after_destroy :update_session
      after_persisting :update_session, unless: :single_access?
      include Session

      persist :persist_by_http_auth, if: :persist_by_http_auth?
      include HttpAuth

      # The next three modules are included in a specific order so magic
      # states gets run after a record is found.

      validate :validate_by_password, if: :authenticating_with_password?
      class << self
        attr_accessor :configured_password_methods
      end
      include Password

      attr_accessor :unauthorized_record
      validate(
        :validate_by_unauthorized_record,
        if: :authenticating_with_unauthorized_record?
      )
      include UnauthorizedRecord

      validate :validate_magic_states, unless: :disable_magic_states?
      include MagicStates

      include Activation
      include ActiveRecordTrickery

      validate :reset_failed_login_count, if: :reset_failed_login_count?
      validate :validate_failed_logins, if: :being_brute_force_protected?
      include BruteForceProtection

      attr_accessor :new_session, :record
      include Existence

      class << self
        attr_accessor :configured_klass_methods
      end
      include Klass

      after_persisting :set_last_request_at
      validate :increase_failed_login_count
      before_save :update_info
      before_save :set_last_request_at
      include MagicColumns

      after_save :reset_perishable_token!
      include PerishableToken

      include Persistence

      attr_writer :scope
      include Scopes

      attr_writer :id
      include Id

      include Validation

      attr_accessor :priority_record
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
    end
  end
end
