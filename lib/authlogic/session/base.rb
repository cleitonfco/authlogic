# frozen_string_literal: true

module Authlogic
  module Session # :nodoc:
    # This is the most important class in Authlogic. You will inherit this class
    # for your own eg. `UserSession`.
    #
    # # Ongoing consolidation of modules
    #
    # We are consolidating modules into this class (inlining mixins). When we
    # are done, there will only be this one file. It will be quite large, but it
    # will be easier to trace execution.
    #
    # Once consolidation is complete, we hope to identify and extract
    # collaborating objects. For example, there may be a "session adapter" that
    # connects this class with the existing `ControllerAdapters`. Perhaps a
    # data object or a state machine will reveal itself.
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

      include Callbacks

      # Included first so that the session resets itself to nil
      include Timeout

      # Included in a specific order so they are tried in this order when persisting
      include Params
      include Cookies
      include Session
      include HttpAuth

      # Included in a specific order so magic states gets run after a record is found
      # TODO: What does "magic states gets run" mean? Be specific.
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
