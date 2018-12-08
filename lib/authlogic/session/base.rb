# frozen_string_literal: true

module Authlogic
  module Session # :nodoc:
    # This is the most important class in Authlogic. You will inherit this class
    # for your own eg. `UserSession`.
    #
    # Code is organized topically. Each topic is represented by a module. So, to
    # learn about password-based authentication, read the `Password` module.
    #
    # It is common for methods (.initialize and #credentials=, for example) to
    # be implemented in multiple mixins. Those methods will call `super`, so the
    # order of `include`s here is important.
    #
    # Also, to fully understand such a method (like #credentials=) you will need
    # to mentally combine all of its definitions. This is perhaps the primary
    # disadvantage of topical organization using modules.
    #
    # # Ongoing consolidation of modules
    #
    # As described above, a chain of half-a-dozen `super`s is hard to follow.
    # So, we are consolidating all modules into this class. When we are done,
    # there will only be this one file. It will be quite large, but it will
    # be easier to trace execution.
    #
    # Once consolidation is complete, we hope to identify and extract
    # collaborating objects. For example, there may be a "session adapter" that
    # connects this class with the existing `ControllerAdapters`. Perhaps a
    # data object or a state machine will reveal itself.
    class Base
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

      include Foundation
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
    end
  end
end
