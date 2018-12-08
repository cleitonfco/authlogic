# frozen_string_literal: true

module Authlogic
  module Session
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
    module Timeout
      def self.included(klass)
        klass.class_eval do
          include InstanceMethods
          before_persisting :reset_stale_state
          after_persisting :enforce_timeout
          attr_accessor :stale_record
        end
      end

      # :nodoc:
      module InstanceMethods
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

        private

        def reset_stale_state
          self.stale_record = nil
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
      end
    end
  end
end
