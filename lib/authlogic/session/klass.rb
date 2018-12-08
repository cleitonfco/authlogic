# frozen_string_literal: true

module Authlogic
  module Session
    # Handles authenticating via a traditional username and password.
    module Klass
      def self.included(klass)
        klass.class_eval do
          extend Config
          include InstanceMethods
        end
      end

      # Class methods for configuration
      module Config
        # Lets you change which model to use for authentication.
        #
        # * <tt>Default:</tt> inferred from the class name. UserSession would
        #   automatically try User
        # * <tt>Accepts:</tt> an ActiveRecord class
        def authenticate_with(klass)
          @klass_name = klass.name
          @klass = klass
        end
        alias authenticate_with= authenticate_with

        # The name of the class that this session is authenticating with. For
        # example, the UserSession class will authenticate with the User class
        # unless you specify otherwise in your configuration. See
        # authenticate_with for information on how to change this value.
        def klass
          @klass ||= klass_name ? klass_name.constantize : nil
        end

        # The string of the model name class guessed from the actual session class name.
        def klass_name
          return @klass_name if defined?(@klass_name)
          @klass_name = name.scan(/(.*)Session/)[0]
          @klass_name = klass_name ? klass_name[0] : nil
        end
      end

      # :nodoc:
      module InstanceMethods
        private

        def klass
          self.class.klass
        end

        def klass_name
          self.class.klass_name
        end
      end
    end
  end
end
