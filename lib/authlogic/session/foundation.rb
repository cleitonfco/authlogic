# frozen_string_literal: true

module Authlogic
  module Session
    # Sort of like an interface, it sets the foundation for the class, such as the
    # required methods. This also allows other modules to overwrite methods and call super
    # on them. It's also a place to put "utility" methods used throughout Authlogic.
    module Foundation
      def self.included(klass)
        klass.class_eval do
          include InstanceMethods
        end
      end

      # :nodoc:
      module InstanceMethods
        private

        def build_key(last_part)
          last_part
        end
      end
    end
  end
end
