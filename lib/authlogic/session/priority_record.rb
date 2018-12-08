# frozen_string_literal: true

module Authlogic
  module Session
    # This module supports ActiveRecord's optimistic locking feature, which is
    # automatically enabled when a table has a `lock_version` column.
    #
    # ```
    # # https://api.rubyonrails.org/classes/ActiveRecord/Locking/Optimistic.html
    # p1 = Person.find(1)
    # p2 = Person.find(1)
    # p1.first_name = "Michael"
    # p1.save
    # p2.first_name = "should fail"
    # p2.save # Raises an ActiveRecord::StaleObjectError
    # ```
    #
    # Now, consider the following Authlogic scenario:
    #
    # ```
    # User.log_in_after_password_change = true
    # ben = User.find(1)
    # UserSession.create(ben)
    # ben.password = "newpasswd"
    # ben.password_confirmation = "newpasswd"
    # ben.save
    # ```
    #
    # We've used one of Authlogic's session maintenance features,
    # `log_in_after_password_change`. So, when we call `ben.save`, there is a
    # `before_save` callback that logs Ben in (`UserSession.find`). Well, when
    # we log Ben in, we update his user record, eg. `login_count`. When we're
    # done logging Ben in, then the normal `ben.save` happens. So, there were
    # two `update` queries. If those two updates came from different User
    # instances, we would get a `StaleObjectError`.
    #
    # Our solution is to carefully pass around a single `User` instance, using
    # it for all `update` queries, thus avoiding the `StaleObjectError`.
    #
    # @api private
    module PriorityRecord
    end
  end
end
