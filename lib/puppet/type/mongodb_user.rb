Puppet::Type.newtype(:mongodb_user) do
  @doc = 'Manage a MongoDB user. This includes management of users password as well as privileges.'

  ensurable

  def initialize(*args)
    super
    # Sort roles array before comparison.
    self[:roles] = Array(self[:roles])\
      .sort_by! { |entry| entry.kind_of?(String) ? ['', entry] : (entry.kind_of?(NilClass) ? ['', ''] : [entry['db'], entry['role']]) }
  end

  newparam(:name, :namevar=>true) do
    desc "The name of the resource."
  end

  newproperty(:username) do
    desc "The name of the user."
    defaultto { @resource[:name] }
  end

  newproperty(:database) do
    desc "The user's target database."
    defaultto do
      fail("Parameter 'database' must be set") if provider.database == :absent
    end
    newvalues(/^(\$external|\w+)$/)
  end

  newparam(:tries) do
    desc "The maximum amount of two second tries to wait MongoDB startup."
    defaultto 10
    newvalues(/^\d+$/)
    munge do |value|
      Integer(value)
    end
  end

  newproperty(:roles, :array_matching => :all) do
    desc "The user's roles."
    defaultto ['dbAdmin']

    def insync?(is)
      raise Puppet::Error, "Invalid value for attribute :roles, must be an array" unless @should.is_a?(Array)

      if is == nil
        if @should.count { |entry| entry != nil } > 0
          return false
        else @should.count { |entry| entry != nil } == 0
          return true
        end
      end

      sorted_should = @should\
        .drop_while { |entry| entry == nil }\
        .sort_by { |entry| entry.kind_of?(String) ? ['', entry] : (entry.kind_of?(NilClass) ? ['', ''] : [entry['db'], entry['role']]) }
      sorted_is = is\
        .drop_while { |entry| entry == nil }\
        .sort_by { |entry| entry.kind_of?(String) ? ['', entry] : (entry.kind_of?(NilClass) ? ['', ''] : [entry['db'], entry['role']]) }

      (sorted_is.length == sorted_should.length) and (sorted_is.zip(sorted_should).all? { |a, b| role_matches?(a, b) })
    end

    def role_matches?(current, desired)
      if current.kind_of?(String) and desired.kind_of?(String)
        current.casecmp(desired) == 0
      elsif current.kind_of?(Hash) and desired.kind_of?(Hash)
        current['db'].casecmp(desired['db']) == 0 and current['role'].casecmp(desired['role']) == 0
      else
        false
      end
    end

    # Pretty output for arrays.
    def should_to_s(value)
      value.inspect
    end

    def is_to_s(value)
      value.inspect
    end
  end

  newproperty(:password_hash) do
    desc "The password hash of the user. Use mongodb_password() for creating hash."
    defaultto do
      fail("Property 'password_hash' must be set. Use mongodb_password() for creating hash.") if provider.database == :absent and @resource[:database] != '$external'
    end
    newvalue(/^\w+$/)
    
    def insync?(is)
      if provider and provider.password_mechanism == :'SCRAM-SHA-1'
        existingKey = provider.password_settings[:stored_key]
        desiredKey = provider.generate_storedkey(@should[0], provider.password_settings[:salt], provider.password_settings[:iterations])
        existingKey == desiredKey
      else
        super(is)
      end
    end
  end

  newparam(:password_mechanism) do
    desc "The password mechanism of the existing user.  Valid values are MONGODB-CR and SCRAM-SHA-1."
    newvalues(:'MONGODB-CR', :'SCRAM-SHA-1')
  end

  newparam(:password_settings) do
    desc "The existing password settings for SCRAM-SHA-1 for the existing user."
  end

  autorequire(:package) do
    'mongodb_client'
  end

  autorequire(:service) do
    'mongodb'
  end

end
