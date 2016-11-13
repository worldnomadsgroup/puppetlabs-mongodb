require 'openssl'
require 'base64'

require File.expand_path(File.join(File.dirname(__FILE__), '..', 'mongodb'))
Puppet::Type.type(:mongodb_user).provide(:mongodb, :parent => Puppet::Provider::Mongodb) do

  desc "Manage users for a MongoDB database."

  defaultfor :kernel => 'Linux'

  def self.instances
    require 'json'

    if db_ismaster
      if mongo_24?
        dbs = JSON.parse mongo_eval('printjson(db.getMongo().getDBs()["databases"].map(function(db){return db["name"]}))') || 'admin'

        allusers = []

        dbs.each do |db|
          users = JSON.parse mongo_eval('printjson(db.system.users.find().toArray())', db)

          allusers += users.collect do |user|
              new(:name          => user['_id'],
                  :ensure        => :present,
                  :username      => user['user'],
                  :database      => db,
                  :roles         => user['roles'].sort,
                  :password_hash => user['pwd'])
          end
        end
        return allusers
      else
        # On MongoDB 3.0+ with auth enabled and no users created, the user cannot look up existing users, so we 
        # need to check for auth failure to detect whether the user is missing.
        # Assumption: .mongorc.js being created as it's required with auth enabled to store saved credentials.
        allusersmissing = false
        if auth_enabled and mongorc_file
          authcheck = mongo_eval('', 'admin', 1, nil, false)
          if authcheck =~ /Error\: Authentication failed/
            allusersmissing = true
          end
        end

        if allusersmissing
          return []
        else
          users = JSON.parse mongo_eval('printjson(db.system.users.find().toArray())')

          users.collect do |user|
              if user['credentials']['MONGODB-CR']
                password_mechanism = :'MONGODB-CR'
                password_hash = user['credentials']['MONGODB-CR']
                password_settings = nil
              elsif user['credentials']['SCRAM-SHA-1']
                password_mechanism = :'SCRAM-SHA-1'
                password_hash = nil
                password_settings = {
                  :stored_key => user['credentials']['SCRAM-SHA-1']['storedKey'],
                  :salt => user['credentials']['SCRAM-SHA-1']['salt'],
                  :iterations => user['credentials']['SCRAM-SHA-1']['iterationCount']
                }
              else
                password_mechanism = nil
                password_hash = nil
                password_settings = nil
              end

              new(:name               => user['_id'],
                  :ensure             => :present,
                  :username           => user['user'],
                  :database           => user['db'],
                  :roles              => from_roles(user['roles'], user['db']),
                  :password_hash      => password_hash,
                  :password_mechanism => password_mechanism,
                  :password_settings  => password_settings)
          end
        end
      end
    else
      Puppet.warning 'User info is available only from master host'
      return []
    end
  end

  # Assign prefetched users based on username and database, not on id and name
  def self.prefetch(resources)
    users = instances
    resources.each do |name, resource|
      if provider = users.find { |user| user.username == resource[:username] and user.database == resource[:database] }
        resources[name].provider = provider
      end
    end
  end

  mk_resource_methods

  def create
    if db_ismaster
      if mongo_24?
        user = {
          :user => @resource[:username],
          :pwd => @resource[:password_hash],
          :roles => @resource[:roles]
        }

        mongo_eval("db.addUser(#{user.to_json})", @resource[:database])
      else
        if @resource[:database] == '$external'
          cmd_json=<<-EOS.gsub(/^\s*/, '').gsub(/$\n/, '')
          {
            "createUser": "#{@resource[:username]}",
            "customData": {"createdBy": "Puppet Mongodb_user['#{@resource[:name]}']"},
            "roles": #{@resource[:roles].to_json},
          }
          EOS
          mongo_eval("db.getSiblingDB('#{@resource[:database]}').runCommand(#{cmd_json})", 'admin')
        else
          cmd_json=<<-EOS.gsub(/^\s*/, '').gsub(/$\n/, '')
          {
            "createUser": "#{@resource[:username]}",
            "pwd": "#{@resource[:password_hash]}",
            "customData": {"createdBy": "Puppet Mongodb_user['#{@resource[:name]}']"},
            "roles": #{@resource[:roles].to_json},
            "digestPassword": false
          }
          EOS
          mongo_eval("db.getSiblingDB('#{@resource[:database]}').runCommand(#{cmd_json})", @resource[:database])
        end
      end

      @property_hash[:ensure] = :present
      @property_hash[:username] = @resource[:username]
      @property_hash[:database] = @resource[:database]
      @property_hash[:password_hash] = ''
      @property_hash[:roles] = @resource[:roles]

      exists? ? (return true) : (return false)
    else
      Puppet.warning 'User creation is available only from master host'
    end
  end


  def destroy
    if db_ismaster
      if mongo_24?
        mongo_eval("db.removeUser('#{@resource[:username]}')")
      else
        mongo_eval("db.getSiblingDB('#{@resource[:database]}').dropUser('#{@resource[:username]}')")
      end
    else
      mongo_eval("db.getSiblingDB('#{@resource[:database]}').dropUser('#{@resource[:username]}')")
    end
  end

  def exists?
    !(@property_hash[:ensure] == :absent or @property_hash[:ensure].nil?)
  end

  def password_hash=(value)
    if db_ismaster
      if @resource[:database] != '$external'
        cmd_json=<<-EOS.gsub(/^\s*/, '').gsub(/$\n/, '')
        {
            "updateUser": "#{@resource[:username]}",
            "pwd": "#{@resource[:password_hash]}",
            "digestPassword": false
        }
        EOS
        mongo_eval("db.runCommand(#{cmd_json})", @resource[:database])
      else
        Puppet.warning 'User password cannot be changed on external users'
      end
    else
      Puppet.warning 'User password operations are available only from master host'
    end
  end

  def roles=(roles)
    if db_ismaster
      if mongo_24?
        mongo_eval("db.system.users.update({user:'#{@resource[:username]}'}, { $set: {roles: #{@resource[:roles].to_json}}})")
      else
        grant = roles-@property_hash[:roles]
        if grant.length > 0
          mongo_eval("db.getSiblingDB('#{@resource[:database]}').grantRolesToUser('#{@resource[:username]}', #{grant.to_json})")
        end

        revoke = @property_hash[:roles]-roles
        if revoke.length > 0
          mongo_eval("db.getSiblingDB('#{@resource[:database]}').revokeRolesFromUser('#{@resource[:username]}', #{revoke.to_json})")
        end
      end
    else
      Puppet.warning 'User roles operations are available only from master host'
    end
  end

  def generate_storedkey(hashedPassword, salt, iterations)
    pbkdf2 = OpenSSL::PKCS5::pbkdf2_hmac_sha1(
      hashedPassword,
      Base64.decode64(salt),
      iterations,
      20)

    hmac = OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha1'), pbkdf2, "Client Key")

    sha1 = OpenSSL::Digest.new('sha1')
    storedKey = sha1.digest(hmac)

    Base64.strict_encode64(storedKey)
  end

  private

  def self.from_roles(roles, db)
    roles.map do |entry|
        if entry['db'] == db
            entry['role']
        else
            { 'role' => entry['role'], 'db' => entry['db'] }
        end
      end.sort_by { |entry| entry.kind_of?(String) ? ['', entry] : [entry['db'], entry['role']] }
  end

end
