require 'puppet'
require 'puppet/type/mongodb_user'
describe Puppet::Type.type(:mongodb_user) do

  before :each do
    @user = Puppet::Type.type(:mongodb_user).new(
              :name => 'test',
              :database => 'testdb',
              :password_hash => 'pass')
  end

  it 'should accept a user name' do
    expect(@user[:name]).to eq('test')
  end

  it 'should accept a database name' do
    expect(@user[:database]).to eq('testdb')
  end

  it 'should accept a tries parameter' do
    @user[:tries] = 5
    expect(@user[:tries]).to eq(5)
  end

  it 'should accept a password' do
    @user[:password_hash] = 'foo'
    expect(@user[:password_hash]).to eq('foo')
  end

  it 'should use default role' do
    expect(@user[:roles]).to eq(['dbAdmin'])
  end

  it 'should accept a String roles array' do
    @user[:roles] = [ 'role1', 'role2' ]
    expect(@user[:roles]).to eq([ 'role1', 'role2' ])
  end

  it 'should accept a Hash roles array' do
    @user[:roles] = [ { 'role' => 'role1', 'db' => 'admin' }, { 'role' => 'role2', 'db' => 'admin' } ]
    expect(@user[:roles]).to eq([ { 'role' => 'role1', 'db' => 'admin' }, { 'role' => 'role2', 'db' => 'admin' } ])
  end

  it 'should accept a mixed roles array' do
    @user[:roles] = [ { 'role' => 'role1', 'db' => 'admin' }, 'role2' ]
    expect(@user[:roles]).to eq([ { 'role' => 'role1', 'db' => 'admin' }, 'role2' ])
  end

  it 'should require a name' do
    expect {
      Puppet::Type.type(:mongodb_user).new({})
    }.to raise_error(Puppet::Error, 'Title or name must be provided')
  end

  it 'should require a database' do
    expect {
      Puppet::Type.type(:mongodb_user).new({:name => 'test', :password_hash => 'pass'})
    }.to raise_error(Puppet::Error, 'Parameter \'database\' must be set')
  end

  it 'should require a password_hash' do
    expect {
      Puppet::Type.type(:mongodb_user).new({:name => 'test', :database => 'testdb'})
    }.to raise_error(Puppet::Error, 'Property \'password_hash\' must be set. Use mongodb_password() for creating hash.')
  end

  it 'should sort databaseless roles' do
    # Reinitialize type with explicit unsorted roles.
    @user = Puppet::Type.type(:mongodb_user).new(
              :name => 'test',
              :database => 'testdb',
              :password_hash => 'pass',
              :roles => [ 'b', 'a' ])
    expect(@user[:roles]).to eq([ 'a', 'b' ])
  end

  it 'should sort database roles' do
    # Reinitialize type with explicit unsorted roles.
    @user = Puppet::Type.type(:mongodb_user).new(
              :name => 'test',
              :database => 'testdb',
              :password_hash => 'pass',
              :roles => [ { 'role' => 'b', 'db' => 'admin' }, { 'role' => 'a', 'db' => 'admin' } ])
    expect(@user[:roles]).to eq([ { 'role' => 'a', 'db' => 'admin' }, { 'role' => 'b', 'db' => 'admin' } ])
  end

  roles_property = Puppet::Type.type(:mongodb_user)::Roles

  describe roles_property do
    before :each do
      @user = Puppet::Type.type(:mongodb_user).new(
                :name => 'test',
                :database => 'testdb',
                :password_hash => 'pass')
      @property = @user.property(:roles)
    end

    it "should be insync? if the String roles are the same" do
      @property.should = ['userAdmin', 'dbAdmin']
      expect(@property.insync?(['userAdmin', 'dbAdmin'])).to eq(true)
    end

    it "should not be insync? if the String roles are different" do
      @property.should = ['userAdmin', 'dbAdmin']
      expect(@property.insync?(['userAdmin'])).to eq(false)
    end

    it "should be insync? if the Hash roles are the same" do
      @property.should = [ { 'role' => 'userAdmin', 'db' => 'admin' }, { 'role' => 'dbAdmin', 'db' => 'admin' } ]
      expect(@property.insync?([ { 'role' => 'userAdmin', 'db' => 'admin' }, { 'role' => 'dbAdmin', 'db' => 'admin' } ])).to eq(true)
    end

    it "should not be insync? if the Hash roles are different" do
      @property.should = [ { 'role' => 'userAdmin', 'db' => 'admin' }, { 'role' => 'dbAdmin', 'db' => 'admin' } ]
      expect(@property.insync?([ { 'role' => 'userAdmin', 'db' => 'admin' }, { 'role' => 'dbAdmin', 'db' => 'different_database' } ])).to eq(false)
    end

    it "should be insync? if the mixed roles are the same" do
      @property.should = [ { 'role' => 'userAdmin', 'db' => 'admin' }, 'dbAdmin' ]
      expect(@property.insync?([ { 'role' => 'userAdmin', 'db' => 'admin' }, 'dbAdmin' ])).to eq(true)
    end

    it "should not be insync? if the mixed roles are different" do
      @property.should = [ { 'role' => 'userAdmin', 'db' => 'admin' }, 'dbAdmin' ]
      expect(@property.insync?([ { 'role' => 'userAdmin', 'db' => 'admin' }, 'different_role' ])).to eq(false)
    end

    it "should be insync? if the roles are nil" do
      @property.should = nil
      expect(@property.insync?(nil)).to eq(true)
    end

    it "should not be insync? if the roles are different" do
      @property.should = [ 'dbAdmin' ]
      expect(@property.insync?(nil)).to eq(false)
    end
  end

end
