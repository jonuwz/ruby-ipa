require 'httpclient'
require 'base64'
require 'gssapi'
require 'json'

module IPAcommon

  @@IPAlist_element = {
    :hostgroup    => 'cn',
    :group        => 'cn',
    :sudocmd      => 'sudocmd',
    :sudorule     => 'cn',
    :sudocmgroup  => 'cn',
    :hbacrule     => 'cn',
    :hbacsvc      => 'cn',
    :hbacsvcgroup => 'cn',
  }

  def initialize(parent)
    @parent   = parent
    @ipaclass = self.class.name.downcase.sub(/^ipa/,'')
  end

  def post(*args)
    @parent.post(*args)
  end

  def list_element
    @@IPAlist_element[@ipaclass.to_sym]
  end

  def list
    results = []
    res = post("#{@ipaclass}_find", [[nil],{"pkey_only" => true,"sizelimit" => 0}] )
    res['result']['result'].each do |group|
      results << group[self.list_element].first
    end
    results
  end

  def show(target)
    res = post("#{@ipaclass}_show", [[target],{}] )
    res['result']['result']
  end

  def add(target,desc=nil)
   desc = target if desc.nil?
   post("#{@ipaclass}_add", [[target],{"description" => desc}] )
  end

  def del(target)
    post("#{@ipaclass}_del", [[target],{}] )
  end

end  

module IPAmembers

  @@IPAmember_element = {
    :hostgroup    => :host,
    :group        => :user,
    :sudocmdgroup => :sudocmd,
    :hbacsvcgroup => :hbacsvc,
  }
  
  def member_element
    @@IPAmember_element[@ipaclass.to_sym]
  end

  [:add, :remove ].each do |action|
    meth = "#{action}"
    define_method(meth) do |target,members|
      members = Array(members)
      post("#{@ipaclass}_#{meth}_member", [[target],{"all" => true, self.member_element => members}] )
    end
  end

  def list(target)
    res = show(target)
    res["member_#{self.member_element}"]
  end

end

class IPAhostgroup 
  include IPAcommon
  include IPAmembers
end

class IPAgroup
  include IPAcommon
  include IPAmembers
end

class IPAsudorule
  include IPAcommon

  def list_user(target,option=nil)
    res = show(target)
    if option.nil?
      { 'user' => res["memberuser_user"], 'group' => res["memberuser_group"] }
    else
      res["memberuser_#{option}"]
    end
  end

  def list_host(target,option=nil)
    res = show(target)
    if option.nil?
      { 'host' => res["memberhost_host"], 'hostgroup' => res["memberhost_hostgroup"] }
    else
      res["memberhost_#{option}"]
    end
  end

  [:allow,:deny].each do |action|
    type="#{action}cmd"
    define_method("list_#{type}") do | target, *option |
      res = show(target)
      if option[0].nil?
        { 'sudocmd' => res["#{type}_sudocmd"], 'sudocmdgroup' => res["#{type}_sudocmdgroup"] }
      else
        res["#{type}_#{option[0]}"]
      end
    end
  end

  [:user, :host, :allow_command, :deny_command].each do |cat|
    [:add, :remove ].each do |action|
      meth = "#{action}_#{cat}"
      define_method(meth) do |target,type,members|
        members = Array(members)
        post("#{@ipaclass}_#{__method__}", [[target],{type => members}] )
      end
    end
  end

  [:add, :remove ].each do |action|
    meth = "#{action}_option"
    define_method(meth) do |target,option|
      post("#{@ipaclass}_#{__method__}", [[target],{'ipasudoopt' => option}] )
    end
  end

  def mod(target,option,value)
    value = "" if value.nil?
    post("#{@ipaclass}_add_option", [[target],{"all" => true,"rights" => true, option => value}] )
  end

  def list_mod(target)
    res = show(target)
    { "usercategory"    => Array(res['usercategory']).first,
      "hostcategory"    => Array(res['hostcategory']).first,
      "cmdcategory"     => Array(res['cmdcategory']).first
    }
  end

  def list_option(target)
    res = show(target)
    res['ipasudoopt']
  end

end

class IPAsudocmd
  include IPAcommon
end

class IPAsudocmdgroup
  include IPAcommon
  include IPAmembers
end

class IPAhbacsvc
  include IPAcommon
end

class IPAhbacrule
  include IPAcommon

  def list_user(target,option=nil)
    res = show(target)
    if option.nil?
      { 'user' => res["memberuser_user"], 'group' => res["memberuser_group"] }
    else
      res["memberuser_#{option}"]
    end
  end

  def list_host(target,option=nil)
    res = show(target)
    if option.nil?
      { 'host' => res["memberhost_host"], 'hostgroup' => res["memberhost_hostgroup"] }
    else
      res["memberhost_#{option}"]
    end
  end

  def list_service(target,option=nil)
    res = show(target)
    if option.nil?
      { 'hbacsvc' => res["memberservice_hbacsvc"], 'hbacsvcgroup' => res["memberservice_hbacsvcgroup"] }
    else
      res["memberhost_#{option}"]
    end
  end

  [:user, :host, :service].each do |cat|
    [:add, :remove ].each do |action|
      meth = "#{action}_#{cat}"
      define_method(meth) do |target,type,members|
        members = Array(members)
        post("#{@ipaclass}_#{__method__}", [[target],{type => members}] )
      end
    end
  end

  def mod(target,option,value)
    value = "" if value.nil?
    post("#{@ipaclass}_add_option", [[target],{"all" => true,"rights" => true, option => value}] )
  end

  def list_mod(target)
    res = show(target)
    { "usercategory"    => Array(res['usercategory']).first,
      "hostcategory"    => Array(res['hostcategory']).first,
      "servicecategory" => Array(res['servicecategory']).first,
    }
  end

end

class IPAhbacsvcgroup
  include IPAcommon
  include IPAmembers
end

class IPA

  attr_reader :hostgroup, :group, :sudorule, :sudocmd, :sudocmdgroup, :hbacrule, :hbacsvc, :hbacsvcgroup

  def initialize(host=nil)
    host = Socket.gethostbyname(Socket.gethostname).first if host.nil?

    @gsok    = false
    @uri     = URI.parse "https://#{host}/ipa/json"
    @robot   = HTTPClient.new
    @gssapi  = GSSAPI::Simple.new(@uri.host, 'HTTP') # Get an auth token for HTTP/fqdn@REALM
                                                     # you must already have a TGT (kinit admin)
    token    = @gssapi.init_context                  # Base64 encode it and shove it in the http header

    @robot.ssl_config.set_trust_ca('/etc/ipa/ca.crt')

    @extheader = { 
      "referer"       => "https://ipa.auto.local/ipa",
      "Content-Type"  => "application/json",
      "Accept"        => "applicaton/json",
      "Authorization" => "Negotiate #{Base64.strict_encode64(token)}",
    }

    @hostgroup    = IPAhostgroup.new(self)
    @group        = IPAgroup.new(self)
    @sudorule     = IPAsudorule.new(self)
    @sudocmd      = IPAsudocmd.new(self)
    @sudocmdgroup = IPAsudocmdgroup.new(self)
    @hbacrule     = IPAhbacrule.new(self)
    @hbacsvc      = IPAhbacsvc.new(self)
    @hbacsvcgroup = IPAhbacsvcgroup.new(self)
  end

  def post(method,params) 
    payload = { "method" => method, "params" => params }
    resp    = @robot.post(@uri, JSON.dump(payload), @extheader)

    # lets look at the response header and see if kerberos liked our auth
    # only do this once since the context is established on success. 

    itok    = resp.header["WWW-Authenticate"].pop.split(/\s+/).last
    @gsok   = @gssapi.init_context(Base64.strict_decode64(itok)) unless @gsok

    if @gsok and resp.status == 200
      result = JSON.parse(resp.content)
      puts "--------OOOOOOOOOPS #{result['error']['message']}" if !result['error'].nil?
      result
    else
      puts "failed"
      nil
    end
  end

end

ipa = IPA.new

# use firebug while using the IPA website to get more useful shizzle
# hostgroups
ipa.hostgroup.remove('sensu_servers','sensu.auto.local') 
puts "Should not contain sunsu_servers : "
p ipa.hostgroup.list('sensu_servers')
ipa.hostgroup.add('sensu_servers','sensu.auto.local') 
puts "Should     contain sunsu_servers : "
p ipa.hostgroup.list('sensu_servers')

p ipa.sudorule.list
p ipa.sudorule.list_user('john')
p ipa.sudorule.list_host('john')
ipa.sudorule.remove_option('john','!authenticate')
p ipa.sudorule.list_option('john')
ipa.sudorule.add_option('john','!authenticate')
p ipa.sudorule.list_option('john')

p ipa.hbacrule.list
p ipa.sudorule.list
p ipa.sudocmd.list
ipa.sudocmd.add('/usr/bin/grep')
p ipa.sudocmd.list
ipa.sudorule.remove_allow_command('puppet server admin','sudocmd','/usr/bin/grep')
p ipa.sudorule.list_allowcmd('puppet server admin')
ipa.sudorule.add_allow_command('puppet server admin','sudocmd','/usr/bin/grep')
p ipa.sudorule.list_allowcmd('puppet server admin')
ipa.hbacsvc.add('john')
p ipa.hbacsvc.list
ipa.hbacsvc.del('john')
p ipa.hbacsvc.list
p ipa.hbacsvcgroup.list('remote unix access')
ipa.hbacsvcgroup.add('remote unix access','kdm')
p ipa.hbacsvcgroup.list('remote unix access')
ipa.hbacsvcgroup.remove('remote unix access','kdm')
p ipa.hbacsvcgroup.list('remote unix access')

p ipa.hbacrule.list_host('remote unix access - all')
p ipa.hbacrule.list_user('remote unix access - all')
p ipa.hbacrule.list_service('remote unix access - all')
p ipa.hbacrule.list_mod('remote unix access - all')
ipa.hbacrule.add_service('remote unix access - all','hbacsvc','gdm')
p ipa.hbacrule.list_service('remote unix access - all')
ipa.hbacrule.remove_service('remote unix access - all','hbacsvc','gdm')
p ipa.hbacrule.list_service('remote unix access - all')

# FIN
