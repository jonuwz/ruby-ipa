#!/opt/puppet/bin/ruby
require 'ipa'

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

