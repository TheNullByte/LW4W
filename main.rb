# This script is to be wrapped in ruby2exe and used to analyze and mail logs for IIS servers

# Author::  TheNullByte

exploits = [
   '^null$',
   '/\.\./\.\./\.\./',
   '\.\./\.\./config\.sys',
   '/\.\./\.\./\.\./autoexec\.bat',
   '/\.\./\.\./windows/user\.dat',
   '\\\x02\\\xb1',
   '\\\x04\\\x01',
   '\\\x05\\\x01',
   '\\\x90\\\x02\\\xb1\\\x02\\\xb1',
   '\\\x90\\\x90\\\x90\\\x90',
   '\\\xff\\\xff\\\xff\\\xff',
   '\\\xe1\\\xcd\\\x80',
   '\\\xff\xe0\\\xe8\\\xf8\\\xff\\\xff\\\xff-m',
   '\\\xc7f\\\x0c',
   '\\\x84o\\\x01',
   '\\\x81',
   '\\\xff\\\xe0\\\xe8',
   '\/c\+dir',
   '\/c\+dir\+c',
   '\.htpasswd',
   'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
   'author\.exe',
   'boot\.ini',
   'cmd\.exe',
   'c%20dir%20c',
   'default\.ida',
   'fp30reg\.dll',
   'httpodbc\.dll',
   'nsiislog\.dll',
   'passwd$',
   'root\.exe',
   'shtml\.exe',
   'win\.ini',
   'xxxxxxxxxxxxxxxxxxxxxx',
   'select',
   'union',
   'drop',
   '--',
   '`.*`',
   'script',
   '\.exe',
   '=http:\/\/',
   '=file:\/\/',
   '\.ini'
]
a400 = []
a200 = []
a500 = []
other = []
haxIP = []
LOG_LOCATION = 'W3SVC1/u_ex120827.log'


myFile = File.open(LOG_LOCATION)
exploits = Regexp.new(exploits.join("|"))
myFile.each {|line|
a400.push(line) if line =~ exploits && line =~ /\s40\d\s/
a200.push(line) if line =~ exploits && line =~ /\s200\s/
a500.push(line) if line =~ exploits && line =~ /\s50\d\s/
other.push(line) if line =~ exploits && line !=~ /\s404\s/
haxIP.push(line.split(/\s/)[8]) if line =~ exploits && haxIP.include?(haxIP.push(line.split(/\s/)[8]))
}

puts "<----------             LW4W 0.0.1 (09/01/2012)             ---------->
            Date Initialized: #{Time.new.inspect}    
            Date Analyzed:    Yesterday
            LogFiles for:     #{`hostname`}
            
   ####################    IIS Start     ########################

The following IP's used known hacks against the system:
"
haxIP.each{|a| puts "--> " + a}

puts "HTTP Response code 40x"
puts "----------------------"
a400.each{|a| a = a.split(/\s/)[8]; puts "    " + a}
