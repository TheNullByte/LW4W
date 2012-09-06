require File.join(File.dirname(__FILE__), 'exploits', 'list')

class LW

@exploit = EXPLOIT_LIST
@a400 = []
@a200 = []
@a500 = []
@other = []
@badIP = []



LOG_LOCATION = 'W3SVC1/u_ex120827.log'


@myFile = File.open(LOG_LOCATION)
@exploits = Regexp.new(@exploit.join("|"))
@myFile.each {|line|
@a400.push(line) if line =~ exploits && line =~ /\s40\d\s/
@a200.push(line) if line =~ exploits && line =~ /\s200\s/
@a500.push(line) if line =~ exploits && line =~ /\s50\d\s/
@other.push(line) if line =~ exploits && line !=~ /\s404\s/
@badIP.push(line.split(/\s/)[8]) if line =~ exploits && haxIP.include?(haxIP.push(line.split(/\s/)[8]))
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
end