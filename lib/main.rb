require File.join(File.dirname(__FILE__), 'exploits', 'list')

class LW4W

attr_accessor :exploits, :a40x, :a20x, :a50x, :other, :badIP

def initialize
   @exploits = Regexp.new(EXPLOIT_LIST.join("|"))
   @a40x = []
   @a20x = []
   @a50x = []
   @other = []
   @badIP = []
end

LOG_LOCATION = 'W3SVC1/u_ex120827.log'

def hack20x? line
   return line =~ @exploits && line =~ /\s200\s/
end

def hack40x? line
   return line =~ @exploits && line =~ /\s40\d\s/
end

def hack50x? line
   return line =~ @exploits && line =~ /\s50\d\s/
end

def exploited? line
   return line =~ @exploits
end

def scanLog logfile = LOG_LOCATION
   @myFile = File.open(logfile)
   @myFile.each {|line|
      @a40x.push(line) if  hack40x?(line)
      @a20x.push(line) if hack20x?(line)
      @a50x.push(line) if hack50x?(line)
      @other.push(line) if exploited?(line) && !hack20x?(line) && !hack50x?(line) && !hack40x?(line)
      @badIP.push(line.split(/\s/)[8]) if exploited?(line) && !@badIP.include?(line.split(/\s/)[8])
   }
end

def print20x
   puts "HTTP Response code 20x"
   puts "----------------------"
   @a20x.each{|a| a = a.split(/\s/); puts "    " + a[1] + " || " + a[3] + " || " + a[4] + " || " + a[8] + " || " + a[9]}
end

def print40x
   puts "HTTP Response code 40x"
   puts "----------------------"
   @a40x.each{|a| a = a.split(/\s/); puts "    " + a[1] + " || " + a[3] + " || " + a[4] + " || " + a[8] + " || " + a[9]}
end

def print50x
   puts "HTTP Response code 50x"
   puts "----------------------"
   @a50x.each{|a| a = a.split(/\s/); puts "    " + a[1] + " || " + a[3] + " || " + a[4] + " || " + a[8] + " || " + a[9]}
end

def printResults time = Time.new.inspect, hostname = `hostname`
   puts "<----------             LW4W 0.0.1 (09/01/2012)             ---------->
               Date Initialized: #{time}    
               Date Analyzed:    Yesterday
               LogFiles for:     #{hostname}
               
      ####################    IIS Start     ########################
   
   The following IP's used known hacks against the system:
   "
   @badIP.each{|a| puts "--> " + a}
   puts "
   "
   print20x
   print40x
   print50x

end


end

LogParse = LW4W.new
LogParse.scanLog
LogParse.printResults