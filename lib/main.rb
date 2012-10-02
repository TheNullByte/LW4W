##Logwatch for Windows version 0.0.2

require File.join(File.dirname(__FILE__), 'exploits', 'list')
require 'net/smtp'
require 'time'

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



logconcat = "u_ex" + (Time.now - 86400).strftime("%y%m%d")
LOG_LOCATION = "W3SVC1/#{logconcat}.log"

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
   x = ''
   x += "HTTP Response code 20x\n"
   x += "----------------------\n"
   @a20x.each{|a| a = a.split(/\s/); x += "    " + a[1] + " || " + a[3] + " || " + a[4] + " || " + a[8] + " || " + a[9] + "\n"}
   return x
end

def print40x
   x = ''
   x += "HTTP Response code 40x\n"
   x += "----------------------\n"
   @a40x.each do |a|
      a = a.split(/\s/)
      x += ("    " + a[1] + " || " + a[3] + " || " + a[4] + " || " + a[8] + " || " + a[9] + "\n")
      end      
   return x
end

def print50x
   x = ''
   x += "HTTP Response code 50x\n"
   x += "----------------------\n"
   @a50x.each{|a| a = a.split(/\s/); x += "    " + a[1] + " || " + a[3] + " || " + a[4] + " || " + a[8] + " || " + a[9] + "\n"}
   return x
end

def printResults time = Time.new.inspect, hostname = `hostname`
   puts "<----------             LW4W 0.0.2 (09/07/2012)             ---------->
               Date Initialized: #{time}    
               Date Analyzed:    Yesterday
               LogFiles for:     #{hostname}
               
      ####################    IIS Start     ########################
   
   The following IP's used known hacks against the system:
   "
   @badIP.each{|a| puts "--> " + a}
   puts "
   "
   puts print20x
   puts print40x
   puts print50x

end

def emailResults time = Time.new.inspect, hostname = `hostname`
   x = ''
   @badIP.each{|a| x+= "\t-->" + a + "\n"}
   ipList = x
   message = <<EOF
From: IIS SERVER <cehdtech@gmu.edu>
To: You <a.harvey@ocxsystems.com>
Subject: IIS Logs

<----------             LW4W 0.0.2 (09/07/2012)             ---------->
            Date Initialized: #{time}    
            Date Analyzed:    Yesterday
            LogFiles for:     #{hostname}
            
   ####################    IIS Start     ########################

The following IP's used known hacks against the system:

#{ipList}

#{print20x}
#{print40x}
#{print50x}
   
EOF

Net::SMTP.start('localhost') do |smtp|
   smtp.send_message message, "a.harvey@ocxsystems.com", "a.harvey@ocxsystems.com"   
end
puts "Email Successful"
end


end

LogParse = LW4W.new  
LogParse.scanLog
LogParse.printResults