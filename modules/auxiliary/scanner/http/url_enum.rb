##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##
require 'msf/core'
require 'net/http'
class Metasploit3 < Msf::Auxiliary
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner
	include Msf::Exploit::Remote::Tcp
	def initialize(info = {})
		super(update_info(info,
			'Name' => 'URL Enumerator',
			'Description' => %q{
					This module uses Bing to enumerate URLs from a specified range of IP addresses.
			},
			'Author' => [ 'Royce Davis <royce[dot]davis[at]cliftonlarsonallen.com>' ],
			'License' => MSF_LICENSE,
			'Version' => '$Revision: 14755 $'))
	
			deregister_options('RHOST','RPORT','VHOST')
	end
	
	def run_host(ip)

		urls = []
        	datastore['RHOST'] = 'www.bing.com'
        	datastore['RPORT'] = 80

        	# We cannot use HttpClient to send a query to bing.com,
        	# because there is a bug in get_once that keeps bailing on us before finishing
        	# getting the data. get_once is the actual function used to receive HTTP data
        	# for send_request_cgi().  See the following ticket for details:
        	# http://dev.metasploit.com/redmine/issues/6499#note-11

        	connect
        	req = %Q|GET /search?q=ip:#{ip} HTTP/1.1\nHost: #{datastore['RHOST']}\nAccept: */*\n
        	|

        	req = req.gsub(/^\t\t/, '')
        	sock.put(req)
        	res = sock.get(-1, 1)
		#res.gsub!(/<.?strong?[>]*>/, "")
		res.to_s.scan(/(<cite>[a-z0-9]+(?:[\-\.])[a-z0-9]+(?:[\-\.])[a-z]{3,5})/) do |url|
			url = url.to_s.gsub(/<cite>/, '')
			urls << url
			print_good("#{url}")
		end

		unless urls.empty?
			report_note(
				:host => ip,
				:data => urls,
				:type => 'URL'
			)
		end
    end
end
