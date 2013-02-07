##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
	# Exploit mixins should be called first
	include Msf::Exploit::Remote::SMB
	include Msf::Exploit::Remote::SMB::Authenticated
	include Msf::Exploit::Remote::DCERPC
	# Scanner mixin should be near last
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report


	def initialize
		super(
			'Name'        => 'SMB Domain User Enumeration',
			'Version'     => '$Revision $',
			'Description' => 'Determine what domain users are logged into a remote system via a DCERPC to NetWkstaUserEnum.',
			'Author'      => 'natron',
			'References'  =>
				[
					[ 'URL', 'http://msdn.microsoft.com/en-us/library/aa370669%28VS.85%29.aspx' ]
				],
			'License'     => MSF_LICENSE
		)
		deregister_options('RPORT', 'RHOST')
	end

	def run_host(ip)
		datastore['RPORT'] = 445
		datastore['SMBDirect'] = true
		begin
			connect()
			smb_login()
			uuid = ['4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0']
			handle = dcerpc_handle(uuid[0], uuid[1], 'ncacn_np', ["\\srvsvc"])
			begin
				dcerpc_bind(handle)
				stub =
					NDR.uwstring("\\\\" + ip) +	# Server Name
					NDR.long(102) +				# Level
					NDR.long(1)  				# ptr to return buff
				dcerpc.call(0x15, stub)
				resp = dcerpc.last_response
				puts resp.stub_data.unpack("V*")
				puts resp.stub_data[50,(resp.stub_data.size - 70)]
				puts resp.stub_data[(resp.stub_data.size - 30), resp.stub_data.size]
				puts resp.raw
			rescue ::Rex::Proto::SMB::Exceptions::ErrorCode => bad
				print_error("Error: #{bad.error_code}")
			end
			disconnect()
		rescue ::Exception
			print_error("Main error: #{$!.to_s}")
		end
	end

end
